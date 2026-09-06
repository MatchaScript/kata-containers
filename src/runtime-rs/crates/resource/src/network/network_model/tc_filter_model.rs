// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use netlink_packet_route::tc::{
    TcAction, TcActionAttribute, TcActionMirror, TcActionMirrorOption, TcActionOption,
    TcActionPedit, TcActionPeditOption, TcActionType, TcFilterU32Option, TcMirror,
    TcMirrorActionType, TcPedit, TcPeditCmd, TcPeditHeaderType, TcPeditKey, TcPeditKeyEx,
    TcPeditKeyExOption, TcU32Key, TcU32Selector, TcU32SelectorFlags,
};
use rtnetlink::Handle;
use scopeguard::defer;

use super::{NetworkModel, NetworkModelType};
use crate::network::{utils, NetworkPair};

const QDISC_ADD_ATTEMPTS: u64 = 5; // Number of attempts when adding an ingress qdisc
const QDISC_ADD_BACKOFF_MS: u64 = 10; // Base delay for the linear backoff between qdisc add retries on EBUSY

#[derive(Debug)]
pub(crate) struct TcFilterModel {}

impl TcFilterModel {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[async_trait]
impl NetworkModel for TcFilterModel {
    fn model_type(&self) -> NetworkModelType {
        NetworkModelType::TcFilter
    }

    async fn add(&self, pair: &NetworkPair) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection().context("new connection")?;
        let thread_handler = tokio::spawn(connection);

        defer!({
            thread_handler.abort();
        });

        let tap_index = fetch_index(&handle, pair.tap.tap_iface.name.as_str())
            .await
            .context("fetch tap by index")?;
        let virt_index = fetch_index(&handle, pair.virt_iface.name.as_str())
            .await
            .context("fetch virt by index")?;

        add_ingress_qdisc(&handle, tap_index as i32)
            .await
            .context("add tap ingress")?;

        add_ingress_qdisc(&handle, virt_index as i32)
            .await
            .context("add virt ingress")?;

        let (tap_options, virt_options) = redirect_pair(pair, tap_index, virt_index)?;

        handle
            .traffic_filter(tap_index as i32)
            .add()
            .parent(0xffff0000)
            // get protocol with network byte order
            .protocol(0x0003_u16.to_be())
            .u32(&tap_options)?
            .execute()
            .await
            .context("add redirect for tap")?;

        handle
            .traffic_filter(virt_index as i32)
            .add()
            .parent(0xffff0000)
            // get protocol with network byte order
            .protocol(0x0003_u16.to_be())
            .u32(&virt_options)?
            .execute()
            .await
            .context("add redirect for virt")?;

        Ok(())
    }

    async fn del(&self, pair: &NetworkPair) -> Result<()> {
        let (connection, handle, _) = rtnetlink::new_connection().context("new connection")?;
        let thread_handler = tokio::spawn(connection);
        defer!({
            thread_handler.abort();
        });
        let virt_index = fetch_index(&handle, &pair.virt_iface.name).await?;
        handle.qdisc().del(virt_index as i32).execute().await?;
        Ok(())
    }
}

/// The two pedit keys rewriting the destination MAC of the ethernet header.
/// The kernel applies `*ptr = (*ptr & mask) ^ val` on the raw packet word at
/// `off`, so both fields carry the bytes in packet order. The second word
/// also holds the first two bytes of the source MAC, which the mask keeps.
fn eth_dst_keys(mac: &[u8; 6]) -> Vec<TcPeditKey> {
    vec![
        pedit_key(0, 0, u32::from_ne_bytes([mac[0], mac[1], mac[2], mac[3]])),
        pedit_key(
            4,
            u32::from_ne_bytes([0, 0, 0xff, 0xff]),
            u32::from_ne_bytes([mac[4], mac[5], 0, 0]),
        ),
    ]
}

// TcPeditKey is #[non_exhaustive], so it can only be built from its default.
fn pedit_key(off: u32, mask: u32, val: u32) -> TcPeditKey {
    let mut key = TcPeditKey::default();
    key.off = off;
    key.mask = mask;
    key.val = val;
    key
}

/// `action pedit ex munge eth dst set <mac> pipe`
fn pedit_eth_dst_action(mac: &[u8; 6]) -> TcAction {
    let keys = eth_dst_keys(mac);
    let keys_ex = vec![
        TcPeditKeyEx::Key(vec![
            TcPeditKeyExOption::HeaderType(TcPeditHeaderType::Eth),
            TcPeditKeyExOption::Cmd(TcPeditCmd::Set),
        ]);
        keys.len()
    ];

    let mut parms = TcPedit::default();
    parms.generic.action = TcActionType::Pipe;
    parms.nkeys = keys.len() as u8;
    parms.keys = keys;

    let mut action = TcAction::default();
    action.attributes = vec![
        TcActionAttribute::Kind(TcActionPedit::KIND.to_string()),
        TcActionAttribute::Options(vec![
            TcActionOption::Pedit(TcActionPeditOption::KeysEx(keys_ex)),
            TcActionOption::Pedit(TcActionPeditOption::ParmsEx(parms)),
        ]),
    ];
    action
}

/// `action mirred egress redirect dev <dst_index>`
fn mirred_redirect_action(dst_index: u32) -> TcAction {
    let mut mirror = TcMirror::default();
    mirror.generic.action = TcActionType::Stolen;
    mirror.eaction = TcMirrorActionType::EgressRedir;
    mirror.ifindex = dst_index;

    let mut action = TcAction::default();
    action.attributes = vec![
        TcActionAttribute::Kind(TcActionMirror::KIND.to_string()),
        TcActionAttribute::Options(vec![TcActionOption::Mirror(TcActionMirrorOption::Parms(
            mirror,
        ))]),
    ];
    action
}

/// `u32 match u8 0 0 [action pedit ex munge eth dst set <dst_mac> pipe]
/// action mirred egress redirect dev <dst_index>`, the same selector and
/// mirred action that `rtnetlink`'s `redirect()` builds.
fn redirect_options(dst_index: u32, dst_mac: Option<[u8; 6]>) -> Vec<TcFilterU32Option> {
    let mut selector = TcU32Selector::default();
    selector.flags = TcU32SelectorFlags::Terminal;
    selector.nkeys = 1;
    selector.keys = vec![TcU32Key::default()];

    let mut actions = Vec::new();
    if let Some(mac) = dst_mac {
        actions.push(pedit_eth_dst_action(&mac));
    }
    actions.push(mirred_redirect_action(dst_index));

    // The kernel reads the action nest as an array indexed by attribute
    // type, so each action has to carry its own 1-based position: leaving
    // them all at the default TCA_ACT_TAB makes the last one overwrite the
    // others and only that one is installed.
    for (i, action) in actions.iter_mut().enumerate() {
        action.tab = i as u16 + 1;
    }

    vec![
        TcFilterU32Option::Selector(selector),
        TcFilterU32Option::Action(actions),
    ]
}

/// The u32 filter options of the tap ingress redirect and of the virt
/// ingress redirect, in that order.
///
/// A netkit in L3 mode has an all-zero MAC and its stack only accepts frames
/// addressed to it, while the guest NIC has a real one. Rewrite the
/// destination MAC in both directions so that neither side drops the frame
/// as PACKET_OTHERHOST.
fn redirect_pair(
    pair: &NetworkPair,
    tap_index: u32,
    virt_index: u32,
) -> Result<(Vec<TcFilterU32Option>, Vec<TcFilterU32Option>)> {
    let (to_guest, to_host) = if pair.l3 {
        let mac = utils::parse_mac(&pair.tap.tap_iface.hard_addr)
            .ok_or_else(|| anyhow!("invalid mac {}", pair.tap.tap_iface.hard_addr))?;
        (Some(mac.0), Some([0u8; 6]))
    } else {
        (None, None)
    };

    Ok((
        redirect_options(virt_index, to_host),
        redirect_options(tap_index, to_guest),
    ))
}

/// Add an ingress qdisc to the device at the given index, retrying on EBUSY
/// with linear backoff (10ms, 20ms, ...).
async fn add_ingress_qdisc(handle: &Handle, index: i32) -> Result<(), rtnetlink::Error> {
    let mut last_err = handle.qdisc().add(index).ingress().execute().await;
    for i in 1..QDISC_ADD_ATTEMPTS {
        match &last_err {
            Ok(()) => return Ok(()),
            Err(e) if !is_ebusy(e) => break,
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(QDISC_ADD_BACKOFF_MS * i)).await;
        last_err = handle.qdisc().add(index).ingress().execute().await;
    }
    last_err
}

fn is_ebusy(err: &rtnetlink::Error) -> bool {
    match err {
        rtnetlink::Error::NetlinkError(msg) => msg.code.is_some_and(|c| c.get() == -libc::EBUSY),
        _ => false,
    }
}

pub async fn fetch_index(handle: &Handle, name: &str) -> Result<u32> {
    let link = crate::network::network_pair::get_link_by_name(handle, name)
        .await
        .context("get link by name")?;
    let base = link.attrs();
    Ok(base.index)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use netlink_packet_core::Emitable;

    use super::*;
    use crate::network::network_pair::{NetworkInterface, TapInterface};

    fn emit_key(key: &TcPeditKey) -> [u8; 24] {
        let mut buf = [0u8; 24];
        key.emit(&mut buf);
        buf
    }

    #[test]
    fn test_eth_dst_keys() {
        // `pedit ex munge eth dst set c6:1b:39:d1:b3:a0`: the MAC bytes go
        // out in packet order, and the second key keeps the two bytes of the
        // source MAC sharing its word.
        let keys = eth_dst_keys(&[0xc6, 0x1b, 0x39, 0xd1, 0xb3, 0xa0]);
        assert_eq!(keys.len(), 2);

        let key = emit_key(&keys[0]);
        assert_eq!(key[0..4], [0, 0, 0, 0]);
        assert_eq!(key[4..8], [0xc6, 0x1b, 0x39, 0xd1]);
        assert_eq!(key[8..12], 0u32.to_ne_bytes());

        let key = emit_key(&keys[1]);
        assert_eq!(key[0..4], [0, 0, 0xff, 0xff]);
        assert_eq!(key[4..8], [0xb3, 0xa0, 0, 0]);
        assert_eq!(key[8..12], 4u32.to_ne_bytes());

        // The all-zero MAC differs only in the written value.
        let keys = eth_dst_keys(&[0u8; 6]);
        let key = emit_key(&keys[0]);
        assert_eq!(key[0..8], [0, 0, 0, 0, 0, 0, 0, 0]);
        let key = emit_key(&keys[1]);
        assert_eq!(key[0..8], [0, 0, 0xff, 0xff, 0, 0, 0, 0]);
    }

    #[test]
    fn test_redirect_options() {
        let mut selector = TcU32Selector::default();
        selector.flags = TcU32SelectorFlags::Terminal;
        selector.nkeys = 1;
        selector.keys = vec![TcU32Key::default()];

        let mut mirror = TcMirror::default();
        mirror.generic.action = TcActionType::Stolen;
        mirror.eaction = TcMirrorActionType::EgressRedir;
        mirror.ifindex = 7;
        let mirred = vec![
            TcActionAttribute::Kind("mirred".to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Mirror(TcActionMirrorOption::Parms(
                mirror,
            ))]),
        ];

        // Without a MAC the filter is what rtnetlink's redirect() builds.
        let options = redirect_options(7, None);
        assert_eq!(options[0], TcFilterU32Option::Selector(selector.clone()));
        let TcFilterU32Option::Action(actions) = &options[1] else {
            panic!("expected an action list");
        };
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].attributes, mirred);

        let mut parms = TcPedit::default();
        parms.generic.action = TcActionType::Pipe;
        parms.nkeys = 2;
        parms.flags = 0;
        parms.keys = eth_dst_keys(&[0u8; 6]);
        let key_ex = TcPeditKeyEx::Key(vec![
            TcPeditKeyExOption::HeaderType(TcPeditHeaderType::Eth),
            TcPeditKeyExOption::Cmd(TcPeditCmd::Set),
        ]);
        let pedit = vec![
            TcActionAttribute::Kind("pedit".to_string()),
            TcActionAttribute::Options(vec![
                TcActionOption::Pedit(TcActionPeditOption::KeysEx(vec![key_ex.clone(), key_ex])),
                TcActionOption::Pedit(TcActionPeditOption::ParmsEx(parms)),
            ]),
        ];

        // With one, the pedit action runs first and pipes into the mirred.
        let options = redirect_options(7, Some([0u8; 6]));
        assert_eq!(options[0], TcFilterU32Option::Selector(selector));
        let TcFilterU32Option::Action(actions) = &options[1] else {
            panic!("expected an action list");
        };
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].attributes, pedit);
        assert_eq!(actions[1].attributes, mirred);
    }

    #[test]
    fn test_action_list_is_indexed() {
        // The kernel walks the action nest as an array indexed by the
        // attribute type, so the two actions have to go out as type 1 and
        // type 2. Emitting both as type 1 would install the mirred only.
        let TcFilterU32Option::Action(actions) = &redirect_options(7, Some([0u8; 6]))[1] else {
            panic!("expected an action list");
        };
        let mut buf = vec![0u8; actions.as_slice().buffer_len()];
        actions.as_slice().emit(&mut buf);

        let mut types = vec![];
        let mut offset = 0;
        while offset < buf.len() {
            let len = u16::from_ne_bytes([buf[offset], buf[offset + 1]]) as usize;
            types.push(u16::from_ne_bytes([buf[offset + 2], buf[offset + 3]]));
            offset += (len + 3) & !3;
        }
        assert_eq!(types, vec![1, 2]);
    }

    #[test]
    fn test_redirect_pair_directions() {
        fn pair(l3: bool) -> NetworkPair {
            NetworkPair {
                tap: TapInterface {
                    tap_iface: NetworkInterface {
                        hard_addr: "c6:1b:39:d1:b3:a0".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                virt_iface: NetworkInterface::default(),
                model: Arc::new(TcFilterModel::new().unwrap()),
                network_qos: false,
                l3,
                network_queues: 1,
            }
        }

        let (tap_options, virt_options) = redirect_pair(&pair(true), 3, 4).unwrap();
        // The tap ingress redirects to the netkit, which only accepts an
        // all-zero destination, ...
        assert_eq!(tap_options, redirect_options(4, Some([0u8; 6])));
        // ... and the netkit ingress redirects to the tap, where the guest
        // NIC only accepts its own MAC.
        assert_eq!(
            virt_options,
            redirect_options(3, Some([0xc6, 0x1b, 0x39, 0xd1, 0xb3, 0xa0]))
        );

        // A veth pair keeps the plain redirect in both directions.
        let (tap_options, virt_options) = redirect_pair(&pair(false), 3, 4).unwrap();
        assert_eq!(tap_options, redirect_options(4, None));
        assert_eq!(virt_options, redirect_options(3, None));
    }
}

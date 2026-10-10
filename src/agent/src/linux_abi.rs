// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::pci;
use anyhow::{Context, Result};
use cfg_if::cfg_if;
use std::str::FromStr;
// Linux ABI related constants.

#[cfg(any(target_arch = "aarch64", test))]
use std::fs;
#[cfg(any(target_arch = "aarch64", test))]
use std::path::Path;

pub const SYSFS_DIR: &str = "/sys";
#[cfg(any(
    all(target_arch = "powerpc64", target_endian = "little"),
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "x86_64",
    target_arch = "x86"
))]
// With NUMA, we need to make sure we use the correct root complex which is
// defined by the pxb-pcie driver.
pub fn create_pci_root_bus_path(root_complex: &str) -> String {
    format!("/devices/pci0000:{root_complex}")
}

/// Minimum guest PCI bus number used by pxb-pcie NUMA expander bridges in the
/// runtime (see `busNrSpacing` in createNUMAPCIeTopology).
const PXB_PCIE_ROOT_BUS_MIN: u8 = 0x20;

fn is_pxb_pcie_root_complex(segment: &str) -> bool {
    u8::from_str_radix(segment, 16)
        .map(|bus| bus >= PXB_PCIE_ROOT_BUS_MIN)
        .unwrap_or(false)
}

// Parses a device tree path into a (root_complex, PCI path) pair.
//
// Supports three formats:
//   - NUMA pxb-pcie path: "root_complex/bus/device" (e.g. "20/00/02") where
//     the first segment is a pxb-pcie guest bus number (>= 0x20) and the rest
//     form the PCI path under that root complex.
//   - Nested hot-plug path on pci0000:00: "parent/bridge/device" (e.g.
//     "02/00/01") used by OVMF Q35 networking; stays on root complex "00".
//   - Legacy path: "bus/device" (e.g. "00/02") which defaults to root complex
//     "00".
pub fn pcipath_from_dev_tree_path(dev_tree_path: &str) -> Result<(&str, pci::Path)> {
    let segments: Vec<&str> = dev_tree_path.split('/').collect();
    if segments.len() >= 3 && is_pxb_pcie_root_complex(segments[0]) {
        let root_complex = segments[0];
        let pci_part = &dev_tree_path[root_complex.len() + 1..];
        let pci_path = pci::Path::from_str(pci_part).with_context(|| {
            format!(
                "Failed to parse PCI path from NUMA path '{}'",
                dev_tree_path
            )
        })?;
        Ok((root_complex, pci_path))
    } else {
        let pci_path = pci::Path::from_str(dev_tree_path)
            .with_context(|| format!("Failed to parse PCI path from '{}'", dev_tree_path))?;
        Ok(("00", pci_path))
    }
}

// Finds the platform device that hosts the PCI root complex. The device tree
// node name varies by VMM ("pcie@..." on QEMU virt, "pci@..." on Cloud
// Hypervisor), so match on the pci0000:<root complex> child instead.
#[cfg(any(target_arch = "aarch64", test))]
fn find_platform_root_bus(platform_dir: &Path, root_complex: &str) -> Option<String> {
    let root_bus = format!("pci0000:{root_complex}");

    fs::read_dir(platform_dir)
        .ok()?
        .flatten()
        .find(|entry| entry.path().join(&root_bus).is_dir())
        .and_then(|entry| {
            Some(format!(
                "/devices/platform/{}/{}",
                entry.file_name().to_str()?,
                root_bus
            ))
        })
}

#[cfg(target_arch = "aarch64")]
pub fn create_pci_root_bus_path(root_complex: &str) -> String {
    let acpi_root_bus_path = format!("/devices/pci0000:{root_complex}");

    // check if there is pci bus path for acpi
    if fs::metadata(format!("{SYSFS_DIR}{acpi_root_bus_path}")).is_ok() {
        return acpi_root_bus_path;
    }

    find_platform_root_bus(
        Path::new(&format!("{SYSFS_DIR}/devices/platform")),
        root_complex,
    )
    .unwrap_or_else(|| format!("/devices/platform/4010000000.pcie/pci0000:{root_complex}"))
}

cfg_if! {
    if #[cfg(target_arch = "s390x")] {
        pub const CCW_ROOT_BUS_PATH: &str = "/devices/css0";
        pub const AP_ROOT_BUS_PATH: &str = "/devices/ap";
        pub const AP_SCANS_PATH: &str = "/sys/bus/ap/scans";
        pub const Z9_CRYPT_DEV_PATH: &str = "/dev/z90crypt";
    }
}

// From https://www.kernel.org/doc/Documentation/acpi/namespace.txt
// The Linux kernel's core ACPI subsystem creates struct acpi_device
// objects for ACPI namespace objects representing devices, power resources
// processors, thermal zones. Those objects are exported to user space via
// sysfs as directories in the subtree under /sys/devices/LNXSYSTM:00
pub const ACPI_DEV_PATH: &str = "/devices/LNXSYSTM";

pub const SYSFS_CPU_PATH: &str = "/sys/devices/system/cpu";
pub const SYSFS_CPU_ONLINE_PATH: &str = "/sys/devices/system/cpu/online";

pub const SYSFS_MEMORY_BLOCK_SIZE_PATH: &str = "/sys/devices/system/memory/block_size_bytes";
pub const SYSFS_MEMORY_HOTPLUG_PROBE_PATH: &str = "/sys/devices/system/memory/probe";
pub const SYSFS_MEMORY_ONLINE_PATH: &str = "/sys/devices/system/memory";

pub const SYSFS_SCSI_HOST_PATH: &str = "/sys/class/scsi_host";
pub const SYSFS_NET_PATH: &str = "/sys/class/net";

pub const SYSFS_BUS_PCI_PATH: &str = "/sys/bus/pci";

pub const SYSFS_CGROUPPATH: &str = "/sys/fs/cgroup";
pub const SYSFS_ONLINE_FILE: &str = "online";

pub const PROC_MOUNTSTATS: &str = "/proc/self/mountstats";
pub const PROC_CGROUPS: &str = "/proc/cgroups";

pub const SYSTEM_DEV_PATH: &str = "/dev";

// Linux UEvent related consts.
pub const U_EVENT_ACTION: &str = "ACTION";
pub const U_EVENT_ACTION_ADD: &str = "add";
pub const U_EVENT_ACTION_REMOVE: &str = "remove";
pub const U_EVENT_DEV_PATH: &str = "DEVPATH";
pub const U_EVENT_SUB_SYSTEM: &str = "SUBSYSTEM";
pub const U_EVENT_SEQ_NUM: &str = "SEQNUM";
pub const U_EVENT_DEV_NAME: &str = "DEVNAME";
pub const U_EVENT_INTERFACE: &str = "INTERFACE";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcipath_from_dev_tree_path_legacy() {
        let (root, path) = pcipath_from_dev_tree_path("02/01").unwrap();
        assert_eq!(root, "00");
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].slot(), 0x02);
        assert_eq!(path[1].slot(), 0x01);
    }

    #[test]
    fn test_pcipath_from_dev_tree_path_nested_ovmf() {
        let (root, path) = pcipath_from_dev_tree_path("02/00/01").unwrap();
        assert_eq!(root, "00");
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].slot(), 0x02);
        assert_eq!(path[1].slot(), 0x00);
        assert_eq!(path[2].slot(), 0x01);
    }

    #[test]
    fn test_pcipath_from_dev_tree_path_numa_pxb() {
        let (root, path) = pcipath_from_dev_tree_path("20/00/02").unwrap();
        assert_eq!(root, "20");
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].slot(), 0x00);
        assert_eq!(path[1].slot(), 0x02);
    }

    fn platform_dir(entries: &[(&str, bool)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, with_root_bus) in entries {
            let path = dir.path().join(name);
            if *with_root_bus {
                fs::create_dir_all(path.join("pci0000:00")).unwrap();
            } else {
                fs::create_dir_all(path).unwrap();
            }
        }
        dir
    }

    #[test]
    fn test_find_platform_root_bus_cloud_hypervisor() {
        let dir = platform_dir(&[("30000000.pci", true)]);
        assert_eq!(
            find_platform_root_bus(dir.path(), "00"),
            Some("/devices/platform/30000000.pci/pci0000:00".to_string())
        );
    }

    #[test]
    fn test_find_platform_root_bus_qemu_virt() {
        let dir = platform_dir(&[("4010000000.pcie", true)]);
        assert_eq!(
            find_platform_root_bus(dir.path(), "00"),
            Some("/devices/platform/4010000000.pcie/pci0000:00".to_string())
        );
    }

    #[test]
    fn test_find_platform_root_bus_skips_entries_without_root_bus() {
        let dir = platform_dir(&[("serial8250", false), ("30000000.pci", false)]);
        assert_eq!(find_platform_root_bus(dir.path(), "00"), None);
    }

    #[test]
    fn test_find_platform_root_bus_empty_or_missing_dir() {
        let dir = platform_dir(&[]);
        assert_eq!(find_platform_root_bus(dir.path(), "00"), None);
        assert_eq!(
            find_platform_root_bus(&dir.path().join("absent"), "00"),
            None
        );
    }
}

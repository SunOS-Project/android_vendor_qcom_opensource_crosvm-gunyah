/*
 * Copyright (c) 2021, 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

mod panic_hook;

use std::env;
use std::default::Default;
use std::path::{Path, PathBuf};
use std::string::String;
use std::fs::{File, OpenOptions};
use std::os::unix::io::{RawFd, FromRawFd};
use std::thread;
use std::io;
use std::fmt::{self, Display};
use std::str::FromStr;
use std::thread::JoinHandle;
use std::process;
use std::net;
use net_util::{MacAddress, Tap, TapT};
extern crate simplelog;
use simplelog::*;

extern crate android_logger;
use libc::{self, c_uint, c_int, c_char, open, O_RDWR, O_WRONLY};

use devices::virtio::{self, base_features, Block, Net};
use hypervisor::{ProtectionType};
use mmio::MmioDevice;

use base::{pagesize, AsRawDescriptor};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError, MemoryRegion};
use std::sync::Arc;
use std::convert::TryInto;

use devices::virtio::block::block::DiskOption;

use crosvm::{
    argument::{self, set_arguments, Argument},
};
use base::{FlockOperation, validate_raw_fd, flock};
use base::{ioctl_with_val, ioctl_io_nr, ioctl_with_ref, ioctl_with_mut_ref, ioctl_iow_nr, ioctl_ior_nr, ioctl_iowr_nr, SafeDescriptor, FromRawDescriptor};

use vhost::NetT;
use virtio_sys;
static VHOST_NET_PATH: &str = "/dev/vhost-net";

// Logging
#[macro_use]
extern crate log;

use log::{Level, LevelFilter};
use android_logger::{Config};

// Minijail
use minijail::Minijail;

static GH_PATH: &str = "/dev/gunyah";
static VIRTIO_BE_PATH: &str = "/dev/gh_virtio_backend_";
static TRACE_MARKER: &str = "/sys/kernel/debug/tracing/trace_marker";
// Todo: Use UAPI header files
const ASSIGN_EVENTFD: u32 = 1;
const GH_IOCTL_TYPE_V2: u32 = 0xB2;
const GH_IOCTL_TYPE_V1: u32 = 0xBC;

const VBE_ASSIGN_IRQFD: u32 = 1;

const EVENT_RESET_RQST: u32 = 2;
const EVENT_INTERRUPT_ACK: u32 = 4;
const EVENT_DRIVER_OK: u32 = 8;
const EVENT_APP_EXIT: u32 = 0x100;

const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x10;
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x14;
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x20;
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x24;
const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x30;
const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x34;
const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x38;
const VIRTIO_MMIO_QUEUE_READY: u64 = 0x44;
const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x64;
const VIRTIO_MMIO_QUEUE_DESC_LOW: u64 = 0x80;
const VIRTIO_MMIO_QUEUE_DESC_HIGH: u64 = 0x84;
const VIRTIO_MMIO_QUEUE_AVAIL_LOW: u64 = 0x90;
const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: u64 = 0x94;
const VIRTIO_MMIO_QUEUE_USED_LOW: u64 = 0xa0;
const VIRTIO_MMIO_QUEUE_USED_HIGH: u64 = 0xa4;
const VIRTIO_MMIO_STATUS: u64 = 0x70;
const VIRTIO_MMIO_STATUS_IDX: u64 = 28;

const GH_VCPU_MAX: u16 = 512;

const CROSVM_MINIJAIL_POLICY: &str = "/system_ext/etc/seccomp_policy/qcrosvm.policy";
const LOG_TAG: &str = "qcrosvm";

#[derive(Debug)]

enum BackendError {
    StrError(String),
    StrNumError{err: String, val: io::Error},
}

impl Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BackendError::*;

        match self {
            StrError(s) => write!(f, "{}", format!("Error: {}", s)),
            StrNumError{err, val} => write!(f, "{}", format!("Error: {} ({})", err, val)),
        }
    }
}

pub struct NetOption{
    ip_addr: net::Ipv4Addr,
    netmask: net::Ipv4Addr,
    mac_addr: MacAddress,
    vq_pairs: u16,
    read_only: bool,
}

struct VirtioDisk {
    disk: DiskOption,
    label: u32,
    mmio: Option<MmioDevice>,
    config_space: Option<Vec<u32>>,
}

pub struct VirtioNet {
    label: u32,
    mmio: Option<MmioDevice>,
    config_space: Option<Vec<u32>>,
}

struct Vcpu {
	id: u8,
	raw_fd: i32,
	thread_handle: Option<JoinHandle<()>>,
}

/// Aggregate of all configurable options for a block device
struct BackendConfig {
    sfd: Option<SafeDescriptor>,
    vm_sfd: Option<SafeDescriptor>,
    vm: Option<String>,
    mem: Option<GuestMemory>,
    vdisks: Vec<VirtioDisk>,
    vnet: Vec<VirtioNet>,
    vcpus: Vec<Vcpu>,
    vcpu_count: u16,
    driver_variant: u8,
    sandbox: bool,
    log_level: LevelFilter,
    network_dev: bool,
    ip_addr: Option<net::Ipv4Addr>,
    netmask: Option<net::Ipv4Addr>,
    mac_addr:Option<net_util::MacAddress>,
    vq_pairs: u16,
    vhost_net_device_path: PathBuf,
    vhost_net: bool,
    log_type: Option<String>,
}

impl Default for BackendConfig {
    fn default() -> BackendConfig {
        BackendConfig {
            vdisks: Vec::new(),
            vnet: Vec::new(),
            vm: None,
            mem: None,
            sfd: None,
	    vm_sfd: None,
	    vcpus: Vec::new(),
	    vcpu_count: 1,
	    driver_variant: 2,
            sandbox: false,
            log_level: log::LevelFilter::Info,
            network_dev: false,
            ip_addr: None,
            netmask: None,
            mac_addr: None,
            vq_pairs: 1,
            vhost_net_device_path: PathBuf::from(VHOST_NET_PATH),
            vhost_net: true,
            log_type: Some("ftrace".to_string()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct fw_name {
	_name: [::std::os::raw::c_char; 16usize],
}

#[repr(C)]
struct VirtioEventfd {
    _label: u32,
    _flags: u32,
    _queue_num: u32,
    _fd: RawFd,
}

#[repr(C)]
struct VirtioIrqfd {
    _label: u32,
    _flags: u32,
    _fd: RawFd,
    _reserved: u32,
}

#[repr(C)]
struct VirtioEvent {
    _label: u32,
    _event: u32,
    _event_data: u32,
    _reserved: u32,
}

#[repr(C)]
struct VirtioDevFeatures {
        _label: u32,
        _reserved: u32,
        _features_sel: u32,
        _features: u32,
}

#[repr(C)]
struct VirtioQueueMax {
        _label: u32,
        _reserved: u32,
        _queue_sel: u32,
        _queue_num_max: u32,
}

#[repr(C)]
struct VirtioConfigData {
        _label: u32,
        _config_size: u32,
        _config_data: *mut libc::c_char,
}

#[repr(C)]
struct VirtioQueueInfo {
        _label: u32,
        _queue_sel: u32,
        _queue_num: u32,
        _queue_ready: u32,
        _queue_desc: u64,
        _queue_driver: u64,
        _queue_device: u64,
}

#[repr(C)]
struct VirtioDriverFeatures {
        _label: u32,
        _reserved: u32,
        _features_sel: u32,
        _features: u32,
}

#[repr(C)]
struct VirtioAckReset {
        _label: u32,
        _reserved: u32,
}

/* system ioctls */
ioctl_io_nr!(GH_CREATE_VM,			GH_IOCTL_TYPE_V2, 0x01);

/* vm ioctls */
ioctl_io_nr!(GH_CREATE_VCPU,           	GH_IOCTL_TYPE_V2, 0x40);
ioctl_iow_nr!(GH_VM_SET_FW_NAME,		GH_IOCTL_TYPE_V2, 0x41, fw_name);
ioctl_ior_nr!(GH_VM_GET_FW_NAME,		GH_IOCTL_TYPE_V2, 0x42, fw_name);
ioctl_io_nr!(GH_GET_VCPU_COUNT,        	GH_IOCTL_TYPE_V2, 0x43);

/* vm ioctls for virtio backend driver */
ioctl_ior_nr!(GET_SHARED_MEMORY_SIZE_V2,   	GH_IOCTL_TYPE_V2, 0x61, u64);
ioctl_iow_nr!(IOEVENTFD_V2,                	GH_IOCTL_TYPE_V2, 0x62, VirtioEventfd);
ioctl_iow_nr!(IRQFD_V2,                    	GH_IOCTL_TYPE_V2, 0x63, VirtioIrqfd);
ioctl_iowr_nr!(WAIT_FOR_EVENT_V2,          	GH_IOCTL_TYPE_V2, 0x64, VirtioEvent);
ioctl_iow_nr!(SET_DEVICE_FEATURES_V2,      	GH_IOCTL_TYPE_V2, 0x65, VirtioDevFeatures);
ioctl_iow_nr!(SET_QUEUE_NUM_MAX_V2,        	GH_IOCTL_TYPE_V2, 0x66, VirtioQueueMax);
ioctl_iow_nr!(SET_DEVICE_CONFIG_DATA_V2,   	GH_IOCTL_TYPE_V2, 0x67, VirtioConfigData);
ioctl_iowr_nr!(GET_DRIVER_CONFIG_DATA_V2,  	GH_IOCTL_TYPE_V2, 0x68, VirtioConfigData);
ioctl_iowr_nr!(GET_QUEUE_INFO_V2,          	GH_IOCTL_TYPE_V2, 0x69, VirtioQueueInfo);
ioctl_iowr_nr!(GET_DRIVER_FEATURES_V2,     	GH_IOCTL_TYPE_V2, 0x6a, VirtioDriverFeatures);
ioctl_iowr_nr!(ACK_DRIVER_OK_V2,           	GH_IOCTL_TYPE_V2, 0x6b, u32);
ioctl_io_nr!(SET_APP_READY_V2,             	GH_IOCTL_TYPE_V2, 0x6c);
ioctl_iow_nr!(ACK_RESET_V2,                	GH_IOCTL_TYPE_V2, 0x6d, VirtioAckReset);

/* virtio backend driver ioctls for backward compatibility */
ioctl_ior_nr!(GET_SHARED_MEMORY_SIZE_V1,   	GH_IOCTL_TYPE_V1, 1, u64);
ioctl_iow_nr!(IOEVENTFD_V1,                	GH_IOCTL_TYPE_V1, 2, VirtioEventfd);
ioctl_iow_nr!(IRQFD_V1,                    	GH_IOCTL_TYPE_V1, 3, VirtioIrqfd);
ioctl_iowr_nr!(WAIT_FOR_EVENT_V1,          	GH_IOCTL_TYPE_V1, 4, VirtioEvent);
ioctl_iow_nr!(SET_DEVICE_FEATURES_V1,      	GH_IOCTL_TYPE_V1, 5, VirtioDevFeatures);
ioctl_iow_nr!(SET_QUEUE_NUM_MAX_V1,        	GH_IOCTL_TYPE_V1, 6, VirtioQueueMax);
ioctl_iow_nr!(SET_DEVICE_CONFIG_DATA_V1,   	GH_IOCTL_TYPE_V1, 7, VirtioConfigData);
ioctl_iowr_nr!(GET_DRIVER_CONFIG_DATA_V1,  	GH_IOCTL_TYPE_V1, 8, VirtioConfigData);
ioctl_iowr_nr!(GET_QUEUE_INFO_V1,          	GH_IOCTL_TYPE_V1, 9, VirtioQueueInfo);
ioctl_iowr_nr!(GET_DRIVER_FEATURES_V1,     	GH_IOCTL_TYPE_V1, 10, VirtioDriverFeatures);
ioctl_iowr_nr!(ACK_DRIVER_OK_V1,           	GH_IOCTL_TYPE_V1, 11, u32);
ioctl_io_nr!(SET_APP_READY_V1,             	GH_IOCTL_TYPE_V1, 12);
ioctl_iow_nr!(ACK_RESET_V1,                	GH_IOCTL_TYPE_V1, 13, VirtioAckReset);

/* vcpu ioctls */
ioctl_io_nr!(GH_VCPU_RUN,			GH_IOCTL_TYPE_V2, 0x80);

enum VmIoctl {
	IoEventFd,
	IrqFd,
	WaitForEvent,
	SetDeviceFeatures,
	SetQueueNumMax,
	SetDeviceConfigData,
	GetDriverConfigData,
	GetQueueInfo,
	GetDriverFeatures,
	AckDriverOk,
	AckReset
}

fn to_cmd(ioc: VmIoctl, version: u8) -> std::result::Result<u64, BackendError> {
	match version {
		2 => match ioc {
			VmIoctl::IoEventFd => Ok(IOEVENTFD_V2()),
			VmIoctl::IrqFd => Ok(IRQFD_V2()),
			VmIoctl::WaitForEvent => Ok(WAIT_FOR_EVENT_V2()),
			VmIoctl::SetDeviceFeatures => Ok(SET_DEVICE_FEATURES_V2()),
			VmIoctl::SetQueueNumMax => Ok(SET_QUEUE_NUM_MAX_V2()),
			VmIoctl::SetDeviceConfigData => Ok(SET_DEVICE_CONFIG_DATA_V2()),
			VmIoctl::GetDriverConfigData => Ok(GET_DRIVER_CONFIG_DATA_V2()),
			VmIoctl::GetQueueInfo => Ok(GET_QUEUE_INFO_V2()),
			VmIoctl::GetDriverFeatures => Ok(GET_DRIVER_FEATURES_V2()),
			VmIoctl::AckDriverOk => Ok(ACK_DRIVER_OK_V2()),
			VmIoctl::AckReset => Ok(ACK_RESET_V2()),
		}
		1 => match ioc {
			VmIoctl::IoEventFd => Ok(IOEVENTFD_V1()),
			VmIoctl::IrqFd => Ok(IRQFD_V1()),
			VmIoctl::WaitForEvent => Ok(WAIT_FOR_EVENT_V1()),
			VmIoctl::SetDeviceFeatures => Ok(SET_DEVICE_FEATURES_V1()),
			VmIoctl::SetQueueNumMax => Ok(SET_QUEUE_NUM_MAX_V1()),
			VmIoctl::SetDeviceConfigData => Ok(SET_DEVICE_CONFIG_DATA_V1()),
			VmIoctl::GetDriverConfigData => Ok(GET_DRIVER_CONFIG_DATA_V1()),
			VmIoctl::GetQueueInfo => Ok(GET_QUEUE_INFO_V1()),
			VmIoctl::GetDriverFeatures => Ok(GET_DRIVER_FEATURES_V1()),
			VmIoctl::AckDriverOk => Ok(ACK_DRIVER_OK_V1()),
			VmIoctl::AckReset => Ok(ACK_RESET_V1()),
		}
		_ => Err(BackendError::StrError(String::from("Unsupported driver variant."))),
	}
}

fn print_usage() {
    println!("qcrosvm [-l] [-s] [--disk=IMAGE_FILE,label=LABEL[,rw=[true|false],sparse=[true|false],block_size=BYTES]] --vm=VMNAME");
    println!("\n[-l] or [--log=[level=trace|debug|info|warn|error],[type=ftrace|logcat|term]]");
    println!("Default logger level: info");
    println!("Default logger type: ftrace");

}

fn new_from_rawfd(ranges: &[(GuestAddress, u64)], fd: &RawFd) -> std::result::Result<GuestMemory, GuestMemoryError> {
        // Compute the memory alignment
        let pg_size = pagesize();
        let mut regions = Vec::new();
        let mut offset = 0;

        for range in ranges {
            if range.1 % pg_size as u64 != 0 {
                return Err(GuestMemoryError::MemoryNotAligned);
            }
	    let file = Arc::new(unsafe { File::from_raw_fd(*fd) });
	    let region = MemoryRegion::new_from_file(range.1, range.0, offset, file)
	    .map_err(|e| {
            error!("{}", format!("failed to create mem region, addr:{}, size:{}. Err: {}", range.0, range.1, e));
	    ()}).expect(&format!("{}:{}", file!(), line!()));
	    regions.push(region);
	    offset += range.1 as u64;
        }

        GuestMemory::from_regions(regions)
}


fn raw_fd_from_path(path: &Path) -> std::result::Result<RawFd, ()> {
    if !path.is_file() {
        return Err(());
    }

    let raw_fd = path
        .file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .and_then(|fd_str| fd_str.parse::<c_int>().ok())
        .ok_or(())?;

    validate_raw_fd(raw_fd).map_err(|_e| {()})
}


fn create_net_devices(cfg: &mut BackendConfig) -> std::result::Result<(), BackendError> {

    if cfg.ip_addr.is_some() || cfg.netmask.is_some() || cfg.mac_addr.is_some() {

           if cfg.ip_addr.is_none() {
               println!("ip address not found");
           }
           if cfg.netmask.is_none() {
               println!("netmask not found");
           }
           if cfg.mac_addr.is_none() {
               println!("mac address not found");
           }
     }

     for vnet in &mut cfg.vnet {
	let mem = cfg.mem.as_ref().expect(&format!("{}:{}", file!(), line!()));
	let sfd :&SafeDescriptor;
	let q_size :Option<u16>;
		match cfg.driver_variant {
			1 => {sfd = cfg.sfd.as_ref().expect(&format!("{}:{}", file!(), line!())); q_size = Some(256)}
			2 => {sfd = cfg.vm_sfd.as_ref().expect(&format!("{}:{}", file!(), line!())); q_size = Some(128)}
			_ => return Err(BackendError::StrError(String::from("Unsupported driver variant.")))
		};

	if let (Some(ip_addr), Some(netmask), Some(mac_addr)) = (cfg.ip_addr, cfg.netmask, cfg.mac_addr) {
		if cfg.vhost_net {
			let ndev = virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(
				&cfg.vhost_net_device_path,
				base_features(ProtectionType::Unprotected),
				ip_addr,
				netmask,
				mac_addr,
				).map_err(|_| BackendError::StrError(String::from("vhost_net_new failed")))?;

			vnet.mmio = Some(MmioDevice::new(mem.clone(), Box::new(ndev)).expect(&format!("{}:{}", file!(), line!())));
			let mut idx = 0;
			let mmio = vnet.mmio.as_ref().expect(&format!("{}:{}", file!(), line!()));

			for e in mmio.queue_evts() {
				let event_fd = VirtioEventfd {
					_label : vnet.label,
					_flags : ASSIGN_EVENTFD,
					_queue_num : idx,
					_fd : e.as_raw_descriptor(),
				};
				idx = idx + 1;
				let ret = unsafe { ioctl_with_ref(sfd, to_cmd(VmIoctl::IoEventFd, cfg.driver_variant)
								.expect(&format!("{}:{}", file!(), line!())), &event_fd) };

				if ret < 0 {
					return Err(BackendError::StrNumError {
						err: String::from("ioeventfd ioctl failed for idx"),
						val: io::Error::last_os_error(),
					});
				}
			}

			let irq_fd = VirtioIrqfd {
				_label: vnet.label,
				_fd : mmio.interrupt_evt().unwrap().as_raw_descriptor(),
				_flags: VBE_ASSIGN_IRQFD,
				_reserved: 0,
			};

			let ret = unsafe { ioctl_with_ref(sfd, to_cmd(VmIoctl::IrqFd, cfg.driver_variant)
							.expect(&format!("{}:{}", file!(), line!())), &irq_fd) };
			if ret < 0 {
				return Err(BackendError::StrNumError {
					err: String::from("irqfd ioctl failed"),
					val: io::Error::last_os_error(),
				});
			}
		}
	}
   }
   Ok(())
}

fn create_bdev(disk: &DiskOption, q_size: Option<u16>) -> std::result::Result<Box<Block>, BackendError> {
	// Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
	let raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {

		// Safe because we will validate |raw_fd|.
		unsafe {File::from_raw_fd(raw_fd_from_path(&disk.path).map_err(|_| BackendError::StrError(String::from("raw_fd_from_path failed")))?)}
	} else {
		OpenOptions::new()
		.read(true)
		.write(!disk.read_only)
		.open(&disk.path).map_err(|_| BackendError::StrNumError {
				err: String::from("open of disk file failed"),
				val: io::Error::last_os_error(),
				})?
	};

	// Lock the disk image to prevent other crosvm instances from using it.
	let lock_op = if disk.read_only {
		FlockOperation::LockShared
	} else {
		FlockOperation::LockExclusive
	};

	flock(&raw_image, lock_op, true).map_err(|_| BackendError::StrNumError {
				err: String::from("flock on disk file failed"),
				val: io::Error::last_os_error(),
			})?;

	let disk_file = disk::create_disk_file(raw_image, disk::MAX_NESTING_DEPTH, Path::new(&disk.path)).map_err(|_| BackendError::StrNumError {
				err: String::from("create_disk_file failed"),
				val: io::Error::last_os_error(),
				})?;

	let dev = virtio::Block::new(
		base_features(ProtectionType::Unprotected) ,
		disk_file ,
		disk.read_only,
		disk.sparse,
		disk.block_size,
		None,
		None,
		q_size,
	).map_err(|_| BackendError::StrError(String::from("virtio_block_new failed")))?;

    Ok(Box::new(dev))
}

fn create_block_devices(cfg: &mut BackendConfig) -> std::result::Result<(), BackendError> {
    for vdisk in &mut cfg.vdisks {
        let mem = cfg.mem.as_ref().expect(&format!("{}:{}", file!(), line!()));
	let sfd :&SafeDescriptor;
	let q_size :Option<u16>;
	match cfg.driver_variant {
		1 => {sfd = cfg.sfd.as_ref().expect(&format!("{}:{}", file!(), line!())); q_size = Some(256)}
		2 => {sfd = cfg.vm_sfd.as_ref().expect(&format!("{}:{}", file!(), line!())); q_size = Some(128)}
		_ => return Err(BackendError::StrError(String::from("Unsupported driver variant.")))
	};

	let bdev = create_bdev(&vdisk.disk, q_size)?;
	vdisk.mmio = Some(MmioDevice::new(mem.clone(), bdev).expect(&format!("{}:{}", file!(), line!())));

        let mut idx = 0;
        let mmio = vdisk.mmio.as_ref().expect(&format!("{}:{}", file!(), line!()));
        for e in mmio.queue_evts() {
            let event_fd = VirtioEventfd {
                _label : vdisk.label,
                _flags : ASSIGN_EVENTFD,
                _queue_num : idx,
                _fd : e.as_raw_descriptor(),
            };
            idx = idx + 1;
            let ret = unsafe { ioctl_with_ref(sfd, to_cmd(VmIoctl::IoEventFd, cfg.driver_variant)
								.expect(&format!("{}:{}", file!(), line!())), &event_fd) };
            if ret < 0 {
                return Err(BackendError::StrNumError {
                   err: String::from("ioeventfd ioctl failed"),
                   val: io::Error::last_os_error(),
                });
            }
        }

        let irq_fd = VirtioIrqfd {
            _label: vdisk.label,
            _fd : mmio.interrupt_evt().expect(&format!("{}:{}", file!(), line!())).as_raw_descriptor(),
            _flags: VBE_ASSIGN_IRQFD,
            _reserved: 0,
        };

        let ret = unsafe { ioctl_with_ref(sfd, to_cmd(VmIoctl::IrqFd, cfg.driver_variant)
		                   .expect(&format!("{}:{}", file!(), line!())), &irq_fd) };
        if ret < 0 {
            return Err(BackendError::StrNumError {
                err: String::from("irqfd ioctl failed"),
                val: io::Error::last_os_error(),
            });
        }
    }

    Ok(())
}

fn handle_driver_ok(label: u32, sfd: &SafeDescriptor, mmio: &mut MmioDevice, cspace: &mut Vec<u32>, driver_variant: u8) {
    let mut cdata = VirtioConfigData {
        _label: label,
        _config_size: 4096,
        _config_data: cspace.as_mut_ptr() as *mut c_char,
    };

    let label_copy = label;

    let ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::GetDriverConfigData, driver_variant)
	                   .expect(&format!("{}:{}", file!(), line!())), &mut cdata)};
    assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

    let mut drv_feat = VirtioDriverFeatures {
        _label: label,
        _reserved: 0,
        _features_sel: 0,
        _features: 0,
    };

    let ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::GetDriverFeatures, driver_variant)
	                   .expect(&format!("{}:{}", file!(), line!())), &mut drv_feat)};
    assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

    let bytes = 0x0u32.to_le_bytes();
    mmio.write(VIRTIO_MMIO_DRIVER_FEATURES_SEL, &bytes);

    let bytes = drv_feat._features.to_le_bytes();
    mmio.write(VIRTIO_MMIO_DRIVER_FEATURES, &bytes);

    drv_feat._features_sel = 1;
    let ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::GetDriverFeatures, driver_variant)
	                   .expect(&format!("{}:{}", file!(), line!())), &mut drv_feat)};
    assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

    let bytes = 0x1u32.to_le_bytes();
    mmio.write(VIRTIO_MMIO_DRIVER_FEATURES_SEL, &bytes);

    let bytes = drv_feat._features.to_le_bytes();
    mmio.write(VIRTIO_MMIO_DRIVER_FEATURES_SEL, &bytes);

    let pos = mmio.get_num_queues();
    for queue in 0..pos as u32  {
    let mut qinfo = VirtioQueueInfo {
                _label: label,
                _queue_sel: queue,
                _queue_num: 0,
                _queue_ready: 0,
                _queue_desc: 0,
                _queue_driver: 0,
                _queue_device: 0,
    };

    let mut queue_addr: u32;

    let ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::GetQueueInfo, driver_variant)
	                   .expect(&format!("{}:{}", file!(), line!())), &mut qinfo)};
    assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

    let bytes = qinfo._queue_sel.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_SEL, &bytes);

    let bytes = qinfo._queue_num.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_NUM, &bytes);

    queue_addr = qinfo._queue_desc as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_DESC_LOW, &bytes);

    queue_addr = (qinfo._queue_desc >> 32) as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_DESC_HIGH, &bytes);

    queue_addr = qinfo._queue_driver as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_AVAIL_LOW, &bytes);

    queue_addr = (qinfo._queue_driver >> 32) as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_AVAIL_HIGH, &bytes);

    queue_addr = qinfo._queue_device as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_USED_LOW, &bytes);

    queue_addr = (qinfo._queue_device >> 32) as u32;
    let bytes = queue_addr.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_USED_HIGH, &bytes);

    let bytes = qinfo._queue_ready.to_le_bytes();
    mmio.write(VIRTIO_MMIO_QUEUE_READY, &bytes);

    }
    let bytes = cspace[VIRTIO_MMIO_STATUS_IDX as usize].to_le_bytes();
    mmio.write(VIRTIO_MMIO_STATUS, &bytes);

    let ret = unsafe { ioctl_with_val(sfd, to_cmd(VmIoctl::AckDriverOk, driver_variant)
	                   .expect(&format!("{}:{}", file!(), line!())), label_copy as u64)};
    assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());
}

fn handle_events(label: u32, sfd: SafeDescriptor, mmio: &mut MmioDevice, cspace: &mut Vec<u32>, driver_variant: u8) -> u32 {
	let mut first_time = 1;
	loop {
		let mut vevent  = VirtioEvent {
			_label: label,
			_event: 0,
			_event_data: 0,
			_reserved: 0,
		};

		let ret = unsafe { ioctl_with_mut_ref(&sfd, to_cmd(VmIoctl::WaitForEvent, driver_variant)
		                   .expect(&format!("{}:{}", file!(), line!())), &mut vevent)};
		assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

		match vevent._event {
			EVENT_DRIVER_OK => handle_driver_ok(label, &sfd, mmio, cspace, driver_variant),
			EVENT_INTERRUPT_ACK =>  {
				let status = vevent._event_data;
				let bytes = status.to_le_bytes();
				mmio.write(VIRTIO_MMIO_INTERRUPT_ACK, &bytes);
			}
			EVENT_RESET_RQST =>  {
				let mut ackrst = VirtioAckReset {
					_label: label,
					_reserved: 0,
				};
				if first_time == 1 {
					let ret = unsafe { ioctl_with_mut_ref(&sfd, to_cmd(VmIoctl::AckReset, driver_variant)
					                   .expect(&format!("{}:{}", file!(), line!())), &mut ackrst)};
					assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());
					first_time = 0;
				} else {
					return 0;
				}
			}
			EVENT_APP_EXIT => return 0,
			_ => error!("{}", format!("Unexpected event {} received", vevent._event)),
		}
	}
}

fn read_banked_reg(mmio: &mut MmioDevice, sel: u32, offset_write: u64, offset_read: u64) -> u32 {

	let mut val: [u8; 4] = [0; 4];

	val[0] = sel as u8;
	mmio.write(offset_write as u64, &val);
	mmio.read(offset_read as u64, &mut val);

	u32::from_le_bytes(val)
}

fn init_config_space(config_space: &mut Vec<u32>, label: u32, mmio: &mut MmioDevice, sfd: &mut SafeDescriptor, driver_variant: u8) {
	let mut val: [u8; 4] = [0; 4];
	let mut reg: u32;
	let mut offset: u32 = 0;
	let mut ret;

	while offset < 4096 {
		mmio.read(offset as u64, &mut val);
		reg = u32::from_le_bytes(val);

		config_space.push(reg);
		offset += 4;
	}

	let mut cdata = VirtioConfigData {
		_label: label,
		_config_size: 4096,
		_config_data: config_space.as_mut_ptr() as *mut c_char,
	};

	ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::SetDeviceConfigData, driver_variant)
			.expect(&format!("{}:{}", file!(), line!())), &mut cdata) };
	assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

	let mut feat = VirtioDevFeatures {
		_label: label,
		_reserved: 0,
		_features_sel: 0,
		_features: 0,
	};

	feat._features = read_banked_reg(mmio, feat._features_sel, VIRTIO_MMIO_DEVICE_FEATURES_SEL, VIRTIO_MMIO_DEVICE_FEATURES);
	ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::SetDeviceFeatures, driver_variant)
			.expect(&format!("{}:{}", file!(), line!())), &mut feat) };
	assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());


	feat._features_sel = 1;
	feat._features = read_banked_reg(mmio, feat._features_sel, VIRTIO_MMIO_DEVICE_FEATURES_SEL, VIRTIO_MMIO_DEVICE_FEATURES);
	ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::SetDeviceFeatures, driver_variant)
			.expect(&format!("{}:{}", file!(), line!())), &mut feat) };
	assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());


	let pos = mmio.get_num_queues();
	for queue in 0..pos as u32  {
		let mut queue_max = VirtioQueueMax {
			_label: label,
			_reserved: 0,
			_queue_sel: queue,
			_queue_num_max: 0,
		};

		queue_max._queue_num_max = read_banked_reg(mmio, queue_max._queue_sel, VIRTIO_MMIO_QUEUE_SEL, VIRTIO_MMIO_QUEUE_NUM_MAX);
		ret = unsafe { ioctl_with_mut_ref(sfd, to_cmd(VmIoctl::SetQueueNumMax, driver_variant)
			.expect(&format!("{}:{}", file!(), line!())), &mut queue_max) };
		assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

	}
}

fn set_minijail(policy: &str) -> Result<(), ()> {
    let mut jail = Minijail::new().map_err(|_| ())?;
    jail.no_new_privs();
    jail.parse_seccomp_filters(Path::new(policy)).map_err(|_| ())?;
    jail.use_seccomp_filter();

    // Jail the current process.
    jail.enter();

    Ok(())
}

fn create_vcpus(cfg: &mut BackendConfig) -> std::result::Result<(), BackendError> {
	let vm_sfd = cfg.vm_sfd.as_ref().expect(&format!("{}:{}", file!(), line!()));
	for vcpu_id in 0..cfg.vcpu_count{
		let vcpu_fd = unsafe { libc::ioctl(vm_sfd.as_raw_descriptor(), GH_CREATE_VCPU(), vcpu_id as c_uint) };
		if vcpu_fd < 0 {
			return Err(BackendError::StrNumError {
				err: String::from("create vcpu ioctl failed"),
				val: io::Error::last_os_error(),});
		}
		cfg.vcpus.push(Vcpu {id: vcpu_id as u8, raw_fd: vcpu_fd, thread_handle: None});
	}
	Ok(())

}

fn run_a_vcpu(vcpu_rawfd: i32, cpu_id: u8, vm_name: &str) -> std::result::Result<JoinHandle<()>, BackendError>{
	let builder = thread::Builder::new()
			.name(format!("{}_vcpu{}", vm_name, cpu_id));
	let vm = vm_name.to_string();
	builder.spawn(move || {
		loop {
			let ret = unsafe { libc::ioctl(vcpu_rawfd, GH_VCPU_RUN()) };
			if ret == 0 {
				error!("{}", format!("{}_vcpu{} returned 0", vm, cpu_id));
				std::process::exit(0);
			}
			else {
				error!("{}", format!("{}_vcpu{} exited with reason {}", vm, cpu_id, ret));
				panic!("{}", format!("{}_vcpu{} exited with reason {}", vm, cpu_id, ret));
			}
		}
        }).map_err(|_| BackendError::StrNumError {
				err: format!("{}_vcpu{} thread create failed", vm_name, cpu_id),
				val: io::Error::last_os_error(),
				})
}

fn run_vcpus(cfg: &mut BackendConfig) ->  std::result::Result<(), BackendError> {
	for vcpu in &mut cfg.vcpus {
		let vcpu_rawfd = vcpu.raw_fd;
		let vm_name = cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!()));
		let handle = run_a_vcpu(vcpu_rawfd, vcpu.id, vm_name);
		if let Err(_handle) = handle {
			return Err(_handle);
		}
		vcpu.thread_handle = Some(handle.expect(&format!("{}:{}", file!(), line!())));
	}
	Ok(())

}

fn run_backend_v2(cfg: &mut BackendConfig) -> std::result::Result<(), ()>
{
	let file_name = format!("{}", GH_PATH);
	let fd: i32 = unsafe { open(file_name.as_ptr() as *const c_char, O_RDWR) };
	if fd < 0 {
		error!("{}", format!("Error: device node open failed {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: device node open failed {:?}", io::Error::last_os_error()));
	}
	cfg.sfd = Some(unsafe { SafeDescriptor::from_raw_descriptor(fd) });
	cfg.driver_variant = 2;
	let sfd = cfg.sfd.as_mut().expect(&format!("{}:{}", file!(), line!())).try_clone()
	                          .expect(&format!("{}:{}", file!(), line!()));

	let vm_fd = unsafe { libc::ioctl(sfd.as_raw_descriptor(), GH_CREATE_VM()) };
	if vm_fd < 0 {
		error!("{}", format!("Error: create vm ioctl failed with error {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: create vm ioctl failed with error {:?}", io::Error::last_os_error()));
	}

	cfg.vm_sfd = Some(unsafe { SafeDescriptor::from_raw_descriptor(vm_fd) });
	let vm_sfd = cfg.vm_sfd.as_ref().expect(&format!("{}:{}", file!(), line!()));

	let vm_name = cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!()));
	let mut fw_name = fw_name {_name: [0; 16],};
	fw_name._name[..vm_name.len()].copy_from_slice(vm_name.as_bytes());
	let ret = unsafe { ioctl_with_ref(vm_sfd, GH_VM_SET_FW_NAME(), &fw_name) };
	if ret != 0 {
		error!("{}", format!("Error: set fw name ioctl failed with error {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: set fw name ioctl failed with error {:?}", io::Error::last_os_error()));
	}

	let vcpu_count = unsafe { libc::ioctl(vm_fd, GH_GET_VCPU_COUNT()) };
	if vcpu_count < 0 || vcpu_count > (GH_VCPU_MAX).try_into().expect(&format!("{}:{}", file!(), line!())) {
		error!("{}", format!("Error: get vcpu count ioctl failed {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: get vcpu count ioctl failed {:?}", io::Error::last_os_error()));
	}
	cfg.vcpu_count = vcpu_count as u16;
	info!("{}", format!("vcpu_count {}", cfg.vcpu_count));

	if !cfg.vdisks.is_empty() || !cfg.vnet.is_empty() {
		let mut shmem_size: u64 = 0;
		let ret = unsafe { ioctl_with_mut_ref(vm_sfd, GET_SHARED_MEMORY_SIZE_V2(), &mut shmem_size) };
		if ret != 0 || shmem_size == 0 {
			error!("{}", format!("Error: get vm shared memory size ioctl failed {:?}", io::Error::last_os_error()));
			panic!("{}", format!("Error: get vm shared memory size ioctl failed {:?}", io::Error::last_os_error()));
		}

		info!("{}", format!("shmem_size {}", shmem_size));

		cfg.mem = Some(self::new_from_rawfd(&[(GuestAddress(0), shmem_size)], &vm_fd)
		               .expect(&format!("{}:{}", file!(), line!())));
    }

	let mut blk_thread_handles  = Vec::new();
	if !cfg.vdisks.is_empty() {
		let e = create_block_devices(cfg);
		if let Err(_e) = e {
			error!("{}", _e);
			panic!("{}", _e);
		}

		for vdisk in &mut cfg.vdisks {
			let label = vdisk.label;
			let mut sfd = cfg.vm_sfd.as_mut().expect(&format!("{}:{}", file!(), line!())).try_clone()
			              .expect(&format!("{}:{}", file!(), line!()));
			let mut mmio = vdisk.mmio.take().expect(&format!("{}:{}", file!(), line!()));
			let mut cspace = vdisk.config_space.take().expect(&format!("{}:{}", file!(), line!()));
			let driver_variant = cfg.driver_variant;
			init_config_space(&mut cspace, label, &mut mmio, &mut sfd, driver_variant);

			debug!("Blk thread being created");
			let handle = thread::spawn(move || {
					handle_events(label, sfd, &mut mmio, &mut cspace, driver_variant);
					});
			blk_thread_handles.push(handle);
		}
	}

    let mut net_thread_handles = Vec::new();
    if !cfg.vnet.is_empty() {
		let e = create_net_devices(cfg);
		if let Err(_e) = e {
			error!("{}", _e);
			panic!("{}", _e);
		}

		for vnet in &mut cfg.vnet {
			let label = vnet.label;
			let mut sfd = cfg.vm_sfd.as_mut().expect(&format!("{}:{}", file!(), line!())).try_clone()
			              .expect(&format!("{}:{}", file!(), line!()));
			let mut mmio = vnet.mmio.take().expect(&format!("{}:{}", file!(), line!()));
			let mut cspace = vnet.config_space.take().expect(&format!("{}:{}", file!(), line!()));
			let driver_variant = cfg.driver_variant;
			init_config_space(&mut cspace, label, &mut mmio, &mut sfd, driver_variant);

			debug!("Net thread being created");
			let handle = thread::spawn(move || {
					handle_events(label, sfd, &mut mmio, &mut cspace, driver_variant);
					});
			net_thread_handles.push(handle);
		}
    }

	let e = create_vcpus(cfg);
	if let Err(_e) = e {
		error!("{}", _e);
		panic!("{}", _e);
	}
	let e = run_vcpus(cfg);
	if let Err(_e) = e {
		error!("{}", _e);
		panic!("{}", _e);
	}

	for vcpu in &mut cfg.vcpus {
		let _ret = vcpu.thread_handle.take().expect(&format!("{}:{}", file!(), line!())).join();
	}
	if !cfg.vdisks.is_empty() {
		for handle in blk_thread_handles {
			let _ret = handle.join();
		}
	}

	if !cfg.vnet.is_empty() {
		for handle in net_thread_handles {
			let _ret = handle.join();
		}
	}

	Ok(())
}

fn run_backend_v1(cfg: &mut BackendConfig) -> std::result::Result<(), ()>
{
	if cfg.vdisks.is_empty() {
		error!("Error: missing disks argument");
		print_usage();
		panic!("Error: missing disks argument");
	}

	let vm_name = cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!()));
	let file_name = format!("{}{}", VIRTIO_BE_PATH, vm_name);
	let fd: i32 = unsafe { open(file_name.as_ptr() as *const c_char, O_RDWR) };
	if fd < 0 {
		error!("{}", format!("Error: device node open failed {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: device node open failed {:?}", io::Error::last_os_error()));
	}
	cfg.sfd = Some(unsafe { SafeDescriptor::from_raw_descriptor(fd) });
	cfg.driver_variant = 1;

	let sfd = cfg.sfd.as_mut().expect(&format!("{}:{}", file!(), line!())).try_clone()
	          .expect(&format!("{}:{}", file!(), line!()));
	let mut shmem_size: u64 = 0;
	let ret = unsafe { ioctl_with_mut_ref(&sfd, GET_SHARED_MEMORY_SIZE_V1(), &mut shmem_size) };
	if ret != 0 || shmem_size == 0 {
		error!("{}", format!("Error: GET_SHARED_MEMORY_SIZE ioctl failed {:?}", io::Error::last_os_error()));
		panic!("{}", format!("Error: GET_SHARED_MEMORY_SIZE ioctl failed {:?}", io::Error::last_os_error()));
	}

	info!("{}", format!("shmem_size {}", shmem_size));

	cfg.mem = Some(self::new_from_rawfd(&[(GuestAddress(0), shmem_size)], &sfd.as_raw_descriptor())
	               .expect(&format!("{}:{}", file!(), line!())));


	let e = create_block_devices(cfg);
	if let Err(_e) = e {
		error!("{}", _e);
		panic!("{}", _e);
	}

	let mut blk_thread_handles  = Vec::new();

	for vdisk in &mut cfg.vdisks {
		let label = vdisk.label;
		let mut sfd = cfg.sfd.as_mut().expect(&format!("{}:{}", file!(), line!())).try_clone()
		              .expect(&format!("{}:{}", file!(), line!()));
		let mut mmio = vdisk.mmio.take().expect(&format!("{}:{}", file!(), line!()));
		let mut cspace = vdisk.config_space.take().expect(&format!("{}:{}", file!(), line!()));
		let driver_variant = cfg.driver_variant;
		init_config_space(&mut cspace, label, &mut mmio, &mut sfd, driver_variant);

		debug!("Thread being created");
		let handle = thread::spawn(move || {
				handle_events(label, sfd, &mut mmio, &mut cspace, driver_variant);
				});
		blk_thread_handles.push(handle);
	}


 //net device

	let e = create_net_devices(cfg);
		if let Err(_e) = e {
   error!("{}", _e);
   return Err(());
  }

  let mut net_handles  = Vec::new();

      for vnet_dev in &mut cfg.vnet {
        let label = vnet_dev.label;
        let mut sfd = cfg.sfd.as_mut().unwrap().try_clone().unwrap();
        let mut mmio = vnet_dev.mmio.take().unwrap();
        let mut cspace = vnet_dev.config_space.take().unwrap();
	let driver_variant = cfg.driver_variant;
	init_config_space(&mut cspace, label, &mut mmio, &mut sfd, driver_variant);

	let net_handle = thread::spawn(move || {
	    handle_events(label, sfd, &mut mmio, &mut cspace, driver_variant);
        });
        net_handles.push(net_handle);

    }

	let ret = unsafe { libc::ioctl(sfd.as_raw_descriptor(), SET_APP_READY_V1(), 0) };
	assert!(ret == 0, "{}:{}:ret={}, {}", file!(), line!(), ret, io::Error::last_os_error());

	let vm_name = cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!()));
	if Err(()) == boot_vm_v1(vm_name) { return Err(()) };

	for handle in blk_thread_handles {
		let _ret = handle.join();
	}

    for net_handle in net_handles {
        let _ret = net_handle.join();
    }

	Ok(())
}

fn boot_vm_v1(vm_name: &str) -> std::result::Result<(), ()>
{
	use std::io::Write;

	let boot_vm_path = format!("/sys/kernel/load_guestvm_{}/boot_guestvm", vm_name);

	if !Path::new(&boot_vm_path).exists() {
		error!("{}", format!("{} path does not exist", boot_vm_path));
		panic!("{}", format!("{} path does not exist", boot_vm_path));
	}

	let fd: i32 = unsafe { open(boot_vm_path.as_ptr() as *const c_char, O_WRONLY) };
	if fd < 0 {
		error!("{}", format!("Error: {} open failed {:?}", boot_vm_path, io::Error::last_os_error()));
		panic!("{}", format!("Error: {} open failed {:?}", boot_vm_path, io::Error::last_os_error()));
	}
	let file = unsafe { File::from_raw_fd(fd) };
	let ret = write!(&file, "1");
	match ret {
		Ok(()) => {
			info!("{}", format!("{} booted successfully", vm_name));
			return Ok(());
		},
		Err(e) => {
			error!("{}", format!("{} boot failed {:?}", vm_name, e));
			panic!("{}", format!("{} boot failed {:?}", vm_name, e));
		},
	};

}

fn run_backend(cfg: &mut BackendConfig) -> std::result::Result<(), ()>
{
	if cfg.vm.is_none() {
		error!("Error: missing vm argument");
		print_usage();
		panic!("Error: missing vm argument");
	}

        // Enforce the current process to be jailed.
        if cfg.sandbox {
            match set_minijail(CROSVM_MINIJAIL_POLICY){
                 Ok(_) => {
                     debug!("Sandboxing using minijail is enabled!!");
                 }
                 Err(_) => {
                     error!("Minijail enforcement failed!!");
                     panic!("Minijail enforcement failed!!");
                 }
            }
        }

	let vm_name = cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!()));
	let virtio_backend_dev_path = format!("{}{}", VIRTIO_BE_PATH, vm_name);
	let gh_path = format!("{}", GH_PATH);


	if Path::new(&gh_path).exists() {
		return run_backend_v2(cfg)
	}
	//Fallback to old driver - VM with virtio disks
	else if Path::new(&virtio_backend_dev_path).exists() {
		return run_backend_v1(cfg)
	}
	//Fallback to old driver - VM without virtio disks.
	else {
		return boot_vm_v1(vm_name)
	}

}

fn set_logger(cfg: &mut BackendConfig) -> std::result::Result<(), ()>
{
	let mut log_tag = String::from(LOG_TAG);

	if !cfg.vm.is_none() {
		log_tag.push('_');
		log_tag.push_str(cfg.vm.as_ref().expect(&format!("{}:{}", file!(), line!())));
	}

	match cfg.log_type.as_ref().expect(&format!("{}:{}", file!(), line!())).as_str() {
		"logcat" => {
			android_logger::init_once(
					Config::default()
					.with_min_level(Level::Trace)
					.with_tag(log_tag.as_str()));
			log::set_max_level(cfg.log_level);
		}
		"term" => {
			let config = ConfigBuilder::new()
				.set_time_level(LevelFilter::Off)
				.set_max_level(LevelFilter::Off)
				.set_location_level(LevelFilter::Off)
				.set_thread_level(LevelFilter::Off)
				.set_target_level(LevelFilter::Off)
				.with_tag(log_tag.as_str())
				.build();
			let _init = SimpleLogger::init(cfg.log_level, config);
		}
		//Default logger
		"ftrace" => {
			let config = ConfigBuilder::new()
				.set_time_level(LevelFilter::Off)
				.set_max_level(LevelFilter::Off)
				.set_location_level(LevelFilter::Off)
				.set_thread_level(LevelFilter::Off)
				.set_target_level(LevelFilter::Off)
				.with_tag(log_tag.as_str())
				.without_new_line()
				.build();
			let _init = WriteLogger::init(cfg.log_level, config, File::create(TRACE_MARKER)
					.expect(&format!("{}:{}", file!(), line!())));

		}

		_ => {}
	}

	return Ok(())
}

fn set_argument(cfg: &mut BackendConfig, name: &str, value: Option<&str>) -> argument::Result<()> {
	match name {
	"disk" => {
		let param = value.expect(&format!("{}:{}", file!(), line!()));
		let mut components = param.split(',');
		let read_only = true;
		let disk_path =
			PathBuf::from(
			components
			.next()
			.ok_or_else(|| argument::Error::InvalidValue {
				value: param.to_owned(),
				expected: String::from("missing disk path"),
			})?
		);

		if !disk_path.exists() {
			return Err(argument::Error::InvalidValue {
				value: param.to_owned(),
				expected: String::from("an existing file"),
			});
		}

		let mut vdisk = VirtioDisk {
			disk: DiskOption {
				path: disk_path,
				read_only,/*mount read only - default*/
				o_direct: false, /*Use O_DIRECT mode to bypass page cache. (default: false)*/
				sparse: true,
				block_size: 512,
				id: None,
			},
			label: 0,
			mmio: None,
			config_space: Some(Vec::new()),
		};

		for opt in components {
			let mut o = opt.splitn(2, '=');
			let kind = o.next().ok_or_else(|| argument::Error::InvalidValue {
				value: opt.to_owned(),
				expected: String::from("disk options must not be empty"),
			})?;

			let value = o.next().ok_or_else(|| argument::Error::InvalidValue {
					value: opt.to_owned(),
					expected: String::from("disk options must be of the form `kind=value`"),
			})?;

			match kind {
			"label" => {
				let label: u32 = u32::from_str_radix(value, 16)
					.map_err(|_| argument::Error::InvalidValue {
						value: value.to_owned(),
						expected: String::from("`label` must be an unsigned integer"),
        			})?;
				if label == 0 {
					return Err(argument::Error::InvalidValue {
						value: value.to_owned(),
						expected: String::from("`label` must be a non zero integer"),
					});

				}
				vdisk.label = label;
			}

			"sparse" => {
				let sparse = value.parse().map_err(|_| argument::Error::InvalidValue {
					value: value.to_owned(),
					expected: String::from("`sparse` must be a boolean"),
				})?;
				vdisk.disk.sparse = sparse;
			}

			"block_size" => {
				let block_size =
					value.parse().map_err(|_| argument::Error::InvalidValue {
						value: value.to_owned(),
						expected: String::from("`block_size` must be an integer"),
					})?;
                                match block_size {
                                    512 | 1024 => vdisk.disk.block_size = block_size,
                                    _ => {
                                        return Err(argument::Error::InvalidValue {
                                            value: value.to_owned(),
                                            expected: String::from("`block_size` must be 512 or 1024"),
                                        });
                                    }
                                }
			}

			"rw" => {
				let rwrite: bool = value.parse().map_err(|_| argument::Error::InvalidValue {
					value: value.to_owned(),
					expected: String::from("`rw` must be a boolean"),
				})?;
				vdisk.disk.read_only = !rwrite;
			}

			_ => {
				return Err(argument::Error::InvalidValue {
					value: kind.to_owned(),
					expected: String::from("supported disk options only"),
				});
			}
			}
		}

		cfg.vdisks.push(vdisk);
	}

	"vm" => {
		cfg.vm = Some(value.expect(&format!("{}:{}", file!(), line!())).to_owned());
		//PID would be required for log analysis of all log levels. Hence error!().
		error!("{}", format!("qcrosvm PID for {}: {}", cfg.vm.as_ref()
		      .expect(&format!("{}:{}", file!(), line!())), process::id()));
	}

	"sandbox" => {
                cfg.sandbox = true;
	}

        "log" => {
		let param = value.expect(&format!("{}:{}", file!(), line!()));
		let components = param.split(',');

		for opt in components {
			let mut o = opt.splitn(2, '=');
			let kind = o.next().ok_or_else(|| argument::Error::InvalidValue {
				value: opt.to_owned(),
				expected: String::from("log options must not be empty"),
			})?;

			let value = o.next().ok_or_else(|| argument::Error::InvalidValue {
					value: opt.to_owned(),
					expected: String::from("log options must be of the form `kind=value`"),
			})?;

			match kind {
				"level" => {
					let level = value.to_owned();
					match Level::from_str(&level)
					{
						Ok(temp_log_level) => {
							// Reset the logging level
							cfg.log_level = temp_log_level.to_level_filter();
						}
						Err(_) =>  {
							return Err(argument::Error::InvalidValue {
								value: level,
								expected: String::from("trace | debug | info | warn | error"),
								});
						}
					}
				}

				"type" => {
					let logger_type = value.to_owned();
					match logger_type.as_str() {
						"logcat"|"term"|"ftrace" => {
							cfg.log_type = Some(logger_type);
						}
						_ => {
							return Err(argument::Error::InvalidValue {
								value: value.to_owned(),
								expected: String::from
								("supported logger options. 'type=logcat|term|ftrace"),
								});
						}
					}
				}

				_ => {
					return Err(argument::Error::InvalidValue {
						value: kind.to_owned(),
						expected: String::from("supported logger options. 'type=logcat | term | ftrace'"),
					});
				}
			}
		}
        }

	"net" => {
		let param = value.unwrap();
		let mut components = param.split(',');
		let network_dev = components.next();
		cfg.network_dev = true;

		let mut vnet_dev = VirtioNet {
			label: 0,
			mmio: None,
			config_space: Some(Vec::new()),
		};

		for opt in components {
			let mut o = opt.splitn(2, '=');
			let kind = o.next().ok_or_else(|| argument::Error::InvalidValue {
				value: opt.to_owned(),
				expected: String::from("net options must not be empty"),
			})?;

			let value = o.next().ok_or_else(|| argument::Error::InvalidValue {
				value: opt.to_owned(),
				expected: String::from("net options must be of the form `kind=value`"),
				})?;

			match kind {
				"label" => {
					let label: u32 = u32::from_str_radix(value, 16)
					.map_err(|_| argument::Error::InvalidValue {
						value: value.to_owned(),
						expected: String::from("`label` must be an unsigned integer"),
					})?;
					if label == 0 {
						return Err(argument::Error::InvalidValue {
							value: value.to_owned(),
							expected: String::from("invalid `label` value"),
						});
					}

					vnet_dev.label = label;
				}

				"ip_addr" => {
					if cfg.ip_addr.is_some() {
						return Err(argument::Error::TooManyArguments(
							"`host_ip` already given".to_owned(),
						));
					}
					cfg.ip_addr =
						Some(
							value
							.parse()
							.map_err(|_| argument::Error::InvalidValue {
								value: value.to_owned(),
								expected: String::from("`ip_addr` needs to be in the form \"x.x.x.x\""),
							})?,
						);
				}

				"netmask" => {
						if cfg.netmask.is_some() {
							return Err(argument::Error::TooManyArguments(
								"`netmask` already given".to_owned(),
							));
						}
						cfg.netmask =
							Some(
								value
									.parse()
									.map_err(|_| argument::Error::InvalidValue {
										value: value.to_owned(),
										expected: String::from("`netmask` needs to be in the form \"x.x.x.x\""),
									})?,
							);
					}
					"mac" => {
						if cfg.mac_addr.is_some() {
							return Err(argument::Error::TooManyArguments(
								"`mac` already given".to_owned(),
							));
						}
						cfg.mac_addr =
							Some(
								value
									.parse()
									.map_err(|_| argument::Error::InvalidValue {
										value: value.to_owned(),
										expected: String::from(
											"`mac` needs to be in the form \"XX:XX:XX:XX:XX:XX\"",
										),
									})?,
							);
					}

				_ => {
					return Err(argument::Error::InvalidValue {
						value: kind.to_owned(),
						expected: String::from("unrecognized net option"),
					});
				}
			}
		}

		cfg.vnet.push(vnet_dev);
	}

	_ => unreachable!(),

	}

	Ok(())
}

fn parse_and_run(args: std::env::Args) -> std::result::Result<(), ()> {
	let arguments =
			&[
			Argument::short_value('d', "disk", "PATH,label=LABEL[,key=value[,key=value[,...]]", "Path to a disk image followed by comma-separated options.
			Valid keys:
			label=LABEL - Indicates the label associated with the virtual (disk)
			sparse=BOOL - Indicates whether the disk should support the discard operation (default: true)
			block_size=BYTES - Set the reported block size of the disk (default: 512)
			rw - Sets the disk as read-writeable"),

			Argument::short_value('l', "log",
			"[level=trace|debug|info|warn|error],[type=ftrace|logcat|term]",
			"Logging Configurations. Default level: info, Default type: ftrace"),
			Argument::short_value('v', "vm", "VMNAME", "Virtual Machine Name"),
			Argument::short_flag('s', "sandbox", "Sandbox using minijail (default: disabled."),

			Argument::short_value('n',"net","label=LABEL[,key=value[,key=value[,...]]]","net device followed by comma-separated options.
            Valid keys:
			label=LABEL - Indicates the label associated with the virtual net dev
			ip_addr=IP - IP address to assign to host tap interface
			netmask=NETMASK - Netmask for VM subnet
			mac=MAC - MAC address for VM"),
		];
	let mut cfg = BackendConfig::default();
	let match_res = set_arguments(args, &arguments[..], |name, value| {
			set_argument(&mut cfg, name, value)
	});

	let dummy = set_logger(&mut cfg);

	match match_res {

	Ok(()) => match run_backend(&mut cfg) {
		Ok(_) => {
			info!("backend exited normally");
			Ok(())
		}

		Err(_) => {
			Err(())
		}
	},

	Err(e) => {
		error!("{}", format!("Error parsing arguments {:?}", e));
		Err(())
	}
	}
}

fn backend_main() -> std::result::Result<(), ()> {

    match env::var("KBDEV") {
	    Ok(_) => panic_hook::set_panic_hook(),
	    Err(_) => {},
    }

    let mut args = std::env::args();

    if args.next().is_none() {
        print_usage();
        return Err(());
    }

    return parse_and_run(args);
}

fn main() {
    std::process::exit(if backend_main().is_ok() { 0 } else { 1 });
}

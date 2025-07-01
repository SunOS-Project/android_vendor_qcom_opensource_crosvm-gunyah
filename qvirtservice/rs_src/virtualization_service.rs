/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

use crate::virtual_machine::{VirtualMachine, VmInstance, VmParameters, UeventInfo};

use crate::utils::UEvent;

use rustutils::system_properties;

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::os::unix::io::RawFd;
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use libc::_exit;

use log::{debug, error, info};

use serde_json::Value;

use std::os::fd::{BorrowedFd};

use vendor_qti_qvirt::aidl::vendor::qti::qvirt::{
    IVirtualMachine::IVirtualMachine,
    IVirtualizationService::{
        BnVirtualizationService, BpVirtualizationService,
        IVirtualizationService,
    },
};
use vendor_qti_qvirt::binder::{
    BinderFeatures, ExceptionCode, Interface, Status, Strong, ThreadState,
};

//use vendor_qti_qvirtvendor::aidl::vendor::qti::qvirtvendor::IVendorVM::IVendorVM;

static VENDOR_CONFIG_FILE: &str = "/vendor/etc/qvirtmgr-vndr.json";
static BOOT_COMPLETE_PROP: &str = "sys.boot_completed";

pub struct VmInstanceWrapper {
    // VmInstance
    // - Arc -> Shared between threads (here, autostart, getVm).
    // - Mutex -> Needs to be mutable anywhere (autostart_complete, etc.)
    instance: Arc<Mutex<VmInstance>>,
    enabled: bool,
    boot_complete_timeout: u16,
    enabled_socs: Vec<String>,
    current_soc: String,
}

//                          < name , VmInstanceWrapper>
type VmInstanceMap = HashMap<String, VmInstanceWrapper>;

pub struct VirtualizationService {
    // VmInstanceMap
    // - Arc -> Shared between threads (here, uevent).
    // - !Mutex -> Only modified in here once in constructor.
    vm_instance_map: Arc<VmInstanceMap>,
}

impl VirtualizationService {
    pub fn to_binder(self) -> Strong<dyn IVirtualizationService> {
        BnVirtualizationService::new_binder(self, BinderFeatures::default())
    }

    pub fn get_descriptor() -> String {
        BpVirtualizationService::get_descriptor().to_string()
    }

    pub fn virtualization_service() -> Self {
        let mut vm_instance_map: VmInstanceMap = Default::default();

        // Store the vm's thread handle for the no_fs_dependent ones.
        let mut no_fs_dependent_handles = Vec::new();

        // Store autostart vms
        let mut autostart_vms = Vec::<(String, bool)>::new();

        // Parse the config file
        if let Ok(vm_parameters_list) = Self::parse_vm_config_file() {
            info!("Parsing VM Config File Success.");

            for vm_param in vm_parameters_list {
                // Save data now for easy access (before locked in mutex).
                let name = vm_param.name.clone();
                let enabled = vm_param.enable.clone();
                let boot_complete_timeout =
                    vm_param.boot_complete_timeout.clone();
                let enabled_socs = vm_param.enabled_socs.clone();
                let mut current_soc = String::new();
                if !(enabled_socs.is_empty()) {
                    if let Ok(Some(value)) = system_properties::read("ro.boot.product.vendor.sku") {
                        debug!("Current sku value is {}",value);
                        current_soc = value.clone();
                        if (vm_param.autostart) && enabled_socs.contains(&value) {
                            autostart_vms.push((
                                name.clone(),
                                vm_param.no_fs_dependency.clone(),
                            ));
                        }
                    }
                }
                else if vm_param.autostart && vm_param.enable {
                    autostart_vms.push((
                        name.clone(),
                        vm_param.no_fs_dependency.clone(),
                    ));
                }

                // Create a VmInstance and put the vm_params inside.
                // When getVm called, give out a VirtualMachine wrapping a ref to the instance
                let wrpr = VmInstanceWrapper {
                    instance: Arc::new(Mutex::new(VmInstance::new(vm_param))),
                    enabled: enabled,
                    boot_complete_timeout: boot_complete_timeout,
                    enabled_socs: enabled_socs,
                    current_soc: current_soc,
                };

                vm_instance_map.insert(name, wrpr); // Put a ref count in the map
            }
        } else {
            unsafe {
                _exit(1);
            }
        }

        let service = VirtualizationService {
            vm_instance_map: Arc::new(vm_instance_map),
        };

        // Create the uevent thread
        let vm_instance_map_clone = service.vm_instance_map.clone();
        thread::spawn(move || {
            Self::uevent_listener(vm_instance_map_clone);
        });

        // Launch autostart VMs
        for (name, no_fs_dependency) in autostart_vms {
            let wrapper = service.vm_instance_map.get(&name).unwrap();
            let timeout_for_thread = wrapper.boot_complete_timeout.clone();
            let instance_for_thread = wrapper.instance.clone();
            if no_fs_dependency {
                let handle = thread::spawn(move || {
                    let mut vm_ssr_enablecheck:bool = false;
                    let mut vm_autostart_done:bool = false;
                    if let Ok(mut vm) = instance_for_thread.lock() {
                        vm.launch_autostart_vm();
                        vm_ssr_enablecheck = vm.vm_parameters.vm_ssr_enable;
                        vm_autostart_done = vm.autostart_done;
                        drop(vm);
                    }
                    if vm_ssr_enablecheck && vm_autostart_done{
                        if let Ok(mut vm) = instance_for_thread.lock() {
                            match vm.autostart_connectvm() {
                                Ok(0)=>{
                                    info!("VM userpspace connection is successful");
                                },
                                Ok(_)=>{
                                    info!("VM userspace connection is not successful, Will be placed in crashed state");
                                },
                                Err(response) => {
                                    error!(
                                        "VM: {} has been removed: {response}",
                                        vm.vm_parameters.name
                                    );
                                }
                            }
                        }
                    }
                    if vm_ssr_enablecheck && vm_autostart_done {
                        let vm_instance = instance_for_thread.clone();
                        info!("Auto Shutdown Thread has been initiated");
                        VmInstance::auto_shutdown_thread_handle_initiator(vm_instance);
                    }
                });
                no_fs_dependent_handles.push(handle);
            } else {
                // Wait for timeout if fs dependent
                thread::spawn(move || {
                    let mut vm_ssr_enablecheck:bool = false;
                    let mut watcher = system_properties::PropertyWatcher::new(BOOT_COMPLETE_PROP).unwrap();
                    if let Ok(_) = watcher.wait_for_value(
                        "1",
                        Some(Duration::new(timeout_for_thread.into(), 0)),
                    ) {
                        debug!("System boot completed.");
                        // Only aquire lock after wait for boot complete.
                        // Allows clients to register cbs during the wait.
                        if let Ok(mut vm) = instance_for_thread.lock() {
                            vm.launch_autostart_vm();
                            vm_ssr_enablecheck = vm.vm_parameters.vm_ssr_enable;
                            drop(vm);
                        }
                        if vm_ssr_enablecheck{
                          if let Ok(mut vm) = instance_for_thread.lock() {
                                match vm.autostart_connectvm() {
                                    Ok(-1)=>{
                                        info!("VM userspace connect is not supported");
                                    },
                                    Ok(0)=>{
                                        info!("VM userpspace connection is successful");
                                    },
                                    Ok(_)=>{
                                        info!("VM userspace connection is not successful, Will be placed in crashed state");
                                    },
                                    Err(response) => {
                                        error!(
                                            "Client: {} has been removed: {response}",
                                            vm.vm_parameters.name
                                        );
                                    }
                                }
                            drop(vm);
                            }
                        }
                        if vm_ssr_enablecheck {
                            let vm_instance = instance_for_thread.clone();
                            info!("Auto Shutdown Thread has been initiated");
                            VmInstance::auto_shutdown_thread_handle_initiator(vm_instance);
                        }
                    } else {
                        error!("Timed out checking for sys.boot_completed.");
                        if let Ok(mut vm) = instance_for_thread.lock() {
                            vm.autostart_done = true;
                        }
                    }
                });
            }
        }

        // Join the no_fs_dependent threads
        for handle in no_fs_dependent_handles {
            let _res = handle.join();
        }

        return service;
    }

    fn parse_event(msg: Vec<u8>) -> Option<UeventInfo> {
        if let Ok(msg) = String::from_utf8(msg) {
            let mut pairs: Vec<&str> =
                msg.trim_matches('\0').split('\0').collect();
            pairs.retain(|s| s.contains("="));

            let mut event = None;
            let mut vm_name = None;
            let mut event_reason = None;
            for pair in pairs {
                let p: Vec<&str> = pair.splitn(2, "=").collect();
                match p[0] {
                    "EVENT" => event = Some(p[1].to_string()),
                    "vm_name" => vm_name = Some(p[1].to_string()),
                    "vm_exit" => event_reason = Some(p[1].to_string()),
                    _ => continue,
                };
            }
            let uevent_info = UeventInfo::new(vm_name.clone().unwrap_or_else(|| String::new()),event.clone().unwrap_or_else(|| String::new()),event_reason.clone().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0));
            if !uevent_info.event.is_empty() {
                info!("These are the uevent_info parameter VM Name: {}, \n \t\t UEVENT Received: {}, \n \t\t Uevent Reason: {}", uevent_info.vm_name, uevent_info.event, uevent_info.event_reason.to_string());
            }
            return Some(uevent_info);
        }
        return None;
    }

    fn handle_uevent_event(
        uevent_fd: RawFd,
        vm_instance_map: &Arc<VmInstanceMap>,
    ) -> () {
        let mut msg = Vec::<u8>::new();
        while let Ok(_res) =
            UEvent::uevent_kernel_multicast_recv(uevent_fd, &mut msg, 1024)
        {
            if let Some(event) = Self::parse_event(msg.clone()) {
                match vm_instance_map.get(&event.vm_name) {
                    Some(wrpr) => {
                        if let Ok(mut instance) = wrpr.instance.lock() {
                            debug!("Initiating request to notify state change to {} clients", &event.vm_name);
                            instance.notify_clients(&event.event, &event.event_reason.to_string());
                        }
                    }
                    None => {
                        if !event.vm_name.is_empty() {
                            debug!("Invalid vm_name received from uevent");
                        }
                    }
                }
            }
        }
    }

    fn uevent_listener(vm_instance_map: Arc<VmInstanceMap>) -> () {
        info!("started uevent listener thread");
        let uevent_fd = UEvent::uevent_open_socket(64 * 1024, true).unwrap();
        fcntl(uevent_fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        let borrowed_uevent_fd = unsafe { BorrowedFd::borrow_raw(uevent_fd) };

        loop {
            let mut ufd = [PollFd::new(borrowed_uevent_fd, PollFlags::POLLIN)];
            if let Ok(nr) = poll(&mut ufd,  PollTimeout::NONE) {
                if nr < 0 {
                    continue;
                }
                if ufd[0].revents().unwrap().contains(PollFlags::POLLIN) {
                    Self::handle_uevent_event(
                        uevent_fd.clone(),
                        &vm_instance_map,
                    );
                }
            }
        }
    }

    // Returns a vector of vmParameters.
    fn parse_vm_config_file() -> Result<Vec<VmParameters>, Box<dyn Error>> {
        let mut vm_parameters_list = Vec::<VmParameters>::new();

        // Uses serde_json to deserialize directly into strongly typed VmParameters object.
        let vendor_config_file = File::open(VENDOR_CONFIG_FILE)?;
        let root: Value = match serde_json::from_reader(vendor_config_file){
            Ok(parsed) => parsed,
            Err(e) => {
                    error!("Parsing of JSON file is incorrect : {}",e);
                    return Err(format!("Error parsing JSON: {}",e).into());
                }
        };
        let json_config_array: &Vec<Value> = root
            .get("qvirtmgr")
            .and_then(|mgr| mgr.get("vm_config"))
            .and_then(|arr| arr.as_array())
            .ok_or("VM Configuration is invalid.")?;
        for config in json_config_array {
            let enable_present = config.get("enable").is_some();
            let enabled_socs_present = config.get("enabled_socs").is_some();
            if enable_present && enabled_socs_present {
                error!("Error: Only one of the predefined keys ('enable', 'enabled_socs') is allowed in config");
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Multiple keys('enable', 'enabled_socs') found")));
            }
            match serde_json::from_value::<VmParameters>(config.to_owned()) {
                Ok(vm_param) => {
                    vm_parameters_list.push(vm_param);
                }
                Err(e) => {
                    // Just skip any malformed vm config.
                    let name: &str = config
                        .get("name")
                        .and_then(|val| val.as_str())
                        .unwrap_or("No Name Specified");
                    error!("Skipping entry for '{}'. Err: {e}", name);
                    continue;
                }
            }
        }
        Ok(vm_parameters_list)
    }
}

impl Interface for VirtualizationService {}

impl IVirtualizationService for VirtualizationService {
    fn getVm(
        &self,
        vm_name: &str,
    ) -> Result<Strong<(dyn IVirtualMachine)>, Status> {
        info!(
            "getVm: Requested vm handle for {} from pid={}",
            vm_name,
            ThreadState::get_calling_pid()
        );

        if let Some(instance_wrpr) = self.vm_instance_map.get(vm_name) {
            if !instance_wrpr.enabled_socs.is_empty() {
                let targets = instance_wrpr.enabled_socs.clone();
                let current_soc = &instance_wrpr.current_soc;
                debug!("Current sku value is {}", current_soc);
                if !targets.contains(current_soc) {
                    error!("getVm: {vm_name} is not enabled on this target, rejecting request.");
                    return Err(Status::new_exception_str(
                        ExceptionCode::UNSUPPORTED_OPERATION,
                        Some("vm not enabled on this target"),
                    ));
                }
            }
            else if !instance_wrpr.enabled {
                error!("getVm: enable bit is false for {vm_name}, rejecting request.");
                return Err(Status::new_exception_str(
                    ExceptionCode::UNSUPPORTED_OPERATION,
                    Some("enable bit false."),
                ));
            }
            // Create a VirtualMachine which wraps the Arc<Mutex<VmInstance>>
            let virtual_machine = VirtualMachine {
                vm_instance: instance_wrpr.instance.to_owned(),
                current_soc: instance_wrpr.current_soc.clone(),
            }; // Increments ref count of instance_obj
            return Ok(virtual_machine.to_binder());
        } else {
            error!("getVm: Invalid name argument passed, rejecting request.");
            return Err(Status::new_exception_str(
                ExceptionCode::ILLEGAL_ARGUMENT,
                Some("Invalid name"),
            ));
        }
    }
}

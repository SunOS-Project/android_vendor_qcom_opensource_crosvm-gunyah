/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/
#![allow(dead_code)]
use std::{
    collections::HashMap,
    error::Error,
    ffi::{CStr, CString},
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    sync::mpsc::{channel, Sender},
    thread,
    time::Duration,
};

use libc::{pid_t, uid_t, _exit};

use serde::Deserialize;

use nix::{
    sys::signal::kill, sys::signal::Signal, sys::wait::waitpid,
    sys::wait::WaitPidFlag, sys::wait::WaitStatus, unistd::execv, unistd::fork,
    unistd::ForkResult, unistd::Pid, unistd::setsid, sys::wait::wait,
};

use rustutils::system_properties;

use log::{debug, error, info};

use vendor_qti_qvirt::aidl::vendor::qti::qvirt::{
    IVirtualMachine::{BnVirtualMachine, IVirtualMachine, ERROR_VM_START},
    IVirtualMachineCallback::IVirtualMachineCallback,
    VirtualMachineState::VirtualMachineState,
    VirtualMachineClientTask::VirtualMachineClientTask,
};

use vendor_qti_qvirt::binder::{
    BinderFeatures, DeathRecipient, ExceptionCode, IBinder, Interface, Status,
    Strong, ThreadState,
};

use vendor_qti_qvirtvendor::aidl::vendor::qti::qvirtvendor::{
    IVendorVM::{BpVendorVM, IVendorVM},
//    VendorVMState::VendorVMState,
    VMErrorCodes::VMErrorCodes,
    VMInfo::VMInfo,
    VMTasks::VMTasks,
};

use vendor_qti_qvirtvendor::binder as vendor_binder;

// ======================================================================
// HELPERS
// ======================================================================

static VM_BINARY_FILE: &str = "/system_ext/bin/qcrosvm";
static DEFAULT_BOOT_COMPLETE_TIMEOUT: u16 = 60;
static DEFAULT_SSR_TIMEOUT: u32 = 60;
static DEFAULT_USERSPACE_WAIT_TIMER: u32 = 120;

fn boot_complete_timeout_default() -> u16 {
    DEFAULT_BOOT_COMPLETE_TIMEOUT
}

fn default_vmssr_true() -> bool {
    false
}

fn default_vmuserspace_waittimer() -> u32{
    DEFAULT_USERSPACE_WAIT_TIMER
}

fn default_vmssr_timeout() -> u32{
    DEFAULT_SSR_TIMEOUT
}

#[derive(Default, Debug, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    #[default]
    Create = 0,
    Start = 1,
    Stop = 2,
    Restart = 3,
    Panic = 4,
    NotSupported = 5,
}

impl FromStr for ControlState {
    type Err = ();
    fn from_str(input: &str) -> Result<ControlState, Self::Err> {
        match input {
            "create" => Ok(ControlState::Create),
            "start" => Ok(ControlState::Start),
            "stop" => Ok(ControlState::Stop),
            "restart" => Ok(ControlState::Restart),
            "panic" => Ok(ControlState::Panic),
            _ => Err(()),
        }
    }
}

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename = "disk")]
pub struct DiskProperties {
    pub image: String,
    pub label: u32,
    pub read_write: bool,
}

#[derive(Default, Debug, Clone, Deserialize)]
pub struct VmParameters {
    pub name: String,
    #[serde(default)]
    pub enable: bool,
    #[serde(skip)]
    pub legacy: bool,
    #[serde(rename = "boot_ops")]
    pub boot_operation: ControlState,
    #[serde(default)]
    pub disk: Vec<DiskProperties>,
    #[serde(default)]
    pub try_count: u8,
    pub boot_wait_time: u8,
    #[serde(default = "boot_complete_timeout_default")]
    pub boot_complete_timeout: u16,
    pub no_fs_dependency: bool,
    pub autostart: bool,
    #[serde(default)]
    pub on_demand_start_supported: bool,
    #[serde(default)]
    pub mem: u32,
    #[serde(default)]
    pub cid: u64,
    #[serde(default)]
    pub vsock_label: String,
    #[serde(default = "default_vmssr_true")]
    pub vm_ssr_enable: bool,
    #[serde(default)]
    pub total_votes: u8,
    #[serde(default = "default_vmssr_timeout")]
    pub vm_ssr_timeout: u32,
    #[serde(default = "default_vmuserspace_waittimer")]
    pub vm_userspace_waittimer: u32,
    #[serde(default)]
    pub enabled_socs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VMClient {
    pub vm_client_callback: Strong<dyn IVirtualMachineCallback>,
    pub client_vote_count: u8,
    pub pid: pid_t,
    pub uid: uid_t,
    pub death_id: usize,
}

#[derive(Default, Debug, Clone)]
pub struct UeventInfo {
    pub vm_name: String,
    pub event: String,
    pub event_reason: u32,
}

#[derive(Debug, Clone)]
pub struct VendorVMInstance{
    pub vendor_vm_instance: Arc<Mutex<Option<Strong <dyn IVendorVM>>>>,
}

#[derive(Clone)]
pub struct AutoShutdownHandleStruct{
    pub auto_shutdown_thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

#[derive(Default)]
pub struct VmInstance {
    pub vm_state: VirtualMachineState,
    pub vm_parameters: VmParameters,
    pub vm_clients: Vec<VMClient>,

    pub vendorvminfo : VMInfo,

    pub autostart_done: bool,

    // Death Recipient Objects for the clients (kept here to stay alive)
    // Upon client death, remove their callback.
    pub death_id: AtomicUsize,
    pub death_recipients: HashMap<usize, DeathRecipient>,
    pub uevent_info: UeventInfo,
    pub vendorvm_instance: VendorVMInstance,
    pub auto_shutdown_thread_handler:AutoShutdownHandleStruct,
    pub shutdown_notifier: Option<Sender<()>>,
    pub childpid: Option<Pid>,
//  pub vendorvm_state: VendorVMState,
    }

impl VMClient{
    pub fn new(vm_client_callback:Strong<dyn IVirtualMachineCallback>, pid: pid_t, uid:uid_t, did:usize ) -> Self {
        VMClient {
            vm_client_callback: vm_client_callback,
            client_vote_count: 0,
            pid:pid,
            uid:uid,
            death_id: did,
        }
    }
}

impl UeventInfo{
    pub fn new(vmname: String, event: String, event_reason: u32) -> Self {
        UeventInfo {
            vm_name: vmname,
            event: event,
            event_reason: event_reason,
        }
    }
}

impl Default for VendorVMInstance{
    fn default() -> Self {
        VendorVMInstance {
            vendor_vm_instance: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for AutoShutdownHandleStruct{
    fn default() -> Self {
        AutoShutdownHandleStruct {
            auto_shutdown_thread: Arc::new(Mutex::new(None)),
        }
    }
}

impl VmInstance {
    pub fn new(vm_parameters: VmParameters) -> Self {
        let inst = Self {
            vm_state: VirtualMachineState::NOT_STARTED,
            vm_parameters: vm_parameters,
            autostart_done: false,
            death_id: AtomicUsize::new(0),
            vm_clients: Vec::new(),
            death_recipients: HashMap::new(),
            vendorvminfo: VMInfo::default(),
            uevent_info : UeventInfo::new(String::new(),String::new(),0),
            vendorvm_instance : VendorVMInstance::default(),
            auto_shutdown_thread_handler: AutoShutdownHandleStruct::default(),
            shutdown_notifier: None,
            childpid: None,
//          vendorvm_state: VendorVMState::VM_NOT_STARTED;
        };
        inst.set_vm_status_property("NOT_STARTED");
        return inst;
    }

    pub fn notify_clients(&mut self, event: &str, event_reason: &str) -> () {
        let reason:u32 = event_reason.parse::<u32>().unwrap_or(0);
        let mut reason_string:String = String::new();
        if event == "create" {
            if self.vm_state == VirtualMachineState::RUNNING {
                info!(
                    "Event=create received for {}, state change to RUNNING",
                    self.vm_parameters.name
                );

            }
            else if self.vm_state == VirtualMachineState::VM_USERSPACE_READY {
                info!(
                    "Event=create received for {}, state change to VM_USERSPACE_READY",
                    self.vm_parameters.name
                );
            }
            else{
                info!(
                    "Event=create received for {}, Unknown VM state",
                    self.vm_parameters.name
                );
            }

        } else if event == "destroy" {
            info!(
                "Event=destroy received for {}, state change to STOPPED",
                self.vm_parameters.name
            );
            self.vm_state = VirtualMachineState::STOPPED;
            self.set_vm_status_property("STOPPED");
            if reason > 3 {
                info!(
                    "Event=destroy received for {}, state change to CRASHED",
                    self.vm_parameters.name
                );
                reason_string = format!("VM crashed and setting VM to crashed state");
                self.vm_state = VirtualMachineState::VM_CRASHED;
                self.set_vm_status_property("VM_CRASHED");
            }
        }

        // notify_clients
        if self.vm_clients.is_empty() {
            info!(
                "No clients registered for {} callback yet.",
                self.vm_parameters.name
            );
            return;
        }
        info!(
            "Notifying {} clients of {} the reason for VM {}",
            self.vm_clients.len(),
            self.vm_parameters.name,
            reason_string
        );

        for vm_client in &self.vm_clients {
            match vm_client.vm_client_callback.onStatusChanged(self.vm_state) {
                Ok(_) => {
                    debug!("notify_clients: {}-CallbackObject[ClientId: {:?}]->onStatusChanged({:?}): success",
                        self.vm_parameters.name, vm_client.vm_client_callback.as_binder(), self.vm_state);
                }
                _ => {
                    debug!("notify_clients: {}-CallbackObject[ClientId]->onStatusChanged({:?}): success",
                        self.vm_parameters.name, self.vm_state);
                }
            }
        }
    }

    fn wait_for_exit(
        pid: &i32,
        force_exit: Option<bool>,
    ) -> Result<(), Box<dyn Error>> {
        // Send kill if forcing exit
        if force_exit.unwrap_or(false)
            && (waitpid(
                Pid::from_raw(*pid),
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED),
            ) == Ok(WaitStatus::StillAlive))
        {
            info!("Sending 'SIGKILL' signal to PID={pid}");
            kill(Pid::from_raw(*pid), Signal::SIGKILL)?;
        }

        match waitpid(
            Pid::from_raw(*pid),
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED),
        ) {
            Ok(status)=>{
            info!("Status of waitforpid: {:?}",status);
            match status {
                WaitStatus::Exited(pid, s) => {
                    if s > 0 {
                        error!("PID:{pid} exit not success (0), result {s}");
                        info!("Enter Exited");
                        return Err("Result {s}".into());
                    }
                }
                WaitStatus::Signaled(pid, sig, _) => {
                    info!("PID:{pid} terminated with signal: {sig}");
                    info!("Enter Signaled");
                    return Err("Result {sig}".into());
                }
                _ => {/* pass through */
                info!("Enter all other conditions");}
            };
            }
            Err(_)=>{
                info!("No Status found waitpid failed");
            }
        }
        return Ok(());
    }

    fn boot_vm(&mut self) -> Result<i32, Box<dyn Error>> {
        let mut pid: i32 = 0;

        if self.vm_parameters.boot_operation != ControlState::Start {
            // Boot operation in JSON file not set to start
            return Ok(pid);
        }

        let mut args: Vec<CString> = Vec::new();
        args.push(CString::new(VM_BINARY_FILE)?);
        for disk_parameter in &self.vm_parameters.disk {
            args.push(CString::new(format!(
                "--disk={},label={},rw={}",
                disk_parameter.image,
                disk_parameter.label,
                disk_parameter.read_write
            ))?);
        }
        args.push(CString::new(format!("--vm={}", self.vm_parameters.name))?);

        //Static CID additions
        if self.vm_parameters.cid > 0 && self.vm_parameters.vsock_label.is_empty() != true
       {
            args.push(CString::new(format!(
                "--vsock=label={},cid={}",
                self.vm_parameters.vsock_label,
                self.vm_parameters.cid
            ))?);
        }

        //Total Memory Check
        if self.vm_parameters.mem > 0
        {
            args.push(CString::new(format!(
                "--mem={}",
                self.vm_parameters.mem
            ))?);
        }

        // Do fork and exec
        match unsafe {fork()}{
            Ok(ForkResult::Parent { .. }) => {
                match wait(){
                    Ok(WaitStatus::Exited(_, _)) => {
                        info!("First Child exited, Parent continues");
                    }
                    Ok(WaitStatus::Signaled(_, _, _)) => {
                        info!("First Child terminated by a signal");
                    }
                    Ok(_) => {
                        info!("Unexpected Status from wait.");
                    }
                    Err(e) => {
                        error!("Fork Error{:?}",e);
                        error!("{}: first child exited unexpectedly", self.vm_parameters.name);
                        return Err("first child exited unexpectedly".into());
                    }
                }
                thread::sleep(Duration::new(
                    self.vm_parameters.boot_wait_time.into(),
                    0,
                ));
                pid = self.childpid.map(|pid| pid.as_raw()).unwrap_or(0);
                return Ok(pid);
            }
            Ok(ForkResult::Child) => {
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child }) => {
                        pid = child.into();
                        thread::sleep(Duration::new(
                            self.vm_parameters.boot_wait_time.into(),
                            0,
                        ));

                        // Wait for qcrosvm to exit
                        match Self::wait_for_exit(&pid, Some(false)) {
                            Ok(_) => {
                                self.childpid = Some(Pid::from_raw(pid).clone());
                                info!("{:?}: qcrosvm created Successfully", pid);
                            }
                            Err(_) => {
                                error!("{}: qcrosvm exited unexpectedly", self.vm_parameters.name);
                            }
                        }
                    }
                    Ok(ForkResult::Child) => {
                        let args_obj: Vec<&CStr> =
                            args.iter().map(|c| c.as_c_str()).collect();
                        match setsid(){
                                        Ok(_) => {
                                        match execv(args_obj[0], &args_obj) {
                                           Ok(_) => {info!("Launch Successful");}
                                           Err(_) => {
                                           error!("+----------------------------------------+");
                                           error!(
                                           "\t{}: launch failed. exiting...",
                                           self.vm_parameters.name
                                           );
                                           error!("+----------------------------------------+");
                                     }
                                }
                            }
                            Err(_) =>{
                                error!("+----------------------------------------+");
                                error!(
                                    "\t{}: launch failed. exiting...",
                                    self.vm_parameters.name
                                );
                                error!("+----------------------------------------+");
                            }
                        }
                        unsafe {
                            _exit(1);
                        }
                    }
                    Err(e) => {
                        error!("Second Child Fork failed = {}", e);
                        return Err("Fork failed".into());
                    }
                }
                unsafe {
                    _exit(1);
                }
            }
            Err(e) => {
                error!("Parent Child Fork failed = {}", e);
                return Err("Fork failed".into());
            }
        }
    }

    fn boot_sequence(&mut self) -> Result<i32, Box<dyn Error>> {
        let mut boot_try = 0u8;
        loop {
            boot_try += 1;

            match self.boot_vm() {
                Ok(pid) => {
                    info!(
                        "Boot operation completed for {}, pid={}",
                        self.vm_parameters.name, pid
                    );
                    return Ok(pid);
                }
                Err(response) => {
                    if boot_try < self.vm_parameters.try_count {
                        error!(
                            "VM boot operation failed for {}, trying again",
                            self.vm_parameters.name
                        );
                        thread::sleep(Duration::new(
                            self.vm_parameters.boot_wait_time.into(),
                            0,
                        ));
                        continue;
                    } else {
                        error!(
                            "{} Boot Failed!!! No. of attempts: {boot_try}",
                            self.vm_parameters.name
                        );
                        return Err(response);
                    }
                }
            }
        }
    }

    fn launch_vm(&mut self) -> Result<i32, Box<dyn Error>> {
        info!("Requested launchVM for {}", self.vm_parameters.name);

        let board_api_level: u32 = system_properties::read("ro.vendor.api_level")
                              .unwrap_or(None)
                              .unwrap_or("0".to_string())
                              .parse()
                              .unwrap();
        if board_api_level < 202504 {
            debug!("VM Shutdown Restart not Supported in Android Versions less than V(15)");
            self.vm_parameters.vm_ssr_enable = false
        }
        else{
            let vm_ssr_enable_runtime_prop: &str = &system_properties::read("ro.vendor.vm.ssr.enable")
                              .unwrap_or(Some(String::from("false")))
                              .unwrap();
            debug!("VM Restart flag value : {}", vm_ssr_enable_runtime_prop);
            if self.vm_parameters.vm_ssr_enable && vm_ssr_enable_runtime_prop != "true"{
                debug!("Please check with the VM team. The feature flag has not been set correctly");
                self.vm_parameters.vm_ssr_enable = false
            }
            if !self.vm_parameters.vm_ssr_enable && vm_ssr_enable_runtime_prop == "true" {
                debug!("Please check with the VM team. The feature flag in the config has not been set correctly");
                self.vm_parameters.vm_ssr_enable = false
            }
            if self.vm_parameters.vm_ssr_enable && vm_ssr_enable_runtime_prop == "true"{
                debug!("VM Shutdown Feature has been enabled");
            }
        }

        if self.vm_state == VirtualMachineState::RUNNING {
            info! {"{} is already in running state.", self.vm_parameters.name};
            return Ok(0);
        }
        else if self.vm_state == VirtualMachineState::VM_USERSPACE_READY {
            info! {"{} is already in running state.", self.vm_parameters.name};
            return Ok(1);
        }
        return self.boot_sequence();
    }

    pub fn launch_autostart_vm(&mut self) -> () {
        debug!("In launch_autostart_vm() for {}", self.vm_parameters.name);

        if let Err(e) = self.launch_vm() {
            error!(
                "launch_autostart_vm: {} failed with reason: {e}",
                self.vm_parameters.name
            );
        }
        self.vm_state = VirtualMachineState::RUNNING;
        self.set_vm_status_property("RUNNING");
        self.autostart_done = true;
    }

    fn set_vm_status_property(&self, vm_status: &str) -> () {
        info!("For {} VM state is being set to {:?}", self.vm_parameters.name, vm_status);
        let vm_status_prop =
            format!("vendor.qvirtmgr.{}.status", self.vm_parameters.name);
        let _res = system_properties::write(&vm_status_prop, vm_status); // Ignore the result.
    }

    // Vendor VM Functions

    fn get_vendorvm_instance(&self) -> Result<(),String>{
        let mut vendorvm_instance = self.vendorvm_instance.vendor_vm_instance.lock().unwrap();
        if self.vm_parameters.vm_ssr_enable && vendorvm_instance.is_none(){
            let vendorvm_description:String = BpVendorVM::get_descriptor().to_owned() + "/default";
            match vendor_binder::get_interface::<dyn IVendorVM>(&vendorvm_description){
                Ok(instance) => {
                    *vendorvm_instance = Some(instance);
                    /* if let Some(ref vendor_vm_death_monitor) = *vendorvm_instance{
                        let vendor_vm_death_monitor_clone = vendor_vm_death_monitor.clone();
                        let mut death_handler = DeathRecipient::new(move || {
                            info!("Vendor VM HAL died. please check if HAL is back");
                            VmInstance::handle_vendor_vm_death(vendor_vm_death_monitor_clone, &self.vm_state, &self.vm_parameters.try_count);
                        });
                        if let Err(e) = vendor_vm_death_monitor.as_binder().link_to_death(&mut death_handler){
                            return Err(e.to_string());
                        }
                    } */
                }
                Err(e) => {
                    return Err(e.to_string());
                }
            }
        }
        return Ok(());
    }

/*  fn handle_vendor_vm_death(vendor_vm_instance: Strong<dyn IVendorVM>, vmstate: &VirtualMachineState, try_count: &u8) -> (){
        thread::spawn(move || {
                for retry_count in 0..*try_count {
                    info!("retry count {} ",retry_count.to_string());
                    thread::sleep(Duration::from_secs(5));
                    let vendorvm_description:String = BpVendorVM::get_descriptor().to_owned() + "/default";
                    if let Ok(instance) = vendor_binder::get_interface::<dyn IVendorVM>(&vendorvm_description){
                            *vendor_vm_instance = Some(instance.into());
                            return;
                    }
                }
                *vmstate = VirtualMachineState::VM_CRASHED;
            }
        );
    } */

    fn set_vendor_vm_info(&mut self) -> () {
        self.vendorvminfo.name = self.vm_parameters.name.clone();
        self.vendorvminfo.cid = self.vm_parameters.cid as i64;
    }

    // handle communication with Vendor VM HAL

    fn connect_vendorvm(&mut self)-> Result<i32, Box<dyn Error>> {
        let mut boot_try = 0u8;
        loop{
            boot_try += 1;
            if boot_try == 1 {
                debug!("Waiting for VM Userspace to be up for the first time");
                thread::sleep(Duration::new(
                                self.vm_parameters.vm_userspace_waittimer.into(),
                                0,
                            ));
            }
            match self.get_vendorvm_instance(){
                Ok(_) => {
                    let vendorvm_instance = self.vendorvm_instance.vendor_vm_instance.lock().unwrap();
                    if let Some(ref vendorvm_instance_unwrap) = *vendorvm_instance{
                        match vendorvm_instance_unwrap.connectvm(&self.vendorvminfo){
                            Ok(VMErrorCodes::SUCCESS) => {
                                self.vm_state = VirtualMachineState::VM_USERSPACE_READY;
                                self.set_vm_status_property("VM_USERSPACE_READY");
                                info!("Connection was successful");
                                return Ok(0);
                            },
                            Ok(_) => {
                                let response_fail: String = "Connection failed".to_string();
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        "VM User Space Connection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Boot Failed!!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    info!("VM being set in crashed state and connections will not be allowed");
                                    if self.childpid != None{
                                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                                            Ok(_) => {
                                                info!("Killing vm Instance and Setting Crashed state");
                                            },
                                            Err(e) => {
                                                error!("{}", format!("Error Killing VM instance {}",e));
                                            }
                                        }
                                    }
                                    self.vm_state = VirtualMachineState::VM_CRASHED;
                                    self.set_vm_status_property("VM_CRASHED");
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response_fail.to_string()),
                                    )));
                                }
                            },
                            Err(response) => {
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        "Vendor VM User Space Connection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Boot Failed!!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    info!("VM being set in crashed state and connections will not be allowed as Error");
                                    if self.childpid != None{
                                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                                            Ok(_) => {
                                                info!("Killing vm Instance and Setting Crashed state");
                                            },
                                            Err(e) => {
                                                error!("{}", format!("Error Killing VM instance {}",e));
                                            }
                                        }
                                    }
                                    self.vm_state = VirtualMachineState::VM_CRASHED;
                                    self.set_vm_status_property("VM_CRASHED");
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response.to_string()),
                                    )));
                                }
                            }
                        }
                    }
                }
                Err(response) => {
                    if self.childpid != None{
                        info!("Vendor VM communication failed");
                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                            Ok(_) => {
                                info!("Killing vm Instance and Setting Crashed state");
                            },
                            Err(e) => {
                                error!("{}", format!("Error Killing VM instance {}",e));
                            }
                        }
                    }
                    self.vm_state = VirtualMachineState::VM_CRASHED;
                    self.set_vm_status_property("VM_CRASHED");
                    return Err(Box::new(Status::new_service_specific_error_str(
                        ERROR_VM_START,
                        Some(response.to_string()),
                    )));
                }
            }
        }
    }

    fn disconnect_vendorvm(&mut self)-> Result<i32, Box<dyn Error>> {
        let mut boot_try = 0u8;
        loop{
            boot_try += 1;
            match self.get_vendorvm_instance(){
                Ok(_) => {
                    let vendorvm_instance = self.vendorvm_instance.vendor_vm_instance.lock().unwrap();
                    if let Some(ref vendorvm_instance_unwrap) = *vendorvm_instance{
                        match vendorvm_instance_unwrap.disconnectvm(&self.vendorvminfo){
                            Ok(VMErrorCodes::SUCCESS) => {
                                info!("Disconnection was successful");
                                return Ok(0);
                            },
                            Ok(_) => {
                                let response_fail: String = "Connection failed".to_string();
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        "Vendor VM disconnection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Disconnection Failed!!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response_fail.to_string()),
                                    )));
                                }
                            },
                            Err(response) => {
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        "Vendor VM disconnection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Disconnection Failed!!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response.to_string()),
                                    )));
                                }
                            }
                        }
                    }
                }
                Err(response) => {
                    if self.childpid != None{
                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                            Ok(_) => {
                                info!("Disconnect: Killing Vendor vm Instance and Setting Crashed state");
                            },
                            Err(e) => {
                                error!("{}", format!("Error Killing Vendor  VM instance {}",e));
                            }
                        }
                    }
                    self.vm_state = VirtualMachineState::VM_CRASHED;
                    self.set_vm_status_property("VM_CRASHED");
                    return Err(Box::new(Status::new_service_specific_error_str(
                        ERROR_VM_START,
                        Some(response.to_string()),
                    )));
                }
            }
        }
    }

    fn prfmtsk_vendorvm(&mut self,vm_task: VMTasks)-> Result<i32, Box<dyn Error>> {
        let mut boot_try = 0u8;
        loop{
            boot_try += 1;
            match self.get_vendorvm_instance(){
                Ok(_) => {
                    let vendorvm_instance = self.vendorvm_instance.vendor_vm_instance.lock().unwrap();
                    if let Some(ref vendorvm_instance_unwrap) = *vendorvm_instance{
                        match vendorvm_instance_unwrap.performtaskvm(&self.vendorvminfo, vm_task){
                            Ok(VMErrorCodes::SUCCESS) => {
                                self.vm_state = VirtualMachineState::STOPPED;
                                self.set_vm_status_property("STOPPED");
                                info!("Shutdown was successful");
                                return Ok(0);
                            },
                            Ok(_) => {
                                let response_fail: String = "Connection failed".to_string();
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        " Vendor VM User Space Connection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Perform Task Failed !!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response_fail.to_string()),
                                    )));
                                }
                            },
                            Err(response) => {
                                if boot_try < self.vm_parameters.try_count {
                                    error!(
                                        "VM User Space Connection failed for {}, trying again",
                                        self.vm_parameters.name
                                    );
                                    thread::sleep(Duration::new(
                                        self.vm_parameters.vm_ssr_timeout.into(),
                                        0,
                                    ));
                                    continue;
                                } else {
                                    error!(
                                        "{} Perform Task Failed!!! No. of attempts: {boot_try}",
                                        self.vm_parameters.name
                                    );
                                    return Err(Box::new(Status::new_service_specific_error_str(
                                        ERROR_VM_START,
                                        Some(response.to_string()),
                                    )));
                                }
                            }
                        }
                    }
                }
                Err(response) => {
                    info!("Not able to get Vendor VM instance inside Perform Task, Hence killing VM");
                    if self.childpid != None{
                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                            Ok(_) => {
                                info!("Killing vm Instance and Setting Crashed state");
                            },
                            Err(e) => {
                                error!("{}", format!("Error Killing VM instance {}",e));
                            }
                        }
                    }
                    self.vm_state = VirtualMachineState::VM_CRASHED;
                    self.set_vm_status_property("VM_CRASHED");
                    return Err(Box::new(Status::new_service_specific_error_str(
                        ERROR_VM_START,
                        Some(response.to_string()),
                    )));
                }
            }
        }
    }

    /* fn updatevendorvm_state(&mut self) -> Result<i32, Box<dyn Error>> {
        match self.get_vendorvm_instance(){
            Ok(_) => {
                let vendorvm_instance = self.vendorvm_instance.vendor_vm_instance.lock().unwrap();
                if let Some(ref vendorvm_instance_unwrap) = *vendorvm_instance{
                    match vendorvm_instance_unwrap.getState(&self.vendorvminfo){
                        Ok(VMErrorCodes::VM_NOT_STARTED) => {
                            self.vendorvm_state = VendorVMState::VM_NOT_STARTED;
                            info!("Got state");
                            return Ok(0);
                        },
                        Ok(VMErrorCodes::VM_BOOT_READY ) => {
                            self.vendorvm_state = VendorVMState::VM_BOOT_READY ;
                            info!("VM_BOOT_READY");
                            return Ok(0);
                        },
                        Ok(VMErrorCodes::VM_USERSPACE_READY) => {
                            self.vendorvm_state = VendorVMState::VM_USERSPACE_READY;
                            info!("Got state: VM_USERSPACE_READY");
                            return Ok(0);
                        },
                        Ok(VMErrorCodes::VM_TASK_INPROGRESS) => {
                            self.vendorvm_state = VendorVMState::VM_TASK_INPROGRESS;
                            info!("Got state : VM_TASK_INPROGRESS");
                            return Ok(0);
                        },
                        Ok(VMErrorCodes::VM_SHUTDOWN) => {
                            self.vendorvm_state = VendorVMState::VM_SHUTDOWN;
                            info!("Got state: VM_SHUTDOWN");
                            return Ok(0);
                        },
                        Ok(VMErrorCodes::VM_CRASHED) => {
                            self.vendorvm_state = VendorVMState::VM_CRASHED;
                            info!("Got State : VM_CRASHED");
                            return Ok(0);
                        },
                        Ok(_) => {
                            let response_fail: String = "Something incorrect with the State Please check".to_string();
                            error!(
                                "{} Get State Failed",
                                self.vm_parameters.name
                            );
                            return Err(Box::new(Status::new_service_specific_error_str(
                                ERROR_VM_START,
                                Some(response_fail.to_string()),
                            )));
                        },
                        Err(response) => {
                            error!(
                                "{} Get State on Vendor VM Failed",
                                self.vm_parameters.name
                            );
                            return Err(Box::new(Status::new_service_specific_error_str(
                                ERROR_VM_START,
                                Some(response.to_string()),
                            )));
                        }
                    }
                }
            }
            Err(response) => {
                self.vm_state = VirtualMachineState::VM_CRASHED;
                self.set_vm_status_property("VM_CRASHED");
                return Err(Box::new(Status::new_service_specific_error_str(
                    ERROR_VM_START,
                    Some(response.to_string()),
                )));
            }
        }
    } */
    // Unregister sequence

    fn vm_client_unregister(&mut self) -> Result<i32, Box<dyn Error>> {
        match self.vm_clients.is_empty(){
            true =>{
                let response =format!("No Callbacks have been registered for the VM : {}",self.vm_parameters.name);
                    error!("{}",response);
                    return Err(response.into());
            },
            false => {
                if let Some(idx) = self.vm_clients
                .iter()
                .position(|client_info| client_info.pid == ThreadState::get_calling_pid() && client_info.uid == ThreadState::get_calling_uid())
                {
                    debug!("Callback is being removed in VM {} for the following id: {}, pid: {}, uid: {}",
                    self.vm_parameters.name,self.vm_clients[idx].death_id,self.vm_clients[idx].pid,self.vm_clients[idx].uid);
                    self.death_recipients.remove(&self.vm_clients[idx].death_id);
                    self.vm_clients.remove(idx);
                    return Ok(0);
                }
                let response = format!("No Callbacks have been registered for the client in the VM : {}",self.vm_parameters.name);
                error!("{}",response);
                return Err(response.into());
            }
        }
    }

    fn start_auto_shutdown(&mut self) -> Result<i32, Box<dyn Error>> {
        match self.prfmtsk_vendorvm(VMTasks::VM_SHUTDOWN){
            Ok(0) => {
                info!("VM Shutdown was succesful. Going forward to disconnecting all the VM's ");
                //Initiate the connection to the vendor VM and connect with the QTVM
                match self.disconnect_vendorvm(){
                    Ok(0) => {
                        info!("VM disonnection is set and we have shutdown the VM");
                    },
                    Ok(_) => {
                        info!("VM disonnection is not successful. Please do a cleanup");
                    },
                    Err(response) => {
                        error!(
                            "VM has been disconnected: {} has been removed: {response}",
                            self.vm_parameters.name
                        );
                        return Err(Box::new(Status::new_service_specific_error_str(
                            ERROR_VM_START,
                            Some(response.to_string()),
                        )));
                    }
                }
                self.vm_state = VirtualMachineState::STOPPED;
                self.set_vm_status_property("STOPPED");
                return Ok(0);
            },
            Ok(_) => {
                info!("VM Shutdown was not succesful. Resetting timers ");
                return Ok(1);
            }
            Err(response) => {
                error!(
                    "Shutdown was not successful: {} It will be removed: {response}",
                    self.vm_parameters.name
                );
                return Err(Box::new(Status::new_service_specific_error_str(
                    ERROR_VM_START,
                    Some(response.to_string()),
                )));
            }
        }
    }

    pub fn autostart_connectvm(&mut self)-> Result<i32, Box<dyn Error>> {
        if self.vm_parameters.vm_ssr_enable && self.autostart_done{
            self.set_vendor_vm_info();
            match self.connect_vendorvm(){
                Ok(_) => {
                    info!("VM Connection is set and we have connected to userspace");
                    //Initiate the connection to the vendor VM and connect with the QTVM
                    self.vm_state = VirtualMachineState::VM_USERSPACE_READY;
                    self.set_vm_status_property("VM_USERSPACE_READY");
                    return Ok(0);
                },
                Err(response) => {
                    error!(
                        "VM: {} has been removed: {response}",
                        self.vm_parameters.name
                    );
                    if self.childpid != None{
                        match kill(self.childpid.unwrap(),Signal::SIGKILL){
                            Ok(_) => {
                                info!("Killing vm Instance and Setting Crashed state");
                            },
                            Err(e) => {
                                error!("{}", format!("Error Killing VM instance {}",e));
                            }
                        }
                    }
                    self.vm_state = VirtualMachineState::VM_CRASHED;
                    self.set_vm_status_property("VM_CRASHED");
                    return Err(Box::new(Status::new_service_specific_error_str(
                        ERROR_VM_START,
                        Some(response.to_string()),
                    )));
                }
            }
        }
        else{
            info!("HAL does not support to connect to userspace,");
            let response="HAL does not support to connect to userspace,";
            return Err(Box::new(Status::new_service_specific_error_str(
                ERROR_VM_START,
                Some(response.to_string()),
            )));
        }
    }

    pub fn auto_shutdown_thread_handle_initiator(self_instance: Arc<Mutex<Self>>) -> () {
        let vm_instance = Arc::clone(&self_instance);

        {
            let vminstance = self_instance.lock().unwrap();

            if let Some(vminstance_shutdown_notifier) = &vminstance.shutdown_notifier{
                let _ = vminstance_shutdown_notifier.send(());
            }

            let  mut shutdown_thread_instance = vminstance.auto_shutdown_thread_handler.auto_shutdown_thread.lock().unwrap();
            if let Some(shutdown_thread) = shutdown_thread_instance.take()
            {
                let _ = shutdown_thread.join();
            }
        }
        {
            let mut vminstance = self_instance.lock().unwrap();
            let (tx,rx) = channel();
            vminstance.shutdown_notifier = Some(tx);


            let new_auto_shutdown_handle: thread::JoinHandle<()> = thread::spawn(move || {
                let boot_try = 0u8;
                loop {
                    info!("Inside Auto shutdown loop");
                    if let Ok(_) = rx.recv_timeout(Duration::from_secs(100)){
                        break;
                    }
                    if let Ok(mut instance) = vm_instance.lock(){
                        info!("Printing the State Inside the VM for Name: {} , State: {:?}",instance.vm_parameters.name, instance.vm_state);
                        if instance.vm_parameters.total_votes == 0 && instance.vm_state == VirtualMachineState::VM_USERSPACE_READY {
                            match instance.start_auto_shutdown(){
                            Ok(0) => {
                                info!("Shutdown is successful");
                                break;
                            },
                            Ok(_) => {
                                info!("Shutdown is not successful resetting timers");
                                drop(instance);
                                thread::sleep(Duration::from_secs(600));
                                continue;
                            },
                            Err(response) => {
                                        if boot_try < instance.vm_parameters.try_count {
                                        error!(
                                            "Shutdown failed for VM: {}, trying again",
                                            instance.vm_parameters.name
                                        );
                                        thread::sleep(Duration::new(
                                            instance.vm_parameters.vm_ssr_timeout.into(),
                                            0,
                                        ));
                                        continue;
                                    } else {
                                        error!(
                                            "{} Shutdown Failed!!! No. of attempts: {boot_try} reason: {}",
                                            instance.vm_parameters.name,response.to_string()
                                        );
                                        drop(instance);
                                        thread::sleep(Duration::from_secs(600));
                                        continue;
                                    }
                                }
                            }
                        }
                        else{
                            drop(instance);
                            thread::sleep(Duration::from_secs(600));
                        }
                    }
                }
            });
            vminstance.auto_shutdown_thread_handler.auto_shutdown_thread = Arc::new(Mutex::new(Some(new_auto_shutdown_handle)));
        }
    }
}

// ======================================================================
// CORE IMPLEMENTATION
// ======================================================================
pub struct VirtualMachine {
    // to_binder consumes VirtualMachine (unique_ptr).
    // As result, cannot store it in virtualization_service.rs map.
    // Instead, put a reference to VmInstance in each VirtualMachine.
    // Store the VmInstance and give out a new IVirtualMachine wrapper each time.

    // vm_instance
    // - Arc -> multple threads calling start, etc.
    // - Mutex -> Only single access at a time.
    pub vm_instance: Arc<Mutex<VmInstance>>,
    pub current_soc: String,
}

impl VirtualMachine {
    pub fn to_binder(self) -> Strong<dyn IVirtualMachine> {
        BnVirtualMachine::new_binder(self, BinderFeatures::default())
    }
}

impl Interface for VirtualMachine {}

// All operations must be atomic.
impl IVirtualMachine for VirtualMachine {
    fn getState(&self) -> Result<VirtualMachineState, Status> {
        // Holds lock until state is returned
        if let Ok(instance) = self.vm_instance.lock() {
            info!(
                "Requested getState for {} from pid={}. State is {:?}",
                instance.vm_parameters.name,
                ThreadState::get_calling_pid(),
                instance.vm_state
            );
            return Ok(instance.vm_state);
        }
        // Strange case, mutex poisoned.
        return Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("Internal Error"),
        ));
    }

    fn registerCallback(
        &self,
        callback: &Strong<(dyn IVirtualMachineCallback)>,
    ) -> Result<(), Status> {
        // Holds lock until cb registered
        if let Ok(mut instance) = self.vm_instance.lock() {
            info!(
                "Requested Callback Registration for {} from pid={}, uid={}",
                instance.vm_parameters.name,
                ThreadState::get_calling_pid(),
                ThreadState::get_calling_uid()
            );

            if instance
                .vm_clients
                .iter()
                .any(|client_info| client_info.vm_client_callback == *callback)
            {
                error!("Duplicate request from CallbackObject for {} from pid={}, uid={}",
                    instance.vm_parameters.name, ThreadState::get_calling_pid(), ThreadState::get_calling_uid());
                return Err(Status::new_exception_str(
                    ExceptionCode::ILLEGAL_ARGUMENT,
                    Some("The callback is already registered"),
                ));
            }
            let id = instance.death_id.fetch_add(1, Ordering::SeqCst); // Generate unique ID for the hashmap.
            let client_info = VMClient::new(callback.clone(), ThreadState::get_calling_pid(), ThreadState::get_calling_uid(),id);
            instance.vm_clients.push(client_info.clone());

            // Register death notification to remove the cb when client dies.
            let vm_instance_clone = self.vm_instance.clone();
            let callback_clone = callback.clone();
            // Create the death notification callback
            let mut death_recipient = DeathRecipient::new(move || {
                // Find and remove the stored callback and DeathRecipient.
                if let Ok(mut vm_instance) = vm_instance_clone.lock() {
                    info!(
                        "Recieved death notification for {} - client {} with pid={}, uid={}!",
                        vm_instance.vm_parameters.name,client_info.death_id,client_info.pid,client_info.uid);
                    match vm_instance.vm_clients.is_empty(){
                        true => {
                                // Client registered but not callback which is  not possible
                            debug!(
                                "No Callback object present for {} - client {} with pid={}, uid={}!",
                                vm_instance.vm_parameters.name,client_info.death_id,client_info.pid,client_info.uid);
                            },
                        false =>{
                            if let Some(idx) = vm_instance.vm_clients.iter().position(|client_info| client_info.vm_client_callback == callback_clone)
                            {
                                debug!(
                                    "Cleared the callback object for {} - client {} with pid={}, uid={}!",
                                    vm_instance.vm_parameters.name,client_info.death_id,client_info.pid,client_info.uid);
                                vm_instance.vm_clients.remove(idx);
                            }
                            // Strange case
                            debug!(
                                "Callback object not found for {} - client {} with pid={}, uid={}!",
                                vm_instance.vm_parameters.name,client_info.death_id,client_info.pid,client_info.uid);
                        }
                    }
                    // If death notification triggered, it is guaranteed that this death recipient is stale.
                    // Remove it regardless of if cb was found. It cannot be triggered again.
                    vm_instance.death_recipients.remove(&client_info.death_id);
                }
            });
            let mut cb_binder = callback.as_binder();
            cb_binder.link_to_death(&mut death_recipient)?;

            debug!(
                "Registered callback for {} - client {} with pid={}, uid={}!",
                instance.vm_parameters.name,client_info.death_id,client_info.pid,client_info.uid);

            // Add DeathRecipient to a vector to keep it alive.
            instance.death_recipients.insert(client_info.death_id, death_recipient);
            return Ok(());
        }
        // Strange case, mutex poisoned.
        return Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("Internal Error"),
        ));
    }

    fn start(&self) -> Result<(), Status> {
        let vm_launch_result : i32;
        let vm_launch_result_response : String;
        if let Ok(mut instance) = self.vm_instance.lock() {
            // Holds lock until completely done with boot.
            info!(
                "Requested start for {} from pid={}",
                instance.vm_parameters.name,
                ThreadState::get_calling_pid()
            );

            // Check if on demand VM
            if instance.vm_parameters.on_demand_start_supported {
                if instance.vm_parameters.enabled_socs.is_empty() {
                    if !(instance.vm_parameters.enable) {
                        error!("Request received from pid={} to start a Vm that doesn't support on-demand start, rejecting it.",
                                ThreadState::get_calling_pid());
                        debug!(
                            "enable: {}, on_demand_start_supported: {}",
                            instance.vm_parameters.enable,
                            instance.vm_parameters.on_demand_start_supported
                        );
                        return Err(Status::new_exception(
                            ExceptionCode::UNSUPPORTED_OPERATION,
                            None,
                        ));
                    }
                }
                else {
                    let current_soc = &self.current_soc;
                    debug!("Current SKU value is {}", current_soc);
                    if !instance.vm_parameters.enabled_socs.contains(current_soc) {
                        error!("Request received from pid={} to start a Vm that doesn't support on-demand start, rejecting it.",
                                ThreadState::get_calling_pid());
                        debug!(
                                "sku: {}, on_demand_start_supported: {}",
                                current_soc,
                                instance.vm_parameters.on_demand_start_supported
                        );
                        return Err(Status::new_exception(
                            ExceptionCode::UNSUPPORTED_OPERATION,
                            None,
                        ));
                    }
                }
            }
            else {
                error!("Request received from pid={} to start a Vm that doesn't support on-demand start, rejecting it.",
                        ThreadState::get_calling_pid());
                return Err(Status::new_exception(
                    ExceptionCode::UNSUPPORTED_OPERATION,
                    None,
                ));
            }

            // Check if autostart and not complete yet
            if instance.vm_parameters.autostart
                && !instance.vm_parameters.no_fs_dependency
                && !instance.autostart_done
            {
                error!("autostart enabled for this VM, requested start from pid={} while bootup ongoing, rejecting it.",
                       ThreadState::get_calling_pid());
                debug!(
                    "autostart: {}, FSDependency: {}, autostart_done: {}",
                    instance.vm_parameters.autostart,
                    instance.vm_parameters.no_fs_dependency,
                    instance.autostart_done
                );
                return Err(Status::new_service_specific_error_str(ERROR_VM_START,
                       Some("autostart enabled for this VM, requested start while bootup ongoing")));
            }
            let board_api_level: u32 = system_properties::read("ro.vendor.api_level")
                              .unwrap_or(None)
                              .unwrap_or("0".to_string())
                              .parse()
                              .unwrap();
            if board_api_level < 202504{
                if instance.vm_state == VirtualMachineState::VM_CRASHED || instance.vm_state == VirtualMachineState::STOPPED {
                    error!("Request received from pid={} to start a Vm which is in STOPPED/CRASHED state, rejecting it.",
                            ThreadState::get_calling_pid());
                    return Err(Status::new_service_specific_error_str(ERROR_VM_START,
                            Some("Cannot start a Vm which is in STOPPED/CRASHED state.")));
                }

            }
            else{
                if instance.vm_state == VirtualMachineState::VM_CRASHED {
                    error!("Request received from pid={} to start a Vm which is in CRASHED state, rejecting it.",
                            ThreadState::get_calling_pid());
                    return Err(Status::new_service_specific_error_str(ERROR_VM_START,
                            Some("Cannot start a Vm which is in CRASHED state.")));
                }
            }

            // Launch it! This block is to allow the VM to be spawned.
            match instance.launch_vm() {
                Ok(1) => {
                    info!("VM Already launched. Status of VM is {:?}",instance.vm_state);
                    vm_launch_result = 1;
                    vm_launch_result_response = ("VM launched Successfully").to_string();
                }
                Ok(_) => {
                    instance.vm_state = VirtualMachineState::RUNNING;
                    instance.set_vm_status_property("RUNNING");
                    info!("VM launch was succesful. Status of VM is {:?}",instance.vm_state);
                    vm_launch_result = 0;
                    vm_launch_result_response = ("VM launched Successfully").to_string();
                },
                Err(response) => {
                    error!(
                        "start: {} launch failed with reason: {response}",
                        instance.vm_parameters.name
                    );
                    vm_launch_result = ERROR_VM_START;
                    vm_launch_result_response = response.to_string();
                }
            }
            drop(instance);
        }
        // Strange case, mutex poisoned. If the initial mutex failed it would come here
        else{
            //If there is any issue in the VM ssr functionality it would fail
            return Err(Status::new_exception_str(
                    ExceptionCode::SERVICE_SPECIFIC,
                    Some("Internal Error"),
                    ));
        }
        if let Ok(mut instance) = self.vm_instance.lock() {
            //This block is for handling the communication between qvirtservice and the VM
            if vm_launch_result == 0 {
                if instance.vm_parameters.vm_ssr_enable {
                    if instance.vm_state == VirtualMachineState::RUNNING {
                        instance.set_vendor_vm_info();
                        match instance.connect_vendorvm(){
                            Ok(_) => {
                                info!("VM Connection is set and we have connected to userspace");
                                //Initiate the connection to the vendor VM and connect with the QTVM
                                instance.vm_state = VirtualMachineState::VM_USERSPACE_READY;
                                instance.set_vm_status_property("VM_USERSPACE_READY");
                            },
                            Err(response) => {
                                //VM communication failed so cleaning up VM resources and setting VM status to crashed
                                error!(
                                    "Client: {} has been removed: {response}",
                                    instance.vm_parameters.name
                                );
                                if instance.childpid != None{
                                    match kill(instance.childpid.unwrap(),Signal::SIGKILL){
                                        Ok(_) => {
                                            info!("Killing vm Instance and Setting Crashed state");
                                        },
                                        Err(e) => {
                                            error!("{}", format!("Error Killing VM instance {}",e));
                                        }
                                    }
                                }
                                instance.vm_state = VirtualMachineState::VM_CRASHED;
                                instance.set_vm_status_property("VM_CRASHED");
                                return Err(Status::new_service_specific_error_str(
                                    ERROR_VM_START,
                                    Some(response.to_string()),
                                ));
                            }
                        }
                        // Start auto the shutdown thread
                        drop(instance);
                        let vm_instance_clone = self.vm_instance.clone();
                        VmInstance::auto_shutdown_thread_handle_initiator(vm_instance_clone);
                    }
                }
                return Ok(());
            }
            else{
                //If there is any issue in the VM ssr functionality it would fail
                return Err(Status::new_service_specific_error_str(
                        ERROR_VM_START,
                        Some(vm_launch_result_response.to_string()),
                    ));
            }
        }
        // Strange case, mutex poisoned. If the initial mutex failed it would come here
        return Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("Internal Error"),
        ));
    }
    fn unregister(&self) -> Result<(), Status> {
        //Cleanup of vm resources
        if let Ok(mut instance) = self.vm_instance.lock() {
            if instance.vm_parameters.total_votes == 0 {
                match instance.vm_client_unregister() {
                    Ok(_) => return Ok(()),
                    Err(response) => {
                        error!(
                            "Client: {} has been removed: {response}",
                            instance.vm_parameters.name
                        );
                        return Err(Status::new_service_specific_error_str(
                            ERROR_VM_START,
                            Some(response.to_string()),
                        ));
                    }
                }
            }
            else{
                error!("Current VM state is {:?} and no client is connected to the HAL",instance.vm_state);
                return Err(Status::new_service_specific_error_str(
                            ERROR_VM_START,
                            Some("No Clients are connected. Please initiate the connection".to_string()),
                        ));

            }
        }
        // Strange case, mutex poisoned.
        return Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("Internal Error"),
        ));
    }
    fn performtask_client(&self, _task: VirtualMachineClientTask) -> Result<(), Status> {
        if let Ok(mut instance) = self.vm_instance.lock() {
            if instance.vm_parameters.vm_ssr_enable {
                if instance.vm_state == VirtualMachineState::VM_USERSPACE_READY {
                    if _task == VirtualMachineClientTask::VOTE {
                        info!("VM client has been voted");
                        instance.vm_parameters.total_votes += 1;
                        if let Some(idx) = instance.vm_clients
                        .iter()
                        .position(|client_info| client_info.pid == ThreadState::get_calling_pid() && client_info.uid == ThreadState::get_calling_uid())
                        {
                            debug!("Voting for the client is happening in VM {} for the following id: {}, pid: {}, uid: {}",
                            instance.vm_parameters.name,instance.vm_clients[idx].death_id,instance.vm_clients[idx].pid,instance.vm_clients[idx].uid);
                            instance.vm_clients[idx].client_vote_count += 1;
                        }
                    }
                    else if _task == VirtualMachineClientTask::UNVOTE {
                        if instance.vm_parameters.total_votes > 0 {
                            info!("VM client has been unvoted");
                            instance.vm_parameters.total_votes -= 1;
                            if let Some(idx) = instance.vm_clients
                            .iter()
                            .position(|client_info| client_info.pid == ThreadState::get_calling_pid() && client_info.uid == ThreadState::get_calling_uid())
                            {
                                debug!("Unvoting for the client is happening in VM {} for the following id: {}, pid: {}, uid: {}",
                                instance.vm_parameters.name,instance.vm_clients[idx].death_id,instance.vm_clients[idx].pid,instance.vm_clients[idx].uid);
                                instance.vm_clients[idx].client_vote_count -= 1;
                            }
                            if instance.vm_parameters.total_votes == 0{
                                if let Some(idx) = instance.vm_clients
                                .iter()
                                .position(|client_info| client_info.pid == ThreadState::get_calling_pid() && client_info.uid == ThreadState::get_calling_uid())
                                {
                                    if instance.vm_clients[idx].client_vote_count != 0 {
                                        error!("Client has not unvoted  while Total vote count has reduced{} for the following id: {}, pid: {}, uid: {}",
                                        instance.vm_parameters.name,instance.vm_clients[idx].death_id,instance.vm_clients[idx].pid,instance.vm_clients[idx].uid);
                                    }
                                }
                                info!("We need to start the shutdown timer");
                                drop(instance);
                                let vm_instance_clone = self.vm_instance.clone();
                                VmInstance::auto_shutdown_thread_handle_initiator(vm_instance_clone);
                            }
                        }
                        else if instance.vm_parameters.total_votes == 0{
                            info!("No Clients to Unvote");
                        }
                    }
                }
                else{
                    info!("Please do a start again and have the connection with the VM established");
                    return Err(Status::new_exception_str(
                    ExceptionCode::SERVICE_SPECIFIC,
                    Some("VM state not supported to do Perform task. Please call start again"),));
                }
                return Ok(());
            }
            else{
                info!("VM voting unvoting feature is disabled");
                return Err(Status::new_exception_str(
                ExceptionCode::SERVICE_SPECIFIC,
                Some("Feature is disabled"),));
            }
        }
        // Strange case, mutex poisoned.
        return Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("Internal Error"),
        ));
    }
}

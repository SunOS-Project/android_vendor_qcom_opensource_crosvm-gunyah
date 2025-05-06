/*
  * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
  * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

use binder::{
    BinderFeatures, DeathRecipient, IBinder, Interface, Strong,
};
use log::LevelFilter;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{thread, time};
use vendor_qti_qvirt::aidl::vendor::qti::qvirt::{
    IVirtualMachine::IVirtualMachine,
    IVirtualMachineCallback::{
        BnVirtualMachineCallback, IVirtualMachineCallback,
    },
    IVirtualizationService::{BpVirtualizationService, IVirtualizationService},
    VirtualMachineState::VirtualMachineState,
    VirtualMachineClientTask::VirtualMachineClientTask,
};
use vendor_qti_qvirt::binder;

struct VirtualMachineCallback {
    name: String,
}

impl Interface for VirtualMachineCallback {}

impl IVirtualMachineCallback for VirtualMachineCallback {
    fn onStatusChanged(
        &self,
        state: VirtualMachineState,
    ) -> Result<(), binder::Status> {
        println!("\n-------------------------------");
        println!("CB Recvd for VM: {}, New State: {:?}", self.name, state);
        println!("-------------------------------\n");
        Ok(())
    }
}

/*
State machine

Type a VM Name
    1 -> getState
    2 -> registerCallback
    3 -> start
    4 -> vote that VM is being used
    5 -> unvote that work on VM is done
    6 -> Unregister the VM connection
    7 -> Stop
 */
struct StateMachine {
    service: Strong<dyn IVirtualizationService>,
    vm: Option<Strong<dyn IVirtualMachine>>,
    name: Option<String>,
    callbacks: Vec<Strong<dyn IVirtualMachineCallback>>,
    _death_recipient: DeathRecipient,
    status: Arc<AtomicBool>,
}

impl StateMachine {
    fn new(service: Strong<dyn IVirtualizationService>) -> Self {
        // Create the death flag
        let status = Arc::new(AtomicBool::new(true));

        // Register for death
        let status_clone = status.clone();
        let mut death_recipient = DeathRecipient::new(move || {
            println!("\n-------------------------------");
            println!("VirtualizationService Died!!");
            println!("-------------------------------\n");
            status_clone.fetch_and(false, Ordering::SeqCst);
        });
        let mut svc = service.as_binder();
        svc.link_to_death(&mut death_recipient).unwrap();

        Self {
            service: service,
            vm: None,
            name: None,
            callbacks: Vec::new(),
            _death_recipient: death_recipient,
            status: status,
        }
    }
    fn get_vm(&mut self) -> () {
        let mut vm_name = String::new();
        println!("Enter VM Name: ");
        if std::io::stdin().read_line(&mut vm_name).is_ok() {
            self.vm = self.service.getVm(&(vm_name.trim())).ok();
            if self.vm.is_some() {
                self.name = Some(vm_name);
            }
        }
    }
    fn operate_vm(&mut self) -> () {
        let mut option = String::new();
        println!("\n------Options------");
        println!("1. getState");
        println!("2. registerCallback");
        println!("3. start");
        println!("4. Vote on the vm");
        println!("5. Unvote on the vm");
        println!("6. unregister the vm");
        println!("7. Drop vm");
        println!("-------------------");
        if std::io::stdin().read_line(&mut option).is_ok() {
            match option.trim().parse::<i32>() {
                Ok(1) => {
                    let state = self.vm.as_ref().unwrap().getState();
                    println!("getState Returned: {:?}", state);
                }
                Ok(2) => {
                    let cb = BnVirtualMachineCallback::new_binder(
                        VirtualMachineCallback {
                            name: self.name.as_ref().unwrap().clone(),
                        },
                        BinderFeatures::default(),
                    );
                    match self.vm.as_ref().unwrap().registerCallback(&cb) {
                        Ok(_) => {
                            println!("Registered!");
                            self.callbacks.push(cb); // Keep the cb alive
                        }
                        Err(e) => {
                            println!(
                                "Failed to register CB: {}",
                                e.get_description()
                            );
                        }
                    };
                }
                Ok(3) => {
                    if self.vm.as_ref().unwrap().start().is_ok() {
                        println!("Started VM");
                    } else {
                        println!("Failed to start VM");
                    }
                }
                Ok(4) => {
                    if self.vm.as_ref().unwrap().performtask_client(VirtualMachineClientTask::VOTE).is_ok() {
                        println!("Voted on the VM");
                    } else {
                        println!("Failed to Vote on the VM");
                    }
                }
                Ok(5) => {
                    if self.vm.as_ref().unwrap().performtask_client(VirtualMachineClientTask::UNVOTE).is_ok() {
                        println!("Un-Voted on the VM");
                    } else {
                        println!("Failed to Un-Vote on the VM");
                    }
                }
                Ok(6) => {
                    if self.vm.as_ref().unwrap().unregister().is_ok() {
                        println!("Unregistered the client on the VM");
                    } else {
                        println!("Failed to Unregister with the VM");
                    }
                }
                Ok(7) => {
                    println!("Dropping VM");
                    self.vm = None;
                    self.name = None;
                }
                _ => {}
            };
        }
    }
    fn run(&mut self) -> Result<(), ()> {
        loop {
            if !self.status.load(Ordering::SeqCst) {
                return Err(());
            } else if self.vm.is_some() {
                self.operate_vm();
            } else {
                self.get_vm();
            };
            thread::sleep(time::Duration::from_millis(500));
        }
    }
}

fn main() {
    binder::ProcessState::start_thread_pool();

    let _init_success = logger::init(
        logger::Config::default()
            .with_tag_on_device("qvirtservice_client")
            .with_max_level(LevelFilter::Debug),
    );

    loop {
        let virt_service: binder::Strong<dyn IVirtualizationService> =
            binder::get_interface(&format!(
                "{}/default",
                BpVirtualizationService::get_descriptor()
            ))
            .expect("Failed to register service.");

        let mut machine = StateMachine::new(virt_service);
        if let Err(_) = machine.run() {
            let mut act = String::new();
            println!("Service Dropped. Retry? (Y/N)");
            if std::io::stdin().read_line(&mut act).is_ok() {
                act = act.trim().to_uppercase();
                match act.as_str() {
                    "Y" | "YES" => continue,
                    "N" | "NO" => {}
                    _ => break,
                };
            }
        }
    }
}

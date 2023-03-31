// Copyright (c) 2021, 2023 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear


// Copyright 2017 The Chromium OS Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

extern crate log;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::convert::TryInto;

use log::{warn, debug};

use devices::virtio::Interrupt;
use base::{Event, Result};
use devices::virtio::{Queue, VirtioDevice};
use vm_memory::{GuestAddress, GuestMemory};
use devices::IrqLevelEvent;

const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

const VENDOR_ID: u32 = 0;

const MMIO_MAGIC_VALUE: u32 = 0x74726976;
const MMIO_VERSION: u32 = 2;

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioDevice {
        device: Box<dyn VirtioDevice>,
        device_activated: bool,
        features_select: u32,
        acked_features_select: u32,
        queue_select: u32,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: Option<IrqLevelEvent>,
        driver_status: u32,
        config_generation: u32,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
        mem: Option<GuestMemory>,
}

impl MmioDevice {

        /// Returns a label suitable for debug output.
        fn debug_label(&self) -> String {
            format!("virtio-mmio ({})", self.device.debug_label())
        }

        /// Constructs a new MMIO transport for the given virtio device.
        pub fn new(mem: GuestMemory, device: Box<dyn VirtioDevice>) -> Result<MmioDevice> {
            let mut queue_evts = Vec::new();
            for _ in device.queue_max_sizes().iter() {
                queue_evts.push(Event::new()?);
            }

            let queues = device
                        .queue_max_sizes()
                        .iter()
                        .map(|&s| Queue::new(s))
                        .collect();

            Ok(MmioDevice {
                        device,
                        device_activated: false,
                        features_select: 0,
                        acked_features_select: 0,
                        queue_select: 0,
                        interrupt_status: Arc::new(AtomicUsize::new(0)),
                        interrupt_evt: Some(IrqLevelEvent::new()?),
                        driver_status: 0,
                        config_generation: 0,
                        queues,
                        queue_evts,
                        mem: Some(mem),
            })
        }

        /// Gets the list of queue events that must be triggered whenever the VM writes to
        /// `virtio::NOTIFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
        /// value being written equals the index of the event in this list.
        pub fn queue_evts(&self) -> &[Event] {
            self.queue_evts.as_slice()
        }

        /// Gets the event this device uses to interrupt the VM when the used queue is changed.
        pub fn interrupt_evt(&self) -> Option<&Event> {
            let interrupt_evt = self.interrupt_evt.as_ref().unwrap();
            Some(interrupt_evt.get_trigger())
        }

        fn is_driver_ready(&self) -> bool {
            let ready_bits = DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK;
            self.driver_status == ready_bits && self.driver_status & DEVICE_FAILED == 0
        }

        fn are_queues_valid(&self) -> bool {
            if let Some(mem) = self.mem.as_ref() {
                self.queues.iter().all(|q| q.is_valid(mem))
            } else {
                false
            }
        }

        fn with_queue<U, F>(&self, d: U, f: F) -> U
        where
        F: FnOnce(&Queue) -> U,
        {
            match self.queues.get(self.queue_select as usize) {
                Some(queue) => f(queue),
                None => d,
            }
        }

        fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
            if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
                f(queue);
                true
            } else {
                false
            }
        }

        pub fn get_num_queues(&self) -> u32 {
                  return self.queues.len() as u32;
		    }

        pub fn read(&mut self, offset: u64, data: &mut [u8]) {
            match offset {
                0x00..=0xff if data.len() == 4 => {
                    let v = match offset {
                        0x0 => MMIO_MAGIC_VALUE,
                        0x04 => MMIO_VERSION,
                        0x08 => self.device.device_type(),
                        0x0c => VENDOR_ID, // vendor id
                        0x10 => {
                            let f: u64 = self.device.features();
                            let mut v: u32 = (f >> (self.features_select * 32)) as u32;
                            v = v | if self.features_select == 1 { 0x3 } else { 0x0 };
                            v
                       }
                       0x34 => self.with_queue(0, |q| q.max_size as u32),
                       0x44 => self.with_queue(0, |q| q.ready as u32),
                       0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                       0x70 => self.driver_status,
                       0xfc => self.config_generation,
                       _ => {
                           warn!("{}", format!("unknown virtio mmio register read {:x}", offset));
                           return;
                      }
                   };

                   data.copy_from_slice(&v.to_le_bytes());
               }
               0x100..=0xfff => {
                   self.device.read_config(offset - 0x100, data);
               }
               _ => {
                   let v: i32 = 0;
                   data.copy_from_slice(&v.to_le_bytes());
                   warn!("{}", format!("invalid virtio mmio read: 0x{:x}:0x{:x}", offset, data.len()));
               }
           };
        }

        pub fn write(&mut self, offset: u64, data: &[u8]) {
            fn hi(v: &mut GuestAddress, x: u32) {
                *v = (*v & 0xffffffff) | ((x as u64) << 32)
            }

            fn lo(v: &mut GuestAddress, x: u32) {
                *v = (*v & !0xffffffff) | (x as u64)
            }

            let mut mut_q = false;
            match offset {
                0x00..=0xff if data.len() == 4 => {
                    let v = u32::from_le_bytes(data.try_into().unwrap());
                    debug!("{}", format!("mmio_write offset {:x} val {:x}", offset, v));
                    match offset {
                        0x14 => self.features_select = v,
                        0x20 => {
                            let features: u64 = (v as u64) << (self.acked_features_select * 32);
                            self.device.ack_features(features);
                            for q in self.queues.iter_mut() {
                                q.ack_features(features);
                            }
                        }
                        0x24 => self.acked_features_select = v,
                        0x30 => self.queue_select = v,
                        0x38 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
                        0x44 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
                        0x64 => {},
                        0x70 => self.driver_status = v,
                        0x80 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
                        0x84 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
                        0x90 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
                        0x94 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
                        0xa0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
                        0xa4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
                        _ => {
                            warn!("{}", format!("unknown virtio mmio register write: 0x{:x}", offset));
                            return;
                        }
                    }
                }
                0x100..=0xfff => {
                    warn!("{}", format!("{:x} [W] ", offset));
                    return self.device.write_config(offset - 0x100, data);
                }
                _ => {
                    warn!("{}", format!("invalid virtio mmio write: 0x{:x}:0x{:x}", offset, data.len()));
                    return;
                }
            }

            if self.device_activated && mut_q && offset != 0x50 {
                warn!("virtio queue was changed after device was activated");
            }

            if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
                let interrupt_evt = self.interrupt_evt.as_ref().unwrap();
                let mem = self.mem.clone().unwrap();
		self.device.on_device_sandboxed();

		let mut interrupt = Interrupt::new(
				    self.interrupt_status.clone(),
				    interrupt_evt.try_clone().unwrap(),
				    None,
				    VIRTIO_MSI_NO_VECTOR,
				    );
		Interrupt::set_skip_check(&mut interrupt);

		self.device.activate(mem, interrupt, self.queues.clone(), self.queue_evts.split_off(0));
		self.device_activated = true;
		debug!("{} activated!", self.debug_label());
            }
      }
}

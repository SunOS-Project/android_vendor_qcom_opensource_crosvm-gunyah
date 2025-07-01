/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

use std::error::Error;
use std::os::unix::io::RawFd;

pub struct UEvent {}

impl UEvent {
    pub fn uevent_open_socket(
        buf_sz: usize,
        passcred: bool,
    ) -> Result<RawFd, Box<dyn Error>> {
        let fd = unsafe {
            uevent_bindgen::uevent_open_socket(buf_sz as i32, passcred)
        };
        if fd < 0 {
            return Err("Error: {fd}".into());
        }
        return Ok(fd);
    }

    pub fn uevent_kernel_multicast_recv(
        socket: RawFd,
        buffer: &mut Vec<u8>,
        length: usize,
    ) -> Result<usize, Box<dyn Error>> {
        *buffer = vec![0u8; length];
        let result = unsafe {
            uevent_bindgen::uevent_kernel_multicast_recv(
                socket,
                buffer.as_mut_ptr() as *mut libc::c_void,
                length,
            )
        };
        if result < 0 {
            *buffer = vec![0u8; length];
            return Err("Error: {result}".into());
        }
        return Ok(result.try_into()?);
    }
}

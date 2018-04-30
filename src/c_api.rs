use elf64::*;
use std::slice;
use libc::{uint8_t, size_t, c_int};

pub extern fn rs_parse_init(h: *mut Box<Elf64>, ptr: *const uint8_t, len: size_t) -> c_int {
    let buf = unsafe { slice::from_raw_parts(ptr, len as usize) };
    match parse_elf64(buf) {
        Ok((_rest, elf)) => {
            h = Box::new(elf) as *;
            (1 as c_int)
        },
        Err(_) => (0 as c_int)
    }
}

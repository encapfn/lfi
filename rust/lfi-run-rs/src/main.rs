use core::ptr;
use core::ffi::c_void;

use liblfi_sys::{lfi_new, LFIOptions};

unsafe extern "C" fn syscall(
    _ctxp: *mut c_void, sysno: u64, _arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64, _arg6: u64) -> u64 {
    println!("Received syscall with number {}", sysno);
    0
}

fn main() {
    let options = LFIOptions {
        poc: false,
        noverify: true,
        pagesize: page_size::get(),
        stacksize: 8 * 1024 * 1024,
        syshandler: Some(syscall),
        p2size: 0,
        gas: 0,
        verifier: ptr::null_mut(),
        sysexternal: false,
    };

    let lfi_engine = unsafe { lfi_new(options) };
    if lfi_engine == ptr::null_mut() {
        panic!("Failed to initialize LFI");
    }

    let err = unsafe { lfi_auto_add_vaspaces(lfi_engine, 0) };
    if err < 0 {
        panic!("Failed to add vaspaces: %d\n", err);
    }



    println!("Hello, world!");
}

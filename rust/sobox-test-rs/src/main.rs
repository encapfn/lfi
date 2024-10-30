use libsobox_sys::{Sobox, sbx_init, sbx_dlopen, sbx_dlsymfn, sbx_dlinvoke, sbx_lfi_proc_regs, sbx_invoke, lfi_regs_arg};

fn main() {
    let mut sbx: Sobox = Sobox { lfimgr: std::ptr::null_mut() };
    
    assert!(
        unsafe { sbx_init(&mut sbx) },
        "Failed to initialize Sobox!"
    );

    let lib = unsafe { sbx_dlopen(
            &mut sbx,
            // c"libsobox/test/libtest.so".as_ptr(),
            c"/root/lfi2/build-toolchain/libsobox/test/libtest.so".as_ptr(),
            0
    ) };
    assert_ne!(lib, std::ptr::null_mut(), "Failed to dlopen library!");

    let symbol = unsafe { sbx_dlsymfn(
            lib,
            c"add".as_ptr(),
            c"".as_ptr(),
    ) };
    assert_ne!(symbol, std::ptr::null_mut(), "Failed to look up `add` symbol!");
    println!("Add symbol: {:p}\n", symbol);

    //let res = unsafe { sbx_dlinvoke(lib, symbol, 12, 30) };
    //println!("Result: {:?}", res);
   
    let regs = unsafe { sbx_lfi_proc_regs(lib) };
    unsafe { *lfi_regs_arg(regs, 0) = 13; }
    unsafe { *lfi_regs_arg(regs, 1) = 30; }
    
    let res = unsafe { sbx_invoke(lib, symbol) };
    println!("Result: {:?}", res);
}

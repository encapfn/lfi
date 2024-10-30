#![feature(naked_functions)]

// Necessary evil:
use encapfn::branding::EFID;
use encapfn::types::{AccessScope, AllocScope};

// Auto-generated bindings, so doesn't follow Rust conventions at all:
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(improper_ctypes)] // TODO: fix this by wrapping functions with u128s
pub mod libsobox_test {
    include!(concat!(env!("OUT_DIR"), "/libsobox_test_bindings.rs"));
}

// These are the Encapsulated Functions wrapper types / traits generated.
use libsobox_test::LibSoboxTestRt;

pub fn with_mockrt_lib<'a, ID: EFID + 'a, A: encapfn::rt::mock::MockRtAllocator, R>(
    brand: ID,
    alloc: A,
    f: impl FnOnce(
        LibSoboxTestRt<ID, encapfn::rt::mock::MockRt<ID, A>>,
        AllocScope<<encapfn::rt::mock::MockRt<ID, A> as encapfn::rt::EncapfnRt>::AllocTracker<'a>, ID>,
        AccessScope<ID>,
    ) -> R,
) -> R {
    // This is unsafe, as it instantiates a runtime that can be used to run
    // foreign functions without memory protection:
    let (rt, alloc, access) = unsafe { encapfn::rt::mock::MockRt::new(false, alloc, brand) };

    // Create a "bound" runtime, which implements the LibSoboxTest API:
    let bound_rt = LibSoboxTestRt::new(&rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}

pub fn with_lfirt_lib<ID: EFID, R>(
    brand: ID,
    f: impl for<'a> FnOnce(
        LibSoboxTestRt<ID, encapfn_lfi::EncapfnLFIRt<ID>>,
        AllocScope<<encapfn_lfi::EncapfnLFIRt<ID> as encapfn::rt::EncapfnRt>::AllocTracker<'a>, ID>,
        AccessScope<ID>,
    ) -> R,
) -> R {
    //let library_path = std::ffi::CString::new(concat!(env!("OUT_DIR"), "/libsobox_demo.so")).unwrap();

    let (rt, alloc, access) = encapfn_lfi::EncapfnLFIRt::new(
        c"/root/lfi2/build-toolchain/libsobox/test/libtest.so",
        brand,
    ).unwrap();

    // Create a "bound" runtime, which implements the LibSoboxTest API:
    let bound_rt = LibSoboxTestRt::new(&rt).unwrap();

    // Run the provided closure:
    f(bound_rt, alloc, access)
}


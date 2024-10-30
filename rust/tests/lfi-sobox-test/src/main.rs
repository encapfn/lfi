use encapfn::branding::EFID;
use encapfn::rt::EncapfnRt;
use encapfn::types::{AllocScope, AccessScope};

use encapfn_lfi_sobox_test::{with_mockrt_lib, with_lfirt_lib};
use encapfn_lfi_sobox_test::libsobox_test::LibSoboxTest;

fn run<ID: EFID, RT: EncapfnRt<ID = ID>, L: LibSoboxTest<ID, RT, RT = RT>>(
    lib: &L,
    _alloc: &mut AllocScope<'_, RT::AllocTracker<'_>, RT::ID>,
    access: &mut AccessScope<RT::ID>,
) {
    let res = lib.add(1, 2, access).unwrap();
    println!("Res: {:?}", res.validate());
}

fn main() {
    env_logger::init();

    //let mock_alloc = encapfn::rt::mock::heap_alloc::HeapAllocator;
    //encapfn::branding::new(move |brand| {
    //    with_mockrt_lib(brand, mock_alloc, |lib, mut alloc, mut access| {
    //        run(&lib, &mut alloc, &mut access)
    //    })
    //});
    
    encapfn::branding::new(move |brand| {
        with_lfirt_lib(brand, |lib, mut alloc, mut access| {
            run(&lib, &mut alloc, &mut access)
        })
    });
}

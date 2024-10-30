use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

fn check_output_res(res: std::io::Result<std::process::Output>, msg: &'static str) {
    match res {
        Err(e) => Err(e).expect(msg),
        Ok(out) => {
            if !out.status.success() {
                panic!(
                    "{},\nstdout: \n{},\nstderr: \n{}",
                    msg,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=./efdemo.encapfn.toml");
    println!("cargo:rerun-if-changed=../../../libsobox/test/lib.h");
    println!("cargo:rerun-if-changed=../../../libsobox/test/lib.c");

    let bindings = bindgen::Builder::default()
        .header("../../../libsobox/test/lib.h")
        .encapfn_configuration_file(Some(
            PathBuf::from("./encapfn-lfi-libsobox-test.encapfn.toml")
                .canonicalize()
                .unwrap(),
        ))
        .rustfmt_configuration_file(Some(
            PathBuf::from("./ef_bindings_rustfmt.toml")
                .canonicalize()
                .unwrap(),
        ))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_path = out_path.join("libsobox_test_bindings.rs");
    bindings.write_to_file(&bindings_path).expect("Couldn't write bindings!");
    println!("cargo::warning=Generated bindings in {}", bindings_path.display());

    // Build the libsobox tests as a shared library too.
    //
    // We cannot use the cc crate, as it does not support building
    // dynamic libraries. Thus, determine the compiler based on the
    // CC environment variable:
    let cc = env::var("CC").expect("No C compiler (CC environment variable) provided!");
    check_output_res(
        std::process::Command::new(&cc)
            .args([
                OsStr::new("-g"),        // Produce debug symbols in the target's native format
                OsStr::new("-ggdb"),     // Provide debug symbols readable by GDB
                OsStr::new("-fPIC"),     // Produce PIC code to support loading as shared lib
                OsStr::new("-rdynamic"), // Add all symbols (not just used) to the ELF
                OsStr::new("-shared"),   // Produce a shared object
                OsStr::new("../../../libsobox/test/lib.c"),
                OsStr::new("-o"),
                out_path.join("libsobox_test.so").as_os_str(),
            ])
            .output(),
        "Failed to compile the Encapfn MPK runtime into a shared library!",
    );

    // For the mock runtime, we also want to link against the library directly.
    // This can be commented out, but there must be no code path to instantiate
    // the MockRt, or otherwise there will be linker errors:
    println!("cargo:rustc-link-search={}", out_path.display());
    println!("cargo:rustc-link-lib=sobox_test");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", out_path.display());
}


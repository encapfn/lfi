use std::env;
use std::path::PathBuf;

// The build scripts working directory is the crate root, which allows us to
// use relative paths to the other lfi components in here:
fn main() {
    // Link to liblfi:
    println!("cargo:rustc-link-search=../../lfi-toolchain/lib/aarch64-linux-gnu");
    println!("cargo:rustc-link-lib=sobox");

    let bindings = bindgen::Builder::default()
        .header("./wrapper.h")
        .clang_arg("-I../../lfi-toolchain/include")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings for libsobox");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("libsobox_bindings.rs"))
        .expect("Couldn't write bindings!");
}


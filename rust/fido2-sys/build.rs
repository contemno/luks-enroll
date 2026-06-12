fn main() {
    println!("cargo:rustc-link-lib=fido2");
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("fido_.*")
        .allowlist_var("FIDO_.*|COSE_.*")
        .generate()
        .expect("failed to generate libfido2 bindings");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("failed to write bindings");
}

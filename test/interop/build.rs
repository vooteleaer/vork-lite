fn main() {
    let c = "../../src";
    cc::Build::new()
        .file(format!("{c}/crypto.c"))
        .file(format!("{c}/vl_blake2s.c"))
        .file(format!("{c}/monocypher.c"))
        .file(format!("{c}/monocypher-ed25519.c"))
        .define("VL_HOST_TEST", None)
        .compile("vl_c");
    cc::Build::new()
        .cpp(true)
        .file(format!("{c}/wg.cpp"))
        .file("shim.cpp")
        .define("VL_HOST_TEST", None)
        .flag_if_supported("-std=c++17")
        .compile("vl_cpp");
    println!("cargo:rerun-if-changed={c}");
    println!("cargo:rerun-if-changed=shim.cpp");
}

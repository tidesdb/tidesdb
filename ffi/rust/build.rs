fn main() {
    println!("cargo:rustc-link-search=native=/wheretidesdbis");
    println!("cargo:rustc-link-lib=dylib=tidesdb");
}
fn main() {
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let rustflags = std::env::var("RUSTFLAGS").unwrap_or_else(|_| {
        std::env::var("CARGO_ENCODED_RUSTFLAGS")
            .unwrap_or_default()
            .replace('\x1f', " ")
    });
    println!(
        "cargo:rustc-env=SPARTAN_WHIR_EXPORT_RUSTFLAGS={}",
        rustflags
    );
}

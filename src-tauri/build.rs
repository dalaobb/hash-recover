fn main() {
    // Select the product variant at compile time. The CI/build script sets
    // HASHRECOVER_VARIANT; direct builds fall back to the "all" variant.
    println!("cargo:rerun-if-env-changed=HASHRECOVER_VARIANT");
    let variant = std::env::var("HASHRECOVER_VARIANT").unwrap_or_else(|_| "all".to_string());
    match variant.as_str() {
        "zip" | "rar" | "sevenz" | "pdf" | "word" | "excel" | "powerpoint" | "office" | "all" => {}
        other => panic!("unknown HASHRECOVER_VARIANT {other:?}"),
    }
    println!("cargo:rustc-cfg=hasrecover_variant=\"{variant}\"");
    println!(
        "cargo:rustc-check-cfg=cfg(hasrecover_variant, values(\"zip\", \"rar\", \"sevenz\", \"pdf\", \"word\", \"excel\", \"powerpoint\", \"office\", \"all\"))"
    );

    tauri_build::build()
}

fn main() -> std::process::ExitCode {
    let code = extractor_core::run_extractor(&zip_extractor::ZipExtractor);
    std::process::ExitCode::from(code)
}

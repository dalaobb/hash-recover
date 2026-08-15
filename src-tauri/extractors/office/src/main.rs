fn main() -> std::process::ExitCode {
    let code = extractor_core::run_extractor(&office_extractor::OfficeExtractor);
    std::process::ExitCode::from(code)
}

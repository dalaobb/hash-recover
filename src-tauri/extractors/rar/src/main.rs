fn main() -> std::process::ExitCode {
    let code = extractor_core::run_extractor(&rar_extractor::RarExtractor);
    std::process::ExitCode::from(code)
}

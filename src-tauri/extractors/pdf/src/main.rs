fn main() -> std::process::ExitCode {
    let code = extractor_core::run_extractor(&pdf_extractor::PdfExtractor);
    std::process::ExitCode::from(code)
}

mod analyzer;
mod attack;
mod engine;
mod formats;
mod gpu;
mod logging;
mod normalizer;
mod strategy;

use analyzer::AnalyzeResult;
use engine::ExtractResult;
use formats::{AppConfig, ACTIVE_VARIANT};
use std::path::Path;
use strategy::{RecoverRequest, RecoverResult};

/// Expose the active product variant and its supported formats to the frontend.
/// The UI derives file picker filters and visible format cards from this.
#[tauri::command]
fn get_app_config() -> AppConfig {
    formats::app_config()
}

/// Identify the file's format from its content signature. Never guesses from
/// the extension; rejects files outside the active variant's formats.
#[tauri::command]
fn analyze_file(path: String) -> AnalyzeResult {
    match std::fs::read(Path::new(&path)) {
        Ok(data) => {
            let result = analyzer::analyze(&data);
            logging::event(
                "analyze_file",
                "analyze",
                if result.ok { "ok" } else { "rejected" },
                result.format_id.or_else(|| result.message).as_deref(),
            );
            result
        }
        Err(err) => {
            logging::event(
                "analyze_file",
                "analyze",
                "read_error",
                Some(&err.to_string()),
            );
            AnalyzeResult::read_error()
        }
    }
}

/// Extract a John/Hashcat-compatible hash from a file using the format's
/// bundled extractor program.
#[tauri::command]
fn extract_hash(path: String) -> ExtractResult {
    let data = match std::fs::read(Path::new(&path)) {
        Ok(data) => data,
        Err(_) => {
            return ExtractResult::error(
                "Could not read this file. It may have been moved or deleted.",
            )
        }
    };
    let Some(family) = analyzer::detect_family(&data) else {
        logging::event("extract_hash", "extract", "unsupported", None);
        return ExtractResult::error("This file type is not supported by HashRecover.");
    };
    if !ACTIVE_VARIANT.supports_family(family) {
        logging::event(
            "extract_hash",
            "extract",
            "not_in_edition",
            Some(family.id()),
        );
        return ExtractResult::error("This format is not included in your edition of HashRecover.");
    }
    let result = engine::extract(family, Path::new(&path));
    // The extracted hash is logged for debugging (user request); it is a
    // password hash, so this line should stay out of production telemetry.
    logging::event(
        "extract_hash",
        "extract",
        if result.ok { "ok" } else { "error" },
        result.hashes.first().map(String::as_str).or(result.message),
    );
    result
}

/// Run a recovery attempt for the given hash and strategy.
#[tauri::command]
fn recover(request: RecoverRequest) -> RecoverResult {
    engine::recover(request)
}

/// Cancel the recovery attempt currently running in the engine layer.
#[tauri::command]
fn cancel_recovery() {
    engine::cancel_recovery();
}

/// Report the compute devices Hashcat can use (for the result screen).
#[tauri::command]
fn get_gpu_info() -> gpu::GpuInfo {
    gpu::detect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    logging::init();
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_app_config,
            analyze_file,
            extract_hash,
            recover,
            cancel_recovery,
            get_gpu_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use strategy::{RecoveryStrategy, StrategyKind, StrategyOptions};

    fn pdf_fixture(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("extractors")
            .join("pdf")
            .join("testdata")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn analyze_and_extract_pdf_end_to_end() {
        let path = pdf_fixture("aes128.pdf");
        let analyzed = analyze_file(path.clone());
        assert!(analyzed.ok, "analysis failed: {:?}", analyzed.message);
        assert_eq!(analyzed.format_id, Some("pdf"));
        assert_eq!(analyzed.format_label, Some("PDF document"));

        let extracted = extract_hash(path);
        assert!(extracted.ok, "extraction failed: {:?}", extracted.message);
        assert_eq!(extracted.hashes.len(), 1);
        assert!(extracted.hashes[0].contains("$pdf$"));
    }

    #[test]
    fn analyze_rejects_unknown_content() {
        let path = std::env::temp_dir().join("hashrecover-unknown.bin");
        std::fs::write(&path, b"this is not any supported format").unwrap();
        let result = analyze_file(path.to_string_lossy().into_owned());
        assert!(!result.ok);
        assert!(result.message.is_some());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn recover_contract_returns_friendly_message() {
        let request = RecoverRequest {
            file_path: pdf_fixture("rc4.pdf"),
            hash: "$pdf$0*...".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions::default(),
            },
        };
        let result = recover(request);
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("This password hash could not be read by the recovery engine.")
        );
    }
}

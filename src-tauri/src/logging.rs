//! Structured logging for the desktop app.
//!
//! Emits JSON lines to stderr so development terminals and CI can inspect
//! recovery events. Passwords, user files and other sensitive content are
//! never logged.

use log::LevelFilter;
use std::io::Write;

/// Initialize the logger. Honors `RUST_LOG` when set; otherwise logs `info`
/// and above.
pub fn init() {
    let mut builder = env_logger::Builder::new();
    if std::env::var("RUST_LOG").is_ok() {
        builder.parse_default_env();
    } else {
        builder.filter_level(LevelFilter::Info);
    }
    builder.format(format_json).init();
}

/// Emit a structured event: `{timestamp, module, event, status, detail}`.
pub fn event(module: &str, event: &str, status: &str, detail: Option<&str>) {
    log::info!(
        "{}",
        serde_json::json!({
            "module": module,
            "event": event,
            "status": status,
            "detail": detail,
        })
    );
}

fn format_json(buf: &mut env_logger::fmt::Formatter, record: &log::Record) -> std::io::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = serde_json::json!({
        "timestamp": now,
        "level": record.level().to_string(),
        "module": record.module_path().unwrap_or(""),
        "message": record.args().to_string(),
    });
    writeln!(buf, "{line}")
}

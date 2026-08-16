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

/// Emit a structured event: `{module, event, status, detail}`. The formatter
/// merges these fields into the top-level record and pretty-prints it, so no
/// nested/escaped JSON string appears in the output.
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
    let mut value = serde_json::json!({
        "timestamp": now,
        "level": record.level().to_string(),
    });
    // Structured events (JSON objects from `event`) are merged into the
    // top-level record so the fields aren't escaped inside a string. Plain
    // messages are logged as a `message` string.
    let message = record.args().to_string();
    match serde_json::from_str::<serde_json::Value>(&message) {
        Ok(serde_json::Value::Object(map)) => {
            for (key, val) in map {
                value[key] = val;
            }
        }
        Ok(other) => {
            value["message"] = other;
        }
        Err(_) => {
            value["message"] = serde_json::Value::String(message);
        }
    }
    writeln!(
        buf,
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    )
}

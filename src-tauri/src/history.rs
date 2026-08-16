//! Local recovery history.
//!
//! Successfully recovered passwords are stored in a single local file so a
//! repeated attempt against the same hash is answered instantly (reuse) and
//! so the user can review what was recovered. The app is the only cache:
//! engine potfiles stay disabled. History never leaves the device.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HISTORY_FILE: &str = "history.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    /// Bare normalized hash (`$pdf$...`), the reuse key.
    pub hash: String,
    /// Base file name the hash was recovered from.
    pub file_name: String,
    /// Friendly encryption name (e.g. "AES-256").
    pub encryption: Option<String>,
    /// "Easy", "Medium" or "Hard".
    pub difficulty: Option<String>,
    /// The recovered password.
    pub password: String,
    /// Which engine found it: "hashcat", "john" or "history" (reuse).
    pub engine: String,
    /// Strategy kind that recovered it ("dictionary", "pattern", ...).
    pub strategy_kind: String,
    /// Unix timestamp in milliseconds.
    pub recovered_at: u64,
}

/// Current time in Unix milliseconds, for entry timestamps.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(HISTORY_FILE)
}

/// Load the current history. A missing or unreadable store is treated as
/// empty so a broken file never blocks the app.
pub fn load(data_dir: &Path) -> Vec<HistoryEntry> {
    match std::fs::read_to_string(file_path(data_dir)) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Find the entry for a normalized hash, if its password was recovered before.
pub fn find(data_dir: &Path, hash: &str) -> Option<HistoryEntry> {
    load(data_dir).into_iter().find(|e| e.hash == hash)
}

/// Record a recovery. The newest entry per hash wins; the file is replaced
/// atomically so a crash mid-write never corrupts the store.
pub fn record(data_dir: &Path, entry: HistoryEntry) {
    let mut entries = load(data_dir);
    entries.retain(|e| e.hash != entry.hash);
    entries.push(entry);
    entries.sort_by_key(|b| std::cmp::Reverse(b.recovered_at));

    let Ok(json) = serde_json::to_string_pretty(&entries) else {
        return;
    };
    if std::fs::create_dir_all(data_dir).is_err() {
        return;
    }
    let final_path = file_path(data_dir);
    let tmp = final_path.with_extension("json.tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, final_path);
    }
}

/// Delete all local history.
pub fn clear(data_dir: &Path) {
    let _ = std::fs::remove_file(file_path(data_dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, password: &str) -> HistoryEntry {
        HistoryEntry {
            hash: hash.into(),
            file_name: "x.pdf".into(),
            encryption: Some("AES-256".into()),
            difficulty: Some("Hard".into()),
            password: password.into(),
            engine: "hashcat".into(),
            strategy_kind: "dictionary".into(),
            recovered_at: now_ms(),
        }
    }

    fn temp_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("hashrecover-history-{}-{id}", std::process::id()))
    }

    #[test]
    fn missing_store_loads_empty() {
        let dir = temp_dir();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_then_find_round_trips() {
        let dir = temp_dir();
        let _ = std::fs::remove_dir_all(&dir);
        record(&dir, entry("$pdf$1", "pw"));
        let found = find(&dir, "$pdf$1");
        assert_eq!(found.as_ref().map(|e| e.password.as_str()), Some("pw"));
        assert_eq!(found.as_ref().map(|e| e.engine.as_str()), Some("hashcat"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn re_record_same_hash_replaces_entry() {
        let dir = temp_dir();
        let _ = std::fs::remove_dir_all(&dir);
        record(&dir, entry("$pdf$1", "old"));
        record(&dir, entry("$pdf$1", "new"));
        let entries = load(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password, "new");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_removes_store() {
        let dir = temp_dir();
        let _ = std::fs::remove_dir_all(&dir);
        record(&dir, entry("$pdf$1", "pw"));
        assert!(find(&dir, "$pdf$1").is_some());
        clear(&dir);
        assert!(find(&dir, "$pdf$1").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_store_loads_empty() {
        let dir = temp_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(HISTORY_FILE), "{ not json").unwrap();
        assert!(load(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}

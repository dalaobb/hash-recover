//! Recovery strategy model.
//!
//! The frontend deals in friendly concepts ("Common passwords", "Unknown
//! password"); the engine maps those to John/Hashcat attack modes internally.
//! No attack-mode numbers ever cross this boundary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StrategyKind {
    Dictionary,
    Partial,
    Pattern,
    Bruteforce,
    /// Two text lists combined into every pairing (`hashcat -a 1`).
    Combinator,
    /// Engine's built-in incremental/random mode (no mask, no wordlist).
    Incremental,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyOptions {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub charset: Option<String>,
    pub dictionary: Option<String>,
    /// Literal prefix baked into the mask (remembered part of the password).
    pub prefix: Option<String>,
    /// Literal suffix baked into the mask.
    pub suffix: Option<String>,
    /// Multiline historical passwords used as the pattern attack wordlist.
    pub history: Option<String>,
    /// First part list for the combinator attack.
    pub part_a: Option<String>,
    /// Second part list for the combinator attack.
    pub part_b: Option<String>,
    /// Friendly variation level driving which rule set is applied to a
    /// wordlist attack: `simple`, `deep` or `extreme`. Maps to different
    /// rule files per engine, so no file names cross the boundary.
    pub rule_level: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStrategy {
    pub kind: StrategyKind,
    pub options: StrategyOptions,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
// Consumed by the recovery-engine phase; kept entire so the frontend contract
// stays stable before the engine lands.
#[allow(dead_code)]
pub struct RecoverRequest {
    pub file_path: String,
    pub hash: String,
    pub strategy: RecoveryStrategy,
    pub gpu_acceleration: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverResult {
    pub ok: bool,
    pub password: Option<String>,
    pub message: Option<&'static str>,
    /// Machine-readable error key for i18n (e.g. "hash_unreadable", "engine_unavailable").
    pub error_key: Option<&'static str>,
    /// True when the user cancelled the attempt; the UI returns to the
    /// previous step instead of showing a failure.
    pub cancelled: bool,
    /// True when the password came from local recovery history (reuse) rather
    /// than a new engine run.
    pub reused: bool,
    /// The actual engine command lines that were invoked, for debug logging.
    pub command_lines: Vec<String>,
}

impl RecoverResult {
    pub fn error(message: &'static str, error_key: &'static str) -> RecoverResult {
        RecoverResult {
            ok: false,
            password: None,
            message: Some(message),
            error_key: Some(error_key),
            cancelled: false,
            reused: false,
            command_lines: Vec::new(),
        }
    }

    pub fn cancelled() -> RecoverResult {
        RecoverResult {
            ok: false,
            password: None,
            message: Some("The recovery attempt was interrupted."),
            error_key: Some("cancelled"),
            cancelled: true,
            reused: false,
            command_lines: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_round_trips_through_json() {
        let strategy = RecoveryStrategy {
            kind: StrategyKind::Bruteforce,
            options: StrategyOptions {
                min_length: Some(1),
                max_length: Some(8),
                charset: Some("abcdef0123456789".into()),
                dictionary: None,
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let back: RecoveryStrategy = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.kind, StrategyKind::Bruteforce));
        assert_eq!(back.options.max_length, Some(8));
    }
}

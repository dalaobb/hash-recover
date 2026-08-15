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
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrategyOptions {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub charset: Option<String>,
    pub dictionary: Option<String>,
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverResult {
    pub ok: bool,
    pub password: Option<String>,
    pub message: Option<&'static str>,
}

impl RecoverResult {
    pub fn error(message: &'static str) -> RecoverResult {
        RecoverResult {
            ok: false,
            password: None,
            message: Some(message),
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
            },
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let back: RecoveryStrategy = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.kind, StrategyKind::Bruteforce));
        assert_eq!(back.options.max_length, Some(8));
    }
}

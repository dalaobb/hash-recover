//! Friendly recovery strategy -> engine arguments.
//!
//! The frontend never speaks attack-mode numbers ("Common passwords",
//! "Remember part of password", "Password habits", "Unknown password").
//! This module translates a [`RecoveryStrategy`] into the arguments both
//! recovery engines understand.
//!
//! | Strategy   | Hashcat               | John                          |
//! | ---------- | --------------------- | ----------------------------- |
//! | Dictionary | `-a 0 <wordlist>`     | `--wordlist=<file>`           |
//! | Partial    | `-a 6 <dict> <mask>`  | `--wordlist --mask` (hybrid)  |
//! | Pattern    | `-a 0 <dict> -r <r>`  | `--wordlist --rules`          |
//! | Bruteforce | `-a 3 <mask> -i`      | `--mask` (+ length limits)    |

use std::path::Path;

use crate::strategy::{RecoveryStrategy, StrategyKind};

/// Default bundled dictionary used when the strategy does not name one.
pub const DEFAULT_DICTIONARY: &str = "common";
/// Default bundled rule set used by the pattern strategy.
pub const DEFAULT_RULES: &str = "best64";

#[derive(Debug)]
pub enum AttackError {
    /// Strategy needs a wordlist but none could be resolved.
    MissingWordlist,
    /// Strategy needs a rule set but none could be resolved.
    MissingRules,
}

impl AttackError {
    pub fn friendly(&self) -> &'static str {
        match self {
            AttackError::MissingWordlist => {
                "The word list is not available. Please reinstall HashRecover."
            }
            AttackError::MissingRules => {
                "The password rules are not available. Please reinstall HashRecover."
            }
        }
    }
}

/// Arguments ready to append to the engine command line.
#[derive(Debug)]
pub struct Attack {
    /// Args appended after `hashcat -m <mode> <hashfile>`.
    pub hashcat_args: Vec<String>,
    /// Args appended after `john --format=<fmt> <hashfile>`.
    pub john_args: Vec<String>,
}

/// Build the engine arguments for a strategy. The caller resolves the
/// wordlist/rules files and passes them in; only the strategy shape decides
/// which arguments are produced.
pub fn build_attack(
    strategy: &RecoveryStrategy,
    wordlist: Option<&Path>,
    rules: Option<&Path>,
) -> Result<Attack, AttackError> {
    match strategy.kind {
        StrategyKind::Dictionary => {
            let wl = wordlist.ok_or(AttackError::MissingWordlist)?;
            Ok(Attack {
                hashcat_args: vec!["-a".into(), "0".into(), wl_str(wl)],
                john_args: vec![format!("--wordlist={}", wl.display())],
            })
        }
        StrategyKind::Partial => {
            let wl = wordlist.ok_or(AttackError::MissingWordlist)?;
            let length = strategy.options.max_length.unwrap_or(4);
            let (mask, custom) =
                build_mask(strategy.options.charset.as_deref().unwrap_or(""), length);
            let (mut hashcat_args, mut john_args) = (Vec::new(), Vec::new());
            hashcat_args.extend(["-a".into(), "6".into(), wl_str(wl)]);
            if let Some(chars) = &custom {
                hashcat_args.push("-1".into());
                hashcat_args.push(chars.clone());
            }
            hashcat_args.push(mask.clone());
            john_args.push(format!("--wordlist={}", wl.display()));
            if let Some(chars) = &custom {
                john_args.push(format!("-1={chars}"));
            }
            john_args.push(format!("--mask={mask}"));
            Ok(Attack {
                hashcat_args,
                john_args,
            })
        }
        StrategyKind::Pattern => {
            let wl = wordlist.ok_or(AttackError::MissingWordlist)?;
            let rules = rules.ok_or(AttackError::MissingRules)?;
            Ok(Attack {
                hashcat_args: vec![
                    "-a".into(),
                    "0".into(),
                    wl_str(wl),
                    "-r".into(),
                    rules.display().to_string(),
                ],
                john_args: vec![format!("--wordlist={}", wl.display()), "--rules".into()],
            })
        }
        StrategyKind::Bruteforce => {
            let min = strategy.options.min_length.unwrap_or(1);
            let max = strategy.options.max_length.unwrap_or(8);
            let length = max.max(min);
            let (mask, custom) =
                build_mask(strategy.options.charset.as_deref().unwrap_or(""), length);
            let (mut hashcat_args, mut john_args) = (Vec::new(), Vec::new());
            hashcat_args.extend(["-a".into(), "3".into()]);
            if let Some(chars) = &custom {
                hashcat_args.push("-1".into());
                hashcat_args.push(chars.clone());
            }
            hashcat_args.push(mask.clone());
            hashcat_args.extend([
                "-i".into(),
                "--increment-min".into(),
                min.to_string(),
                "--increment-max".into(),
                max.to_string(),
            ]);
            if let Some(chars) = &custom {
                john_args.push(format!("-1={chars}"));
            }
            john_args.push(format!("--mask={mask}"));
            john_args.push(format!("--min-length={min}"));
            john_args.push(format!("--max-length={max}"));
            Ok(Attack {
                hashcat_args,
                john_args,
            })
        }
    }
}

fn wl_str(wl: &Path) -> String {
    wl.display().to_string()
}

/// Map a friendly charset name to a mask atom and, for a literal charset
/// string, the characters that must be registered as `?1`.
fn mask_atom(charset: &str) -> (String, Option<String>) {
    match charset {
        "" | "all" | "any" => ("?a".into(), None),
        "alpha" | "lower" | "lowercase" => ("?l".into(), None),
        "upper" | "uppercase" => ("?u".into(), None),
        "alpha-upper" | "mixed" => ("?u?l".into(), None),
        "alnum" | "alphanumeric" | "alpha-numeric" => ("?l?d".into(), None),
        "numeric" | "digits" | "digit" => ("?d".into(), None),
        "hex-lower" => ("?h".into(), None),
        "hex-upper" => ("?H".into(), None),
        custom => ("?1".into(), Some(custom.to_string())),
    }
}

/// Build a mask of the given length plus any custom charset to register.
fn build_mask(charset: &str, length: usize) -> (String, Option<String>) {
    let (atom, custom) = mask_atom(charset);
    (atom.repeat(length), custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{RecoveryStrategy, StrategyOptions};

    fn strategy(kind: StrategyKind, options: StrategyOptions) -> RecoveryStrategy {
        RecoveryStrategy { kind, options }
    }

    #[test]
    fn dictionary_uses_wordlist_for_both_engines() {
        let a = build_attack(
            &strategy(
                StrategyKind::Dictionary,
                StrategyOptions {
                    dictionary: Some("common".into()),
                    ..Default::default()
                },
            ),
            Some(Path::new("/wl.txt")),
            None,
        )
        .unwrap();
        assert_eq!(a.hashcat_args, ["-a", "0", "/wl.txt"]);
        assert_eq!(a.john_args, ["--wordlist=/wl.txt"]);
    }

    #[test]
    fn dictionary_without_wordlist_is_missing() {
        let r = build_attack(
            &strategy(StrategyKind::Dictionary, Default::default()),
            None,
            None,
        );
        assert!(matches!(r, Err(AttackError::MissingWordlist)));
    }

    #[test]
    fn bruteforce_builds_incremental_mask() {
        let a = build_attack(
            &strategy(
                StrategyKind::Bruteforce,
                StrategyOptions {
                    min_length: Some(4),
                    max_length: Some(6),
                    charset: Some("alpha".into()),
                    ..Default::default()
                },
            ),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            a.hashcat_args,
            [
                "-a",
                "3",
                "?l?l?l?l?l?l",
                "-i",
                "--increment-min",
                "4",
                "--increment-max",
                "6"
            ]
        );
        assert!(a.john_args.contains(&"--mask=?l?l?l?l?l?l".to_string()));
        assert!(a.john_args.contains(&"--min-length=4".to_string()));
    }

    #[test]
    fn custom_charset_becomes_question_one() {
        let a = build_attack(
            &strategy(
                StrategyKind::Bruteforce,
                StrategyOptions {
                    min_length: Some(2),
                    max_length: Some(2),
                    charset: Some("abc123".into()),
                    ..Default::default()
                },
            ),
            None,
            None,
        )
        .unwrap();
        assert!(a.hashcat_args.contains(&"-1".to_string()));
        assert!(a.hashcat_args.contains(&"abc123".to_string()));
        assert!(a.hashcat_args.contains(&"?1?1".to_string()));
        assert!(a.john_args.contains(&"-1=abc123".to_string()));
    }

    #[test]
    fn numeric_charset_maps_to_digit_mask() {
        let a = build_attack(
            &strategy(
                StrategyKind::Bruteforce,
                StrategyOptions {
                    min_length: Some(4),
                    max_length: Some(4),
                    charset: Some("numeric".into()),
                    ..Default::default()
                },
            ),
            None,
            None,
        )
        .unwrap();
        assert!(a.hashcat_args.contains(&"?d?d?d?d".to_string()));
    }

    #[test]
    fn pattern_requires_rules() {
        let r = build_attack(
            &strategy(StrategyKind::Pattern, Default::default()),
            Some(Path::new("/wl.txt")),
            None,
        );
        assert!(matches!(r, Err(AttackError::MissingRules)));
    }

    #[test]
    fn partial_builds_hybrid_args() {
        let a = build_attack(
            &strategy(
                StrategyKind::Partial,
                StrategyOptions {
                    max_length: Some(3),
                    charset: Some("alnum".into()),
                    ..Default::default()
                },
            ),
            Some(Path::new("/wl.txt")),
            None,
        )
        .unwrap();
        assert_eq!(a.hashcat_args, ["-a", "6", "/wl.txt", "?l?d?l?d?l?d"]);
        assert!(a.john_args.contains(&"--mask=?l?d?l?d?l?d".to_string()));
    }
}

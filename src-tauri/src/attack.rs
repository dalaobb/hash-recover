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
//! | Dictionary + rules | `-a 0 <dict> -r <r>` | `--wordlist --rules=<set>` |
//! | Partial    | `-a 6 <dict> <mask>`  | `--wordlist --mask` (hybrid)  |
//! | Pattern    | `-a 0 <dict> -r <r>`  | `--wordlist --rules=<set>`    |
//! | Bruteforce | `-a 3 <mask> -i`      | `--mask` (+ length limits)    |
//! | Combinator | `-a 1 <listA> <listB>`| (unsupported, Hashcat only)   |

use std::path::{Path, PathBuf};

use crate::strategy::{RecoveryStrategy, StrategyKind};

/// Default bundled dictionary used when the strategy does not name one.
pub const DEFAULT_DICTIONARY: &str = "common";
/// Default variation level applied to wordlist attacks (pattern strategy).
pub const DEFAULT_RULE_LEVEL: &str = "simple";

/// Map a friendly variation level to the per-engine rule names.
///
/// Hashcat needs a rule *file* (`-r rules/<stem>.rule`); John needs the
/// `[List.Rules:<name>]` section in john.conf, which `.include`s the matching
/// `rules/<name>.rule` file — John cannot load a rule file directly.
///
/// The "simple" level is intentionally engine-specific: hashcat's
/// `best66.rule` uses hashcat-only commands that John's parser rejects, so
/// John uses its own `best64.rule`. `d3ad0ne.rule` and `dive.rule` are
/// John-origin rule files both engines ship and both can parse, so they share
/// a name.
pub fn rule_names(level: &str) -> (&'static str, &'static str) {
    match level {
        "deep" => ("d3ad0ne", "d3ad0ne"),
        "extreme" => ("dive", "dive"),
        _ => ("best66", "best64"),
    }
}

/// Hashcat rule-file stems to try for a variation level, most-preferred
/// first. John is unaffected (it resolves the level to a john.conf rule-set
/// name in [`rule_names`]). "simple" prefers hashcat's `best66.rule` and
/// falls back to `best64.rule`, which both engines ship and hashcat can
/// parse — some hashcat packages (e.g. Debian/Ubuntu) omit `best66.rule`.
pub fn hashcat_rule_candidates(level: &str) -> &'static [&'static str] {
    match level {
        "deep" => &["d3ad0ne"],
        "extreme" => &["dive"],
        _ => &["best66", "best64"],
    }
}

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

/// Files the strategy needs (resolved by the engine layer before building the
/// attack). The combinator attack consumes two wordlists.
#[derive(Debug, Default)]
pub struct AttackFiles {
    pub wordlist: Option<PathBuf>,
    pub wordlist_second: Option<PathBuf>,
    pub rules: Option<PathBuf>,
}

/// Build the engine arguments for a strategy. The caller resolves the
/// wordlist/rules files and passes them in; only the strategy shape decides
/// which arguments are produced.
pub fn build_attack(
    strategy: &RecoveryStrategy,
    files: &AttackFiles,
) -> Result<Attack, AttackError> {
    match strategy.kind {
        StrategyKind::Dictionary => {
            let wl = files
                .wordlist
                .as_deref()
                .ok_or(AttackError::MissingWordlist)?;
            let (mut hashcat_args, mut john_args) = (Vec::new(), Vec::new());
            hashcat_args.extend(["-a".into(), "0".into(), wl_str(wl)]);
            john_args.push(format!("--wordlist={}", wl.display()));
            if let Some(level) = strategy.options.rule_level.as_deref() {
                let rules = files.rules.as_deref().ok_or(AttackError::MissingRules)?;
                let (_, john_rules) = rule_names(level);
                hashcat_args.extend(["-r".into(), rules.display().to_string()]);
                john_args.push(format!("--rules={john_rules}"));
            }
            Ok(Attack {
                hashcat_args,
                john_args,
            })
        }
        StrategyKind::Partial => {
            let wl = files
                .wordlist
                .as_deref()
                .ok_or(AttackError::MissingWordlist)?;
            let length = strategy.options.max_length.unwrap_or(4);
            let (mask, custom) = build_mask(
                strategy.options.charset.as_deref().unwrap_or(""),
                length,
                "",
                "",
            );
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
            let wl = files
                .wordlist
                .as_deref()
                .ok_or(AttackError::MissingWordlist)?;
            let rules = files.rules.as_deref().ok_or(AttackError::MissingRules)?;
            let level = strategy
                .options
                .rule_level
                .as_deref()
                .unwrap_or(DEFAULT_RULE_LEVEL);
            let (_, john_rules) = rule_names(level);
            Ok(Attack {
                hashcat_args: vec![
                    "-a".into(),
                    "0".into(),
                    wl_str(wl),
                    "-r".into(),
                    rules.display().to_string(),
                ],
                john_args: vec![
                    format!("--wordlist={}", wl.display()),
                    format!("--rules={john_rules}"),
                ],
            })
        }
        StrategyKind::Bruteforce => {
            let min = strategy.options.min_length.unwrap_or(1);
            let max = strategy.options.max_length.unwrap_or(8);
            let length = max.max(min);
            let (mask, custom) = build_mask(
                strategy.options.charset.as_deref().unwrap_or(""),
                length,
                strategy.options.prefix.as_deref().unwrap_or(""),
                strategy.options.suffix.as_deref().unwrap_or(""),
            );
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
        StrategyKind::Combinator => {
            let a = files
                .wordlist
                .as_deref()
                .ok_or(AttackError::MissingWordlist)?;
            let b = files
                .wordlist_second
                .as_deref()
                .ok_or(AttackError::MissingWordlist)?;
            // John has no combinator mode; this attack is Hashcat-only.
            Ok(Attack {
                hashcat_args: vec!["-a".into(), "1".into(), wl_str(a), wl_str(b)],
                john_args: Vec::new(),
            })
        }
    }
}

fn wl_str(wl: &Path) -> String {
    wl.display().to_string()
}

/// Escape a literal mask prefix/suffix so hashcat/john treat `?` and `\` as
/// plain characters rather than mask syntax.
fn mask_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '?' => out.push_str("\\?"),
            _ => out.push(c),
        }
    }
    out
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
/// Optional literal prefix/suffix are baked into the mask so the user's
/// remembered characters are fixed around the wildcard positions.
fn build_mask(
    charset: &str,
    length: usize,
    prefix: &str,
    suffix: &str,
) -> (String, Option<String>) {
    let (atom, custom) = mask_atom(charset);
    let mut mask = mask_literal(prefix);
    mask.push_str(&atom.repeat(length));
    mask.push_str(&mask_literal(suffix));
    (mask, custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{RecoveryStrategy, StrategyOptions};

    fn strategy(kind: StrategyKind, options: StrategyOptions) -> RecoveryStrategy {
        RecoveryStrategy { kind, options }
    }

    fn files(
        wordlist: Option<&str>,
        wordlist_second: Option<&str>,
        rules: Option<&str>,
    ) -> AttackFiles {
        AttackFiles {
            wordlist: wordlist.map(PathBuf::from),
            wordlist_second: wordlist_second.map(PathBuf::from),
            rules: rules.map(PathBuf::from),
        }
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
            &files(Some("/wl.txt"), None, None),
        )
        .unwrap();
        assert_eq!(a.hashcat_args, ["-a", "0", "/wl.txt"]);
        assert_eq!(a.john_args, ["--wordlist=/wl.txt"]);
    }

    #[test]
    fn dictionary_with_rules_appends_engine_specific_rule() {
        // "simple" maps to hashcat best66.rule (file) and john best64
        // (john.conf rule-set section) — two different names per engine.
        let a = build_attack(
            &strategy(
                StrategyKind::Dictionary,
                StrategyOptions {
                    dictionary: Some("common".into()),
                    rule_level: Some("simple".into()),
                    ..Default::default()
                },
            ),
            &files(Some("/wl.txt"), None, Some("/rules/best66.rule")),
        )
        .unwrap();
        assert_eq!(
            a.hashcat_args,
            ["-a", "0", "/wl.txt", "-r", "/rules/best66.rule"]
        );
        assert_eq!(a.john_args, ["--wordlist=/wl.txt", "--rules=best64"]);
    }

    #[test]
    fn dictionary_with_rules_without_rules_file_is_missing() {
        let r = build_attack(
            &strategy(
                StrategyKind::Dictionary,
                StrategyOptions {
                    dictionary: Some("common".into()),
                    rule_level: Some("simple".into()),
                    ..Default::default()
                },
            ),
            &files(Some("/wl.txt"), None, None),
        );
        assert!(matches!(r, Err(AttackError::MissingRules)));
    }

    #[test]
    fn rule_level_maps_to_per_engine_names() {
        assert_eq!(rule_names("simple"), ("best66", "best64"));
        assert_eq!(rule_names("deep"), ("d3ad0ne", "d3ad0ne"));
        assert_eq!(rule_names("extreme"), ("dive", "dive"));
        assert_eq!(rule_names("unknown"), ("best66", "best64"));
    }

    #[test]
    fn simple_level_has_best64_hashcat_fallback() {
        assert_eq!(hashcat_rule_candidates("simple"), &["best66", "best64"]);
        assert_eq!(hashcat_rule_candidates("deep"), &["d3ad0ne"]);
        assert_eq!(hashcat_rule_candidates("extreme"), &["dive"]);
        assert_eq!(hashcat_rule_candidates("unknown"), &["best66", "best64"]);
    }

    #[test]
    fn dictionary_without_wordlist_is_missing() {
        let r = build_attack(
            &strategy(StrategyKind::Dictionary, Default::default()),
            &AttackFiles::default(),
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
            &AttackFiles::default(),
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
    fn prefix_and_suffix_are_baked_into_mask() {
        let a = build_attack(
            &strategy(
                StrategyKind::Bruteforce,
                StrategyOptions {
                    min_length: Some(4),
                    max_length: Some(4),
                    charset: Some("digit".into()),
                    prefix: Some("ab?c".into()),
                    suffix: Some("!".into()),
                    ..Default::default()
                },
            ),
            &AttackFiles::default(),
        )
        .unwrap();
        assert!(a.hashcat_args.contains(&"ab\\?c?d?d?d?d!".to_string()));
        assert!(a.john_args.contains(&"--mask=ab\\?c?d?d?d?d!".to_string()));
    }

    #[test]
    fn combinator_uses_both_lists() {
        let a = build_attack(
            &strategy(StrategyKind::Combinator, Default::default()),
            &files(Some("/a.txt"), Some("/b.txt"), None),
        )
        .unwrap();
        assert_eq!(a.hashcat_args, ["-a", "1", "/a.txt", "/b.txt"]);
        assert!(a.john_args.is_empty());
    }

    #[test]
    fn combinator_requires_both_lists() {
        let r = build_attack(
            &strategy(StrategyKind::Combinator, Default::default()),
            &files(Some("/a.txt"), None, None),
        );
        assert!(matches!(r, Err(AttackError::MissingWordlist)));
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
            &AttackFiles::default(),
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
            &AttackFiles::default(),
        )
        .unwrap();
        assert!(a.hashcat_args.contains(&"?d?d?d?d".to_string()));
    }

    #[test]
    fn pattern_requires_rules() {
        let r = build_attack(
            &strategy(StrategyKind::Pattern, Default::default()),
            &files(Some("/wl.txt"), None, None),
        );
        assert!(matches!(r, Err(AttackError::MissingRules)));
    }

    #[test]
    fn pattern_uses_level_rules_for_both_engines() {
        let a = build_attack(
            &strategy(
                StrategyKind::Pattern,
                StrategyOptions {
                    rule_level: Some("deep".into()),
                    ..Default::default()
                },
            ),
            &files(Some("/wl.txt"), None, Some("/rules/d3ad0ne.rule")),
        )
        .unwrap();
        assert_eq!(
            a.hashcat_args,
            ["-a", "0", "/wl.txt", "-r", "/rules/d3ad0ne.rule"]
        );
        assert_eq!(a.john_args, ["--wordlist=/wl.txt", "--rules=d3ad0ne"]);
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
            &files(Some("/wl.txt"), None, None),
        )
        .unwrap();
        assert_eq!(a.hashcat_args, ["-a", "6", "/wl.txt", "?l?d?l?d?l?d"]);
        assert!(a.john_args.contains(&"--mask=?l?d?l?d?l?d".to_string()));
    }
}

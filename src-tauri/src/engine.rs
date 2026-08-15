//! Recovery engine layer: locates the bundled extractor and recovery
//! programs, normalizes hashes, and runs Hashcat or John.
//!
//! The engine never leaks raw process errors to the UI. A missing or broken
//! engine program degrades to a friendly "unavailable" message instead of
//! crashing the app, per the project's error-handling rules.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::attack;
use crate::formats::Family;
use crate::normalizer;
use crate::strategy::{RecoverRequest, RecoverResult, StrategyKind};

// ---------------------------------------------------------------------------
// Public extractor contract
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub ok: bool,
    /// John/Hashcat-compatible hash lines (`<filename>:<hash>`).
    pub hashes: Vec<String>,
    /// User-facing failure message when `ok` is false.
    pub message: Option<&'static str>,
}

fn unavailable() -> ExtractResult {
    ExtractResult {
        ok: false,
        hashes: Vec::new(),
        message: Some("Recovery engine unavailable. Please reinstall HashRecover."),
    }
}

impl ExtractResult {
    pub fn error(message: &'static str) -> ExtractResult {
        ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some(message),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery pipeline
// ---------------------------------------------------------------------------

/// Run a recovery attempt: normalize the hash, pick an engine, run it, and
/// translate the process result into a user-facing outcome.
///
/// Engine selection: Hashcat runs first whenever a mode exists for the hash.
/// If Hashcat rejects the hash ("No hashes loaded.") or cannot run, John is
/// tried as a fallback. A hash with no Hashcat mode goes straight to John.
pub fn recover(request: RecoverRequest) -> RecoverResult {
    let normalized = match normalizer::normalize_hash(&request.hash) {
        Ok(n) => n,
        Err(_) => {
            return RecoverResult::error(
                "This password hash could not be read by the recovery engine.",
            )
        }
    };

    let wordlist = if strategy_needs_wordlist(request.strategy.kind) {
        let direct = request
            .strategy
            .options
            .dictionary
            .as_deref()
            .and_then(resolve_dictionary);
        direct.or_else(|| resolve_dictionary(attack::DEFAULT_DICTIONARY))
    } else {
        None
    };
    let rules = if matches!(request.strategy.kind, StrategyKind::Pattern) {
        resolve_rules(attack::DEFAULT_RULES)
    } else {
        None
    };

    let attack_args =
        match attack::build_attack(&request.strategy, wordlist.as_deref(), rules.as_deref()) {
            Ok(a) => a,
            Err(e) => return RecoverResult::error(e.friendly()),
        };

    let workspace = match TempWorkspace::new() {
        Some(ws) => ws,
        None => {
            return RecoverResult::error(
                "Could not create temporary files for this recovery attempt.",
            )
        }
    };
    let Some(hashcat_file) = workspace.write("hash.txt", &normalized.hash) else {
        return RecoverResult::error("Could not prepare the password hash for recovery.");
    };

    // Hashcat first when this hash has a supported mode.
    if let Some(mode) = normalized.hashcat_mode {
        if let Some(hashcat) = resolve_program("hashcat") {
            match run_hashcat(&hashcat, mode, &hashcat_file, &attack_args.hashcat_args) {
                HashcatOutcome::Cracked(password) => return ok_result(password),
                HashcatOutcome::NotFound => return not_found(),
                // NoHashesLoaded / Error: fall through and let John try.
                _ => {}
            }
        }
    }

    // John fallback, and the only engine for Hashcat-less hashes.
    if let Some(john_format) = normalized.john_format {
        if let Some(john) = resolve_program("john") {
            let display_name = normalized.filename.as_deref().unwrap_or("hashrecover");
            let john_input = format!("{display_name}:{}", normalized.hash);
            let Some(john_file) = workspace.write("john.txt", &john_input) else {
                return RecoverResult::error("Could not prepare the password hash for recovery.");
            };
            let pot_file = workspace.path("john.pot");
            match run_john(
                &john,
                john_format,
                &john_file,
                &pot_file,
                &attack_args.john_args,
                display_name,
            ) {
                JohnOutcome::Cracked(password) => return ok_result(password),
                JohnOutcome::NotFound => return not_found(),
                JohnOutcome::Error => {}
            }
        }
    }

    RecoverResult::error("Recovery engine unavailable. Please reinstall HashRecover.")
}

fn strategy_needs_wordlist(kind: StrategyKind) -> bool {
    matches!(
        kind,
        StrategyKind::Dictionary | StrategyKind::Partial | StrategyKind::Pattern
    )
}

fn ok_result(password: String) -> RecoverResult {
    RecoverResult {
        ok: true,
        password: Some(password),
        message: None,
    }
}

fn not_found() -> RecoverResult {
    RecoverResult {
        ok: false,
        password: None,
        message: None,
    }
}

// ---------------------------------------------------------------------------
// Hashcat execution
// ---------------------------------------------------------------------------

enum HashcatOutcome {
    Cracked(String),
    NotFound,
    NoHashesLoaded,
    Error,
}

/// Run Hashcat against the bare hash and capture the cracked password line
/// (`<hash>:<password>` on stdout) or translate the exit into an outcome.
fn run_hashcat(
    binary: &Path,
    mode: u32,
    hash_file: &Path,
    attack_args: &[String],
) -> HashcatOutcome {
    let output = std::process::Command::new(binary)
        .arg("-m")
        .arg(mode.to_string())
        .arg(hash_file)
        .args(attack_args)
        .arg("--potfile-disable")
        .arg("--restore-disable")
        .arg("--quiet")
        .output();
    let output = match output {
        Ok(out) => out,
        Err(_) => return HashcatOutcome::Error,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if stdout.contains("No hashes loaded.") || stderr.contains("No hashes loaded.") {
        return HashcatOutcome::NoHashesLoaded;
    }
    if let Some(password) = crack_line(&stdout) {
        return HashcatOutcome::Cracked(password);
    }

    match output.status.code() {
        Some(0) | Some(1) => HashcatOutcome::NotFound,
        _ => HashcatOutcome::Error,
    }
}

/// Find the `<hash>:<password>` line Hashcat prints when a password is found.
fn crack_line(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim_end)
        .filter(|l| l.starts_with('$'))
        .find_map(|l| {
            let (_, pw) = l.rsplit_once(':')?;
            Some(decode_password(pw))
        })
}

// ---------------------------------------------------------------------------
// John execution
// ---------------------------------------------------------------------------

enum JohnOutcome {
    Cracked(String),
    NotFound,
    Error,
}

/// Run John against a `name:$hash$` file, then read the cracked password back
/// with `--show`. The pot file is per-attempt and removed afterwards, so no
/// password is stored permanently.
fn run_john(
    binary: &Path,
    format: &str,
    hash_file: &Path,
    pot_file: &Path,
    attack_args: &[String],
    display_name: &str,
) -> JohnOutcome {
    let run = std::process::Command::new(binary)
        .arg(format!("--format={format}"))
        .arg(format!("--pot={}", pot_file.display()))
        .args(attack_args)
        .arg(hash_file)
        .output();
    if run.is_err() {
        return JohnOutcome::Error;
    }

    let show = std::process::Command::new(binary)
        .arg("--show")
        .arg(format!("--pot={}", pot_file.display()))
        .arg(hash_file)
        .output();
    let show = match show {
        Ok(out) => out,
        Err(_) => return JohnOutcome::Error,
    };
    if !show.status.success() {
        return JohnOutcome::Error;
    }

    let shown = String::from_utf8_lossy(&show.stdout);
    for line in shown.lines() {
        if let Some((name, rest)) = line.split_once(':') {
            if name.trim() == display_name && !rest.trim().is_empty() {
                return JohnOutcome::Cracked(decode_password(rest.trim()));
            }
        }
    }
    JohnOutcome::NotFound
}

// ---------------------------------------------------------------------------
// Password decoding
// ---------------------------------------------------------------------------

/// Hashcat and John wrap non-printable passwords as `$HEX[hex]`.
fn decode_password(raw: &str) -> String {
    let Some(hex) = raw.strip_prefix("$HEX[").and_then(|s| s.strip_suffix(']')) else {
        return raw.to_string();
    };
    if hex.len() % 2 != 0 {
        return raw.to_string();
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for pair in chars.chunks(2) {
        let (Some(hi), Some(lo)) = (pair[0].to_digit(16), pair[1].to_digit(16)) else {
            return raw.to_string();
        };
        bytes.push((hi as u8) << 4 | lo as u8);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Temporary workspace
// ---------------------------------------------------------------------------

/// Per-attempt temp directory, removed on drop so no hashes or passwords
/// outlive the request.
struct TempWorkspace {
    dir: PathBuf,
}

impl TempWorkspace {
    fn new() -> Option<TempWorkspace> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("hashrecover-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        Some(TempWorkspace { dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> Option<PathBuf> {
        let p = self.path(name);
        std::fs::write(&p, contents).ok()?;
        Some(p)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Program and resource resolution
// ---------------------------------------------------------------------------

/// Locate an engine program. Checks bundled/sidecar locations first, then the
/// system PATH. `pub` because GPU detection reuses the same lookup.
///
/// Bundled locations support both a flat layout (`<dir>/hashcat.exe`) and a
/// self-contained subfolder named after the program (`<dir>/hashcat/hashcat.exe`)
/// so the data files of Hashcat and John (both ship an `OpenCL/` tree, etc.)
/// never clash when bundled side by side.
pub fn resolve_program(name: &str) -> Option<PathBuf> {
    let candidates = program_names(name);

    if let Some(path) = find_program_in_dirs(&bundled_bin_dirs(), name, &candidates) {
        return Some(path);
    }

    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            for candidate in &candidates {
                let p = dir.join(candidate);
                if is_executable(&p) {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Search the given directories for a program binary, checking both the flat
/// layout and a subfolder named after the program.
fn find_program_in_dirs(dirs: &[PathBuf], name: &str, candidates: &[String]) -> Option<PathBuf> {
    for dir in dirs {
        for candidate in candidates {
            let p = dir.join(candidate);
            if is_executable(&p) {
                return Some(p);
            }
        }
        let subdir = dir.join(name);
        for candidate in candidates {
            let p = subdir.join(candidate);
            if is_executable(&p) {
                return Some(p);
            }
        }
    }
    None
}

/// Binary names to look for, covering the Tauri sidecar triple suffix used in
/// packaged builds and the plain name used in development.
fn program_names(name: &str) -> Vec<String> {
    let mut names = Vec::new();
    let exe = std::env::consts::EXE_SUFFIX;
    let triple = target_triple();
    if !triple.is_empty() {
        names.push(format!("{name}-{triple}{exe}"));
    }
    names.push(format!("{name}{exe}"));
    names
}

fn target_triple() -> &'static str {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => "",
    }
}

fn bundled_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("HASHRECOVER_BIN_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
            dirs.push(parent.join("bin"));
        }
    }
    if let Some(root) = resource_root() {
        dirs.push(root.join("bin"));
    }
    dirs
}

/// Project root (dev) or packaged resource root.
fn resource_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
}

/// Resolve a wordlist by name. A literal filesystem path wins; otherwise a
/// bundled `wordlists/<name>.txt` is searched.
fn resolve_dictionary(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(name);
    if p.is_file() {
        return Some(p);
    }
    let stem = name.strip_suffix(".txt").unwrap_or(name);
    for dir in wordlist_dirs() {
        let candidate = dir.join(format!("{stem}.txt"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn wordlist_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("HASHRECOVER_WORDLISTS") {
        dirs.push(PathBuf::from(dir));
    }
    if let Some(root) = resource_root() {
        dirs.push(root.join("wordlists"));
    }
    dirs
}

/// Resolve a rule set by name (e.g. `best64` -> `rules/best64.rule`).
fn resolve_rules(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(name);
    if p.is_file() {
        return Some(p);
    }
    let stem = name.strip_suffix(".rule").unwrap_or(name);
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("HASHRECOVER_RULES") {
        dirs.push(PathBuf::from(dir));
    }
    if let Some(root) = resource_root() {
        dirs.push(root.join("rules"));
    }
    for dir in dirs {
        let candidate = dir.join(format!("{stem}.rule"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Extractor runner (unchanged contract)
// ---------------------------------------------------------------------------

/// Locate an extractor binary. In development builds it resolves to the
/// workspace build output; packaged builds resolve through the sidecar
/// directory instead (see bundling phase).
fn resolve_extractor(extractor: &str) -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    let profile = "debug";
    #[cfg(not(debug_assertions))]
    let profile = "release";

    let name = format!("{extractor}{}", std::env::consts::EXE_SUFFIX);

    let candidates = [
        std::env::current_dir()
            .ok()?
            .join("target")
            .join(profile)
            .join(&name),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(profile)
            .join(&name),
    ];

    candidates.into_iter().find(|p| is_executable(p))
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Run the extractor for the given family against a file and return the hash
/// lines it produced, translating process results into friendly messages.
/// The caller is responsible for variant support checks.
pub fn extract(family: Family, path: &Path) -> ExtractResult {
    let Some(binary) = resolve_extractor(family.extractor()) else {
        log::warn!(
            "extractor {} binary not found in target/debug or target/release",
            family.extractor()
        );
        return unavailable();
    };

    let output = match std::process::Command::new(&binary).arg(path).output() {
        Ok(out) => out,
        Err(err) => {
            log::warn!("extractor {} failed to start: {err}", family.extractor());
            return unavailable();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hashes: Vec<String> = stdout.lines().map(|l| l.to_string()).collect();

    match output.status.code() {
        Some(0) if !hashes.is_empty() => ExtractResult {
            ok: true,
            hashes,
            message: None,
        },
        Some(0) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("No recoverable hash was found in this file."),
        },
        Some(2) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("This file does not appear to be password-protected."),
        },
        _ => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("Could not extract a password hash from this file."),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{RecoveryStrategy, StrategyOptions};

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("extractors")
            .join("pdf")
            .join("testdata")
            .join(name)
    }

    #[test]
    fn pdf_extractor_produces_a_valid_hash() {
        // Requires the pdf-extractor binary, which `cargo test --workspace`
        // builds as part of the pdf-extractor crate.
        let result = extract(Family::Pdf, &fixture("rc4.pdf"));
        assert!(result.ok, "extraction failed: {:?}", result.message);
        assert_eq!(result.hashes.len(), 1);
        assert!(
            result.hashes[0].contains("$pdf$"),
            "unexpected hash line {}",
            result.hashes[0]
        );
    }

    #[test]
    fn unencrypted_pdf_is_rejected_friendly() {
        let result = extract(Family::Pdf, &fixture("plain.pdf"));
        assert!(!result.ok);
        assert!(result.message.is_some());
        assert!(result.hashes.is_empty());
    }

    #[test]
    fn missing_extractor_reports_unavailable() {
        // zip-extractor is not implemented yet, so this exercises the
        // graceful-degradation path for every variant.
        let result = extract(Family::Zip, Path::new("/nonexistent/archive.zip"));
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("Recovery engine unavailable. Please reinstall HashRecover.")
        );
    }

    #[test]
    fn malformed_hash_is_friendly_error() {
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: "$pdf$0*0*garbage".into(),
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

    #[test]
    fn dictionary_without_wordlist_is_friendly() {
        // "common" is not bundled in this dev checkout, so this must degrade
        // with a friendly message rather than a raw process error.
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: "$pdf$5*6*256*1*2*3".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions {
                    dictionary: Some("common".into()),
                    ..Default::default()
                },
            },
        };
        let result = recover(request);
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("The word list is not available. Please reinstall HashRecover.")
        );
    }

    #[test]
    fn cracks_pdf_with_hashcat_end_to_end() {
        // Requires hashcat on PATH (dev machine) and a wordlist containing the
        // fixture password `password123`.
        let (dir, wl) = temp_wordlist("password123\n");
        let request = RecoverRequest {
            file_path: fixture("aes256.pdf").to_string_lossy().into_owned(),
            hash: reference_hash("aes256"),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions {
                    dictionary: Some(wl.to_string_lossy().into_owned()),
                    ..Default::default()
                },
            },
        };
        let result = recover(request);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.ok, "recovery failed: {:?}", result.message);
        assert_eq!(result.password.as_deref(), Some("password123"));
    }

    #[test]
    fn decodes_hex_passwords() {
        assert_eq!(decode_password("hello"), "hello");
        assert_eq!(decode_password("$HEX[70617373776f7264]"), "password");
        assert_eq!(decode_password("$HEX[abc]"), "$HEX[abc]");
    }

    #[test]
    fn resolves_program_in_named_subfolder() {
        let dir = std::env::temp_dir().join(format!("hashrecover-bin-{}", std::process::id()));
        let sub = dir.join("hashcat");
        std::fs::create_dir_all(&sub).unwrap();
        let exe = format!("hashcat{}", std::env::consts::EXE_SUFFIX);
        let bin = sub.join(&exe);
        std::fs::write(&bin, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let candidates = program_names("hashcat");
        let found = find_program_in_dirs(&[dir.clone()], "hashcat", &candidates);

        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(found, Some(bin));
    }

    fn temp_wordlist(contents: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("hashrecover-wl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wl = dir.join("test-wordlist.txt");
        std::fs::write(&wl, contents).unwrap();
        (dir, wl)
    }

    fn reference_hash(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("extractors")
            .join("pdf")
            .join("testdata")
            .join("reference")
            .join(format!("{name}.hash"));
        std::fs::read_to_string(path).unwrap().trim().to_string()
    }
}

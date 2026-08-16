//! Recovery engine layer: locates the bundled extractor and recovery
//! programs, normalizes hashes, and runs Hashcat or John.
//!
//! The engine never leaks raw process errors to the UI. A missing or broken
//! engine program degrades to a friendly "unavailable" message instead of
//! crashing the app, per the project's error-handling rules.

use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::attack::{self, AttackFiles};
use crate::formats::Family;
use crate::normalizer;
use crate::strategy::{RecoverRequest, RecoverResult, StrategyKind};

/// Handle of the engine process currently running, so the user can cancel a
/// recovery attempt from the UI.
static ACTIVE_CHILD: Mutex<Option<Child>> = Mutex::new(None);
/// Set when the user cancels; `recover` checks it between engine runs.
static CANCELLED: AtomicBool = AtomicBool::new(false);
/// Serializes recovery attempts so at most one engine process runs at a time
/// (hashcat instances contend for the same OpenCL device).
static RUN_LOCK: Mutex<()> = Mutex::new(());

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
    /// Friendly encryption name (e.g. "AES-256") shown on the file card.
    pub encryption: Option<String>,
    /// "Easy", "Medium" or "Hard", shown on the file card.
    pub difficulty: Option<&'static str>,
}

fn unavailable() -> ExtractResult {
    ExtractResult {
        ok: false,
        hashes: Vec::new(),
        message: Some("Recovery engine unavailable. Please reinstall HashRecover."),
        encryption: None,
        difficulty: None,
    }
}

impl ExtractResult {
    pub fn error(message: &'static str) -> ExtractResult {
        ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some(message),
            encryption: None,
            difficulty: None,
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
    let _run_guard = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    CANCELLED.store(false, Ordering::SeqCst);

    let normalized = match normalizer::normalize_hash(&request.hash) {
        Ok(n) => n,
        Err(_) => {
            return RecoverResult::error(
                "This password hash could not be read by the recovery engine.",
            )
        }
    };

    let workspace = match TempWorkspace::new() {
        Some(ws) => ws,
        None => {
            return RecoverResult::error(
                "Could not create temporary files for this recovery attempt.",
            )
        }
    };

    let files = match prepare_attack_files(&request, &workspace) {
        Ok(files) => files,
        Err(e) => return RecoverResult::error(e.friendly()),
    };
    if cancelled() {
        return RecoverResult::cancelled();
    }

    let attack_args = match attack::build_attack(&request.strategy, &files) {
        Ok(a) => a,
        Err(e) => return RecoverResult::error(e.friendly()),
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
        if cancelled() {
            return RecoverResult::cancelled();
        }
        // The combinator attack has no John fallback; if Hashcat did not
        // succeed it is simply unavailable.
        if matches!(request.strategy.kind, StrategyKind::Combinator) {
            return RecoverResult::error(
                "Recovery engine unavailable. Please reinstall HashRecover.",
            );
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

    if cancelled() {
        return RecoverResult::cancelled();
    }
    RecoverResult::error("Recovery engine unavailable. Please reinstall HashRecover.")
}

/// Resolve the wordlist/rules files a strategy needs. Historical passwords
/// and combinator parts are materialized as temporary wordlists so the
/// engines receive plain files; everything else resolves to a bundled or
/// user-supplied dictionary.
fn prepare_attack_files(
    request: &RecoverRequest,
    workspace: &TempWorkspace,
) -> Result<AttackFiles, attack::AttackError> {
    let options = &request.strategy.options;

    let wordlist: Option<PathBuf>;
    let mut wordlist_second: Option<PathBuf> = None;
    let rules: Option<PathBuf>;

    match request.strategy.kind {
        StrategyKind::Dictionary => {
            wordlist = options
                .dictionary
                .as_deref()
                .and_then(resolve_dictionary)
                .or_else(|| resolve_dictionary(attack::DEFAULT_DICTIONARY));
            rules = None;
        }
        StrategyKind::Partial => {
            wordlist = resolve_dictionary(attack::DEFAULT_DICTIONARY);
            rules = None;
        }
        StrategyKind::Pattern => {
            wordlist = match options.history.as_deref() {
                Some(text) if !text.trim().is_empty() => {
                    workspace.write("history.txt", &normalize_wordlist(text))
                }
                _ => options
                    .dictionary
                    .as_deref()
                    .and_then(resolve_dictionary)
                    .or_else(|| resolve_dictionary(attack::DEFAULT_DICTIONARY)),
            };
            rules = resolve_rules(attack::DEFAULT_RULES);
        }
        StrategyKind::Combinator => {
            wordlist = options
                .part_a
                .as_deref()
                .and_then(|text| workspace.write("part_a.txt", &normalize_wordlist(text)));
            wordlist_second = options
                .part_b
                .as_deref()
                .and_then(|text| workspace.write("part_b.txt", &normalize_wordlist(text)));
            rules = None;
        }
        StrategyKind::Bruteforce => {
            wordlist = None;
            rules = None;
        }
    }

    Ok(AttackFiles {
        wordlist,
        wordlist_second,
        rules,
    })
}

/// Trim blank lines from user-entered password lists (one password per line).
fn normalize_wordlist(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

/// Cancel the recovery attempt in progress: flag the engine layer and kill
/// the running child process if there is one.
pub fn cancel_recovery() {
    CANCELLED.store(true, Ordering::SeqCst);
    if let Ok(mut guard) = ACTIVE_CHILD.lock() {
        if let Some(child) = guard.as_mut() {
            let _ = child.kill();
        }
    }
}

/// Spawn a process while registering it as the cancellable active child.
fn spawn_tracked(cmd: &mut Command) -> io::Result<Output> {
    // `spawn` alone inherits stdio; `wait_with_output` needs pipes to capture.
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = cmd.spawn()?;
    {
        let mut guard = ACTIVE_CHILD.lock().unwrap();
        *guard = Some(child);
    }
    let child = ACTIVE_CHILD.lock().unwrap().take().unwrap();
    child.wait_with_output()
}

fn ok_result(password: String) -> RecoverResult {
    RecoverResult {
        ok: true,
        password: Some(password),
        message: None,
        cancelled: false,
    }
}

fn not_found() -> RecoverResult {
    RecoverResult {
        ok: false,
        password: None,
        message: None,
        cancelled: false,
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
    let mut cmd = std::process::Command::new(binary);
    cmd.arg("-m")
        .arg(mode.to_string())
        .arg(hash_file)
        .args(attack_args)
        .arg("--potfile-disable")
        .arg("--restore-disable")
        .arg("--quiet");
    let output = spawn_tracked(&mut cmd);
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
    let mut run = std::process::Command::new(binary);
    run.arg(format!("--format={format}"))
        .arg(format!("--pot={}", pot_file.display()))
        .args(attack_args)
        .arg(hash_file);
    let run = spawn_tracked(&mut run);
    if run.is_err() {
        return JohnOutcome::Error;
    }

    let mut show = std::process::Command::new(binary);
    show.arg("--show")
        .arg(format!("--pot={}", pot_file.display()))
        .arg(hash_file);
    let show = spawn_tracked(&mut show);
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
///
/// A literal path wins; otherwise a bundled `rules/` tree is searched, then
/// the `rules/` trees shipped inside the Hashcat and John installs (the
/// engines always bundle `best64.rule` themselves, so no separate copy is
/// needed).
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
    for dir in engine_data_dirs() {
        dirs.push(dir.join("rules"));
        dirs.push(dir.join("run").join("rules"));
    }
    for dir in dirs {
        let candidate = dir.join(format!("{stem}.rule"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Directories that may hold an engine binary or its data tree. Used to find
/// rule sets and wordlists shipped with Hashcat/John rather than bundling a
/// second copy.
fn engine_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for base in bundled_bin_dirs() {
        dirs.push(base.clone());
        dirs.push(base.join("hashcat"));
        dirs.push(base.join("john"));
        dirs.push(base.join("run"));
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            dirs.push(dir.clone());
            dirs.push(dir.join("hashcat"));
            dirs.push(dir.join("john"));
            dirs.push(dir.join("run"));
            if let Some(parent) = dir.parent() {
                dirs.push(parent.join("share").join("hashcat"));
                dirs.push(parent.join("share").join("john"));
            }
        }
    }
    dirs
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

    let describe = hashes
        .first()
        .and_then(|h| normalizer::describe_hash(h))
        .map(|d| (Some(d.encryption), Some(d.difficulty)))
        .unwrap_or((None, None));

    match output.status.code() {
        Some(0) if !hashes.is_empty() => ExtractResult {
            ok: true,
            hashes,
            message: None,
            encryption: describe.0,
            difficulty: describe.1,
        },
        Some(0) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("No recoverable hash was found in this file."),
            encryption: None,
            difficulty: None,
        },
        Some(2) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("This file does not appear to be password-protected."),
            encryption: None,
            difficulty: None,
        },
        _ => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("Could not extract a password hash from this file."),
            encryption: None,
            difficulty: None,
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
    fn unknown_dictionary_falls_back_to_bundled_wordlist() {
        // An unknown custom dictionary falls back to the bundled default
        // instead of failing hard. Without an engine on PATH this still ends
        // in a friendly "engine unavailable" message, never a raw error.
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: "$pdf$5*6*256*1*2*3".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions {
                    dictionary: Some("no-such-dictionary".into()),
                    ..Default::default()
                },
            },
        };
        let result = recover(request);
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("Recovery engine unavailable. Please reinstall HashRecover.")
        );
    }

    #[test]
    fn bundled_default_dictionary_resolves() {
        assert!(
            resolve_dictionary(attack::DEFAULT_DICTIONARY).is_some(),
            "default dictionary must be resolvable"
        );
    }

    #[test]
    fn history_passwords_are_materialized_as_wordlist() {
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: "$pdf$5*6*256*1*2*3".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Pattern,
                options: StrategyOptions {
                    history: Some(" pass \n\nword2 \n".into()),
                    ..Default::default()
                },
            },
        };
        let ws = TempWorkspace::new().unwrap();
        let files = prepare_attack_files(&request, &ws).unwrap();
        let wl = files.wordlist.unwrap();
        let contents = std::fs::read_to_string(&wl).unwrap();
        assert_eq!(contents, "pass\nword2");
    }

    #[test]
    fn combinator_materializes_both_parts() {
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: "$pdf$5*6*256*1*2*3".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Combinator,
                options: StrategyOptions {
                    part_a: Some("alpha\nbeta".into()),
                    part_b: Some("01\n02".into()),
                    ..Default::default()
                },
            },
        };
        let ws = TempWorkspace::new().unwrap();
        let files = prepare_attack_files(&request, &ws).unwrap();
        let a = std::fs::read_to_string(files.wordlist.unwrap()).unwrap();
        let b = std::fs::read_to_string(files.wordlist_second.unwrap()).unwrap();
        assert_eq!(a, "alpha\nbeta");
        assert_eq!(b, "01\n02");
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

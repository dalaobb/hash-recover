//! Recovery engine layer: locates the bundled extractor and recovery
//! programs, normalizes hashes, and runs Hashcat or John.
//!
//! The engine never leaks raw process errors to the UI. A missing or broken
//! engine program degrades to a friendly "unavailable" message instead of
//! crashing the app, per the project's error-handling rules.

use serde::Serialize;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::attack::{self, AttackFiles};
use crate::formats::Family;
use crate::history;
use crate::normalizer::{self, NormalizedHash};
use crate::strategy::{RecoverRequest, RecoverResult, StrategyKind};

/// Handle of the engine process currently running, so the user can cancel a
/// recovery attempt from the UI.
static ACTIVE_CHILD: Mutex<Option<Child>> = Mutex::new(None);
/// Which engine is currently running, so pause/resume picks the right action.
static ACTIVE_SOURCE: Mutex<Option<ProgressSource>> = Mutex::new(None);
/// Set when the user cancels; `recover` checks it between engine runs.
static CANCELLED: AtomicBool = AtomicBool::new(false);
/// Runtime resource directory set by the Tauri layer at startup. Wordlists and
/// rules bundled as Tauri resources live here; the compile-time
/// `CARGO_MANIFEST_DIR` path only works in dev builds.
static RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Set the runtime resource directory. Called once by the Tauri layer before
/// any recovery is attempted.
pub fn set_resource_dir(dir: PathBuf) {
    let _ = RESOURCE_DIR.set(dir);
}

/// Live progress pushed to the UI while an engine runs. Every field is
/// optional: Hashcat exposes tried/total/percent/speed/candidate/eta, John
/// only percent and speed, and nothing reports all of them.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryProgress {
    /// Candidates tested so far in the current attack segment.
    pub tried: Option<u64>,
    /// Total candidates in the current attack segment.
    pub total: Option<u64>,
    /// Completion as 0..100 (Hashcat `Progress`, John percentage).
    pub percent: Option<f64>,
    /// Candidate rate as printed by the engine (e.g. `1.2 MH/s`).
    pub speed: Option<String>,
    /// The candidate currently being tested, when the engine reports it.
    pub candidate: Option<String>,
    /// Estimated time remaining, as printed by the engine.
    pub eta: Option<String>,

    /// Internal: raw total from the current segment (not accumulated).
    #[serde(skip)]
    pub(crate) segment_total: Option<u64>,
    /// Internal: last tried value seen, to detect increment-length resets.
    #[serde(skip)]
    pub(crate) prev_tried: Option<u64>,
    /// Internal: sum of completed segment totals.
    #[serde(skip)]
    pub(crate) accum_total: u64,
    /// Cumulative tried count across all completed segments plus current.
    pub cumulative_tried: Option<u64>,
    /// Cumulative total count across all completed segments plus current.
    pub cumulative_total: Option<u64>,
}

/// A shareable sink for progress events. The UI passes one in; the engine
/// calls it from its stdout/stderr reader threads.
pub type ProgressSink = Arc<dyn Fn(&RecoveryProgress) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressSource {
    Hashcat,
    John,
}

/// Captured process output, collected while progress is streamed.
struct TrackedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
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
    /// Machine-readable error key for i18n (e.g. "not_encrypted", "extraction_failed").
    pub error_key: Option<&'static str>,
    /// Friendly encryption name (e.g. "AES-256") shown on the file card.
    pub encryption: Option<String>,
    /// "Easy", "Medium" or "Hard", shown on the file card.
    pub difficulty: Option<&'static str>,
    /// Non-fatal warning shown on the file card (e.g. oversized hash).
    pub warning: Option<&'static str>,
}

fn unavailable() -> ExtractResult {
    ExtractResult {
        ok: false,
        hashes: Vec::new(),
        message: Some("Password recovery for this format is not available."),
        error_key: Some("engine_unavailable"),
        encryption: None,
        difficulty: None,
        warning: None,
    }
}

impl ExtractResult {
    pub fn error(message: &'static str) -> ExtractResult {
        ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some(message),
            error_key: None,
            encryption: None,
            difficulty: None,
            warning: None,
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
///
/// `recover` is the test-facing convenience wrapper; the Tauri command uses
/// `recover_with_sink` to stream progress events to the UI.
#[allow(dead_code)]
pub fn recover(request: RecoverRequest) -> RecoverResult {
    recover_with_sink(request, Arc::new(|_| {}), None)
}

/// `recover` with a sink for live progress events. The sink runs on the
/// engine's stdout/stderr reader threads while the process is alive.
///
/// `history_dir` is the app data dir where recovered passwords are stored for
/// reuse; a `None` skips both the history lookup and recording.
pub fn recover_with_sink(
    request: RecoverRequest,
    sink: ProgressSink,
    history_dir: Option<&Path>,
) -> RecoverResult {
    let _run_guard = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    CANCELLED.store(false, Ordering::SeqCst);

    let normalized = match normalizer::normalize_hash(&request.hash) {
        Ok(n) => n,
        Err(_) => {
            crate::logging::event("engine", "recover", "hash_unreadable", None);
            return RecoverResult::error(
                "This password hash could not be read.",
                "hash_unreadable",
            );
        }
    };

    // A previous recovery already found this password: answer instantly.
    if let Some(entry) = history_dir.and_then(|dir| history::find(dir, &normalized.hash)) {
        crate::logging::event("recover", "recover", "reused", None);
        return reused_result(entry.password);
    }

    let workspace = match TempWorkspace::new() {
        Some(ws) => ws,
        None => {
            return RecoverResult::error(
                "Could not create temporary files.",
                "temp_workspace_failed",
            )
        }
    };

    let files = match prepare_attack_files(&request, &workspace) {
        Ok(files) => files,
        Err(e) => {
            let (msg, key) = e.friendly();
            return RecoverResult::error(msg, key);
        }
    };
    if cancelled() {
        return RecoverResult::cancelled();
    }

    let attack_args = match attack::build_attack(&request.strategy, &files) {
        Ok(a) => a,
        Err(e) => {
            let (msg, key) = e.friendly();
            return RecoverResult::error(msg, key);
        }
    };

    crate::logging::event(
        "engine",
        "recover",
        "normalized",
        Some(&format!(
            "hashcat_mode={:?} john_format={:?} hash_len={}",
            normalized.hashcat_mode,
            normalized.john_format,
            normalized.hash.len()
        )),
    );

    let Some(hashcat_file) = workspace.write("hash.txt", &normalized.hash) else {
        return RecoverResult::error(
            "Could not prepare the password hash.",
            "hash_prepare_failed",
        );
    };

    // Collect the exact command lines invoked so the UI can log them for
    // debugging (in addition to the live structured log in spawn_tracked).
    let mut commands: Vec<String> = Vec::new();

    // Hashcat has architecture-dependent hash line limits for archive formats
    // because the hash includes compressed data for password verification.
    // When the hash exceeds the limit, skip hashcat and let John handle it —
    // John has no length restriction.
    //
    //   ZIP  (17200/17220): ~8 KB limit
    //   7z   (11600):       ~320 KB limit
    //   RAR3 (12500):       no limit (fixed-format hash, no compressed data)
    //   RAR5 (13000):       no limit (fixed-format hash, no compressed data)
    let hash_too_long_for_hashcat = match normalized.hashcat_mode {
        Some(17200 | 17220) => normalized.hash.len() > 8192,
        Some(11600) => normalized.hash.len() > 320_000,
        _ => false,
    };

    // Hashcat first when this hash has a supported mode and GPU acceleration
    // is enabled.  When gpu_acceleration is false the user prefers John-only.
    let gpu_enabled = request.gpu_acceleration.unwrap_or(true);
    if let Some(mode) = normalized.hashcat_mode.filter(|_| gpu_enabled) {
        if hash_too_long_for_hashcat {
            crate::logging::event(
                "engine",
                "hashcat",
                "skip_oversized",
                Some(&format!("hash_len={}", normalized.hash.len())),
            );
        }
        if !hash_too_long_for_hashcat {
            if let Some(hashcat) = resolve_program("hashcat") {
                match run_hashcat(
                    &hashcat,
                    mode,
                    &hashcat_file,
                    &attack_args.hashcat_args,
                    sink.clone(),
                    &mut commands,
                ) {
                    HashcatOutcome::Cracked(password) => {
                        record_history(history_dir, &request, &normalized, "GPU", &password);
                        return ok_result(password, &commands);
                    }
                    HashcatOutcome::NotFound => {
                        if cancelled() {
                            return RecoverResult::cancelled();
                        }
                        // Fall through to let John try.
                    }
                    // NoHashesLoaded / Error: fall through and let John try.
                    _ => {}
                }
            }
        }
        if cancelled() {
            return RecoverResult::cancelled();
        }
    }

    // The combinator attack is Hashcat-only; if Hashcat was skipped or failed
    // it is simply unavailable.
    if matches!(request.strategy.kind, StrategyKind::Combinator) {
        crate::logging::event("engine", "recover", "combinator_no_hashcat", None);
        return RecoverResult::error(
            "This recovery method is not available in your current version.",
            "method_unavailable",
        );
    }

    // John fallback, and the only engine for Hashcat-less hashes.
    if let Some(john_format) = normalized.john_format {
        let john_path = resolve_program("john");
        crate::logging::event(
            "engine",
            "john_resolve",
            if john_path.is_some() {
                "found"
            } else {
                "not_found"
            },
            john_path
                .as_ref()
                .map(|p| p.display().to_string())
                .as_deref(),
        );
        if let Some(john) = john_path {
            let display_name = john_login_name(normalized.filename.as_deref());
            let john_input = format!("{display_name}:{}", normalized.hash);
            let Some(john_file) = workspace.write("john.txt", &john_input) else {
                return RecoverResult::error(
                    "Could not prepare the password hash.",
                    "hash_prepare_failed",
                );
            };
            let pot_file = workspace.path("john.pot");
            match run_john(
                &john,
                john_format,
                &john_file,
                &pot_file,
                &attack_args.john_args,
                &display_name,
                sink.clone(),
                &mut commands,
            ) {
                JohnOutcome::Cracked(password) => {
                    record_history(history_dir, &request, &normalized, "CPU", &password);
                    return ok_result(password, &commands);
                }
                JohnOutcome::NotFound => {
                    if cancelled() {
                        return RecoverResult::cancelled();
                    }
                    return not_found(&commands);
                }
                JohnOutcome::Error => {}
            }
        }
    }

    if cancelled() {
        return RecoverResult::cancelled();
    }
    RecoverResult::error("No recovery engine is available.", "engine_unavailable")
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
    let file_path = Path::new(&request.file_path);

    let wordlist: Option<PathBuf>;
    let mut wordlist_second: Option<PathBuf> = None;
    let rules: Option<PathBuf>;

    match request.strategy.kind {
        StrategyKind::Dictionary => {
            wordlist = options
                .dictionary
                .as_deref()
                .and_then(resolve_dictionary)
                .or_else(|| resolve_dictionary(attack::DEFAULT_DICTIONARY))
                .and_then(|wl| prepend_filename_candidates(workspace, &wl, file_path));
            rules = options
                .rule_level
                .as_deref()
                .and_then(resolve_hashcat_rules);
        }
        StrategyKind::Partial => {
            wordlist = resolve_dictionary(attack::DEFAULT_DICTIONARY)
                .and_then(|wl| prepend_filename_candidates(workspace, &wl, file_path));
            rules = None;
        }
        StrategyKind::Pattern => {
            wordlist = match options.history.as_deref() {
                Some(text) if !text.trim().is_empty() => workspace
                    .write("history.txt", &normalize_wordlist(text))
                    .and_then(|wl| prepend_filename_candidates(workspace, &wl, file_path)),
                _ => options
                    .dictionary
                    .as_deref()
                    .and_then(resolve_dictionary)
                    .or_else(|| resolve_dictionary(attack::DEFAULT_DICTIONARY))
                    .and_then(|wl| prepend_filename_candidates(workspace, &wl, file_path)),
            };
            rules = resolve_hashcat_rules(
                options
                    .rule_level
                    .as_deref()
                    .unwrap_or(attack::DEFAULT_RULE_LEVEL),
            );
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
        StrategyKind::Bruteforce | StrategyKind::Incremental => {
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

/// Last path component, independent of the OS separator, so a Windows path in
/// a hash line behaves the same on any host.
fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Candidate words derived from the target file's name. John's single-crack
/// mode famously uses the login/filename as a mangling base (a file named
/// `xxx.pdf` often has a password related to `xxx`); the app runs explicit
/// wordlist attacks instead, so these candidates are prepended to the
/// wordlist to keep the advantage for both engines.
fn filename_candidates(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Some(name) = path.to_str().map(base_name) else {
        return out;
    };
    if !name.is_empty() {
        out.push(name.to_string());
        let stem = name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .filter(|s| !s.is_empty())
            .unwrap_or(name);
        if stem != name {
            out.push(stem.to_string());
        }
    }
    out
}

/// Copy a wordlist into the temp workspace with the file-name candidates
/// first, so both engines try the name-derived words ahead of the dictionary.
fn prepend_filename_candidates(
    workspace: &TempWorkspace,
    wordlist: &Path,
    file_path: &Path,
) -> Option<PathBuf> {
    let candidates = filename_candidates(file_path);
    if candidates.is_empty() {
        return Some(wordlist.to_path_buf());
    }
    // read_to_string fails on non-UTF-8 wordlists (e.g. rockyou.txt which is
    // Latin-1). Fall back to the original path; the engines read wordlists as
    // raw byte streams and handle any encoding.
    let contents = match std::fs::read_to_string(wordlist) {
        Ok(c) => c,
        Err(_) => return Some(wordlist.to_path_buf()),
    };
    let mut lines = candidates;
    for line in contents.lines() {
        let line = line.trim();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    workspace.write("wordlist.txt", &lines.join("\n"))
}

/// A safe login name for John's `login:$hash$` input line. The raw file path
/// is unusable here: Windows drive letters (`C:\...`) and colons inside
/// filenames would break John's parser, which splits the line on the first
/// `:`. The file's base name without extension is used instead, and John's
/// `--show` output is matched against the same name.
fn john_login_name(filename: Option<&str>) -> String {
    let Some(name) = filename.map(base_name).filter(|s| !s.is_empty()) else {
        return "hashrecover".into();
    };
    let stem = name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    stem.to_string()
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

/// Spawn a process while registering it as the cancellable active child, and
/// stream its output: stdout/stderr reader threads push parsed progress to
/// the sink and the calling thread polls `try_wait` until the process exits
/// (killing it if the user cancelled). The child stays registered for the
/// whole run so `cancel_recovery` and pause/resume can reach it.
/// Hashcat 7.x resolves its OpenCL kernels, modules and shared libs from
/// paths relative to the process working directory (defaulting to
/// `./OpenCL/`), so launching it from any other directory fails with
/// `./OpenCL/: No such file or directory`. Every engine child therefore runs
/// with its own binary directory as the working directory, and hashcat's data
/// folders are pinned through its documented environment variables.
/// Hash/wordlist paths are absolute, so the cwd never affects attack inputs.
fn run_from_binary_dir(cmd: &mut Command, binary: &Path) {
    let Some(dir) = binary.parent() else {
        return;
    };
    cmd.current_dir(dir);
    for (var, subdir) in [
        ("HASHCAT_OPENCL_KERNELS", "OpenCL"),
        ("HASHCAT_MODULES", "modules"),
        ("HASHCAT_LIBS", "libs"),
    ] {
        if dir.join(subdir).is_dir() {
            cmd.env(var, dir.join(subdir));
        }
    }
}

fn spawn_tracked(
    cmd: &mut Command,
    sink: ProgressSink,
    source: ProgressSource,
) -> io::Result<TrackedOutput> {
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::logging::event("engine", "command", "spawn", Some(&format_command(cmd)));
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    {
        let mut guard = ACTIVE_CHILD.lock().unwrap();
        *guard = Some(child);
    }
    *ACTIVE_SOURCE.lock().unwrap() = Some(source);

    let out_thread = std::thread::spawn({
        let sink = sink.clone();
        move || read_stream(stdout, source, sink)
    });
    let err_thread = std::thread::spawn({
        let sink = sink.clone();
        move || read_stream(stderr, source, sink)
    });

    let status = loop {
        std::thread::sleep(Duration::from_millis(50));
        let mut guard = ACTIVE_CHILD.lock().unwrap();
        let child = guard.as_mut().expect("active child is set while running");
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if CANCELLED.load(Ordering::SeqCst) {
                    let _ = child.kill();
                }
            }
        }
    };

    {
        let mut guard = ACTIVE_CHILD.lock().unwrap();
        *guard = None;
    }
    *ACTIVE_SOURCE.lock().unwrap() = None;

    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(TrackedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Read a pipe line by line, accumulate the raw bytes (used later to find the
/// cracked-password line) and forward any parseable progress lines to the sink.
fn read_stream(reader: impl std::io::Read, source: ProgressSource, sink: ProgressSink) -> Vec<u8> {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    let mut line = Vec::new();
    let mut last = RecoveryProgress::default();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&line);
        let text = String::from_utf8_lossy(&line);
        let updated = match source {
            ProgressSource::Hashcat => parse_hashcat_progress(text.trim_end(), &mut last),
            ProgressSource::John => parse_john_progress(text.trim_end(), &mut last),
        };
        if updated {
            sink(&last);
        }
    }
    buf
}

/// Parse one Hashcat status line, updating the running progress snapshot.
///
/// Status blocks (printed once per `--status-timer` second) look like:
/// `Progress.........: 1024/1048576 (0.10%)`, `Speed.#*.........: 1.2 MH/s`,
/// `Candidates.#1....: pw123 -> pw123`, `Time.Estimated...: ... (1 hour)`.
fn parse_hashcat_progress(line: &str, last: &mut RecoveryProgress) -> bool {
    let Some((key, value)) = line.split_once(':') else {
        return false;
    };
    // Keys are padded with dots (`Progress.........`); strip them.
    let key = key.trim().trim_end_matches('.');
    let value = value.trim();
    match key {
        "Progress" => {
            parse_hashcat_frac(value, last);
            true
        }
        "Speed.#*" | "Speed.#1" => {
            if !value.is_empty() {
                last.speed = Some(normalize_speed(value));
            }
            true
        }
        "Candidates.#1" => {
            let current = value.split(" -> ").next().unwrap_or(value).trim();
            if !current.is_empty() {
                last.candidate = Some(current.to_string());
            }
            true
        }
        "Time.Estimated" => {
            last.eta = Some(
                value
                    .rsplit_once('(')
                    .and_then(|(_, inner)| inner.strip_suffix(')'))
                    .map(str::trim)
                    .unwrap_or(value)
                    .to_string(),
            );
            true
        }
        _ => false,
    }
}

/// Parse `tried/total (percent%)` into the progress snapshot.
///
/// For incremental mode, Hashcat resets `tried` and `total` when moving to the
/// next length.  We detect the reset (tried decreases) and accumulate a
/// running sum so the UI shows a single growing counter.
fn parse_hashcat_frac(value: &str, last: &mut RecoveryProgress) {
    if let Some((tried_str, rest)) = value.split_once('/') {
        if let Ok(t) = tried_str.trim().parse::<u64>() {
            // Detect increment-length reset: tried dropped below the previous
            // value.  When that happens the prior segment is complete, so add
            // its total to the cumulative counter.
            if let Some(prev) = last.prev_tried {
                if t < prev {
                    if let Some(seg) = last.segment_total {
                        last.accum_total += seg;
                    }
                }
            }
            last.prev_tried = Some(t);
            last.tried = Some(t);
            last.cumulative_tried = Some(last.accum_total + t);
        }
        if let Ok(t) = rest.split_whitespace().next().unwrap_or("").parse::<u64>() {
            last.segment_total = Some(t);
            last.total = Some(t);
            last.cumulative_total = Some(last.accum_total + t);
        }
    }
    if let Some(open) = value.find('(') {
        let end = value[open + 1..]
            .find('%')
            .map(|i| open + 1 + i)
            .unwrap_or(value.len());
        if let Ok(p) = value[open + 1..end].trim().parse::<f64>() {
            last.percent = Some(p);
        }
    }
}

/// Normalize a speed string to a unified `"/s"` suffix.
///
/// Converts engine-specific units to a consistent format:
/// - Hashcat: `"1.2 MH/s"` → `"1.2M/s"`, `"512 KH/s"` → `"512K/s"`
/// - John: `"1134Kp/s"` → `"1134K/s"`, `"2.178g/s"` → `"2.178/s"`
fn normalize_speed(raw: &str) -> String {
    let trimmed = raw.trim();
    // Strip trailing "/s" first, then any engine-specific suffix before it.
    if let Some(rest) = trimmed.strip_suffix("/s") {
        // rest is like "1.2 MH", "1134Kp", "2.178g"
        // Find the last digit/dot/comma to locate the number boundary.
        if let Some(idx) = rest.rfind(|c: char| c.is_ascii_digit() || c == '.' || c == ',') {
            let number_part = &rest[..=idx];
            let suffix = rest[idx + 1..].trim(); // e.g. "MH", "Kp", "g"
                                                 // Keep only the SI prefix (K, M, G, T, etc.) if present.
            let si_prefix = suffix
                .chars()
                .next()
                .filter(|c| matches!(c, 'K' | 'M' | 'G' | 'T' | 'P' | 'E'))
                .map(|c| c.to_string())
                .unwrap_or_default();
            return format!("{number_part}{si_prefix}/s");
        }
    }
    // Fallback: return as-is.
    trimmed.to_string()
}

/// Parse one John progress line (`--progress-every`). John outputs:
///
/// Progress: `0g 0:00:00:03 26.19% (ETA: 21:50:09) 0g/s 1134Kp/s ...`
/// Done:     `1g 0:00:00:00 DONE (2026-08-17 21:48) 2.178g/s 1122Kp/s ...`
///
/// Parsed fields: tried (`Xg` token), percent (token 2), speed (`NUMBERp/s`
/// token), ETA (`ETA: HH:MM:SS`).  Like Hashcat's incremental mode, John
/// resets its guess counter when moving to the next mask group; we accumulate
/// across groups so the UI shows a single growing number.
fn parse_john_progress(line: &str, last: &mut RecoveryProgress) -> bool {
    let mut updated = false;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // Token 0: "0g" or "1234g" — guesses tried in the current segment.
    if let Some(g_token) = tokens.first() {
        if let Some(g_str) = g_token.strip_suffix('g') {
            if let Ok(g) = g_str.parse::<u64>() {
                // Detect segment reset: guess count dropped.
                if let Some(prev) = last.prev_tried {
                    if g < prev {
                        if let Some(seg) = last.segment_total {
                            last.accum_total += seg;
                        }
                    }
                }
                last.prev_tried = Some(g);
                last.tried = Some(g);
                last.cumulative_tried = Some(last.accum_total + g);
                updated = true;
            }
        }
    }
    if let Some(pct) = tokens.get(2).and_then(|t| t.strip_suffix('%')) {
        if let Ok(p) = pct.parse::<f64>() {
            last.percent = Some(p);
            updated = true;
        }
    }
    // Speed: token like "1134Kp/s" or "1122Kp/s" (passwords/s — the useful metric).
    // John also prints "0g/s" (guesses/s) which is usually 0 and not useful.
    for token in &tokens {
        if token.ends_with("p/s") && token.len() > 3 {
            last.speed = Some(normalize_speed(token));
            updated = true;
            break;
        }
    }
    // ETA: "(ETA: 21:50:09)" — John reports wall-clock ETA, not duration.
    if let Some(idx) = line.find("(ETA:") {
        let rest = &line[idx + 5..];
        if let Some(end) = rest.find(')') {
            let eta = rest[..end].trim();
            if !eta.is_empty() {
                last.eta = Some(eta.to_string());
                updated = true;
            }
        }
    }
    updated
}

/// Pause the running engine. Hashcat pauses natively when `p` is sent to its
/// stdin; John is suspended with an OS signal (SIGSTOP / NtSuspendProcess).
pub fn pause_recovery() {
    crate::logging::event("engine", "pause", "start", None);
    match *ACTIVE_SOURCE.lock().unwrap() {
        Some(ProgressSource::Hashcat) | Some(ProgressSource::John) => suspend_active(),
        None => {}
    }
    crate::logging::event("engine", "pause", "done", None);
}

/// Resume a paused engine.
pub fn resume_recovery() {
    crate::logging::event("engine", "resume", "start", None);
    match *ACTIVE_SOURCE.lock().unwrap() {
        Some(ProgressSource::Hashcat) | Some(ProgressSource::John) => resume_active(),
        None => {}
    }
    crate::logging::event("engine", "resume", "done", None);
}

fn active_pid() -> Option<u32> {
    ACTIVE_CHILD
        .lock()
        .unwrap()
        .as_ref()
        .map(|child| child.id())
}

#[cfg(unix)]
fn suspend_active() {
    if let Some(pid) = active_pid() {
        // Safety: SIGSTOP on our own spawned child.
        unsafe {
            libc::kill(pid as i32, libc::SIGSTOP);
        }
    }
}

#[cfg(unix)]
fn resume_active() {
    if let Some(pid) = active_pid() {
        // Safety: SIGCONT on our own spawned child.
        unsafe {
            libc::kill(pid as i32, libc::SIGCONT);
        }
    }
}

#[cfg(windows)]
fn suspend_active() {
    if let Some(pid) = active_pid() {
        windows_pause::suspend(pid);
    }
}

#[cfg(windows)]
fn resume_active() {
    if let Some(pid) = active_pid() {
        windows_pause::resume(pid);
    }
}

/// Windows has no POSIX signals; suspend/resume the process by calling the
/// undocumented `NtSuspendProcess`/`NtResumeProcess` in ntdll.
#[cfg(windows)]
mod windows_pause {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

    type NtSuspendFn = unsafe extern "system" fn(*mut c_void) -> i32;

    fn nt_function(name: &[u8]) -> Option<NtSuspendFn> {
        // Safety: loads a fixed ntdll export whose signature is stable.
        unsafe {
            let module = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if module.is_null() {
                return None;
            }
            // `FARPROC` is `Option<unsafe extern "system" fn()>`; unwrap it and
            // transmute the function pointer to the typed signature.
            match GetProcAddress(module, name.as_ptr()) {
                Some(proc) => Some(std::mem::transmute::<_, NtSuspendFn>(proc)),
                None => None,
            }
        }
    }

    fn with_process_handle(pid: u32, f: NtSuspendFn) {
        // Safety: OpenProcess/CloseHandle on our own spawned child.
        unsafe {
            let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
            if handle.is_null() {
                return;
            }
            let _ = f(handle as *mut c_void);
            CloseHandle(handle);
        }
    }

    pub fn suspend(pid: u32) {
        if let Some(f) = nt_function(b"NtSuspendProcess\0") {
            with_process_handle(pid, f);
        }
    }

    pub fn resume(pid: u32) {
        if let Some(f) = nt_function(b"NtResumeProcess\0") {
            with_process_handle(pid, f);
        }
    }
}

/// Render a command line for logging: the program path and each argument,
/// quoting arguments that contain whitespace so the line can be copied.
fn format_command(cmd: &Command) -> String {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|arg| {
            let s = arg.to_string_lossy();
            if s.chars().any(char::is_whitespace) {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn ok_result(password: String, commands: &[String]) -> RecoverResult {
    RecoverResult {
        ok: true,
        password: Some(password),
        message: None,
        error_key: None,
        cancelled: false,
        reused: false,
        command_lines: commands.to_vec(),
    }
}

fn reused_result(password: String) -> RecoverResult {
    RecoverResult {
        ok: true,
        password: Some(password),
        message: None,
        error_key: None,
        cancelled: false,
        reused: true,
        command_lines: Vec::new(),
    }
}

fn not_found(commands: &[String]) -> RecoverResult {
    RecoverResult {
        ok: false,
        password: None,
        message: None,
        error_key: None,
        cancelled: false,
        reused: false,
        command_lines: commands.to_vec(),
    }
}

/// Store a successful recovery in the local history for future reuse. The
/// store key is the bare normalized hash; metadata comes from the request.
fn record_history(
    history_dir: Option<&Path>,
    request: &RecoverRequest,
    normalized: &NormalizedHash,
    engine: &str,
    password: &str,
) {
    let Some(dir) = history_dir else {
        return;
    };
    let description = normalizer::describe_hash(&request.hash);
    let file_name = Path::new(&request.file_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .or_else(|| normalized.filename.clone())
        .unwrap_or_else(|| "unknown".to_string());
    history::record(
        dir,
        history::HistoryEntry {
            hash: normalized.hash.clone(),
            file_name,
            encryption: description.as_ref().map(|d| d.encryption.clone()),
            difficulty: description.as_ref().map(|d| d.difficulty.to_string()),
            password: password.to_string(),
            engine: engine.to_string(),
            strategy_kind: format!("{:?}", request.strategy.kind).to_lowercase(),
            recovered_at: history::now_ms(),
        },
    );
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
///
/// Hashcat runs without `--quiet` so its periodic `--status` blocks can be
/// parsed into progress events; the extra banner/status noise is harmless to
/// the cracked-line parser below. `--status-timer=1` keeps the blocks fresh.
fn run_hashcat(
    binary: &Path,
    mode: u32,
    hash_file: &Path,
    attack_args: &[String],
    sink: ProgressSink,
    commands: &mut Vec<String>,
) -> HashcatOutcome {
    let mut cmd = std::process::Command::new(binary);
    run_from_binary_dir(&mut cmd, binary);
    cmd.arg("-m")
        .arg(mode.to_string())
        .arg(hash_file)
        .args(attack_args)
        .arg("--potfile-disable")
        .arg("--restore-disable")
        .arg("--status")
        .arg("--status-timer=1");
    commands.push(format_command(&cmd));
    let output = spawn_tracked(&mut cmd, sink, ProgressSource::Hashcat);
    let output = match output {
        Ok(out) => out,
        Err(_) => return HashcatOutcome::Error,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let outcome = if stdout.contains("No hashes loaded.") || stderr.contains("No hashes loaded.") {
        HashcatOutcome::NoHashesLoaded
    } else if let Some(password) = crack_line(&stdout) {
        HashcatOutcome::Cracked(password)
    } else {
        match output.status.code() {
            Some(0) | Some(1) => HashcatOutcome::NotFound,
            _ => HashcatOutcome::Error,
        }
    };

    if !matches!(outcome, HashcatOutcome::Cracked(_)) {
        // Internal diagnostics only: log the exit code and a sanitized stderr
        // excerpt so a hashcat fallback can be investigated. Candidate lines
        // and hash lines are filtered out — never log passwords.
        let excerpt = sanitize_hashcat_diagnostic(&stderr);
        let detail = match excerpt {
            Some(excerpt) => Some(format!("exit={:?} | {excerpt}", output.status.code())),
            None => Some(format!("exit={:?}", output.status.code())),
        };
        crate::logging::event("engine", "hashcat", "not_cracked", detail.as_deref());
    }

    outcome
}

/// Last few lines of hashcat stderr that are safe for the log. Lines carrying
/// candidate words (`Candidates.#1....:`) or hash targets (`$...`) are dropped
/// so no password material reaches the log; what remains is device/error/
/// progress diagnostics.
fn sanitize_hashcat_diagnostic(stderr: &str) -> Option<String> {
    let kept: Vec<&str> = stderr
        .lines()
        .rev()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.contains("Candidates.")
                && !trimmed.contains("Hash.Target")
                && !trimmed.contains('$')
        })
        .take(6)
        .collect();
    if kept.is_empty() {
        return None;
    }
    Some(kept.iter().rev().copied().collect::<Vec<_>>().join(" | "))
}

/// Find the `<hash>:<password>` line Hashcat prints when a password is found.
///
/// With stdin piped, Hashcat shows an interactive prompt line and appends the
/// crack line to it (`[s]tatus ... => \r  $pdf$...:password123`), so the hash
/// is located anywhere in the line, not only at its start. The hash segment
/// (leading `$` up to the first `:`) never contains spaces, which rules out
/// the prompt prefix and status lines like `Hash.Target......: $pdf$...`.
fn crack_line(stdout: &str) -> Option<String> {
    stdout.lines().map(str::trim_end).find_map(|line| {
        let start = line.find('$')?;
        let rest = &line[start..];
        let (hash, _) = rest.split_once(':')?;
        if hash.contains(' ') {
            return None;
        }
        let (_, pw) = rest.rsplit_once(':')?;
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
/// password is stored permanently. `--progress-every=1` makes John emit its
/// progress line to stderr once per second for the progress sink.
#[allow(clippy::too_many_arguments)]
fn run_john(
    binary: &Path,
    format: &str,
    hash_file: &Path,
    pot_file: &Path,
    attack_args: &[String],
    display_name: &str,
    sink: ProgressSink,
    commands: &mut Vec<String>,
) -> JohnOutcome {
    let mut run = std::process::Command::new(binary);
    run_from_binary_dir(&mut run, binary);
    run.arg(format!("--format={format}"))
        .arg(format!("--pot={}", pot_file.display()))
        .arg("--progress-every=1")
        .args(attack_args)
        .arg(hash_file);
    commands.push(format_command(&run));
    let run = spawn_tracked(&mut run, sink.clone(), ProgressSource::John);
    if run.is_err() {
        return JohnOutcome::Error;
    }

    let mut show = std::process::Command::new(binary);
    run_from_binary_dir(&mut show, binary);
    show.arg("--show")
        .arg(format!("--pot={}", pot_file.display()))
        .arg(hash_file);
    commands.push(format_command(&show));
    let show = spawn_tracked(&mut show, sink, ProgressSource::John);
    let show = match show {
        Ok(out) => out,
        Err(_) => return JohnOutcome::Error,
    };
    if !show.status.success() {
        return JohnOutcome::Error;
    }

    // John's --show output format: `login:hash:password`.
    // rsplit_once(':') extracts the password from the last segment, since
    // the hash itself may contain colons in some formats.
    let shown = String::from_utf8_lossy(&show.stdout);
    for line in shown.lines() {
        if let Some((prefix, password)) = line.rsplit_once(':') {
            if !password.is_empty() && prefix.starts_with(display_name) {
                return JohnOutcome::Cracked(decode_password(password));
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
    // Development: cargo builds extractors into CARGO_MANIFEST_DIR/target/{debug,release}.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    #[cfg(debug_assertions)]
    dirs.push(manifest.join("target").join("debug"));
    #[cfg(not(debug_assertions))]
    dirs.push(manifest.join("target").join("release"));
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
        crate::logging::event(
            "engine",
            "resolve_dict",
            "literal",
            Some(&p.display().to_string()),
        );
        return Some(p);
    }
    let stem = name.strip_suffix(".txt").unwrap_or(name);
    for dir in wordlist_dirs() {
        let candidate = dir.join(format!("{stem}.txt"));
        if candidate.is_file() {
            crate::logging::event(
                "engine",
                "resolve_dict",
                "bundled",
                Some(&candidate.display().to_string()),
            );
            return Some(candidate);
        }
    }
    crate::logging::event(
        "engine",
        "resolve_dict",
        "not_found",
        Some(&format!("name={name}  dirs={:?}", wordlist_dirs())),
    );
    None
}

fn wordlist_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dir) = std::env::var("HASHRECOVER_WORDLISTS") {
        dirs.push(PathBuf::from(dir));
    }
    if let Some(dir) = RESOURCE_DIR.get() {
        dirs.push(dir.join("wordlists"));
    }
    // Dev builds: CARGO_MANIFEST_DIR points to the project root.
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
    if let Some(dir) = RESOURCE_DIR.get() {
        dirs.push(dir.join("rules"));
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

/// Resolve the hashcat rule file for a variation level, trying each candidate
/// name in order (e.g. `best66` then `best64`) until one exists.
fn resolve_hashcat_rules(level: &str) -> Option<PathBuf> {
    attack::hashcat_rule_candidates(level)
        .iter()
        .find_map(|name| resolve_rules(name))
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
    let Some(binary) = resolve_program(family.extractor()) else {
        log::warn!("extractor {} binary not found", family.extractor());
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
        Some(0) if !hashes.is_empty() => {
            // Warn when the hash is too long for hashcat — John will be used instead.
            let hash_len = hashes.first().map_or(0, |h| h.len());
            let warning = if matches!(family, Family::Zip) && hash_len > 8192 {
                Some("The password hash is very long. Hashcat may not work; John the Ripper will be used.")
            } else if matches!(family, Family::SevenZ) && hash_len > 320_000 {
                Some("The password hash is very long. Hashcat may not work; John the Ripper will be used.")
            } else {
                None
            };
            ExtractResult {
                ok: true,
                hashes,
                message: None,
                error_key: None,
                encryption: describe.0,
                difficulty: describe.1,
                warning,
            }
        }
        Some(0) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some(
                "This file was read successfully, but no password hash was found inside.",
            ),
            error_key: Some("no_hash"),
            encryption: None,
            difficulty: None,
            warning: None,
        },
        Some(2) => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("This file does not appear to be password-protected."),
            error_key: Some("not_encrypted"),
            encryption: None,
            difficulty: None,
            warning: None,
        },
        _ => ExtractResult {
            ok: false,
            hashes: Vec::new(),
            message: Some("Could not extract a password hash from this file."),
            error_key: Some("extraction_failed"),
            encryption: None,
            difficulty: None,
            warning: None,
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
        // RAR extractor is not implemented, so this exercises the
        // graceful-degradation path for every variant.
        let result = extract(Family::Rar, Path::new("/nonexistent/archive.rar"));
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("Password recovery for this format is not available.")
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
            gpu_acceleration: None,
        };
        let result = recover(request);
        assert!(!result.ok);
        assert_eq!(
            result.message,
            Some("This password hash could not be read.")
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
            gpu_acceleration: None,
        };
        let result = recover(request);
        assert!(!result.ok);
        assert_eq!(result.message, Some("No recovery engine is available."));
    }

    #[test]
    fn bundled_default_dictionary_resolves() {
        assert!(
            resolve_dictionary(attack::DEFAULT_DICTIONARY).is_some(),
            "default dictionary must be resolvable"
        );
    }

    #[test]
    fn long_zip_hash_skips_hashcat() {
        // A ZIP hash over 8192 bytes should be flagged as too long for hashcat.
        let long_payload = "a".repeat(9000);
        let hash = format!("$zip2$*0*3*0*aaaa*1024*{long_payload}*bbbb*1024*$/zip2$");
        assert!(hash.len() > 8192);
        let n = normalizer::normalize_hash(&hash).unwrap();
        assert_eq!(n.hashcat_mode, Some(17200));
        let too_long = matches!(n.hashcat_mode, Some(17200 | 17220)) && n.hash.len() > 8192;
        assert!(too_long, "long ZIP hash should be flagged");
    }

    #[test]
    fn long_7z_hash_skips_hashcat() {
        // A 7z hash over 320 KB should be flagged as too long for hashcat.
        let long_payload = "a".repeat(350_000);
        let hash = format!("$7z$*0*0*0*0*0*0*0*0*{long_payload}");
        assert!(hash.len() > 320_000);
        let n = normalizer::normalize_hash(&hash).unwrap();
        assert_eq!(n.hashcat_mode, Some(11600));
        let too_long = n.hashcat_mode == Some(11600) && n.hash.len() > 320_000;
        assert!(too_long, "long 7z hash should be flagged");
    }

    #[test]
    fn rar_hash_never_too_long() {
        // RAR hashes are fixed-format and never exceed limits.
        let n = normalizer::normalize_hash("$rar3$*0*aaaa*bbbb").unwrap();
        assert_eq!(n.hashcat_mode, Some(12500));
        let too_long = matches!(n.hashcat_mode, Some(17200 | 17220 | 11600)) && n.hash.len() > 8192;
        assert!(!too_long, "RAR hash should never be flagged");
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
            gpu_acceleration: None,
        };
        let ws = TempWorkspace::new().unwrap();
        let files = prepare_attack_files(&request, &ws).unwrap();
        let wl = files.wordlist.unwrap();
        let contents = std::fs::read_to_string(&wl).unwrap();
        // The file-name candidates are prepended ahead of the history lines.
        assert!(contents.ends_with("x.pdf\nx\npass\nword2"));
    }

    #[test]
    fn filename_candidates_derive_base_and_stem() {
        let windows = filename_candidates(Path::new(r"D:\Downloads\xxx.pdf"));
        assert_eq!(windows, ["xxx.pdf", "xxx"]);
        let simple = filename_candidates(Path::new("/tmp/notes.txt"));
        assert_eq!(simple, ["notes.txt", "notes"]);
        assert!(filename_candidates(Path::new("/")).is_empty());
    }

    #[test]
    fn john_login_name_is_path_and_extension_free() {
        // A Windows path must not leak colons into John's `login:$hash$` line.
        assert_eq!(john_login_name(Some(r"D:\Downloads\xxx.pdf")), "xxx");
        assert_eq!(john_login_name(Some("archive.zip")), "archive");
        assert_eq!(john_login_name(None), "hashrecover");
    }

    #[test]
    fn dictionary_wordlist_gets_filename_candidates_prepended() {
        let request = RecoverRequest {
            file_path: "/tmp/secret.pdf".into(),
            hash: "$pdf$5*6*256*1*2*3".into(),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions {
                    dictionary: Some("no-such-dictionary".into()),
                    ..Default::default()
                },
            },
            gpu_acceleration: None,
        };
        let ws = TempWorkspace::new().unwrap();
        let files = prepare_attack_files(&request, &ws).unwrap();
        let contents = std::fs::read_to_string(files.wordlist.unwrap()).unwrap();
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some("secret.pdf"));
        assert_eq!(lines.next(), Some("secret"));
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
            gpu_acceleration: None,
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
            gpu_acceleration: None,
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
    fn normalize_speed_strips_engine_suffixes() {
        // Hashcat units
        assert_eq!(normalize_speed("1.2 MH/s"), "1.2M/s");
        assert_eq!(normalize_speed("512 KH/s"), "512K/s");
        assert_eq!(normalize_speed("3.5 GH/s"), "3.5G/s");
        assert_eq!(normalize_speed("100 H/s"), "100/s");
        // John units
        assert_eq!(normalize_speed("1134Kp/s"), "1134K/s");
        assert_eq!(normalize_speed("2.178g/s"), "2.178/s");
        assert_eq!(normalize_speed("0p/s"), "0/s");
        // Edge cases
        assert_eq!(normalize_speed(" 1.0 MH/s "), "1.0M/s");
        assert_eq!(normalize_speed("42/s"), "42/s");
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
        let found = find_program_in_dirs(std::slice::from_ref(&dir), "hashcat", &candidates);

        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn hashcat_status_progress_is_parsed() {
        let mut p = RecoveryProgress::default();
        assert!(parse_hashcat_progress(
            "Progress.........: 1024/1048576 (0.10%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(1024));
        assert_eq!(p.total, Some(1048576));
        assert_eq!(p.percent, Some(0.10));
        assert!(parse_hashcat_progress(
            "Speed.#*.........: 1.2 MH/s",
            &mut p
        ));
        assert_eq!(p.speed.as_deref(), Some("1.2M/s"));
        assert!(parse_hashcat_progress(
            "Candidates.#1....: pw123 -> pw456",
            &mut p
        ));
        assert_eq!(p.candidate.as_deref(), Some("pw123"));
        assert!(parse_hashcat_progress(
            "Time.Estimated...: Sun Aug 16 18:00:00 2026 (1 hour, 5 mins)",
            &mut p
        ));
        assert_eq!(p.eta.as_deref(), Some("1 hour, 5 mins"));
    }

    #[test]
    fn hashcat_increment_accumulates_tried() {
        let mut p = RecoveryProgress::default();
        // Length 1: 50 out of 95 tried.
        assert!(parse_hashcat_progress(
            "Progress.........: 50/95 (52.63%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(50));
        assert_eq!(p.total, Some(95));
        assert_eq!(p.cumulative_tried, Some(50));
        assert_eq!(p.cumulative_total, Some(95));
        // Length 1 completes: 95/95.
        assert!(parse_hashcat_progress(
            "Progress.........: 95/95 (100.00%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(95));
        assert_eq!(p.total, Some(95));
        assert_eq!(p.cumulative_tried, Some(95));
        assert_eq!(p.cumulative_total, Some(95));
        // Length 2 starts: tried resets to 0, total changes to 9025.
        assert!(parse_hashcat_progress(
            "Progress.........: 0/9025 (0.00%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(0)); // raw
        assert_eq!(p.total, Some(9025)); // raw
        assert_eq!(p.cumulative_tried, Some(95)); // 95 from length 1 + 0
        assert_eq!(p.cumulative_total, Some(9120)); // 95 + 9025
                                                    // 200 tried in length 2.
        assert!(parse_hashcat_progress(
            "Progress.........: 200/9025 (2.22%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(200)); // raw
        assert_eq!(p.total, Some(9025)); // raw
        assert_eq!(p.cumulative_tried, Some(295)); // 95 + 200
        assert_eq!(p.cumulative_total, Some(9120)); // 95 + 9025
                                                    // Length 2 completes: 9025/9025.
        assert!(parse_hashcat_progress(
            "Progress.........: 9025/9025 (100.00%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(9025)); // raw
        assert_eq!(p.total, Some(9025)); // raw
        assert_eq!(p.cumulative_tried, Some(9120)); // 95 + 9025
        assert_eq!(p.cumulative_total, Some(9120)); // 95 + 9025
                                                    // Length 3 starts.
        assert!(parse_hashcat_progress(
            "Progress.........: 0/857375 (0.00%)",
            &mut p
        ));
        assert_eq!(p.tried, Some(0)); // raw
        assert_eq!(p.total, Some(857375)); // raw
        assert_eq!(p.cumulative_tried, Some(9120)); // 95 + 9025 + 0
        assert_eq!(p.cumulative_total, Some(866495)); // 95 + 9025 + 857375
    }

    #[test]
    fn sanitize_drops_candidate_and_hash_lines() {
        let excerpt = sanitize_hashcat_diagnostic(
            "Hash.Target......: $pdf$5*6*256\nCandidates.#1....: password123 -> p@ssword123\nERROR: CUDA SDK 8.0 not installed",
        )
        .unwrap();
        assert_eq!(excerpt, "ERROR: CUDA SDK 8.0 not installed");
        assert!(!excerpt.contains("Candidates"));
        assert!(!excerpt.contains('$'));
    }

    #[test]
    fn sanitize_empty_when_only_noise() {
        assert_eq!(sanitize_hashcat_diagnostic("Candidates.#1....: x\n"), None);
    }

    #[test]
    fn john_progress_is_parsed() {
        let mut p = RecoveryProgress::default();
        assert!(parse_john_progress(
            "0g 0:00:00:03 26.19% (ETA: 21:50:09) 0g/s 1134Kp/s 1134Kc/s 1134KC/s sean91704..sean-crysta",
            &mut p
        ));
        assert_eq!(p.percent, Some(26.19));
        assert_eq!(p.speed.as_deref(), Some("1134K/s"));
        assert_eq!(p.eta.as_deref(), Some("21:50:09"));
    }

    #[test]
    fn john_done_line_parses_speed() {
        let mut p = RecoveryProgress::default();
        assert!(parse_john_progress(
            "1g 0:00:00:00 DONE (2026-08-17 21:48) 2.178g/s 1122Kp/s 1122Kc/s 1122KC/s 0234065415..0234991515",
            &mut p
        ));
        assert_eq!(p.speed.as_deref(), Some("1122K/s"));
    }

    #[test]
    #[cfg(unix)]
    fn spawn_tracked_streams_progress_and_captures_output() {
        let _guard = RUN_LOCK.lock().unwrap();
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink: ProgressSink = Arc::new({
            let events = events.clone();
            move |p| events.lock().unwrap().push(p.clone())
        });
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "printf '%s\\n' 'Progress.........: 5/10 (50.00%)' 'Speed.#*.........: 1.0 MH/s'",
        ]);
        let out = spawn_tracked(&mut cmd, sink, ProgressSource::Hashcat).unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            out.stdout,
            b"Progress.........: 5/10 (50.00%)\nSpeed.#*.........: 1.0 MH/s\n"
        );
        let events = events.lock().unwrap();
        assert!(!events.is_empty());
        assert_eq!(events.first().unwrap().tried, Some(5));
        assert_eq!(events.first().unwrap().total, Some(10));
        assert_eq!(events.first().unwrap().percent, Some(50.0));
    }

    #[test]
    #[cfg(unix)]
    fn pause_and_resume_hashcat_via_stdin() {
        let Some(hashcat) = resolve_program("hashcat") else {
            eprintln!("skipping: hashcat not available");
            return;
        };
        let _guard = RUN_LOCK.lock().unwrap();
        let ws = TempWorkspace::new().unwrap();
        let hash_file = ws.write("hash.txt", &reference_hash("aes256")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let sink: ProgressSink = Arc::new(move |p| {
            let _ = tx.send(p.clone());
        });

        let mut cmd = Command::new(&hashcat);
        cmd.arg("-m")
            .arg("10700")
            .arg(&hash_file)
            .arg("-a")
            .arg("3")
            .arg("?d?d?d?d?d?d?d?d")
            .arg("--potfile-disable")
            .arg("--restore-disable")
            .arg("--status")
            .arg("--status-timer=1");
        let handle =
            std::thread::spawn(move || spawn_tracked(&mut cmd, sink, ProgressSource::Hashcat));

        // Wait for a real `Progress` status line, then pause, resume, cancel.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut got_tried = false;
        while std::time::Instant::now() < deadline {
            let event = rx
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("hashcat should stream status blocks");
            if event.tried.is_some() {
                got_tried = true;
                break;
            }
        }
        assert!(got_tried, "hashcat status never reported a tried count");
        pause_recovery();
        std::thread::sleep(Duration::from_millis(300));
        resume_recovery();
        std::thread::sleep(Duration::from_millis(300));
        cancel_recovery();

        let out = handle
            .join()
            .unwrap()
            .expect("spawn_tracked should succeed");
        assert!(!out.stdout.is_empty());
    }

    #[test]
    fn recovery_history_answers_repeat_attempt_instantly() {
        let dir = std::env::temp_dir().join(format!("hashrecover-reuse-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let request = RecoverRequest {
            file_path: "x.pdf".into(),
            hash: reference_hash("aes256"),
            strategy: RecoveryStrategy {
                kind: StrategyKind::Dictionary,
                options: StrategyOptions::default(),
            },
            gpu_acceleration: None,
        };
        let normalized = normalizer::normalize_hash(&request.hash).unwrap();
        record_history(Some(&dir), &request, &normalized, "GPU", "password123");
        assert!(history::find(&dir, &normalized.hash).is_some());

        // A repeat attempt answers from history without running any engine.
        let result = recover_with_sink(request, Arc::new(|_| {}), Some(&dir));
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.ok, "reuse failed: {:?}", result.message);
        assert!(result.reused);
        assert_eq!(result.password.as_deref(), Some("password123"));
    }

    #[test]
    fn successful_crack_is_recorded_for_reuse() {
        let Some(_hashcat) = resolve_program("hashcat") else {
            eprintln!("skipping: hashcat not available");
            return;
        };
        // recover_with_sink serializes itself via RUN_LOCK; the e2e crack is
        // the only engine run here.
        let dir = std::env::temp_dir().join(format!("hashrecover-record-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let (wl_dir, wl) = temp_wordlist("password123\n");
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
            gpu_acceleration: None,
        };
        let result = recover_with_sink(request, Arc::new(|_| {}), Some(&dir));
        std::fs::remove_dir_all(&wl_dir).ok();
        assert!(result.ok, "recovery failed: {:?}", result.message);
        assert!(!result.reused);

        let normalized = normalizer::normalize_hash(&reference_hash("aes256")).unwrap();
        let entry = history::find(&dir, &normalized.hash);
        assert_eq!(
            entry.as_ref().map(|e| e.password.as_str()),
            Some("password123")
        );
        assert_eq!(entry.as_ref().map(|e| e.engine.as_str()), Some("hashcat"));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn temp_wordlist(contents: &str) -> (PathBuf, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("hashrecover-wl-{}-{id}", std::process::id()));
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

//! Recovery engine layer: locates the bundled extractor and recovery
//! programs, normalizes hashes, and runs Hashcat or John.
//!
//! The engine never leaks raw process errors to the UI. A missing or broken
//! engine program degrades to a friendly "unavailable" message instead of
//! crashing the app, per the project's error-handling rules.

use serde::Serialize;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::attack::{self, AttackFiles};
use crate::formats::Family;
use crate::history;
use crate::normalizer::{self, NormalizedHash};
use crate::strategy::{RecoverRequest, RecoverResult, StrategyKind};

/// Handle of the engine process currently running, so the user can cancel a
/// recovery attempt from the UI.
static ACTIVE_CHILD: Mutex<Option<Child>> = Mutex::new(None);
/// Hashcat's stdin, kept open so its native `p` key can pause/resume it.
static ACTIVE_STDIN: Mutex<Option<std::process::ChildStdin>> = Mutex::new(None);
/// Which engine is currently running, so pause/resume picks the right action.
static ACTIVE_SOURCE: Mutex<Option<ProgressSource>> = Mutex::new(None);
/// Set when the user cancels; `recover` checks it between engine runs.
static CANCELLED: AtomicBool = AtomicBool::new(false);

/// Live progress pushed to the UI while an engine runs. Every field is
/// optional: Hashcat exposes tried/total/percent/speed/candidate/eta, John
/// only percent and speed, and nothing reports all of them.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryProgress {
    /// Candidates tested so far (Hashcat's `Progress` line).
    pub tried: Option<u64>,
    /// Total candidates in the attack (Hashcat's `Progress` line).
    pub total: Option<u64>,
    /// Completion as 0..100 (Hashcat `Progress`, John percentage).
    pub percent: Option<f64>,
    /// Candidate rate as printed by the engine (e.g. `1.2 MH/s`).
    pub speed: Option<String>,
    /// The candidate currently being tested, when the engine reports it.
    pub candidate: Option<String>,
    /// Estimated time remaining, as printed by the engine.
    pub eta: Option<String>,
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
            return RecoverResult::error(
                "This password hash could not be read by the recovery engine.",
            )
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

    // Collect the exact command lines invoked so the UI can log them for
    // debugging (in addition to the live structured log in spawn_tracked).
    let mut commands: Vec<String> = Vec::new();

    // Hashcat first when this hash has a supported mode.
    if let Some(mode) = normalized.hashcat_mode {
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
                    record_history(history_dir, &request, &normalized, "hashcat", &password);
                    return ok_result(password, &commands);
                }
                HashcatOutcome::NotFound => return not_found(&commands),
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
            let display_name = john_login_name(normalized.filename.as_deref());
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
                &display_name,
                sink.clone(),
                &mut commands,
            ) {
                JohnOutcome::Cracked(password) => {
                    record_history(history_dir, &request, &normalized, "john", &password);
                    return ok_result(password, &commands);
                }
                JohnOutcome::NotFound => return not_found(&commands),
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
    let contents = std::fs::read_to_string(wordlist).ok()?;
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
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    {
        let mut guard = ACTIVE_CHILD.lock().unwrap();
        *guard = Some(child);
    }
    *ACTIVE_STDIN.lock().unwrap() = stdin;
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
    *ACTIVE_STDIN.lock().unwrap() = None;
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
                last.speed = Some(value.to_string());
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
fn parse_hashcat_frac(value: &str, last: &mut RecoveryProgress) {
    if let Some((tried, rest)) = value.split_once('/') {
        if let Ok(t) = tried.trim().parse() {
            last.tried = Some(t);
        }
        if let Ok(t) = rest.split_whitespace().next().unwrap_or("").parse() {
            last.total = Some(t);
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

/// Parse one John progress line (`--progress-every`): a word like
/// `0g 0:00:00:07 0.00% (g/s: 5.4M)`. John only reports percentage and speed.
fn parse_john_progress(line: &str, last: &mut RecoveryProgress) -> bool {
    let mut updated = false;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if let Some(pct) = tokens.get(2).and_then(|t| t.strip_suffix('%')) {
        if let Ok(p) = pct.parse::<f64>() {
            last.percent = Some(p);
            updated = true;
        }
    }
    if let Some(idx) = line.find("g/s:") {
        if let Some(speed) = line[idx + 4..].split_whitespace().next() {
            last.speed = Some(speed.trim_end_matches([')', ',']).to_string());
            updated = true;
        }
    }
    updated
}

/// Pause the running engine. Hashcat pauses natively when `p` is sent to its
/// stdin; John is suspended with an OS signal (SIGSTOP / NtSuspendProcess).
pub fn pause_recovery() {
    match *ACTIVE_SOURCE.lock().unwrap() {
        Some(ProgressSource::Hashcat) => write_stdin(b"p"),
        Some(ProgressSource::John) => suspend_active(),
        None => {}
    }
}

/// Resume a paused engine.
pub fn resume_recovery() {
    match *ACTIVE_SOURCE.lock().unwrap() {
        Some(ProgressSource::Hashcat) => write_stdin(b"p"),
        Some(ProgressSource::John) => resume_active(),
        None => {}
    }
}

fn write_stdin(data: &[u8]) {
    if let Ok(mut guard) = ACTIVE_STDIN.lock() {
        if let Some(stdin) = guard.as_mut() {
            let _ = stdin.write_all(data);
        }
    }
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
        assert_eq!(p.speed.as_deref(), Some("1.2 MH/s"));
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
    fn john_progress_is_parsed() {
        let mut p = RecoveryProgress::default();
        assert!(parse_john_progress(
            "0g 0:00:00:07 0.00% (g/s: 5.4M)",
            &mut p
        ));
        assert_eq!(p.percent, Some(0.0));
        assert_eq!(p.speed.as_deref(), Some("5.4M"));
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
        };
        let normalized = normalizer::normalize_hash(&request.hash).unwrap();
        record_history(Some(&dir), &request, &normalized, "hashcat", "password123");
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

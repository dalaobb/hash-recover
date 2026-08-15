//! Shared contract for per-format hash extractor programs.
//!
//! Every extractor is a self-contained native binary with a machine-readable
//! CLI:
//!
//! - `extractor <file>`
//! - stdout: John/Hashcat-compatible hash lines, one per line
//! - stderr: human-readable errors only
//! - exit codes: 0 ok, 1 usage, 2 unsupported file, 3 extraction failed

use std::fmt;
use std::io::Write;
use std::path::Path;

pub const EXIT_OK: u8 = 0;
pub const EXIT_USAGE: u8 = 1;
pub const EXIT_UNSUPPORTED: u8 = 2;
pub const EXIT_EXTRACT_FAILED: u8 = 3;

/// Errors produced during extraction. Exit code is derived from the variant.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Unsupported(String),
    Extract(String),
    InvalidHash(String),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Io(_) | Error::Extract(_) | Error::InvalidHash(_) => EXIT_EXTRACT_FAILED,
            Error::Unsupported(_) => EXIT_UNSUPPORTED,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Extract(m) => write!(f, "extraction failed: {m}"),
            Error::InvalidHash(m) => write!(f, "invalid hash: {m}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// One John/Hashcat-compatible hash line: `<filename>:<hash>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLine {
    pub filename: String,
    pub hash: String,
}

impl HashLine {
    pub fn render(&self) -> String {
        format!("{}:{}", self.filename, self.hash)
    }
}

impl fmt::Display for HashLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.filename, self.hash)
    }
}

/// Contract every format extractor implements.
pub trait HashExtractor {
    /// Format id from the registry, e.g. `pdf`, `office`.
    fn format_id(&self) -> &'static str;

    /// Content-signature check. Must not require a full parse.
    fn detect(&self, data: &[u8]) -> bool;

    /// Produce John/Hashcat-compatible hash lines for the input file.
    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error>;

    /// Structural validation of a produced hash line.
    fn validate(&self, line: &HashLine) -> bool {
        line.hash.starts_with(&format!("${}$", self.format_id()))
    }
}

/// Shared CLI harness used by every extractor binary.
pub fn run_extractor<E: HashExtractor>(extractor: &E) -> u8 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!(
            "usage: {} <file>",
            args.first().map(|s| s.as_str()).unwrap_or("extractor")
        );
        return EXIT_USAGE;
    }
    let path = Path::new(&args[1]);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error reading {}: {e}", args[1]);
            return EXIT_EXTRACT_FAILED;
        }
    };
    if !extractor.detect(&data) {
        eprintln!("unsupported file: {}", args[1]);
        return EXIT_UNSUPPORTED;
    }
    match extractor.extract(path) {
        Ok(lines) => {
            if lines.is_empty() {
                eprintln!("no recoverable hash found in {}", args[1]);
                return EXIT_EXTRACT_FAILED;
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for line in &lines {
                if !extractor.validate(line) {
                    eprintln!("generated hash failed validation: {}", line.render());
                    return EXIT_EXTRACT_FAILED;
                }
                if writeln!(out, "{}", line.render()).is_err() {
                    return EXIT_EXTRACT_FAILED;
                }
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("{e}");
            e.exit_code()
        }
    }
}

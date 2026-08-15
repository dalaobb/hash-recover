//! Hash normalization layer.
//!
//! Extractors emit John/Hashcat-compatible hash lines (`<filename>:<hash>`).
//! Before a hash reaches a recovery engine it passes through here so we can:
//!
//! - strip the leading `filename:` prefix,
//! - validate the hash shape for its format family,
//! - pick the Hashcat mode, and
//! - decide which engine should run it (Hashcat where a mode exists, John
//!   otherwise, e.g. PDF variants Hashcat cannot handle).
//!
//! The normalizer never runs a process; it is a pure mapping with tests.

/// Which recovery engine should attempt this hash first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Hashcat is preferred for this hash.
    Hashcat,
    /// Only John can handle this hash.
    John,
}

/// A hash normalized for the recovery engine layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHash {
    /// Bare hash without any `filename:` prefix.
    pub hash: String,
    /// Leading filename prefix, when the extractor emitted one.
    pub filename: Option<String>,
    /// Hashcat mode for this hash, if a supported mode exists.
    pub hashcat_mode: Option<u32>,
    /// John format name for this hash, when John can handle it.
    pub john_format: Option<&'static str>,
    /// Engine that should run first.
    pub engine: Engine,
}

/// The input is not a recognized HashRecover hash.
#[derive(Debug)]
pub struct NormalizeError;

const JOHN_FORMAT_PDF: &str = "pdf";
const JOHN_FORMAT_OFFICE: &str = "office";
const JOHN_FORMAT_OLDOFFICE: &str = "oldoffice";
const JOHN_FORMAT_ZIP: &str = "zip";
const JOHN_FORMAT_RAR: &str = "rar";
const JOHN_FORMAT_7Z: &str = "7z";

/// Split a hash line into its optional `filename:` prefix and the hash body.
/// Extractor output is `name:$hash$...`; the hash itself never contains `:`.
///
/// The separator is the first `:` whose remainder begins with `$`, so Windows
/// drive letters (`C:\...`) and colons inside filenames are handled too.
fn split_filename(input: &str) -> (Option<String>, &str) {
    for (i, c) in input.char_indices() {
        if c == ':' {
            let rest = input[i + 1..].trim_start();
            if rest.starts_with('$') {
                let filename = input[..i].trim();
                return (Some(filename.to_string()), rest);
            }
        }
    }
    (None, input)
}

/// The tag between the leading `$` and the next `$`, e.g. "pdf", "oldoffice".
fn tag(hash: &str) -> Option<&str> {
    let rest = hash.strip_prefix('$')?;
    let end = rest.find('$')?;
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

/// The fields after the closing tag, e.g. `["2", "3", "128", ...]`.
fn fields(hash: &str) -> Option<Vec<&str>> {
    let rest = hash.strip_prefix('$')?;
    let end = rest.find('$')?;
    let body = &rest[end + 1..];
    Some(body.split('*').collect())
}

/// Normalize a hash line. Unknown or malformed hashes yield `NormalizeError`.
pub fn normalize_hash(input: &str) -> Result<NormalizedHash, NormalizeError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NormalizeError);
    }
    let (filename, hash) = split_filename(trimmed);

    let t = tag(hash).ok_or(NormalizeError)?;
    let fields = fields(hash).ok_or(NormalizeError)?;

    let (hashcat_mode, john_format) = match t {
        "pdf" => normalize_pdf(&fields)?,
        "office" => normalize_office(&fields)?,
        "oldoffice" => normalize_oldoffice(&fields)?,
        "zip2" => (Some(17200), Some(JOHN_FORMAT_ZIP)),
        "zip3" => (Some(17220), Some(JOHN_FORMAT_ZIP)),
        "rar3" | "RAR3" => (Some(12500), Some(JOHN_FORMAT_RAR)),
        "rar5" | "RAR5" => (Some(13000), Some(JOHN_FORMAT_RAR)),
        "7z" => (Some(11600), Some(JOHN_FORMAT_7Z)),
        _ => return Err(NormalizeError),
    };

    Ok(NormalizedHash {
        hash: hash.to_string(),
        filename,
        hashcat_mode,
        john_format,
        engine: if hashcat_mode.is_some() {
            Engine::Hashcat
        } else {
            Engine::John
        },
    })
}

/// PDF hashes are `$pdf$<V>*<R>*...`. The Hashcat mode is keyed by the pair:
///
/// | V   | R   | Encryption   | Hashcat | John |
/// | --- | --- | ------------ | ------- | ---- |
/// | 1   | 2   | RC4-40       | 10400   | pdf  |
/// | 2   | 3   | RC4-128      | 10500   | pdf  |
/// | 4   | 4   | AES-128      | -       | pdf  |
/// | 5   | 5   | AES-256 (L3) | 10600   | pdf  |
/// | 5   | 6   | AES-256 (L8) | 10700   | pdf  |
///
/// AES-128 (V=4) has no Hashcat mode and is handed to John. Any pair outside
/// this table is malformed and rejected.
fn normalize_pdf(fields: &[&str]) -> Result<(Option<u32>, Option<&'static str>), NormalizeError> {
    if fields.len() < 2 {
        return Err(NormalizeError);
    }
    let v: u32 = fields[0].parse().map_err(|_| NormalizeError)?;
    let r: u32 = fields[1].parse().map_err(|_| NormalizeError)?;
    let mode = match (v, r) {
        (1, 2) => 10400,
        (2, 3) => 10500,
        (5, 5) => 10600,
        (5, 6) => 10700,
        (4, 4) => {
            // AES-128: no Hashcat mode, John only.
            return Ok((None, Some(JOHN_FORMAT_PDF)));
        }
        _ => return Err(NormalizeError),
    };
    Ok((Some(mode), Some(JOHN_FORMAT_PDF)))
}

/// Agile OOXML hashes are `$office$*<version>*...`. Versions map to the
/// Hashcat 9400/9500/9600 family; anything newer than 2013 shares the 2013
/// algorithm. The `$office$` tag is followed by a `*`, so the first field is
/// the empty string and the version is the first non-empty field.
fn normalize_office(
    fields: &[&str],
) -> Result<(Option<u32>, Option<&'static str>), NormalizeError> {
    let version: u32 = fields
        .iter()
        .find(|f| !f.is_empty())
        .ok_or(NormalizeError)?
        .parse()
        .map_err(|_| NormalizeError)?;
    let mode = match version {
        2007 => 9400,
        2010 => 9500,
        2013.. => 9600,
        _ => return Err(NormalizeError),
    };
    Ok((Some(mode), Some(JOHN_FORMAT_OFFICE)))
}

/// Legacy binary Office hashes are `$oldoffice$<typ>*...`. Hashcat covers the
/// MD5+RC4 (`$0`/`$1`) and SHA1+RC4 (`$3`/`$4`) families; `$5`/`$6`
/// (SHA-512+RC4) are John-only.
fn normalize_oldoffice(
    fields: &[&str],
) -> Result<(Option<u32>, Option<&'static str>), NormalizeError> {
    let typ: u32 = fields
        .iter()
        .find(|f| !f.is_empty())
        .ok_or(NormalizeError)?
        .parse()
        .map_err(|_| NormalizeError)?;
    let mode = match typ {
        0 | 1 => 9700,
        3 | 4 => 9800,
        5 | 6 => return Ok((None, Some(JOHN_FORMAT_OLDOFFICE))),
        _ => return Err(NormalizeError),
    };
    Ok((Some(mode), Some(JOHN_FORMAT_OLDOFFICE)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_filename_prefix() {
        let n = normalize_hash("rc4.pdf:$pdf$2*3*128*1*2*3").unwrap();
        assert_eq!(n.filename.as_deref(), Some("rc4.pdf"));
        assert_eq!(n.hash, "$pdf$2*3*128*1*2*3");
    }

    #[test]
    fn strips_windows_drive_letter_prefix() {
        let n = normalize_hash("C:\\Users\\me\\Desktop\\a.pdf:$pdf$2*3*128*1*2*3").unwrap();
        assert_eq!(n.filename.as_deref(), Some("C:\\Users\\me\\Desktop\\a.pdf"));
        assert_eq!(n.hash, "$pdf$2*3*128*1*2*3");
    }

    #[test]
    fn handles_colons_inside_filenames() {
        let n = normalize_hash("/tmp/weird:name.pdf:$pdf$5*6*256*..").unwrap();
        assert_eq!(n.filename.as_deref(), Some("/tmp/weird:name.pdf"));
        assert_eq!(n.hash, "$pdf$5*6*256*..");
    }

    #[test]
    fn bare_hash_has_no_filename() {
        let n = normalize_hash("$pdf$5*6*256*-1028*1*16*00*00*00").unwrap();
        assert_eq!(n.filename, None);
    }

    #[test]
    fn pdf_modes_are_keyed_by_v_and_r() {
        assert_eq!(
            normalize_hash("$pdf$1*2*40*...").unwrap().hashcat_mode,
            Some(10400)
        );
        assert_eq!(
            normalize_hash("$pdf$2*3*128*...").unwrap().hashcat_mode,
            Some(10500)
        );
        assert_eq!(
            normalize_hash("$pdf$5*5*256*...").unwrap().hashcat_mode,
            Some(10600)
        );
        assert_eq!(
            normalize_hash("$pdf$5*6*256*...").unwrap().hashcat_mode,
            Some(10700)
        );
    }

    #[test]
    fn pdf_aes128_is_john_only() {
        let n = normalize_hash("$pdf$4*4*128*...").unwrap();
        assert_eq!(n.engine, Engine::John);
        assert_eq!(n.hashcat_mode, None);
        assert_eq!(n.john_format, Some("pdf"));
    }

    #[test]
    fn pdf_malformed_vr_is_rejected() {
        assert!(normalize_hash("$pdf$0*0*...").is_err());
        assert!(normalize_hash("$pdf$2*9*...").is_err());
        assert!(normalize_hash("$pdf$x*y*...").is_err());
        assert!(normalize_hash("$pdf$2").is_err());
    }

    #[test]
    fn office_versions_map_to_agile_modes() {
        assert_eq!(
            normalize_hash("$office$*2007*20*128*16*..")
                .unwrap()
                .hashcat_mode,
            Some(9400)
        );
        assert_eq!(
            normalize_hash("$office$*2010*100000*128*16*..")
                .unwrap()
                .hashcat_mode,
            Some(9500)
        );
        assert_eq!(
            normalize_hash("$office$*2013*100000*256*16*..")
                .unwrap()
                .hashcat_mode,
            Some(9600)
        );
        assert_eq!(
            normalize_hash("$office$*2016*100000*256*16*..")
                .unwrap()
                .hashcat_mode,
            Some(9600)
        );
        assert!(normalize_hash("$office$*2006*...").is_err());
    }

    #[test]
    fn oldoffice_types_map_to_legacy_modes() {
        assert_eq!(
            normalize_hash("$oldoffice$0*...").unwrap().hashcat_mode,
            Some(9700)
        );
        assert_eq!(
            normalize_hash("$oldoffice$1*...").unwrap().hashcat_mode,
            Some(9700)
        );
        assert_eq!(
            normalize_hash("$oldoffice$3*...*second")
                .unwrap()
                .hashcat_mode,
            Some(9800)
        );
        assert_eq!(
            normalize_hash("$oldoffice$4*...").unwrap().hashcat_mode,
            Some(9800)
        );
    }

    #[test]
    fn oldoffice_sha512_types_are_john_only() {
        let n = normalize_hash("$oldoffice$5*...").unwrap();
        assert_eq!(n.engine, Engine::John);
        assert_eq!(n.hashcat_mode, None);
        assert_eq!(n.john_format, Some("oldoffice"));
        let n = normalize_hash("$oldoffice$6*...").unwrap();
        assert_eq!(n.engine, Engine::John);
        assert_eq!(n.hashcat_mode, None);
    }

    #[test]
    fn archive_tags_map_to_registered_modes() {
        assert_eq!(
            normalize_hash("a.zip:$zip2$*0*...").unwrap().hashcat_mode,
            Some(17200)
        );
        assert_eq!(
            normalize_hash("$zip3$*0*...").unwrap().hashcat_mode,
            Some(17220)
        );
        assert_eq!(
            normalize_hash("$rar3$*0*...").unwrap().hashcat_mode,
            Some(12500)
        );
        assert_eq!(
            normalize_hash("$rar5$*0*...").unwrap().hashcat_mode,
            Some(13000)
        );
        assert_eq!(
            normalize_hash("$7z$*0*...").unwrap().hashcat_mode,
            Some(11600)
        );
    }

    #[test]
    fn unknown_tags_are_rejected() {
        assert!(normalize_hash("$crypto$*...").is_err());
        assert!(normalize_hash("plain text").is_err());
        assert!(normalize_hash("").is_err());
        assert!(normalize_hash("not:$a$b").is_err());
    }
}

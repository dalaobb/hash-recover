//! Content-signature file analysis.
//!
//! The analyzer checks the file header against the families supported by the
//! active variant and reports a friendly result. It never guesses from the
//! file extension, and it never surfaces raw parser errors to the user.

use serde::Serialize;

use crate::formats::{Family, ACTIVE_VARIANT};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResult {
    /// True when the file matches a format this edition supports.
    pub ok: bool,
    /// Detected family id (e.g. "office", "pdf"), when identified.
    pub format_id: Option<&'static str>,
    /// Friendly detected-family label.
    pub format_label: Option<&'static str>,
    /// User-facing explanation when `ok` is false.
    pub message: Option<&'static str>,
}

/// Detect the file family from its content signature.
pub fn detect_family(data: &[u8]) -> Option<Family> {
    [
        Family::Zip,
        Family::Rar,
        Family::SevenZ,
        Family::Pdf,
        Family::Office,
    ]
    .into_iter()
    .find(|f| f.detect(data))
}

/// Analyze a file's contents against the active variant's supported formats.
pub fn analyze(data: &[u8]) -> AnalyzeResult {
    let Some(family) = detect_family(data) else {
        return AnalyzeResult {
            ok: false,
            format_id: None,
            format_label: None,
            message: Some("This file type is not supported by HashRecover."),
        };
    };

    if !ACTIVE_VARIANT.supports_family(family) {
        return AnalyzeResult {
            ok: false,
            format_id: Some(family.id()),
            format_label: Some(family.label()),
            message: Some("This format is not included in your edition of HashRecover."),
        };
    }

    AnalyzeResult {
        ok: true,
        format_id: Some(family.id()),
        format_label: Some(family.label()),
        message: None,
    }
}

impl AnalyzeResult {
    pub fn read_error() -> AnalyzeResult {
        AnalyzeResult {
            ok: false,
            format_id: None,
            format_label: None,
            message: Some("Could not read this file. It may have been moved or deleted."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_every_signature() {
        assert_eq!(detect_family(b"PK\x03\x04rest"), Some(Family::Zip));
        assert_eq!(detect_family(b"Rar!\x1a\x07\x00more"), Some(Family::Rar));
        assert_eq!(
            detect_family(b"7z\xbc\xaf\x27\x1cmore"),
            Some(Family::SevenZ)
        );
        assert_eq!(detect_family(b"%PDF-1.7"), Some(Family::Pdf));
        assert_eq!(
            detect_family(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
            Some(Family::Office)
        );
    }

    #[test]
    fn rejects_unknown_content() {
        assert_eq!(detect_family(b"not a real file"), None);
        assert_eq!(detect_family(&[]), None);
    }

    #[test]
    fn analyze_unknown_file_is_friendly() {
        let result = analyze(b"nothing here");
        assert!(!result.ok);
        assert!(result.message.is_some());
        assert!(result.format_id.is_none());
    }

    #[test]
    fn unsupported_family_reports_edition() {
        let all_families = [
            Family::Zip,
            Family::Rar,
            Family::SevenZ,
            Family::Pdf,
            Family::Office,
        ];
        let unsupported: Vec<Family> = all_families
            .into_iter()
            .filter(|f| !ACTIVE_VARIANT.supports_family(*f))
            .collect();
        if unsupported.is_empty() {
            // This build ships every family; nothing is out of edition.
            for family in all_families {
                assert!(analyze(&magic(family)).ok);
            }
        } else {
            for family in unsupported {
                let result = analyze(&magic(family));
                assert!(!result.ok);
                assert_eq!(result.format_id, Some(family.id()));
                assert!(result.message.is_some());
            }
        }
    }

    #[test]
    fn analyze_supported_family_succeeds() {
        for family in ACTIVE_VARIANT.formats().iter().map(|f| f.family()) {
            let result = analyze(&magic(family));
            assert!(result.ok, "{} should be accepted", family.id());
            assert_eq!(result.format_id, Some(family.id()));
        }
    }

    fn magic(family: Family) -> Vec<u8> {
        let mut data = match family {
            Family::Zip => b"PK\x03\x04".to_vec(),
            Family::Rar => b"Rar!\x1a\x07\x00".to_vec(),
            Family::SevenZ => b"7z\xbc\xaf\x27\x1c".to_vec(),
            Family::Pdf => b"%PDF-".to_vec(),
            Family::Office => vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
        };
        data.extend_from_slice(b"payload");
        data
    }
}

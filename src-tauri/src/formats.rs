//! Format registry and product-variant configuration.
//!
//! This is the single source of truth for what a HashRecover build supports.
//! The active product variant is selected at compile time via the
//! `HASHRECOVER_VARIANT` environment variable (see `scripts/build-variant.mjs`
//! and `build.rs`). Every build ships the formats its variant allows; the
//! frontend derives its file picker filters and visible cards from
//! `get_app_config()`, never from a hardcoded list.

use serde::Serialize;

/// Formats the application can recover passwords for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatId {
    Zip,
    Rar,
    SevenZ,
    Pdf,
    Word,
    Excel,
    PowerPoint,
}

impl FormatId {
    pub fn id(self) -> &'static str {
        match self {
            FormatId::Zip => "zip",
            FormatId::Rar => "rar",
            FormatId::SevenZ => "7z",
            FormatId::Pdf => "pdf",
            FormatId::Word => "word",
            FormatId::Excel => "excel",
            FormatId::PowerPoint => "powerpoint",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FormatId::Zip => "ZIP",
            FormatId::Rar => "RAR",
            FormatId::SevenZ => "7-Zip",
            FormatId::Pdf => "PDF",
            FormatId::Word => "Word",
            FormatId::Excel => "Excel",
            FormatId::PowerPoint => "PowerPoint",
        }
    }

    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            FormatId::Zip => &["zip"],
            FormatId::Rar => &["rar"],
            FormatId::SevenZ => &["7z"],
            FormatId::Pdf => &["pdf"],
            FormatId::Word => &["doc", "docx"],
            FormatId::Excel => &["xls", "xlsx"],
            FormatId::PowerPoint => &["ppt", "pptx"],
        }
    }

    /// Bundled native extractor program that handles this format.
    pub fn extractor(self) -> &'static str {
        match self {
            FormatId::Zip => "zip-extractor",
            FormatId::Rar => "rar-extractor",
            FormatId::SevenZ => "sevenz-extractor",
            FormatId::Pdf => "pdf-extractor",
            FormatId::Word | FormatId::Excel | FormatId::PowerPoint => "office-extractor",
        }
    }

    /// Detection family. Multiple formats share one family when they use the
    /// same container (encrypted OOXML and legacy binary Office files are all
    /// OLE compound documents).
    pub fn family(self) -> Family {
        match self {
            FormatId::Zip => Family::Zip,
            FormatId::Rar => Family::Rar,
            FormatId::SevenZ => Family::SevenZ,
            FormatId::Pdf => Family::Pdf,
            FormatId::Word | FormatId::Excel | FormatId::PowerPoint => Family::Office,
        }
    }
}

/// A file family recognized by content signature. Several format ids may map
/// to one family (word/excel/powerpoint share the OLE container).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Zip,
    Rar,
    SevenZ,
    Pdf,
    Office,
}

impl Family {
    pub fn id(self) -> &'static str {
        match self {
            Family::Zip => "zip",
            Family::Rar => "rar",
            Family::SevenZ => "7z",
            Family::Pdf => "pdf",
            Family::Office => "office",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Family::Zip => "ZIP archive",
            Family::Rar => "RAR archive",
            Family::SevenZ => "7-Zip archive",
            Family::Pdf => "PDF document",
            Family::Office => "Office document",
        }
    }

    /// Content-signature check; extractors identify files by these same bytes.
    pub fn detect(self, data: &[u8]) -> bool {
        match self {
            Family::Zip => {
                data.starts_with(b"PK\x03\x04")
                    || data.starts_with(b"PK\x05\x06")
                    || data.starts_with(b"PK\x07\x08")
            }
            Family::Rar => {
                data.starts_with(b"Rar!\x1a\x07\x00") || data.starts_with(b"Rar!\x1a\x07\x01\x00")
            }
            Family::SevenZ => data.starts_with(b"7z\xbc\xaf\x27\x1c"),
            Family::Pdf => data.starts_with(b"%PDF-"),
            Family::Office => data.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
        }
    }

    /// Native extractor program that handles this family.
    pub fn extractor(self) -> &'static str {
        match self {
            Family::Zip => "zip-extractor",
            Family::Rar => "rar-extractor",
            Family::SevenZ => "sevenz-extractor",
            Family::Pdf => "pdf-extractor",
            Family::Office => "office-extractor",
        }
    }
}

/// Product variants. Each bundles only the engine programs its formats need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Every variant is defined here regardless of the active build; which one is
// reachable is decided at compile time, so the rest are intentionally unused.
#[allow(dead_code)]
pub enum Variant {
    Zip,
    Rar,
    SevenZ,
    Pdf,
    Word,
    Excel,
    PowerPoint,
    Office,
    All,
}

impl Variant {
    pub fn id(self) -> &'static str {
        match self {
            Variant::Zip => "zip",
            Variant::Rar => "rar",
            Variant::SevenZ => "sevenz",
            Variant::Pdf => "pdf",
            Variant::Word => "word",
            Variant::Excel => "excel",
            Variant::PowerPoint => "powerpoint",
            Variant::Office => "office",
            Variant::All => "all",
        }
    }

    pub fn product_name(self) -> &'static str {
        match self {
            Variant::Zip => "HashRecover for ZIP",
            Variant::Rar => "HashRecover for RAR",
            Variant::SevenZ => "HashRecover for 7z",
            Variant::Pdf => "HashRecover for PDF",
            Variant::Word => "HashRecover for Word",
            Variant::Excel => "HashRecover for Excel",
            Variant::PowerPoint => "HashRecover for PowerPoint",
            Variant::Office => "HashRecover for Office",
            Variant::All => "HashRecover All",
        }
    }

    pub fn formats(self) -> &'static [FormatId] {
        match self {
            Variant::Zip => &[FormatId::Zip],
            Variant::Rar => &[FormatId::Rar],
            Variant::SevenZ => &[FormatId::SevenZ],
            Variant::Pdf => &[FormatId::Pdf],
            Variant::Word => &[FormatId::Word],
            Variant::Excel => &[FormatId::Excel],
            Variant::PowerPoint => &[FormatId::PowerPoint],
            Variant::Office => &[FormatId::Word, FormatId::Excel, FormatId::PowerPoint],
            Variant::All => &[
                FormatId::Zip,
                FormatId::Rar,
                FormatId::SevenZ,
                FormatId::Pdf,
                FormatId::Word,
                FormatId::Excel,
                FormatId::PowerPoint,
            ],
        }
    }

    /// Unique bundled extractor programs for this variant.
    pub fn extractors(self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();
        for format in self.formats() {
            let extractor = format.extractor();
            if !names.contains(&extractor) {
                names.push(extractor);
            }
        }
        names
    }

    pub fn supports_family(self, family: Family) -> bool {
        self.formats().iter().any(|f| f.family() == family)
    }
}

/// Active variant for this build, selected at compile time.
#[cfg(hasrecover_variant = "zip")]
pub const ACTIVE_VARIANT: Variant = Variant::Zip;
#[cfg(hasrecover_variant = "rar")]
pub const ACTIVE_VARIANT: Variant = Variant::Rar;
#[cfg(hasrecover_variant = "sevenz")]
pub const ACTIVE_VARIANT: Variant = Variant::SevenZ;
#[cfg(hasrecover_variant = "pdf")]
pub const ACTIVE_VARIANT: Variant = Variant::Pdf;
#[cfg(hasrecover_variant = "word")]
pub const ACTIVE_VARIANT: Variant = Variant::Word;
#[cfg(hasrecover_variant = "excel")]
pub const ACTIVE_VARIANT: Variant = Variant::Excel;
#[cfg(hasrecover_variant = "powerpoint")]
pub const ACTIVE_VARIANT: Variant = Variant::PowerPoint;
#[cfg(hasrecover_variant = "office")]
pub const ACTIVE_VARIANT: Variant = Variant::Office;
#[cfg(hasrecover_variant = "all")]
pub const ACTIVE_VARIANT: Variant = Variant::All;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatInfo {
    id: &'static str,
    label: &'static str,
    extensions: Vec<&'static str>,
    extractor: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    variant: &'static str,
    product_name: &'static str,
    formats: Vec<FormatInfo>,
    extractors: Vec<&'static str>,
}

/// Configuration snapshot exposed to the frontend through `get_app_config()`.
pub fn app_config() -> AppConfig {
    let variant = ACTIVE_VARIANT;
    AppConfig {
        variant: variant.id(),
        product_name: variant.product_name(),
        formats: variant
            .formats()
            .iter()
            .map(|&f| FormatInfo {
                id: f.id(),
                label: f.label(),
                extensions: f.extensions().to_vec(),
                extractor: f.extractor(),
            })
            .collect(),
        extractors: variant.extractors(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variant_covers_every_format() {
        let all: Vec<&str> = Variant::All.formats().iter().map(|f| f.id()).collect();
        assert_eq!(all.len(), 7);
        for format in [
            FormatId::Zip,
            FormatId::Rar,
            FormatId::SevenZ,
            FormatId::Pdf,
            FormatId::Word,
            FormatId::Excel,
            FormatId::PowerPoint,
        ] {
            assert!(
                all.contains(&format.id()),
                "{} missing from all",
                format.id()
            );
        }
    }

    #[test]
    fn office_variant_shares_one_extractor() {
        let extractors = Variant::Office.extractors();
        assert_eq!(extractors, vec!["office-extractor"]);
    }

    #[test]
    fn every_format_has_distinct_extensions() {
        for a in [
            FormatId::Zip,
            FormatId::Rar,
            FormatId::SevenZ,
            FormatId::Pdf,
            FormatId::Word,
            FormatId::Excel,
            FormatId::PowerPoint,
        ] {
            for b in [
                FormatId::Zip,
                FormatId::Rar,
                FormatId::SevenZ,
                FormatId::Pdf,
                FormatId::Word,
                FormatId::Excel,
                FormatId::PowerPoint,
            ] {
                if a != b {
                    for ea in a.extensions() {
                        assert!(
                            !b.extensions().contains(ea),
                            "{ea} claimed by both {} and {}",
                            a.id(),
                            b.id()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn active_variant_is_valid() {
        assert!(!ACTIVE_VARIANT.formats().is_empty());
        assert!(!ACTIVE_VARIANT.extractors().is_empty());
    }
}

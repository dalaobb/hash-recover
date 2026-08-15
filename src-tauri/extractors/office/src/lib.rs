//! Native Rust port of office2john.
//!
//! Reference implementation: openwall/john `run/office2john.py`.
//! Covers word (doc), excel (xls), powerpoint (ppt) legacy binary formats and
//! the encrypted OOXML containers (docx/xlsx/pptx, stored as OLE CFB with an
//! EncryptionInfo stream). Plain OOXML zip packages are not encrypted.

use extractor_core::{Error, HashExtractor, HashLine};
use std::path::Path;

mod legacy;
mod newoffice;
mod ole;

pub struct OfficeExtractor;

impl HashExtractor for OfficeExtractor {
    fn format_id(&self) -> &'static str {
        "office"
    }

    fn detect(&self, data: &[u8]) -> bool {
        // Encrypted Office files (legacy binary and encrypted OOXML) are OLE
        // compound files. Plain OOXML is a zip container, which we reject.
        data.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    }

    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error> {
        let mut file = cfb::open(path)?;
        let lines = dispatch(&mut file, path)?;
        Ok(vec![lines])
    }

    fn validate(&self, line: &HashLine) -> bool {
        line.hash.starts_with("$office$") || line.hash.starts_with("$oldoffice$")
    }
}

fn dispatch(file: &mut cfb::CompoundFile<std::fs::File>, path: &Path) -> Result<HashLine, Error> {
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    // New Office (2007+) formats: an EncryptionInfo stream is present.
    if ole::has_stream(file, "/EncryptionInfo") {
        return newoffice::process(file, filename);
    }

    if ole::has_stream(file, "/Workbook") || ole::has_stream(file, "/Book") {
        return legacy::process_xls(file, filename);
    }

    if ole::has_stream(file, "/WordDocument") {
        return legacy::process_doc(file, filename);
    }

    if ole::has_stream(file, "/PowerPoint Document") {
        return legacy::process_ppt(file, filename);
    }

    Err(Error::Unsupported(
        "no supported Office streams found".into(),
    ))
}

fn hash_line(filename: String, hash: String) -> HashLine {
    HashLine { filename, hash }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn extract_hash(name: &str) -> String {
        let extractor = OfficeExtractor;
        let lines = extractor
            .extract(&fixture(name))
            .expect("extraction should succeed");
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(extractor.validate(line));
        line.hash.clone()
    }

    #[test]
    fn detect_accepts_ole_and_rejects_zip() {
        let extractor = OfficeExtractor;
        assert!(extractor.detect(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]));
        assert!(!extractor.detect(b"PK\x03\x04 not an encrypted office file"));
        assert!(!extractor.detect(b"garbage"));
    }

    fn reference_hash(name: &str) -> String {
        std::fs::read_to_string(fixture("reference").join(format!("{name}.hash")))
            .expect("reference hash should exist")
            .trim()
            .to_string()
    }

    #[test]
    fn extract_matches_office2john_reference() {
        for name in [
            "xls_rc4.xls",
            "xls_rc4_40.xls",
            "xls_rc4_128.xls",
            "doc_rc4.doc",
            "doc_rc4_40.doc",
            "doc_rc4_128.doc",
            "ppt_rc4_40.ppt",
            "ppt_rc4_128.ppt",
            "docx_2007_aes128.docx",
            "xlsx_2010_sha1.xlsx",
            "pptx_2013_sha512.pptx",
        ] {
            assert_eq!(
                extract_hash(name),
                reference_hash(name).split(':').nth(1).unwrap(),
                "mismatch for {name}"
            );
        }
    }

    #[test]
    fn extract_rejects_unencrypted_zip_package() {
        let extractor = OfficeExtractor;
        let path = fixture("plain.docx");
        if path.exists() {
            assert!(extractor.extract(&path).is_err());
        }
    }
}

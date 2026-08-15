//! Native Rust port of pdf2john.
//!
//! Reference implementation: openwall/john `run/pdf2john.py` (pyhanko based).
//! Output: `$pdf$<V>*<R>*<Length>*<P>*<EncryptMetadata>*<idlen>*<idhex>*[<len>*<hex>]*...`
//! where the trailing pairs are /U, /O, /OE, /UE in that order, each truncated
//! to the revision's key length (32 bytes for R2-R4, 48 bytes for R5+).

use extractor_core::{Error, HashExtractor, HashLine};
use std::collections::HashMap;
use std::path::Path;

pub struct PdfExtractor;

const MAX_HEADER_SCAN: usize = 1024;

/// Parsed /Encrypt dictionary plus document id.
#[derive(Debug, Default)]
struct EncryptionInfo {
    v: i64,
    r: i64,
    length: i64,
    p: i64,
    encrypt_metadata: bool,
    document_id: Vec<u8>,
    u: Option<Vec<u8>>,
    o: Option<Vec<u8>>,
    oe: Option<Vec<u8>>,
    ue: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Name(String),
    Str(Vec<u8>),
    Array(Vec<Val>),
    Dict(HashMap<String, Val>),
    Ref(u64),
}

impl HashExtractor for PdfExtractor {
    fn format_id(&self) -> &'static str {
        "pdf"
    }

    fn detect(&self, data: &[u8]) -> bool {
        let window = &data[..data.len().min(MAX_HEADER_SCAN)];
        window.windows(b"%PDF-".len()).any(|w| w == b"%PDF-")
    }

    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error> {
        let data = std::fs::read(path)?;
        let doc = PdfDoc::parse(&data)?;
        let info = doc.encryption_info()?;
        Ok(vec![HashLine {
            filename: path.to_string_lossy().into_owned(),
            hash: render_hash(&info),
        }])
    }
}

fn render_hash(info: &EncryptionInfo) -> String {
    let max_key_len = if info.r >= 5 { 48 } else { 32 };
    let mut passwords: Vec<String> = Vec::new();
    for value in [&info.u, &info.o, &info.oe, &info.ue].into_iter().flatten() {
        let truncated = &value[..value.len().min(max_key_len)];
        passwords.push(truncated.len().to_string());
        passwords.push(hex_encode(truncated));
    }
    let mut parts = vec![
        format!("$pdf${}", info.v),
        info.r.to_string(),
        info.length.to_string(),
        info.p.to_string(),
        if info.encrypt_metadata { "1" } else { "0" }.to_string(),
        info.document_id.len().to_string(),
        hex_encode(&info.document_id),
    ];
    parts.extend(passwords);
    parts.join("*")
}

// ---------------------------------------------------------------------------
// Minimal PDF parser
// ---------------------------------------------------------------------------

/// Lightweight PDF structural parser. It scans objects by their
/// `N G obj ... endobj` markers and locates the trailer dictionary.
struct PdfDoc {
    objects: HashMap<u64, Vec<u8>>,
    trailer: Val,
}

impl PdfDoc {
    fn parse(data: &[u8]) -> Result<PdfDoc, Error> {
        let objects = scan_objects(data);
        let trailer_pos = find_trailer(data, &objects);
        let (_pos, trailer_bytes) =
            trailer_pos.ok_or_else(|| Error::Extract("no trailer found".into()))?;
        let mut parser = Parser::new(trailer_bytes);
        let trailer = parser
            .parse_value()
            .ok_or_else(|| Error::Extract("malformed trailer".into()))?;
        Ok(PdfDoc { objects, trailer })
    }

    /// Extract /Encrypt and /ID from the trailer.
    fn encryption_info(&self) -> Result<EncryptionInfo, Error> {
        let trailer = self
            .trailer
            .as_dict()
            .ok_or_else(|| Error::Extract("trailer is not a dictionary".into()))?;

        let encrypt_val = trailer
            .get("Encrypt")
            .ok_or_else(|| Error::Extract("document is not encrypted (no /Encrypt)".into()))?;
        let encrypt = self.resolve(encrypt_val)?;
        let enc = encrypt
            .as_dict()
            .ok_or_else(|| Error::Extract("/Encrypt is not a dictionary".into()))?;

        let mut info = EncryptionInfo {
            encrypt_metadata: true,
            ..Default::default()
        };
        info.v = enc
            .get("V")
            .and_then(|v| v.as_int())
            .ok_or_else(|| Error::Extract("missing /V".into()))?;
        info.r = enc
            .get("R")
            .and_then(|v| v.as_int())
            .ok_or_else(|| Error::Extract("missing /R".into()))?;
        info.length = enc.get("Length").and_then(|v| v.as_int()).unwrap_or(40);
        info.p = enc
            .get("P")
            .and_then(|v| v.as_int())
            .ok_or_else(|| Error::Extract("missing /P".into()))?;
        if let Some(md) = enc.get("EncryptMetadata") {
            info.encrypt_metadata = md.as_bool().unwrap_or(true);
        }
        info.u = enc.get("U").and_then(|v| v.as_bytes_opt());
        info.o = enc.get("O").and_then(|v| v.as_bytes_opt());
        info.oe = enc.get("OE").and_then(|v| v.as_bytes_opt());
        info.ue = enc.get("UE").and_then(|v| v.as_bytes_opt());

        let id = trailer
            .get("ID")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_bytes_opt())
            .ok_or_else(|| Error::Extract("missing /ID in trailer".into()))?;
        info.document_id = id;

        Ok(info)
    }

    fn resolve(&self, val: &Val) -> Result<Val, Error> {
        match val {
            Val::Ref(id) => self
                .objects
                .get(id)
                .map(|content| {
                    let mut parser = Parser::new(content);
                    parser.parse_value().unwrap_or(Val::Null)
                })
                .ok_or_else(|| Error::Extract(format!("object {id} not found"))),
            other => Ok(other.clone()),
        }
    }
}

impl Val {
    fn as_dict(&self) -> Option<&HashMap<String, Val>> {
        match self {
            Val::Dict(d) => Some(d),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Val]> {
        match self {
            Val::Array(a) => Some(a),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Val::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_bytes_opt(&self) -> Option<Vec<u8>> {
        match self {
            Val::Str(b) => Some(b.clone()),
            _ => None,
        }
    }
}

/// Scan every `N G obj ... endobj` region in the file.
fn scan_objects(data: &[u8]) -> HashMap<u64, Vec<u8>> {
    let mut objects = HashMap::new();
    let mut i = 0usize;
    while i + 3 < data.len() {
        match obj_header_at(data, i) {
            Some((id, after_obj)) => {
                let end = find_bytes(data, b"endobj", after_obj).unwrap_or(data.len());
                let stream_start = find_bytes(data, b"stream", after_obj);
                let content_end = stream_start.filter(|s| *s < end).unwrap_or(end);
                if content_end > after_obj {
                    objects.insert(id, data[after_obj..content_end].to_vec());
                }
                i = if end + 6 < data.len() {
                    end + 6
                } else {
                    data.len()
                };
            }
            None => i += 1,
        }
    }
    objects
}

/// Match `\d+ \d+ obj` at `pos`; return the object id and offset after `obj`.
fn obj_header_at(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let (num1, mut i) = parse_int_at(data, pos)?;
    i = skip_ws(data, i);
    let (num2, i2) = parse_int_at(data, i)?;
    if num2 != 0 {
        return None;
    }
    let i2 = skip_ws(data, i2);
    if data.get(i2..i2 + 3) == Some(b"obj")
        && !(data.get(i2 + 3) == Some(&b'/') || is_word_char(data.get(i2 + 3)))
    {
        Some((num1 as u64, i2 + 3))
    } else {
        None
    }
}

/// Locate the trailer dictionary: the last `trailer <<...>>` in the file,
/// falling back to the first `/Type /XRef` object dictionary.
fn find_trailer<'a>(
    data: &'a [u8],
    objects: &'a HashMap<u64, Vec<u8>>,
) -> Option<(usize, &'a [u8])> {
    let mut end = data.len();
    while let Some(found) = data[..end]
        .windows(b"trailer".len())
        .rposition(|w| w == b"trailer")
    {
        let after = skip_ws(data, found + b"trailer".len());
        if data.get(after) == Some(&b'<') && data.get(after + 1) == Some(&b'<') {
            return Some((after, &data[after..]));
        }
        end = found;
    }
    // xref-stream trailer fallback
    for content in objects.values() {
        let mut parser = Parser::new(content);
        if let Some(Val::Dict(d)) = parser.parse_value() {
            if d.get("Type").and_then(|v| v.as_name_opt()) == Some("XRef") {
                return Some((0, content));
            }
        }
    }
    None
}

fn parse_int_at(data: &[u8], pos: usize) -> Option<(i64, usize)> {
    let mut i = skip_ws(data, pos);
    let start = i;
    if data.get(i) == Some(&b'-') {
        i += 1;
    }
    let digits_start = i;
    while matches!(data.get(i), Some(b'0'..=b'9')) {
        i += 1;
    }
    if i == digits_start {
        return None;
    }
    let s = std::str::from_utf8(&data[start..i]).ok()?;
    s.parse().ok().map(|v| (v, i))
}

fn skip_ws(data: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i < data.len() && data[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_word_char(b: Option<&u8>) -> bool {
    matches!(b, Some(b) if b.is_ascii_alphanumeric() || *b == b'_')
}

fn find_bytes(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Value parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Parser { data, pos: 0 }
    }

    fn parse_value(&mut self) -> Option<Val> {
        self.pos = skip_ws(self.data, self.pos);
        let c = *self.data.get(self.pos)?;
        match c {
            b'<' => {
                if self.data.get(self.pos + 1) == Some(&b'<') {
                    self.pos += 2;
                    self.parse_dict()
                } else {
                    self.parse_hex_string().map(Val::Str)
                }
            }
            b'[' => self.parse_array(),
            b'(' => self.parse_literal_string().map(Val::Str),
            b'/' => self.parse_name().map(Val::Name),
            b't' if self.data[self.pos..].starts_with(b"true") => {
                self.pos += 4;
                Some(Val::Bool(true))
            }
            b'f' if self.data[self.pos..].starts_with(b"false") => {
                self.pos += 5;
                Some(Val::Bool(false))
            }
            b'n' if self.data[self.pos..].starts_with(b"null") => {
                self.pos += 4;
                Some(Val::Null)
            }
            b'0'..=b'9' | b'-' | b'+' | b'.' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_dict(&mut self) -> Option<Val> {
        let mut dict = HashMap::new();
        loop {
            self.pos = skip_ws(self.data, self.pos);
            if self.data.get(self.pos) == Some(&b'>') && self.data.get(self.pos + 1) == Some(&b'>')
            {
                self.pos += 2;
                return Some(Val::Dict(dict));
            }
            let key = self.parse_name()?;
            self.pos = skip_ws(self.data, self.pos);
            let value = self.parse_value()?;
            dict.insert(key, value);
        }
    }

    fn parse_array(&mut self) -> Option<Val> {
        // consume '['
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.pos = skip_ws(self.data, self.pos);
            if self.data.get(self.pos) == Some(&b']') {
                self.pos += 1;
                return Some(Val::Array(items));
            }
            items.push(self.parse_value()?);
        }
    }

    fn parse_name(&mut self) -> Option<String> {
        // consume '/'
        self.pos += 1;
        let mut name = String::new();
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            if is_delimiter(c) || c.is_ascii_whitespace() {
                break;
            }
            if c == b'#' {
                let hex = self.data.get(self.pos + 1..self.pos + 3)?;
                name.push(char::from(
                    u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?,
                ));
                self.pos += 3;
            } else {
                name.push(c as char);
                self.pos += 1;
            }
        }
        Some(name)
    }

    fn parse_hex_string(&mut self) -> Option<Vec<u8>> {
        // consume '<'
        self.pos += 1;
        let mut bytes = Vec::new();
        let mut pending: Option<u8> = None;
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            self.pos += 1;
            if c == b'>' {
                if let Some(hi) = pending {
                    bytes.push(hi << 4);
                }
                return Some(bytes);
            }
            if c.is_ascii_whitespace() {
                continue;
            }
            let nibble = (c as char).to_digit(16)? as u8;
            match pending {
                None => pending = Some(nibble),
                Some(hi) => {
                    bytes.push((hi << 4) | nibble);
                    pending = None;
                }
            }
        }
        None
    }

    fn parse_literal_string(&mut self) -> Option<Vec<u8>> {
        // consume '('
        self.pos += 1;
        let mut bytes = Vec::new();
        let mut depth = 1usize;
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            match c {
                b'\\' => {
                    let esc = *self.data.get(self.pos + 1)?;
                    self.pos += 2;
                    match esc {
                        b'n' => bytes.push(b'\n'),
                        b'r' => bytes.push(b'\r'),
                        b't' => bytes.push(b'\t'),
                        b'b' => bytes.push(0x08),
                        b'f' => bytes.push(0x0c),
                        b'(' => bytes.push(b'('),
                        b')' => bytes.push(b')'),
                        b'\\' => bytes.push(b'\\'),
                        b'\r' => {
                            if self.data.get(self.pos) == Some(&b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut value = esc - b'0';
                            let mut count = 1;
                            while count < 3 && matches!(self.data.get(self.pos), Some(b'0'..=b'7'))
                            {
                                value = value * 8 + (self.data[self.pos] - b'0');
                                self.pos += 1;
                                count += 1;
                            }
                            bytes.push(value);
                        }
                        _ => bytes.push(esc),
                    }
                }
                b'(' => {
                    depth += 1;
                    bytes.push(b'(');
                    self.pos += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        return Some(bytes);
                    }
                    bytes.push(b')');
                    self.pos += 1;
                }
                b'\r' => {
                    if self.data.get(self.pos + 1) == Some(&b'\n') {
                        self.pos += 1;
                    }
                    self.pos += 1;
                }
                _ => {
                    bytes.push(c);
                    self.pos += 1;
                }
            }
        }
        None
    }

    fn parse_number(&mut self) -> Option<Val> {
        // Try integer first (and possibly a reference).
        let start = self.pos;
        let mut i = self.pos;
        if matches!(self.data.get(i), Some(b'-') | Some(b'+')) {
            i += 1;
        }
        let digits_start = i;
        while matches!(self.data.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        let is_int = i > digits_start;
        if is_int {
            // Check for reference: `int int R`
            let after_first = skip_ws(self.data, i);
            if let Some((_second, after_second)) = parse_int_at(self.data, after_first) {
                let after_second = skip_ws(self.data, after_second);
                if self.data.get(after_second) == Some(&b'R')
                    && !is_word_char(self.data.get(after_second + 1))
                {
                    self.pos = after_second + 1;
                    let first: i64 = std::str::from_utf8(&self.data[start..i])
                        .ok()?
                        .parse()
                        .ok()?;
                    return Some(Val::Ref(first as u64));
                }
            }
            let value: i64 = std::str::from_utf8(&self.data[start..i])
                .ok()?
                .parse()
                .ok()?;
            self.pos = i;
            return Some(Val::Int(value));
        }
        // Real number
        let mut i = self.pos;
        if matches!(self.data.get(i), Some(b'-') | Some(b'+')) {
            i += 1;
        }
        while matches!(self.data.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if self.data.get(i) == Some(&b'.') {
            i += 1;
            while matches!(self.data.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        if i == start || i == start + 1 && matches!(self.data.get(start), Some(b'-') | Some(b'+')) {
            return None;
        }
        let value: f64 = std::str::from_utf8(&self.data[start..i])
            .ok()?
            .parse()
            .ok()?;
        self.pos = i;
        Some(Val::Int(value as i64))
    }
}

fn is_delimiter(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

impl Val {
    fn as_name_opt(&self) -> Option<&str> {
        match self {
            Val::Name(n) => Some(n),
            _ => None,
        }
    }
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

    fn reference_hash(name: &str) -> String {
        std::fs::read_to_string(fixture("reference").join(format!("{name}.hash")))
            .unwrap_or_else(|_| {
                panic!("reference hash for {name} missing; run scripts/make_pdf_fixtures.py")
            })
            .trim()
            .to_string()
    }

    fn extract_hash(name: &str) -> String {
        let extractor = PdfExtractor;
        let lines = extractor
            .extract(&fixture(name))
            .expect("extraction should succeed");
        assert_eq!(lines.len(), 1);
        assert!(extractor.validate(&lines[0]));
        lines[0].hash.clone()
    }

    #[test]
    fn detect_accepts_encrypted_pdfs() {
        let extractor = PdfExtractor;
        for name in ["plain.pdf", "rc4.pdf", "aes128.pdf", "aes256.pdf"] {
            let data = std::fs::read(fixture(name)).unwrap();
            assert!(extractor.detect(&data), "detect failed for {name}");
        }
    }

    #[test]
    fn detect_rejects_non_pdf() {
        let extractor = PdfExtractor;
        assert!(!extractor.detect(b"PK\x03\x04 garbage"));
        assert!(!extractor.detect(b"not a pdf at all"));
    }

    #[test]
    fn extract_matches_pdf2john_reference() {
        for name in ["rc4", "aes128", "aes256"] {
            assert_eq!(
                extract_hash(&format!("{name}.pdf")),
                reference_hash(name),
                "hash mismatch for {name}"
            );
        }
    }

    #[test]
    fn extract_rejects_unencrypted() {
        let extractor = PdfExtractor;
        let err = extractor.extract(&fixture("plain.pdf")).unwrap_err();
        assert!(matches!(err, Error::Extract(_)));
    }
}

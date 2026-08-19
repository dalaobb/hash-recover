use extractor_core::{Error, HashExtractor, HashLine};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub struct RarExtractor;

// ── RAR 3 constants ──────────────────────────────────────────────────────────

const RAR3_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";

// ── RAR 5 constants ──────────────────────────────────────────────────────────

const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";

// Header types
const HEAD_MAIN: u8 = 0x01;
const HEAD_FILE: u8 = 0x02;
const HEAD_SERVICE: u8 = 0x03;
const HEAD_CRYPT: u8 = 0x04;
const HEAD_ENDARC: u8 = 0x05;

// Header flags
const HFL_EXTRA: u64 = 1;
const HFL_DATA: u64 = 2;

// File header flags
const FHFL_UTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

// Extra field types
const FHEXTRA_CRYPT: u64 = 0x01;

// Encryption flags
const FHEXTRA_CRYPT_PSWCHECK: u64 = 0x01;

// RAR5 sizes
const SIZE_SALT50: usize = 16;
const SIZE_INITV: usize = 16;
const SIZE_PSWCHECK: usize = 8;
const SIZE_PSWCHECK_CSUM: usize = 4;
const CRYPT5_KDF_LG2_COUNT_MAX: u64 = 24;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

// ── RAR 5 variable-length integer reader ─────────────────────────────────────

struct Rar5Reader<R> {
    inner: R,
}

impl<R: Read + Seek> Rar5Reader<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        self.inner.read_exact(&mut buf).map_err(|e| Error::Io(e))?;
        Ok(buf[0])
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf).map_err(|e| Error::Io(e))?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; n];
        self.inner.read_exact(&mut buf).map_err(|e| Error::Io(e))?;
        Ok(buf)
    }

    /// Read a RAR5 variable-length integer (7 bits per byte, high bit = more).
    fn read_vuint(&mut self) -> Result<u64, Error> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..10 {
            let b = self.read_u8()?;
            result += ((b & 0x7F) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Error::Extract("RAR5 vint too long".into()))
    }

    fn skip_bytes(&mut self, n: u64) -> Result<(), Error> {
        self.inner
            .seek(SeekFrom::Current(n as i64))
            .map_err(|e| Error::Io(e))?;
        Ok(())
    }

    fn position(&mut self) -> Result<u64, Error> {
        self.inner.stream_position().map_err(|e| Error::Io(e))
    }
}

// ── RAR 3 extraction ─────────────────────────────────────────────────────────

/// Extract hash from RAR3 archive (type 0: -hp mode).
///
/// For type 0, the salt and encrypted known-plaintext are in the last 24 bytes
/// of the archive (end-of-archive marker block).
fn extract_rar3(path: &Path) -> Result<Vec<HashLine>, Error> {
    let mut file = std::fs::File::open(path).map_err(|e| Error::Io(e))?;
    let file_len = file.metadata().map_err(|e| Error::Io(e))?.len();

    if file_len < RAR3_MAGIC.len() as u64 + 13 {
        return Err(Error::Extract("RAR3 file too short".into()));
    }

    // Read archive header flags to detect type 0 (hp mode).
    file.seek(SeekFrom::Start(RAR3_MAGIC.len() as u64 + 4))
        .map_err(|e| Error::Io(e))?;
    let mut hdr_buf = [0u8; 2];
    file.read_exact(&mut hdr_buf).map_err(|e| Error::Io(e))?;
    let archive_flags = u16::from_le_bytes(hdr_buf);

    if archive_flags & 0x0080 == 0 {
        return Err(Error::Unsupported(
            "RAR3 file is not encrypted with -hp mode".into(),
        ));
    }

    // Type 0: read last 24 bytes (8 salt + 16 encrypted).
    if file_len < 24 {
        return Err(Error::Extract("RAR3 file too short for hash".into()));
    }
    file.seek(SeekFrom::End(-24)).map_err(|e| Error::Io(e))?;
    let mut buf = [0u8; 24];
    file.read_exact(&mut buf).map_err(|e| Error::Io(e))?;

    let salt = hex_encode(&buf[0..8]);
    let encrypted = hex_encode(&buf[8..24]);

    let hash = format!("$rar3$*0*{salt}*{encrypted}");
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    Ok(vec![HashLine { filename, hash }])
}

// ── RAR 5 extraction ─────────────────────────────────────────────────────────

/// State carried across RAR5 header parsing.
struct Rar5State {
    salt: Option<[u8; SIZE_SALT50]>,
    lg2_count: Option<u8>,
    iv: Option<[u8; SIZE_INITV]>,
    psw_check: Option<[u8; SIZE_PSWCHECK]>,
    use_psw_check: bool,
    encrypted_header: bool,
}

impl Rar5State {
    fn new() -> Self {
        Self {
            salt: None,
            lg2_count: None,
            iv: None,
            psw_check: None,
            use_psw_check: false,
            encrypted_header: false,
        }
    }

    fn has_hash(&self) -> bool {
        self.salt.is_some() && self.lg2_count.is_some() && self.iv.is_some()
    }

    fn build_hash(&self) -> String {
        let salt = hex_encode(self.salt.as_ref().unwrap());
        let lg2 = self.lg2_count.unwrap();
        let iv = hex_encode(self.iv.as_ref().unwrap());
        if let Some(ref chk) = self.psw_check {
            let chk_hex = hex_encode(chk);
            format!("$rar5${salt}${lg2}${iv}${}${chk_hex}", SIZE_PSWCHECK,)
        } else {
            format!("$rar5${salt}${lg2}${iv}$0$")
        }
    }
}

/// Process the "extra" data block (type 0x01) in RAR5 file/service headers.
fn process_extra_crypt<R: Read + Seek>(
    reader: &mut Rar5Reader<R>,
    field_size: u64,
    state: &mut Rar5State,
) -> Result<bool, Error> {
    let start = reader.position()?;
    let _enc_version = reader.read_vuint()?;
    let flags = reader.read_vuint()?;
    let use_psw_check = flags & FHEXTRA_CRYPT_PSWCHECK != 0;

    let lg2_count = reader.read_u8()?;
    if lg2_count as u64 > CRYPT5_KDF_LG2_COUNT_MAX {
        return Err(Error::Extract("RAR5 KDF iteration count too large".into()));
    }

    let salt = {
        let mut s = [0u8; SIZE_SALT50];
        let data = reader.read_bytes(SIZE_SALT50)?;
        s.copy_from_slice(&data);
        s
    };

    let iv = {
        let mut v = [0u8; SIZE_INITV];
        let data = reader.read_bytes(SIZE_INITV)?;
        v.copy_from_slice(&data);
        v
    };

    let psw_check = if use_psw_check {
        let mut c = [0u8; SIZE_PSWCHECK];
        let data = reader.read_bytes(SIZE_PSWCHECK)?;
        c.copy_from_slice(&data);
        Some(c)
    } else {
        None
    };

    // Consume any remaining bytes in this field.
    let consumed = reader.position()? - start;
    if consumed < field_size {
        reader.skip_bytes(field_size - consumed)?;
    }

    state.salt = Some(salt);
    state.lg2_count = Some(lg2_count);
    state.iv = Some(iv);
    state.psw_check = psw_check;
    state.use_psw_check = use_psw_check;

    Ok(true)
}

/// Read one RAR5 header and advance the position to the next block.
/// Returns the header type, or `None` on end-of-archive.
fn read_rar5_header<R: Read + Seek>(
    reader: &mut Rar5Reader<R>,
    state: &mut Rar5State,
) -> Result<Option<u8>, Error> {
    // If headers are encrypted, the first SIZE_INITV bytes are the IV.
    if state.encrypted_header {
        let _headers_iv = reader.read_bytes(SIZE_INITV)?;
        // We already have salt/iv/pswcheck from HEAD_CRYPT; the encrypted
        // header IV is a different value used for header decryption, but for
        // hash extraction we already have what we need from the extra data.
        return Ok(None);
    }

    let _head_crc = reader.read_u32()?;
    let block_size = reader.read_vuint()?;
    let header_type = reader.read_u8()?;
    let flags = reader.read_vuint()?;

    let mut extra_size: u64 = 0;
    let mut data_size: u64 = 0;

    if flags & HFL_EXTRA != 0 {
        extra_size = reader.read_vuint()?;
    }
    if flags & HFL_DATA != 0 {
        data_size = reader.read_vuint()?;
    }

    match header_type {
        HEAD_CRYPT => {
            let crypt_version = reader.read_vuint()?;
            if crypt_version > 0 {
                return Err(Error::Extract(format!(
                    "RAR5 unsupported crypt version: {crypt_version}"
                )));
            }
            let enc_flags = reader.read_vuint()?;
            state.use_psw_check = enc_flags & FHEXTRA_CRYPT_PSWCHECK != 0;

            let lg2_count = reader.read_u8()?;
            if lg2_count as u64 > CRYPT5_KDF_LG2_COUNT_MAX {
                return Err(Error::Extract("RAR5 KDF iteration count too large".into()));
            }
            state.lg2_count = Some(lg2_count);

            let salt = {
                let mut s = [0u8; SIZE_SALT50];
                let data = reader.read_bytes(SIZE_SALT50)?;
                s.copy_from_slice(&data);
                s
            };
            state.salt = Some(salt);

            if state.use_psw_check {
                let chk = {
                    let mut c = [0u8; SIZE_PSWCHECK];
                    let data = reader.read_bytes(SIZE_PSWCHECK)?;
                    c.copy_from_slice(&data);
                    c
                };
                state.psw_check = Some(chk);

                // Verify the PSWCHECK checksum (SHA-256 truncated to 4 bytes).
                let _chksum = reader.read_bytes(SIZE_PSWCHECK_CSUM)?;
                // We trust the archive integrity; skip SHA-256 verification.
            }

            state.encrypted_header = true;
            Ok(Some(HEAD_CRYPT))
        }
        HEAD_MAIN => {
            // Skip remaining header + extra + data.
            let total = block_size + extra_size + data_size;
            reader.skip_bytes(total)?;
            Ok(Some(HEAD_MAIN))
        }
        HEAD_FILE | HEAD_SERVICE => {
            // We need to parse enough to find extra data with encryption info.
            let file_flags = reader.read_vuint()?;
            let _unp_size = reader.read_vuint()?;
            let _file_attr = reader.read_vuint()?;

            // Read optional fields based on flags.
            if file_flags & FHFL_UTIME != 0 {
                let _mtime = reader.read_u32()?;
            }
            if file_flags & FHFL_CRC32 != 0 {
                let _crc = reader.read_u32()?;
            }

            let _comp_info = reader.read_vuint()?;
            let _host_os = reader.read_vuint()?;
            let name_size = reader.read_vuint()?;

            // Skip the field name.
            reader.skip_bytes(name_size)?;

            // Process extra data if present.
            if extra_size != 0 {
                process_file_header_extra(reader, extra_size, state)?;
            }

            // Skip any remaining data.
            reader.skip_bytes(data_size)?;

            Ok(Some(header_type))
        }
        HEAD_ENDARC => Ok(None),
        _ => {
            // Unknown header type; skip remaining data.
            reader.skip_bytes(extra_size + data_size)?;
            Ok(Some(header_type))
        }
    }
}

/// Process extra data in a RAR5 file/service header.
fn process_file_header_extra<R: Read + Seek>(
    reader: &mut Rar5Reader<R>,
    extra_size: u64,
    state: &mut Rar5State,
) -> Result<(), Error> {
    let mut remaining = extra_size;

    while remaining > 0 {
        let field_size = reader.read_vuint()?;
        remaining = remaining.saturating_sub(1); // vint itself

        let field_type = reader.read_vuint()?;
        remaining = remaining.saturating_sub(1); // vint itself

        if field_size > remaining {
            break;
        }

        if field_type == FHEXTRA_CRYPT {
            process_extra_crypt(reader, field_size, state)?;
        } else {
            reader.skip_bytes(field_size)?;
        }

        remaining = remaining.saturating_sub(field_size);
    }

    Ok(())
}

/// Extract hash from RAR5 archive.
fn extract_rar5(path: &Path) -> Result<Vec<HashLine>, Error> {
    let file = std::fs::File::open(path).map_err(|e| Error::Io(e))?;
    let mut reader = Rar5Reader::new(file);
    let mut state = Rar5State::new();

    loop {
        match read_rar5_header(&mut reader, &mut state)? {
            Some(HEAD_CRYPT) => {
                // HEAD_CRYPT sets state.encrypted_header = true.
                // The next header read will return None (encrypted headers
                // can't be parsed without decryption). We have salt/iv/pswcheck.
                continue;
            }
            Some(HEAD_ENDARC) | None => break,
            _ => continue,
        }
    }

    if !state.has_hash() {
        return Err(Error::Unsupported(
            "No RAR5 encryption metadata found".into(),
        ));
    }

    let hash = state.build_hash();
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    Ok(vec![HashLine { filename, hash }])
}

// ── HashExtractor implementation ─────────────────────────────────────────────

impl HashExtractor for RarExtractor {
    fn format_id(&self) -> &'static str {
        "rar"
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.starts_with(RAR3_MAGIC) || data.starts_with(RAR5_MAGIC)
    }

    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error> {
        // Sniff the magic to decide RAR3 vs RAR5.
        let mut magic = [0u8; 8];
        let mut file = std::fs::File::open(path).map_err(|e| Error::Io(e))?;
        let n = file.read(&mut magic).map_err(|e| Error::Io(e))?;

        if n >= 7 && magic[..7] == *RAR3_MAGIC {
            extract_rar3(path)
        } else if n >= 8 && magic[..8] == *RAR5_MAGIC {
            extract_rar5(path)
        } else {
            Err(Error::Unsupported("Unknown RAR version".into()))
        }
    }

    fn validate(&self, line: &HashLine) -> bool {
        line.hash.starts_with("$rar3$") || line.hash.starts_with("$rar5$")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rar3() {
        let ext = RarExtractor;
        assert!(ext.detect(b"Rar!\x1a\x07\x00\x01"));
        assert!(!ext.detect(b"PK\x03\x04"));
    }

    #[test]
    fn detect_rar5() {
        let ext = RarExtractor;
        assert!(ext.detect(b"Rar!\x1a\x07\x01\x00"));
        assert!(!ext.detect(b"Not a rar file!!"));
    }

    #[test]
    fn validate_hashes() {
        let ext = RarExtractor;
        assert!(ext.validate(&HashLine {
            filename: "test.rar".into(),
            hash: "$rar3$*0*abc*def".into(),
        }));
        assert!(ext.validate(&HashLine {
            filename: "test.rar".into(),
            hash: "$rar5$16$abc$15$def$8$ghi".into(),
        }));
        assert!(!ext.validate(&HashLine {
            filename: "test.rar".into(),
            hash: "$zip2$*abc".into(),
        }));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0x01]), "0001");
    }
}

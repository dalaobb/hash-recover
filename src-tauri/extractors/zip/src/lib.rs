//! Native Rust port of zip2john.
//!
//! Reference implementation: openwall/john `src/zip2john.c`
//!
//! Output formats:
//! - WinZip AES: `$zip2$*0*<strength>*0*<salt>*<verify>*<ct_len>*<ct>*<auth>*$/zip2$`
//! - ZipCrypto:  `$pkzip$<count>*<check_bytes>*[<entries>]*$/pkzip$`

use extractor_core::{Error, HashExtractor, HashLine};
use std::path::Path;

pub struct ZipExtractor;

// ZIP magic numbers
const LOCAL_FILE_HEADER: u32 = 0x04034b50;
const CENTRAL_DIR_HEADER: u32 = 0x02014b50;
const EOCD_RECORD: u32 = 0x06054b50;
const EOCD64_RECORD: u32 = 0x06064b50;

// Flags
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_LOCAL_SIZE_UNKNOWN: u16 = 8;

// AES constants
const AES_AUTH_CODE_LENGTH: usize = 10;
const AES_VERIFY_LENGTH: usize = 2;

// Method 99 = AES
const METHOD_AES: u16 = 99;

// Max inline blob size (same as zip2john: 16 GB)
const MAX_BLOB_INLINE_SIZE: u64 = 0x400000000;

#[allow(dead_code)]
struct ZipEntry {
    version: u16,
    flags: u16,
    method: u16,
    crc: u32,
    compressed_size: u64,
    decompressed_size: u64,
    offset: u64,
    filename: String,
    extra_field_len: u16,
    lastmod_time: u16,
    lastmod_date: u16,
    aes_strength: u8,
    aes_found: bool,
}

#[allow(dead_code)]
struct ZipArchive {
    entries: Vec<ZipEntry>,
    zip64: bool,
    check_bytes: u8,
}

#[inline]
fn get_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn get_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn get_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

fn ensure(data: &[u8], off: usize, n: usize, ctx: &str) -> Result<(), Error> {
    if off + n > data.len() {
        Err(Error::Extract(format!(
            "{ctx}: need bytes at offset {off}, file is only {}",
            data.len()
        )))
    } else {
        Ok(())
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

impl ZipArchive {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        let len = data.len();
        if len < 22 {
            return Err(Error::Unsupported("File too small for ZIP".into()));
        }

        // Find EOCD by scanning backwards
        let scan_start = len.saturating_sub(22 + 65535);
        let mut zip64 = false;
        let mut cd_offset: u64 = 0;
        let mut _cd_size: u64 = 0;
        let mut num_entries: u64 = 0;
        let mut found = false;

        for pos in scan_start..len.saturating_sub(3) {
            if get_u32(data, pos) == EOCD_RECORD {
                _cd_size = get_u32(data, pos + 12) as u64;
                cd_offset = get_u32(data, pos + 16) as u64;
                num_entries = get_u16(data, pos + 10) as u64;
                zip64 = false;
                found = true;
                break;
            }
            if pos + 56 <= len && get_u32(data, pos) == EOCD64_RECORD {
                zip64 = true;
                let rp = pos + 4;
                num_entries = get_u64(data, rp + 20);
                _cd_size = get_u64(data, rp + 36);
                cd_offset = get_u64(data, rp + 44);
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::Unsupported("No ZIP central directory found".into()));
        }

        // Parse central directory
        let mut entries = Vec::new();
        let mut cd_pos = cd_offset as usize;

        for _ in 0..num_entries {
            ensure(data, cd_pos, 46, "central directory header")?;
            let sig = get_u32(data, cd_pos);
            if sig != CENTRAL_DIR_HEADER {
                return Err(Error::Extract("Invalid central directory entry".into()));
            }

            let version_needed = get_u16(data, cd_pos + 6) & 0xff;
            let flags = get_u16(data, cd_pos + 8);
            let method = get_u16(data, cd_pos + 10);
            let lastmod_time = get_u16(data, cd_pos + 12);
            let lastmod_date = get_u16(data, cd_pos + 14);
            let crc = get_u32(data, cd_pos + 16);
            let mut compressed_size = get_u32(data, cd_pos + 20) as u64;
            let mut decompressed_size = get_u32(data, cd_pos + 24) as u64;
            let fn_len = get_u16(data, cd_pos + 28) as usize;
            let extra_len = get_u16(data, cd_pos + 30) as usize;
            let comment_len = get_u16(data, cd_pos + 32) as usize;
            let mut local_header_offset = get_u32(data, cd_pos + 42) as u64;

            let fn_start = cd_pos + 46;
            let fn_end = fn_start + fn_len;
            ensure(data, fn_start, fn_len, "CD filename")?;
            let filename = String::from_utf8_lossy(&data[fn_start..fn_end]).into_owned();

            // Parse extra fields
            let extra_start = fn_end;
            let extra_end = extra_start + extra_len;
            let mut aes_found = false;
            let mut aes_strength: u8 = 0;
            let mut ef = extra_start;

            while ef + 4 <= extra_end {
                let efh_id = get_u16(data, ef);
                let efh_len = get_u16(data, ef + 2) as usize;
                if ef + 4 + efh_len > extra_end {
                    break;
                }
                let efh_data = ef + 4;
                if efh_id == 0x9901 && efh_len >= 7 {
                    aes_found = true;
                    aes_strength = data[efh_data + 4];
                }
                if efh_id == 0x0001 {
                    let mut off = efh_data;
                    if decompressed_size == 0xFFFFFFFF && off + 8 <= extra_end {
                        decompressed_size = get_u64(data, off);
                        off += 8;
                    }
                    if compressed_size == 0xFFFFFFFF && off + 8 <= extra_end {
                        compressed_size = get_u64(data, off);
                        off += 8;
                    }
                    if local_header_offset == 0xFFFFFFFF && off + 8 <= extra_end {
                        local_header_offset = get_u64(data, off);
                    }
                }
                ef += 4 + efh_len;
            }

            entries.push(ZipEntry {
                version: version_needed,
                flags,
                method,
                crc,
                compressed_size,
                decompressed_size,
                offset: local_header_offset,
                filename,
                extra_field_len: extra_len as u16,
                lastmod_time,
                lastmod_date,
                aes_strength,
                aes_found,
            });

            cd_pos = extra_end + comment_len;
        }

        let check_bytes = if entries.iter().any(|e| e.version >= 20) {
            1
        } else {
            2
        };

        Ok(ZipArchive {
            entries,
            zip64,
            check_bytes,
        })
    }

    fn has_encrypted_entries(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.flags & FLAG_ENCRYPTED != 0 || e.method == METHOD_AES)
    }

    fn has_aes_entries(&self) -> bool {
        self.entries.iter().any(|e| e.method == METHOD_AES)
    }

    fn has_legacy_entries(&self) -> bool {
        self.entries.iter().any(|e| {
            e.flags & FLAG_ENCRYPTED != 0
                && e.method != METHOD_AES
                && (e.method == 0 || e.method == 8)
        })
    }
}

fn local_data_offset(data: &[u8], entry: &ZipEntry) -> Result<usize, Error> {
    let off = entry.offset as usize;
    ensure(data, off, 30, "local header")?;
    let sig = get_u32(data, off);
    if sig != LOCAL_FILE_HEADER {
        return Err(Error::Extract("Invalid local file header".into()));
    }
    let fn_len = get_u16(data, off + 26) as usize;
    let extra_len = get_u16(data, off + 28) as usize;
    Ok(off + 30 + fn_len + extra_len)
}

fn render_aes_hash(data: &[u8], entry: &ZipEntry, basename: &str) -> Result<String, Error> {
    let data_start = local_data_offset(data, entry)?;

    let salt_length = match entry.aes_strength {
        1 => 8,
        2 => 12,
        3 => 16,
        _ => return Err(Error::Extract("Invalid AES strength".into())),
    };

    let need = salt_length + AES_VERIFY_LENGTH + AES_AUTH_CODE_LENGTH;
    ensure(data, data_start, need, "AES blob")?;

    let salt = &data[data_start..data_start + salt_length];
    let verify = &data[data_start + salt_length..data_start + salt_length + AES_VERIFY_LENGTH];
    let ct_start = data_start + salt_length + AES_VERIFY_LENGTH;

    let total = entry.compressed_size as usize;
    let overhead = salt_length + AES_VERIFY_LENGTH + AES_AUTH_CODE_LENGTH;
    let ct_len = total.saturating_sub(overhead);

    let auth_start = if ct_len > 0 {
        ct_start + ct_len
    } else {
        data_start + salt_length + AES_VERIFY_LENGTH
    };
    ensure(data, auth_start, AES_AUTH_CODE_LENGTH, "AES auth code")?;
    let auth_code = &data[auth_start..auth_start + AES_AUTH_CODE_LENGTH];

    let mut h = String::with_capacity(256);
    h.push_str("$zip2$*0*");
    h.push_str(&format!("{:x}", entry.aes_strength));
    h.push_str("*0*");
    h.push_str(&hex_encode(salt));
    h.push('*');
    h.push_str(&hex_encode(verify));
    h.push('*');
    h.push_str(&format!("{:x}", ct_len));
    h.push('*');

    if ct_len > 0 && ct_len as u64 <= MAX_BLOB_INLINE_SIZE {
        ensure(data, ct_start, ct_len, "AES ciphertext")?;
        h.push_str(&hex_encode(&data[ct_start..ct_start + ct_len]));
    } else if ct_len > 0 {
        h.push_str(&format!("ZFILE*{}*{:x}*0", basename, entry.offset));
    }

    h.push('*');
    h.push_str(&hex_encode(auth_code));
    h.push_str("*$/zip2$");
    Ok(h)
}

fn render_legacy_hash(data: &[u8], archive: &ZipArchive) -> Result<String, Error> {
    let mut legacy: Vec<&ZipEntry> = archive
        .entries
        .iter()
        .filter(|e| {
            e.flags & FLAG_ENCRYPTED != 0
                && e.method != METHOD_AES
                && (e.method == 0 || e.method == 8)
                && e.decompressed_size >= 4
        })
        .collect();

    if legacy.is_empty() {
        return Err(Error::Unsupported("No legacy encrypted entries".into()));
    }

    legacy.sort_by_key(|e| e.compressed_size);
    legacy.truncate(8);

    let count = legacy.len();
    let check_bytes = archive.check_bytes;
    let first = legacy[0];

    let data_start = local_data_offset(data, first)?;
    let offex = data_start - first.offset as usize;

    let cs = if first.flags & FLAG_LOCAL_SIZE_UNKNOWN != 0 {
        format!(
            "{:02x}{:02x}",
            first.lastmod_time >> 8,
            first.lastmod_time & 0xFF
        )
    } else {
        format!(
            "{:02x}{:02x}",
            (first.crc >> 24) & 0xFF,
            (first.crc >> 16) & 0xFF
        )
    };

    let cmp_len = first.compressed_size;
    let data_len = (12u64 + 24).min(cmp_len) as usize;

    let mut h = String::with_capacity(256);
    h.push_str(&format!("$pkzip${}*{}*", count, check_bytes));

    // DT=2, full inline
    h.push_str(&format!(
        "2*0*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*",
        first.method, data_len, first.decompressed_size, first.crc, first.offset, offex,
    ));

    h.push_str(&format!("{:x}*{}*", cmp_len, cs));

    ensure(data, data_start, data_len, "legacy ciphertext")?;
    h.push_str(&hex_encode(&data[data_start..data_start + data_len]));
    h.push('*');
    h.push_str("$/pkzip$");

    Ok(h)
}

impl HashExtractor for ZipExtractor {
    fn format_id(&self) -> &'static str {
        "zip"
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.len() >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04
    }

    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error> {
        let data = std::fs::read(path)?;
        let archive = ZipArchive::parse(&data)?;

        if !archive.has_encrypted_entries() {
            return Err(Error::Unsupported("File is not encrypted".into()));
        }

        let mut lines = Vec::new();
        let basename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        if archive.has_aes_entries() {
            for entry in &archive.entries {
                if entry.method == METHOD_AES {
                    let hash = render_aes_hash(&data, entry, &basename)?;
                    lines.push(HashLine {
                        filename: format!("{}/{}", basename, entry.filename),
                        hash,
                    });
                }
            }
        } else if archive.has_legacy_entries() {
            let hash = render_legacy_hash(&data, &archive)?;
            lines.push(HashLine {
                filename: basename,
                hash,
            });
        }

        Ok(lines)
    }

    fn validate(&self, line: &HashLine) -> bool {
        line.hash.starts_with("$zip2$")
            || line.hash.starts_with("$pkzip$")
            || line.hash.starts_with("$zip3$")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_signature() {
        let ext = ZipExtractor;
        assert!(ext.detect(b"PK\x03\x04rest"));
        assert!(!ext.detect(b"PK\x03\x05rest"));
        assert!(!ext.detect(b"PK\x04\x04rest"));
        assert!(!ext.detect(b"not a zip"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(b"\x00\x01\x0f\xff"), "00010fff");
        assert_eq!(hex_encode(b""), "");
    }

    #[test]
    fn test_non_encrypted_zip_error() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("zip_test_not_enc");
        let _ = std::fs::create_dir_all(&dir);
        let zip_path = dir.join("plain.zip");
        let mut f = std::fs::File::create(&zip_path).unwrap();
        // Minimal valid ZIP with one uncompressed stored (not encrypted) file "a" containing "hi"
        let a_name = b"a";
        let content = b"hi";
        let crc: u32 = 0x3d7bb5ec; // CRC32 of "hi"
                                   // local file header
        f.write_all(&[0x50, 0x4b, 0x03, 0x04]).unwrap();
        f.write_all(&20u16.to_le_bytes()).unwrap(); // version needed
        f.write_all(&0u16.to_le_bytes()).unwrap(); // flags (not encrypted)
        f.write_all(&0u16.to_le_bytes()).unwrap(); // method stored
        f.write_all(&0u16.to_le_bytes()).unwrap(); // mod time
        f.write_all(&0u16.to_le_bytes()).unwrap(); // mod date
        f.write_all(&crc.to_le_bytes()).unwrap();
        f.write_all(&(content.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&(content.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&(a_name.len() as u16).to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap(); // extra len
        f.write_all(a_name).unwrap();
        f.write_all(content).unwrap();
        // central directory
        f.write_all(&[0x50, 0x4b, 0x01, 0x02]).unwrap();
        f.write_all(&20u16.to_le_bytes()).unwrap(); // version made by
        f.write_all(&20u16.to_le_bytes()).unwrap(); // version needed
        f.write_all(&0u16.to_le_bytes()).unwrap(); // flags
        f.write_all(&0u16.to_le_bytes()).unwrap(); // method
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&crc.to_le_bytes()).unwrap();
        f.write_all(&(content.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&(content.len() as u32).to_le_bytes()).unwrap();
        f.write_all(&(a_name.len() as u16).to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(a_name).unwrap();
        // EOCD
        f.write_all(&[0x50, 0x4b, 0x05, 0x06]).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.write_all(&1u16.to_le_bytes()).unwrap();
        f.write_all(&1u16.to_le_bytes()).unwrap();
        let cd_size = 46u32 + a_name.len() as u32;
        f.write_all(&cd_size.to_le_bytes()).unwrap();
        let cd_offset = (30 + a_name.len() + content.len()) as u32;
        f.write_all(&cd_offset.to_le_bytes()).unwrap();
        f.write_all(&0u16.to_le_bytes()).unwrap();
        f.flush().unwrap();
        drop(f);

        let ext = ZipExtractor;
        let err = ext.extract(&zip_path).unwrap_err();
        match err {
            Error::Unsupported(msg) => assert!(msg.contains("not encrypted")),
            _ => panic!("expected Unsupported, got {:?}", err),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

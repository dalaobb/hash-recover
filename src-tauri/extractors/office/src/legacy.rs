//! Legacy binary Office formats: word (doc), excel (xls), powerpoint (ppt).
//!
//! Port of the corresponding sections of office2john.py. Hash formats:
//!
//! - `$oldoffice$0*<salt>*<verifier>*<verifierHash>`       (xls, RC4 simple)
//! - `$oldoffice$1*<salt>*<verifier>*<verifierHash>`       (doc, RC4 simple)
//! - `$oldoffice$3*<salt>*<verifier>*<verifierHash>*<block>` (RC4-40)
//! - `$oldoffice$4*<salt>*<verifier>*<verifierHash>`       (RC4-128)
//! - `$oldoffice$5*<salt>*<verifier>*<verifierHash>`       (RC4-56)

use cfb::CompoundFile;
use extractor_core::{Error, HashLine};
use std::fmt::Write;

use crate::ole::Cursor;
use crate::{hash_line, hex_encode};

const OLD_OFFICE: &str = "$oldoffice$";

/// Office 2007 CryptoAPI encryption header, [MS-OFFCRYPTO] 2.3.5.1.
struct CryptoApiHeader {
    typ: u16,
    salt: Vec<u8>,
    encrypted_verifier: Vec<u8>,
    encrypted_verifier_hash: Vec<u8>,
}

fn parse_cryptoapi_header(cur: &mut Cursor) -> Result<CryptoApiHeader, Error> {
    cur.skip(4)?; // encryptionFlags
    let mut header_len = cur.u32()? as usize;
    for _ in 0..2 {
        cur.skip(4)?; // skipFlags, sizeExtra
        header_len -= 4;
    }
    cur.skip(4)?; // algId
    header_len -= 4;
    cur.skip(4)?; // algHashId
    header_len -= 4;
    let key_size = cur.u32()?;
    header_len -= 4;
    for _ in 0..3 {
        cur.skip(4)?; // providerType, unused, unused
        header_len -= 4;
    }
    cur.skip(header_len)?; // CSPName (utf-16, ignored)

    let typ = match key_size {
        128 => 4,
        40 | 0 => 3,
        56 => 5,
        _ => {
            return Err(Error::Extract(format!(
                "unsupported RC4 key size {key_size}"
            )))
        }
    };

    let salt_size = cur.u32()?;
    if salt_size != 16 {
        return Err(Error::Extract(format!("unexpected salt size {salt_size}")));
    }
    let salt = cur.take(16)?.to_vec();
    let encrypted_verifier = cur.take(16)?.to_vec();
    let verifier_hash_size = cur.u32()?;
    if verifier_hash_size != 20 {
        return Err(Error::Extract(format!(
            "unexpected verifier hash size {verifier_hash_size}"
        )));
    }
    let encrypted_verifier_hash = cur.take(verifier_hash_size as usize)?.to_vec();

    Ok(CryptoApiHeader {
        typ,
        salt,
        encrypted_verifier,
        encrypted_verifier_hash,
    })
}

fn render_oldoffice(typ: u16, header: &CryptoApiHeader, second_block: Option<&[u8]>) -> String {
    let mut out = String::new();
    write!(
        out,
        "{OLD_OFFICE}{}*{}*{}*{}",
        typ,
        hex_encode(&header.salt),
        hex_encode(&header.encrypted_verifier),
        hex_encode(&header.encrypted_verifier_hash)
    )
    .expect("writing to string cannot fail");
    if let Some(block) = second_block {
        write!(out, "*{}", hex_encode(block)).expect("writing to string cannot fail");
    }
    out
}

/// Excel (xls): scan the Workbook/Book stream for a FILEPASS record.
pub fn process_xls(
    file: &mut CompoundFile<std::fs::File>,
    filename: String,
) -> Result<HashLine, Error> {
    let stream_name = if crate::ole::has_stream(file, "/Workbook") {
        "/Workbook"
    } else {
        "/Book"
    };
    let data = crate::ole::read_stream(file, stream_name)?;

    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let rec_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let rec_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + rec_len > data.len() {
            break;
        }
        let record = &data[pos..pos + rec_len];
        pos += rec_len;

        if rec_type != 0x2f {
            // FILEPASS
            continue;
        }
        if rec_len == 4 {
            // Excel 95 XOR obfuscation - not recoverable with this engine.
            continue;
        }
        if record.starts_with(&[0x00, 0x00]) {
            // XOR obfuscation
            continue;
        }
        if record.starts_with(&[0x01, 0x00, 0x01, 0x00, 0x01, 0x00]) {
            // RC4 simple encryption header.
            if record.len() < 54 {
                return Err(Error::Extract("truncated RC4 header".into()));
            }
            let salt = &record[6..22];
            let verifier = &record[22..38];
            let verifier_hash = &record[38..54];
            return Ok(hash_line(
                filename,
                format!(
                    "{OLD_OFFICE}0*{}*{}*{}",
                    hex_encode(salt),
                    hex_encode(verifier),
                    hex_encode(verifier_hash)
                ),
            ));
        }
        if record.starts_with(&[0x01, 0x00, 0x02, 0x00])
            || record.starts_with(&[0x01, 0x00, 0x03, 0x00])
            || record.starts_with(&[0x01, 0x00, 0x04, 0x00])
        {
            // RC4 CryptoAPI encryption.
            let mut cur = Cursor::new(record);
            cur.skip(2)?; // flags
            cur.skip(4)?; // major_version, minor_version
            let header = parse_cryptoapi_header(&mut cur)?;
            let second_block = if header.typ == 3 {
                if pos >= 1024 {
                    return Err(Error::Extract(
                        "RC4-40 header block offset out of range".into(),
                    ));
                }
                let end = (1024 + 32).min(data.len());
                Some(&data[1024..end])
            } else {
                None
            };
            return Ok(hash_line(
                filename,
                render_oldoffice(header.typ, &header, second_block),
            ));
        }
    }

    Err(Error::Extract(
        "no recoverable FILEPASS record found, is the document encrypted?".into(),
    ))
}

/// Word (doc): parse the FIB in WordDocument to locate the Table stream.
pub fn process_doc(
    file: &mut CompoundFile<std::fs::File>,
    filename: String,
) -> Result<HashLine, Error> {
    let word = crate::ole::read_stream(file, "/WordDocument")?;
    if word.len() < 12 {
        return Err(Error::Extract("WordDocument stream too short".into()));
    }
    if u16::from_le_bytes([word[0], word[1]]) != 0xa5ec {
        return Err(Error::Extract("invalid Word document header".into()));
    }
    let flags = word[11];
    let f = flags & 1;
    let g = flags & 2;
    let m = flags & 128;
    if f == 1 && m == 1 {
        return Err(Error::Extract("XOR obfuscation is not supported".into()));
    }
    if f == 0 {
        return Err(Error::Extract("document is not encrypted".into()));
    }
    let stream_name = if g == 0 { "/0Table" } else { "/1Table" };
    let table = crate::ole::read_stream(file, stream_name)?;

    if table.len() < 4 {
        return Err(Error::Extract("Table stream too short".into()));
    }
    let major = u16::from_le_bytes([table[0], table[1]]);
    let minor = u16::from_le_bytes([table[2], table[3]]);

    if major == 1 || minor == 1 {
        if table.len() < 52 {
            return Err(Error::Extract("truncated RC4 header".into()));
        }
        return Ok(hash_line(
            filename,
            format!(
                "{OLD_OFFICE}1*{}*{}*{}",
                hex_encode(&table[4..20]),
                hex_encode(&table[20..36]),
                hex_encode(&table[36..52])
            ),
        ));
    }

    if major >= 2 && minor == 2 {
        let mut cur = Cursor::new(&table[4..]);
        let header = parse_cryptoapi_header(&mut cur)?;
        let second_block = if header.typ == 3 {
            let offset = 4 + cur.pos();
            if offset >= 512 {
                return Err(Error::Extract(
                    "RC4-40 header block offset out of range".into(),
                ));
            }
            let end = (512 + 32).min(table.len());
            Some(&table[512..end])
        } else {
            None
        };
        return Ok(hash_line(
            filename,
            render_oldoffice(header.typ, &header, second_block),
        ));
    }

    Err(Error::Extract(
        "cannot find RC4 pass info, is the document encrypted?".into(),
    ))
}

/// Powerpoint (ppt): navigate Current User -> UserEditAtom -> PersistDirectory
/// to the encryption header inside the PowerPoint Document stream.
pub fn process_ppt(
    file: &mut CompoundFile<std::fs::File>,
    filename: String,
) -> Result<HashLine, Error> {
    let current_user = crate::ole::read_stream(file, "/Current User")?;
    if current_user.len() < 20 {
        return Err(Error::Extract("Current User stream too short".into()));
    }
    let offset = u32::from_le_bytes([
        current_user[16],
        current_user[17],
        current_user[18],
        current_user[19],
    ]) as usize;

    let data = crate::ole::read_stream(file, "/PowerPoint Document")?;

    if offset + 8 > data.len() {
        return Err(Error::Extract(
            "document is not encrypted or is corrupt".into(),
        ));
    }
    let rec_type = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
    let rec_len = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    if rec_len != 32 {
        return Err(Error::Extract("document is not encrypted".into()));
    }
    if rec_type != 0x0ff5 {
        return Err(Error::Extract("document is corrupt".into()));
    }

    let mut cur = Cursor::new(&data[offset + 8..]);
    cur.skip(4)?; // lastSlideRef
    cur.skip(2)?; // version
    cur.skip(2)?; // minorVersion, majorVersion
    cur.skip(4)?; // offsetLastEdit
    let persist_dir = cur.u32()? as usize; // offsetPersistDirectory
    cur.skip(4)?; // docPersistIdRef
    cur.skip(4)?; // persistIdSeed
    cur.skip(2)?; // lastView
    cur.skip(2)?; // unused
    let encrypt_session_persist_id_ref = cur.u16()?;

    let mut p = persist_dir + 8 + 4; // record header + unused
    let mut persist_offset = 0u32;
    for _ in 0..encrypt_session_persist_id_ref {
        if p + 4 > data.len() {
            return Err(Error::Extract("corrupt persist directory".into()));
        }
        persist_offset = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        p += 4;
    }

    let q = persist_offset as usize + 8; // record header
    if q + 4 > data.len() {
        return Err(Error::Extract(
            "cannot find RC4 pass info, is the document encrypted?".into(),
        ));
    }
    let major = u16::from_le_bytes([data[q], data[q + 1]]);
    let minor = u16::from_le_bytes([data[q + 2], data[q + 3]]);

    if major >= 2 && minor == 2 {
        let mut cur = Cursor::new(&data[q + 4..]);
        let header = parse_cryptoapi_header(&mut cur)?;
        let second_block = if header.typ == 3 {
            let end = 32.min(data.len());
            Some(&data[..end])
        } else {
            None
        };
        return Ok(hash_line(
            filename,
            render_oldoffice(header.typ, &header, second_block),
        ));
    }

    Err(Error::Extract(
        "cannot find RC4 pass info, is the document encrypted?".into(),
    ))
}

//! New Office formats: encrypted OOXML containers (docx/xlsx/pptx).
//!
//! Encrypted OOXML files are OLE compound files holding an EncryptionInfo
//! stream plus an EncryptedPackage stream ([MS-OFFCRYPTO]). Port of the
//! `process_new_office`/`xml_metadata_parser` sections of office2john.py.
//! Hash formats:
//!
//! - `$office$*2007*<verifierHashSize>*<keySize>*<saltSize>*<salt>*<verifier>*<verifierHash>`
//! - `$office$*2010|2013*<spinCount>*<keyBits>*<saltSize>*<salt>*<verifierHashInput>*<verifierHashValue>`

use base64::Engine;
use cfb::CompoundFile;
use extractor_core::{Error, HashLine};
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::ole::Cursor;
use crate::{hash_line, hex_encode};

const OFFICE: &str = "$office$";

pub fn process(
    file: &mut CompoundFile<std::fs::File>,
    filename: String,
) -> Result<HashLine, Error> {
    let data = crate::ole::read_stream(file, "/EncryptionInfo")?;
    if data.len() < 8 {
        return Err(Error::Extract("EncryptionInfo stream too short".into()));
    }
    let major = u16::from_le_bytes([data[0], data[1]]);
    let minor = u16::from_le_bytes([data[2], data[3]]);
    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if flags == 16 {
        // fExternal
        return Err(Error::Unsupported(
            "an external cryptographic provider is not supported".into(),
        ));
    }

    if major == 4 && minor == 4 {
        // Office 2010 / 2013 agile encryption; the rest is XML metadata.
        if flags != 0x40 {
            return Err(Error::Extract(
                "encryption flags are not consistent with the encryption type".into(),
            ));
        }
        process_agile(&data[8..], filename)
    } else {
        // Office 2007 CryptoAPI encryption header.
        process_2007(&data[8..], filename)
    }
}

fn process_2007(data: &[u8], filename: String) -> Result<HashLine, Error> {
    let mut cur = Cursor::new(data);
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

    let salt_size = cur.u32()?;
    if salt_size != 16 {
        return Err(Error::Extract(format!("unexpected salt size {salt_size}")));
    }
    let salt = cur.take(16)?;
    let encrypted_verifier = cur.take(16)?;
    let verifier_hash_size = cur.u32()? as usize;
    let encrypted_verifier_hash = cur.take(verifier_hash_size)?;

    // office2john.py truncates the verifier hash to 32 bytes (64 hex chars).
    let truncated = &encrypted_verifier_hash[..encrypted_verifier_hash.len().min(32)];
    Ok(hash_line(
        filename,
        format!(
            "{OFFICE}*2007*{verifier_hash_size}*{key_size}*{salt_size}*{}*{}*{}",
            hex_encode(salt),
            hex_encode(encrypted_verifier),
            hex_encode(truncated)
        ),
    ))
}

fn process_agile(xml: &[u8], filename: String) -> Result<HashLine, Error> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()) != b"encryptedKey" {
                    continue;
                }
                return parse_encrypted_key(e.attributes(), filename);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(Error::Extract(format!("malformed encryption XML: {e}")));
            }
        }
    }

    Err(Error::Extract(
        "no encryptedKey element found in encryption metadata".into(),
    ))
}

fn parse_encrypted_key(
    attrs: quick_xml::events::attributes::Attributes,
    filename: String,
) -> Result<HashLine, Error> {
    let mut attrs_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for attr in attrs {
        let attr = attr.map_err(|e| Error::Extract(format!("malformed attribute: {e}")))?;
        let key = String::from_utf8_lossy(local_name(attr.key.as_ref())).into_owned();
        let value = attr
            .unescape_value()
            .map_err(|e| Error::Extract(format!("bad value: {e}")))?;
        attrs_map.insert(key, value.into_owned());
    }

    let get = |k: &str| -> Result<&str, Error> {
        attrs_map
            .get(k)
            .map(|s| s.as_str())
            .ok_or_else(|| Error::Extract(format!("missing attribute {k} in encryptedKey")))
    };

    let hash_algorithm = get("hashAlgorithm")?;
    let version = match hash_algorithm {
        "SHA1" => 2010,
        "SHA512" => 2013,
        other => {
            return Err(Error::Unsupported(format!(
                "unsupported hashing algorithm {other}"
            )));
        }
    };
    let cipher_algorithm = get("cipherAlgorithm")?;
    if !cipher_algorithm.contains("AES") {
        return Err(Error::Unsupported(format!(
            "unsupported cipher algorithm {cipher_algorithm}"
        )));
    }

    let spin_count = get("spinCount")?;
    let salt_size = get("saltSize")?;
    let key_bits = get("keyBits")?;
    let salt_value = decode_b64(get("saltValue")?)?;
    let verifier_hash_input = decode_b64(get("encryptedVerifierHashInput")?)?;
    let verifier_hash_value = decode_b64(get("encryptedVerifierHashValue")?)?;

    let truncated = &verifier_hash_value[..verifier_hash_value.len().min(32)];
    Ok(hash_line(
        filename,
        format!(
            "{OFFICE}*{version}*{spin_count}*{key_bits}*{salt_size}*{}*{}*{}",
            hex_encode(&salt_value),
            hex_encode(&verifier_hash_input),
            hex_encode(truncated)
        ),
    ))
}

/// Element/attribute local name: strip XML namespace prefix (`ns:name`) and
/// expanded-form (`{uri}name`) prefixes.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b':' || b == b'}') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

fn decode_b64(input: &str) -> Result<Vec<u8>, Error> {
    use base64::engine::general_purpose::STANDARD;
    STANDARD
        .decode(input.trim())
        .map_err(|e| Error::Extract(format!("invalid base64 value: {e}")))
}

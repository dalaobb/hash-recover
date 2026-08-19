use extractor_core::{Error, HashExtractor, HashLine};
use std::path::Path;

pub struct SevenZExtractor;

// ── 7z constants ─────────────────────────────────────────────────────────────

const MAGIC: &[u8; 6] = b"7z\xbc\xaf\x27\x1c";
const SIGNATURE_HEADER_SIZE: u64 = 32;

// Header IDs
const HDR_END: u8 = 0x00;
const HDR_HEADER: u8 = 0x01;
const HDR_ARCHIVE_PROPERTIES: u8 = 0x02;
const HDR_ENCODED_HEADER: u8 = 0x17;
const HDR_MAIN_STREAMS_INFO: u8 = 0x04;
const HDR_PACK_INFO: u8 = 0x06;
const HDR_UNPACK_INFO: u8 = 0x07;
const HDR_SUBSTREAMS_INFO: u8 = 0x08;
const HDR_CRC: u8 = 0x0a;
const HDR_SIZE: u8 = 0x09;

// Codec IDs (variable-length, multi-byte)
const CODEC_LZMA1: &[u8] = &[0x03, 0x01, 0x01];
const CODEC_LZMA2: &[u8] = &[0x21];
const CODEC_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const CODEC_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
const CODEC_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
const CODEC_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];

// Compression type nibbles (lower 4 bits of data_type)
const UNCOMPRESSED: u8 = 0;
const LZMA1_COMPRESSED: u8 = 1;
const LZMA2_COMPRESSED: u8 = 2;
const PPMD_COMPRESSED: u8 = 3;
const BZIP2_COMPRESSED: u8 = 6;
const DEFLATE_COMPRESSED: u8 = 7;

const DEFAULT_POWER: u8 = 19;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn ensure(data: &[u8], off: usize, n: usize, ctx: &str) -> Result<(), Error> {
    if off + n > data.len() {
        Err(Error::Extract(format!(
            "{ctx}: need {n} bytes at offset {off}, file is only {}",
            data.len()
        )))
    } else {
        Ok(())
    }
}

// ── 7z variable-length integer reader ────────────────────────────────────────

struct SevenZipReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SevenZipReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        ensure(self.data, self.pos, 1, "read_u8")?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        ensure(self.data, self.pos, 4, "read_u32")?;
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        ensure(self.data, self.pos, 8, "read_u64")?;
        let v = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        ensure(self.data, self.pos, n, "read_bytes")?;
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    #[allow(dead_code)]
    fn skip(&mut self, n: usize) -> Result<(), Error> {
        ensure(self.data, self.pos, n, "skip")?;
        self.pos += n;
        Ok(())
    }

    /// Read a 7z variable-length integer.
    fn read_number(&mut self) -> Result<u64, Error> {
        let first = self.read_u8()?;
        if first & 0x80 == 0 {
            return Ok(first as u64);
        }
        let mut value = self.read_u8()? as u64;
        for i in 1..8u32 {
            let mask = 0x80u8 >> i;
            if first & mask == 0 {
                let high = first & (mask - 1);
                value |= (high as u64) << (i * 8);
                return Ok(value);
            }
            let next = self.read_u8()? as u64;
            value |= next << (i * 8);
        }
        Ok(value)
    }

    fn read_id(&mut self) -> Result<Vec<u8>, Error> {
        let num = self.read_number()?;
        if num == 0 {
            return Ok(vec![0x00]);
        }
        let mut id = Vec::new();
        let mut n = num;
        while n > 0 {
            id.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        Ok(id)
    }

    fn read_bool_vector(&mut self, count: usize) -> Result<Vec<bool>, Error> {
        let mut vec = Vec::with_capacity(count);
        let mut v = 0u8;
        let mut mask = 0u8;
        for _ in 0..count {
            if mask == 0 {
                v = self.read_u8()?;
                mask = 0x80;
            }
            vec.push(v & mask != 0);
            mask >>= 1;
        }
        Ok(vec)
    }

    #[allow(dead_code)]
    fn read_bool_vector_check_all(&mut self, count: usize) -> Result<Vec<bool>, Error> {
        let first = self.read_u8()?;
        if first == 0x01 {
            Ok(vec![true; count])
        } else {
            self.read_bool_vector(count)
        }
    }
}

// ── Data structures ──────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct FolderCoder {
    codec_id: Vec<u8>,
    attributes: Vec<u8>,
    num_in: usize,
    num_out: usize,
}

#[derive(Debug, Default)]
struct Folder {
    coders: Vec<FolderCoder>,
    num_packed_streams: usize,
    sum_packed_streams: u64,
    unpack_sizes: Vec<u64>,
}

#[derive(Debug, Default)]
struct PackInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct DigestEntry {
    defined: bool,
    crc: u32,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct UnpackInfo {
    folders: Vec<Folder>,
    num_folders: usize,
    digest_entries: Vec<DigestEntry>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct SubstreamsInfo {
    unpack_sizes: Vec<u64>,
    digest_entries: Vec<DigestEntry>,
}

#[derive(Debug, Default)]
struct StreamsInfo {
    pack_info: Option<PackInfo>,
    unpack_info: Option<UnpackInfo>,
    substreams_info: Option<SubstreamsInfo>,
}

struct DecoderProperties {
    salt_len: usize,
    salt: Vec<u8>,
    iv_len: usize,
    iv: Vec<u8>,
    number_cycles_power: u8,
}

fn get_decoder_properties(attributes: &[u8]) -> DecoderProperties {
    let default_iv = vec![0u8; 16];
    let mut result = DecoderProperties {
        salt_len: 0,
        salt: Vec::new(),
        iv_len: 16,
        iv: default_iv,
        number_cycles_power: DEFAULT_POWER,
    };

    if attributes.is_empty() {
        return result;
    }

    let first_byte = attributes[0];
    result.number_cycles_power = first_byte & 0x3f;

    if first_byte & 0xc0 == 0 {
        return result;
    }

    let salt_len_hi = (first_byte >> 7) & 1;
    let iv_len_hi = (first_byte >> 6) & 1;

    if attributes.len() < 2 {
        return result;
    }

    let second_byte = attributes[1];
    result.salt_len = salt_len_hi as usize + ((second_byte >> 4) as usize);
    result.iv_len = iv_len_hi as usize + (second_byte & 0x0f) as usize;

    let mut offset = 2;
    if offset + result.salt_len <= attributes.len() {
        result.salt = attributes[offset..offset + result.salt_len].to_vec();
        offset += result.salt_len;
    }
    if offset + result.iv_len <= attributes.len() {
        result.iv = attributes[offset..offset + result.iv_len].to_vec();
        // Pad IV to 16 bytes
        result.iv.resize(16, 0);
    }

    result
}

fn codec_type_for(compressor_type: u8, preprocessor_type: u8) -> u8 {
    if compressor_type == 0 && preprocessor_type == 0 {
        0
    } else {
        (preprocessor_type << 4) | compressor_type
    }
}

// ── Header parsing ───────────────────────────────────────────────────────────

fn parse_header(buf: &[u8]) -> Result<StreamsInfo, Error> {
    let mut r = SevenZipReader::new(buf);
    let hdr_type = r.read_id()?;

    if hdr_type == [HDR_ENCODED_HEADER] {
        // Read ARCHIVE_PROPERTIES to get pack stream sizes
        let id = r.read_id()?;
        if id != [HDR_ARCHIVE_PROPERTIES] {
            return Err(Error::Extract(format!(
                "expected ARCHIVE_PROPERTIES after ENCODED_HEADER, got 0x{:02x}",
                id[0]
            )));
        }

        let mut pack_sizes = Vec::new();
        let pack_pos: u64;

        loop {
            let prop_id = r.read_id()?;
            if prop_id == [HDR_END] {
                break;
            }
            if prop_id == [HDR_SIZE] {
                let num_sizes = r.read_number()? as usize;
                for _ in 0..num_sizes {
                    pack_sizes.push(r.read_number()?);
                }
            } else {
                // Unknown property, skip its content
                let num_sizes = r.read_number()? as usize;
                for _ in 0..num_sizes {
                    let _ = r.read_number()?;
                }
            }
        }

        // The pack data follows right after the ARCHIVE_PROPERTIES in the
        // decompressed header.  Compute cumulative pack_pos.
        pack_pos = pack_sizes.iter().sum();

        let pack_info = PackInfo {
            pack_pos,
            pack_sizes,
        };

        // Parse remaining header content (MAIN_STREAMS_INFO etc.)
        let mut streams = StreamsInfo {
            pack_info: Some(pack_info),
            ..Default::default()
        };

        // Continue parsing the rest of the header
        while r.pos < buf.len() {
            let id = r.read_id()?;
            if id == [HDR_END] {
                break;
            }
            match id[0] {
                HDR_MAIN_STREAMS_INFO => {
                    parse_main_streams_info(&mut r, &mut streams)?;
                }
                _ => {
                    // Skip unknown sections
                    break;
                }
            }
        }

        Ok(streams)
    } else if hdr_type == [HDR_HEADER] {
        // Direct HEADER (no encryption on header)
        let mut streams = StreamsInfo::default();
        parse_main_streams_info(&mut r, &mut streams)?;
        Ok(streams)
    } else {
        Err(Error::Unsupported(format!(
            "unsupported header type: 0x{:02x}",
            hdr_type[0]
        )))
    }
}

fn parse_main_streams_info(r: &mut SevenZipReader, streams: &mut StreamsInfo) -> Result<(), Error> {
    loop {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        match id[0] {
            HDR_PACK_INFO => {
                parse_pack_info(r, streams)?;
            }
            HDR_UNPACK_INFO => {
                parse_unpack_info(r, streams)?;
            }
            HDR_SUBSTREAMS_INFO => {
                parse_substreams_info(r, streams)?;
            }
            _ => {
                // Unknown section, stop
                break;
            }
        }
    }
    Ok(())
}

fn parse_pack_info(r: &mut SevenZipReader, streams: &mut StreamsInfo) -> Result<(), Error> {
    let pack_pos = r.read_number()?;
    let num_pack_streams = r.read_number()? as usize;

    let mut pack_sizes = Vec::with_capacity(num_pack_streams);

    // There may be a SIZE property defining pack stream sizes
    loop {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        if id == [HDR_SIZE] {
            let num_sizes = r.read_number()? as usize;
            for _ in 0..num_sizes {
                pack_sizes.push(r.read_number()?);
            }
        } else {
            // Unknown property in pack info, skip
            let num_sizes = r.read_number()? as usize;
            for _ in 0..num_sizes {
                let _ = r.read_number()?;
            }
        }
    }

    streams.pack_info = Some(PackInfo {
        pack_pos,
        pack_sizes,
    });
    Ok(())
}

fn parse_unpack_info(r: &mut SevenZipReader, streams: &mut StreamsInfo) -> Result<(), Error> {
    let mut folders = Vec::new();
    let mut num_folders = 0usize;

    loop {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        match id[0] {
            0x0b => {
                // FOLDER
                let external = r.read_u8()?;
                num_folders = r.read_number()? as usize;
                folders.reserve(num_folders);

                if external == 0x00 {
                    for _ in 0..num_folders {
                        let mut folder = Folder::default();
                        let num_coders = r.read_number()? as usize;
                        for _ in 0..num_coders {
                            let mut coder = FolderCoder::default();
                            let main_byte = r.read_u8()?;
                            let codec_id_len = (main_byte & 0x0f) as usize;
                            let _complex = main_byte & 0x10 != 0;
                            let _attributes_present = main_byte & 0x20 != 0;
                            coder.num_in = if main_byte & 0x40 != 0 { 2 } else { 1 };
                            coder.num_out = if main_byte & 0x80 != 0 { 2 } else { 1 };
                            coder.codec_id = r.read_bytes(codec_id_len)?.to_vec();

                            if _attributes_present {
                                let attr_len = r.read_number()? as usize;
                                coder.attributes = r.read_bytes(attr_len)?.to_vec();
                            }
                            folder.coders.push(coder);
                        }
                        // Simple binding for packed streams
                        let num_bind_pairs = r.read_number()?;
                        for _ in 0..num_bind_pairs {
                            let _ = r.read_number()?;
                            let _ = r.read_number()?;
                        }
                        let num_packed_streams = if num_coders > 1 { r.read_number()? } else { 0 };
                        for _ in 0..num_packed_streams {
                            let _ = r.read_number()?;
                        }
                        folder.num_packed_streams = num_packed_streams as usize;
                        folders.push(folder);
                    }
                } else {
                    return Err(Error::Extract("external folders not supported".into()));
                }
            }
            0x0c => {
                // UNPACK_SIZE
                let num_folders = folders.len();
                let _ = r.read_number()?; // number of unpack sizes
                for folder in &mut folders {
                    folder.unpack_sizes.push(r.read_number()?);
                }
                // Continue reading remaining unpack sizes
                for _ in 1..num_folders {
                    if let Some(folder) = folders.last_mut() {
                        folder.unpack_sizes.push(r.read_number()?);
                    }
                }
            }
            0x0d => {
                // NUM_UNPACK_STREAM
                let _ = r.read_number()?;
            }
            0x0e | 0x0f | 0x10 => {
                // EMPTY_STREAM, EMPTY_FILE, ANTI_FILE
                let count = r.read_number()? as usize;
                let _ = r.read_bool_vector(count)?;
            }
            0x11 => {
                // NAME
                let _external = r.read_u8()?;
                let _size = r.read_number()?;
                let _ = r.read_bytes(_size as usize)?;
            }
            0x12 | 0x13 | 0x14 => {
                // CREATION_TIME, ACCESS_TIME, MODIFICATION_TIME
                let external = r.read_u8()?;
                if external == 0x01 {
                    let _ = r.read_number()?;
                } else {
                    let _ = r.read_number()?;
                    let all_defined = r.read_u8()?;
                    if all_defined != 0x01 {
                        let _ = r.read_bool_vector(num_folders)?;
                    }
                    // Read timestamps
                    for _ in 0..num_folders {
                        let _ = r.read_u64()?;
                    }
                }
            }
            0x15 => {
                // WIN_ATTRIBUTE
                let external = r.read_u8()?;
                if external != 0x01 {
                    let _ = r.read_number()?;
                    let all_defined = r.read_u8()?;
                    if all_defined != 0x01 {
                        let _ = r.read_bool_vector(num_folders)?;
                    }
                    for _ in 0..num_folders {
                        let _ = r.read_u32()?;
                    }
                }
            }
            _ => {
                break;
            }
        }
    }

    // Compute sum_packed_streams per folder
    let _pack_sizes = streams
        .pack_info
        .as_ref()
        .map(|p| p.pack_sizes.len())
        .unwrap_or(0);
    for folder in &mut folders {
        let fps = folder.coders.len().min(1); // simplified
        folder.sum_packed_streams = fps as u64;
    }

    // Also parse digests from UNPACK_INFO
    // CRC comes after the unpack_size section
    // Re-read CRC from the remaining buffer (we're already past it in the loop above)

    streams.unpack_info = Some(UnpackInfo {
        folders,
        num_folders,
        digest_entries: Vec::new(),
    });
    Ok(())
}

fn parse_substreams_info(r: &mut SevenZipReader, streams: &mut StreamsInfo) -> Result<(), Error> {
    let unpack_info = streams.unpack_info.as_ref().unwrap();
    let num_folders = unpack_info.num_folders;

    // NUM_UNPACK_STREAMS per folder
    let mut num_unpack_streams = Vec::new();
    loop {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        if id == [0x0d] {
            // NUM_UNPACK_STREAM
            let _ = r.read_number()?;
            for _ in 0..num_folders {
                num_unpack_streams.push(r.read_number()?);
            }
        } else if id == [0x0c] {
            // UNPACK_SIZE (in substreams context)
            let _ = r.read_number()?;
            let _total: u64 = num_unpack_streams.iter().sum();
            let _ = r.read_number()?;
        } else if id == [HDR_CRC] {
            // CRC
            let _ = r.read_number()?;
            let all_defined = r.read_u8()?;
            if all_defined != 0x01 {
                let _ = r.read_bool_vector(num_folders)?;
            }
            for _ in 0..num_folders {
                let _ = r.read_u32()?;
            }
        } else {
            break;
        }
    }

    streams.substreams_info = Some(SubstreamsInfo::default());
    Ok(())
}

// ── Hash extraction ──────────────────────────────────────────────────────────

impl HashExtractor for SevenZExtractor {
    fn format_id(&self) -> &'static str {
        "7z"
    }

    fn detect(&self, data: &[u8]) -> bool {
        data.len() >= 6 && &data[..6] == MAGIC
    }

    fn extract(&self, path: &Path) -> Result<Vec<HashLine>, Error> {
        let data = std::fs::read(path)?;

        ensure(&data, 0, SIGNATURE_HEADER_SIZE as usize, "signature header")?;

        // Validate magic
        if &data[..6] != MAGIC {
            return Err(Error::Unsupported("Not a 7z file".into()));
        }

        // Read start header CRC
        let start_crc = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);

        // Validate start header CRC (covers bytes 12..24)
        if data.len() < 24 {
            return Err(Error::Extract("File too small".into()));
        }
        let computed_crc = crc32fast::hash(&data[12..24]);
        if computed_crc != start_crc {
            return Err(Error::Extract("Start header CRC mismatch".into()));
        }

        let next_header_offset = u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);
        let next_header_size = u64::from_le_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);
        let _next_header_crc = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        if next_header_size == 0 {
            return Err(Error::Unsupported("Empty 7z archive".into()));
        }

        let nh_start = next_header_offset as usize;
        let nh_end = nh_start + next_header_size as usize;
        if nh_end > data.len() {
            return Err(Error::Extract("next header extends beyond file".into()));
        }
        let next_header = &data[nh_start..nh_end];

        // Read header type
        let hdr_type = next_header[0];

        if hdr_type == HDR_ENCODED_HEADER {
            // Header is encrypted. We need to:
            // 1. Find AES cipher properties from ARCHIVE_PROPERTIES section
            // 2. Read pack stream data right after signature header (32 bytes)
            // 3. Decompress the pack data (LZMA)
            // 4. Parse the decompressed header for streams_info

            // Parse ARCHIVE_PROPERTIES to get pack sizes
            let mut r = SevenZipReader::new(next_header);
            let _ = r.read_id()?; // HDR_ENCODED_HEADER
            let prop_id = r.read_id()?;
            if prop_id != [HDR_ARCHIVE_PROPERTIES] {
                return Err(Error::Extract("expected ARCHIVE_PROPERTIES".into()));
            }

            let mut pack_sizes = Vec::new();
            loop {
                let id = r.read_id()?;
                if id == [HDR_END] {
                    break;
                }
                if id == [HDR_SIZE] {
                    let _num = r.read_number()? as usize;
                    for _ in 0.._num {
                        pack_sizes.push(r.read_number()?);
                    }
                } else {
                    break;
                }
            }

            if pack_sizes.is_empty() {
                return Err(Error::Extract("no pack stream sizes".into()));
            }

            // Pack data starts right after signature header
            let pack_data_start = SIGNATURE_HEADER_SIZE as usize;
            let pack_data_end = pack_data_start + pack_sizes[0] as usize;
            if pack_data_end > data.len() {
                return Err(Error::Extract("pack stream extends beyond file".into()));
            }

            // The first coder in the next header section tells us the encryption
            // properties.  After ARCHIVE_PROPERTIES + HDR_END, the remaining
            // bytes contain the MAIN_STREAMS_INFO with folder/coder definitions.

            // Find AES coder properties from the rest of the header
            let mut aes_r = SevenZipReader::new(next_header);
            aes_r.pos = r.pos; // continue from where we left off

            // Skip to find FOLDER definition
            let mut aes_salt = Vec::new();
            let mut aes_iv = vec![0u8; 16];
            let mut number_cycles_power = DEFAULT_POWER;
            let mut found_aes = false;
            // Read remaining header sections
            loop {
                if aes_r.pos >= next_header.len() {
                    break;
                }
                let id = match aes_r.read_id() {
                    Ok(id) => id,
                    Err(_) => break,
                };
                if id == [HDR_END] {
                    break;
                }
                if id == [HDR_MAIN_STREAMS_INFO] {
                    // Parse main streams info inline to find folder coders
                    loop {
                        let sub_id = aes_r.read_id()?;
                        if sub_id == [HDR_END] {
                            break;
                        }
                        if sub_id == [HDR_UNPACK_INFO] {
                            // Parse UNPACK_INFO to find folders with AES coders
                            parse_unpack_info_for_aes(
                                &mut aes_r,
                                &mut aes_salt,
                                &mut aes_iv,
                                &mut number_cycles_power,
                                &mut found_aes,
                            )?;
                            break;
                        } else {
                            // Skip unknown section
                            let _ = aes_r.read_number()?;
                        }
                    }
                    break;
                }
            }

            if !found_aes {
                return Err(Error::Extract("no AES cipher found in header".into()));
            }

            // Decompress the pack data (LZMA)
            let pack_data = &data[pack_data_start..pack_data_end];
            let decompressed = decompress_lzma(pack_data)?;

            // Parse decompressed header
            let streams = parse_header(&decompressed)?;

            // Now find AES from streams_info folders
            // The decompressed header has the actual streams_info with folder details

            // Find the first folder with AES encryption
            let unpack_info = streams
                .unpack_info
                .as_ref()
                .ok_or_else(|| Error::Extract("no unpack_info in decompressed header".into()))?;

            let pack_info = streams
                .pack_info
                .as_ref()
                .ok_or_else(|| Error::Extract("no pack_info".into()))?;

            // Find AES folder
            let mut aes_folder_idx = None;
            let mut aes_coder_idx = 0;
            for (fi, folder) in unpack_info.folders.iter().enumerate() {
                for (ci, coder) in folder.coders.iter().enumerate() {
                    if coder.codec_id == CODEC_AES {
                        aes_folder_idx = Some(fi);
                        aes_coder_idx = ci;
                        break;
                    }
                }
                if aes_folder_idx.is_some() {
                    break;
                }
            }

            let folder_idx = aes_folder_idx
                .ok_or_else(|| Error::Extract("no AES-encrypted folder found".into()))?;
            let folder = &unpack_info.folders[folder_idx];

            // Get AES properties from coder attributes
            let aes_coder = &folder.coders[aes_coder_idx];
            let props = get_decoder_properties(&aes_coder.attributes);

            // Compute pack stream data offset
            // Sum pack sizes of previous folders' packed streams
            let mut data_offset = pack_info.pack_pos as usize;
            for fi in 0..folder_idx {
                let f = &unpack_info.folders[fi];
                for ps in 0..f.coders.len() {
                    if ps < pack_info.pack_sizes.len() {
                        data_offset += pack_info.pack_sizes[ps] as usize;
                    }
                }
            }

            // Get pack size for this folder
            let pack_size = pack_info.pack_sizes.get(folder_idx).copied().unwrap_or(0) as usize;

            // Extract CRC from digests
            // The CRC is in unpack_info.digests (after the FOLDER section in UNPACK_INFO)
            // We need to re-parse the UNPACK_INFO section to get digests
            // For now, extract CRC from the decompressed header

            // Find CRC by re-scanning the header
            let crc = find_crc_in_header(&decompressed, folder_idx)?;

            // Read encrypted data from pack stream
            let data_end = data_offset + pack_size;
            if data_end > data.len() {
                return Err(Error::Extract("encrypted data extends beyond file".into()));
            }
            let enc_data = &data[data_offset..data_end];

            // Build the hash
            let data_type = codec_type_for(get_primary_compression_type(folder), 0);

            let hash = format!(
                "$7z${data_type}${cost}${salt_len}${salt}${iv_len}${iv}${crc}${data_len}${dec_len}${enc_data}",
                data_type = data_type,
                cost = props.number_cycles_power,
                salt_len = props.salt.len(),
                salt = hex_encode(&props.salt),
                iv_len = props.iv.len(),
                iv = hex_encode(&props.iv),
                crc = crc,
                data_len = enc_data.len(),
                dec_len = folder.unpack_sizes.first().copied().unwrap_or(0),
                enc_data = hex_encode(enc_data),
            );

            let basename = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            Ok(vec![HashLine {
                filename: basename,
                hash,
            }])
        } else if hdr_type == HDR_HEADER {
            // Header is not encrypted — extract AES properties from streams_info
            let mut r = SevenZipReader::new(next_header);
            let _ = r.read_id()?; // HDR_HEADER

            let mut streams = StreamsInfo::default();
            parse_main_streams_info(&mut r, &mut streams)?;

            let unpack_info = streams
                .unpack_info
                .as_ref()
                .ok_or_else(|| Error::Extract("no unpack_info".into()))?;
            let pack_info = streams
                .pack_info
                .as_ref()
                .ok_or_else(|| Error::Extract("no pack_info".into()))?;

            // Find AES folder
            let mut aes_folder_idx = None;
            let mut aes_coder_idx = 0;
            for (fi, folder) in unpack_info.folders.iter().enumerate() {
                for (ci, coder) in folder.coders.iter().enumerate() {
                    if coder.codec_id == CODEC_AES {
                        aes_folder_idx = Some(fi);
                        aes_coder_idx = ci;
                        break;
                    }
                }
                if aes_folder_idx.is_some() {
                    break;
                }
            }

            let folder_idx = aes_folder_idx
                .ok_or_else(|| Error::Extract("no AES-encrypted folder found".into()))?;
            let folder = &unpack_info.folders[folder_idx];

            let aes_coder = &folder.coders[aes_coder_idx];
            let props = get_decoder_properties(&aes_coder.attributes);

            let mut data_offset = pack_info.pack_pos as usize;
            for fi in 0..folder_idx {
                let f = &unpack_info.folders[fi];
                for ps in 0..f.coders.len() {
                    if ps < pack_info.pack_sizes.len() {
                        data_offset += pack_info.pack_sizes[ps] as usize;
                    }
                }
            }

            let pack_size = pack_info.pack_sizes.get(folder_idx).copied().unwrap_or(0) as usize;

            let data_end = data_offset + pack_size;
            if data_end > data.len() {
                return Err(Error::Extract("encrypted data extends beyond file".into()));
            }
            let enc_data = &data[data_offset..data_end];

            let crc = find_crc_in_header(&decompressed_data(&next_header)?, folder_idx)?;

            let data_type = codec_type_for(get_primary_compression_type(folder), 0);

            let hash = format!(
                "$7z${data_type}${cost}${salt_len}${salt}${iv_len}${iv}${crc}${data_len}${dec_len}${enc_data}",
                data_type = data_type,
                cost = props.number_cycles_power,
                salt_len = props.salt.len(),
                salt = hex_encode(&props.salt),
                iv_len = props.iv.len(),
                iv = hex_encode(&props.iv),
                crc = crc,
                data_len = enc_data.len(),
                dec_len = folder.unpack_sizes.first().copied().unwrap_or(0),
                enc_data = hex_encode(enc_data),
            );

            let basename = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            Ok(vec![HashLine {
                filename: basename,
                hash,
            }])
        } else {
            Err(Error::Unsupported(format!(
                "unsupported 7z header type: 0x{hdr_type:02x}"
            )))
        }
    }

    fn validate(&self, line: &HashLine) -> bool {
        line.hash.starts_with("$7z$")
    }
}

// ── Helper functions ─────────────────────────────────────────────────────────

fn decompressed_data(header: &[u8]) -> Result<Vec<u8>, Error> {
    // For unencrypted headers, the header IS the data to parse
    Ok(header.to_vec())
}

fn get_primary_compression_type(folder: &Folder) -> u8 {
    // Find the first non-AES, non-preprocessor coder
    for coder in &folder.coders {
        if coder.codec_id == CODEC_AES {
            continue;
        }
        match coder.codec_id.as_slice() {
            CODEC_LZMA1 => return LZMA1_COMPRESSED,
            CODEC_LZMA2 => return LZMA2_COMPRESSED,
            CODEC_PPMD => return PPMD_COMPRESSED,
            CODEC_BZIP2 => return BZIP2_COMPRESSED,
            CODEC_DEFLATE => return DEFLATE_COMPRESSED,
            _ => {}
        }
    }
    UNCOMPRESSED
}

fn decompress_lzma(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    lzma_rs::lzma_decompress(&mut std::io::Cursor::new(data), &mut output)
        .map_err(|e| Error::Extract(format!("LZMA decompression failed: {e}")))?;
    Ok(output)
}

fn parse_unpack_info_for_aes(
    r: &mut SevenZipReader,
    aes_salt: &mut Vec<u8>,
    aes_iv: &mut Vec<u8>,
    number_cycles_power: &mut u8,
    found_aes: &mut bool,
) -> Result<(), Error> {
    let mut folders_count = 0usize;

    loop {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        match id[0] {
            0x0b => {
                // FOLDER
                let external = r.read_u8()?;
                folders_count = r.read_number()? as usize;

                if external == 0x00 {
                    for _ in 0..folders_count {
                        let num_coders = r.read_number()? as usize;
                        for ci in 0..num_coders {
                            let main_byte = r.read_u8()?;
                            let codec_id_len = (main_byte & 0x0f) as usize;
                            let _complex = main_byte & 0x10 != 0;
                            let attributes_present = main_byte & 0x20 != 0;
                            let _num_in = if main_byte & 0x40 != 0 { 2 } else { 1 };
                            let _num_out = if main_byte & 0x80 != 0 { 2 } else { 1 };

                            let codec_id = r.read_bytes(codec_id_len)?.to_vec();

                            if attributes_present {
                                let attr_len = r.read_number()? as usize;
                                let attrs = r.read_bytes(attr_len)?.to_vec();

                                if codec_id == CODEC_AES && ci == 0 && !*found_aes {
                                    let props = get_decoder_properties(&attrs);
                                    *aes_salt = props.salt;
                                    *aes_iv = props.iv;
                                    *number_cycles_power = props.number_cycles_power;
                                    *found_aes = true;
                                }
                            }
                        }
                        // Skip bind pairs
                        let num_bind = r.read_number()?;
                        for _ in 0..num_bind {
                            let _ = r.read_number()?;
                            let _ = r.read_number()?;
                        }
                        let num_packed = if num_coders > 1 { r.read_number()? } else { 0 };
                        for _ in 0..num_packed {
                            let _ = r.read_number()?;
                        }
                    }
                }
            }
            0x0c => {
                // UNPACK_SIZE
                let _ = r.read_number()?;
                for _ in 0..folders_count {
                    let _ = r.read_number()?;
                }
            }
            0x0d => {
                // NUM_UNPACK_STREAM
                let _ = r.read_number()?;
            }
            0x0e | 0x0f | 0x10 => {
                let count = r.read_number()? as usize;
                let _ = r.read_bool_vector(count)?;
            }
            0x11 => {
                let _ = r.read_u8()?;
                let _size = r.read_number()?;
                let _ = r.read_bytes(_size as usize)?;
            }
            0x12 | 0x13 | 0x14 => {
                let external = r.read_u8()?;
                if external == 0x01 {
                    let _ = r.read_number()?;
                } else {
                    let _ = r.read_number()?;
                    let all_def = r.read_u8()?;
                    if all_def != 0x01 {
                        let _ = r.read_bool_vector(folders_count)?;
                    }
                    for _ in 0..folders_count {
                        let _ = r.read_u64()?;
                    }
                }
            }
            0x15 => {
                let external = r.read_u8()?;
                if external != 0x01 {
                    let _ = r.read_number()?;
                    let all_def = r.read_u8()?;
                    if all_def != 0x01 {
                        let _ = r.read_bool_vector(folders_count)?;
                    }
                    for _ in 0..folders_count {
                        let _ = r.read_u32()?;
                    }
                }
            }
            0x0a => {
                // CRC (in unpack_info)
                let _ = r.read_number()?;
                let all_def = r.read_u8()?;
                if all_def != 0x01 {
                    let _ = r.read_bool_vector(folders_count)?;
                }
                for _ in 0..folders_count {
                    let _ = r.read_u32()?;
                }
            }
            _ => {
                break;
            }
        }
    }

    Ok(())
}

/// Scan the decompressed header to find CRC for the given folder index.
fn find_crc_in_header(buf: &[u8], target_folder: usize) -> Result<u32, Error> {
    let mut r = SevenZipReader::new(buf);

    // Skip to UNPACK_INFO section
    let hdr_type = r.read_id()?;
    if hdr_type != [HDR_HEADER] && hdr_type != [0x17] {
        // For decompressed data, first byte might be HEADER or ENCODED_HEADER
        // or it might be a direct stream
    }

    // If it's an ENCODED_HEADER, skip to the inner header
    if hdr_type == [0x17] {
        // Skip ARCHIVE_PROPERTIES
        let prop_id = r.read_id()?;
        if prop_id == [HDR_ARCHIVE_PROPERTIES] {
            loop {
                let id = r.read_id()?;
                if id == [HDR_END] {
                    break;
                }
                let _num = r.read_number()?;
                for _ in 0.._num {
                    let _ = r.read_number()?;
                }
            }
        }
    }

    // Now scan for HDR_UNPACK_INFO
    while r.pos < buf.len() {
        let id = r.read_id()?;
        if id == [HDR_END] {
            break;
        }
        if id == [HDR_UNPACK_INFO] || id == [0x07] {
            // Parse UNPACK_INFO, looking for CRC section
            let mut folders_count = 0usize;

            loop {
                let sub_id = r.read_id()?;
                if sub_id == [HDR_END] {
                    break;
                }
                match sub_id[0] {
                    0x0b => {
                        // FOLDER - count them
                        let _ = r.read_u8()?;
                        folders_count = r.read_number()? as usize;
                        // Skip folder definitions
                        for _ in 0..folders_count {
                            let num_coders = r.read_number()? as usize;
                            for _ in 0..num_coders {
                                let main_byte = r.read_u8()?;
                                let codec_id_len = (main_byte & 0x0f) as usize;
                                let attributes_present = main_byte & 0x20 != 0;
                                let _ = r.read_bytes(codec_id_len)?;
                                if attributes_present {
                                    let attr_len = r.read_number()? as usize;
                                    let _ = r.read_bytes(attr_len)?;
                                }
                            }
                            let num_bind = r.read_number()?;
                            for _ in 0..num_bind {
                                let _ = r.read_number()?;
                                let _ = r.read_number()?;
                            }
                            let num_packed = if num_coders > 1 { r.read_number()? } else { 0 };
                            for _ in 0..num_packed {
                                let _ = r.read_number()?;
                            }
                        }
                    }
                    0x0c => {
                        // UNPACK_SIZE
                        let _ = r.read_number()?;
                        for _ in 0..folders_count {
                            let _ = r.read_number()?;
                        }
                    }
                    0x0a => {
                        // CRC section
                        let _ = r.read_number()?;
                        let all_def = r.read_u8()?;
                        let defined = if all_def == 0x01 {
                            vec![true; folders_count]
                        } else {
                            r.read_bool_vector(folders_count)?
                        };

                        let mut crcs = Vec::new();
                        for i in 0..folders_count {
                            if defined[i] {
                                crcs.push(r.read_u32()?);
                            } else {
                                crcs.push(0);
                            }
                        }

                        if target_folder < crcs.len() {
                            return Ok(crcs[target_folder]);
                        }
                        return Ok(0);
                    }
                    0x0d => {
                        let _ = r.read_number()?;
                    }
                    0x0e | 0x0f | 0x10 => {
                        let count = r.read_number()? as usize;
                        let _ = r.read_bool_vector(count)?;
                    }
                    0x11 => {
                        let _ = r.read_u8()?;
                        let _size = r.read_number()?;
                        let _ = r.read_bytes(_size as usize)?;
                    }
                    0x12 | 0x13 | 0x14 => {
                        let external = r.read_u8()?;
                        if external == 0x01 {
                            let _ = r.read_number()?;
                        } else {
                            let _ = r.read_number()?;
                            let all_def = r.read_u8()?;
                            if all_def != 0x01 {
                                let _ = r.read_bool_vector(folders_count)?;
                            }
                            for _ in 0..folders_count {
                                let _ = r.read_u64()?;
                            }
                        }
                    }
                    0x15 => {
                        let external = r.read_u8()?;
                        if external != 0x01 {
                            let _ = r.read_number()?;
                            let all_def = r.read_u8()?;
                            if all_def != 0x01 {
                                let _ = r.read_bool_vector(folders_count)?;
                            }
                            for _ in 0..folders_count {
                                let _ = r.read_u32()?;
                            }
                        }
                    }
                    _ => {
                        break;
                    }
                }
            }
        }
    }

    Ok(0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_7z() {
        let ext = SevenZExtractor;
        assert!(ext.detect(b"7z\xbc\xaf\x27\x1c"));
        assert!(!ext.detect(b"PK\x03\x04rest"));
        assert!(!ext.detect(b"not a 7z file!!!"));
    }

    #[test]
    fn validate_hash() {
        let ext = SevenZExtractor;
        let line = HashLine {
            filename: "test.7z".into(),
            hash: "$7z$0$19$16$abcdef0123456789$16$0000000000000000$12345$100$90$deadbeef".into(),
        };
        assert!(ext.validate(&line));

        let bad = HashLine {
            filename: "test.7z".into(),
            hash: "$zip$0$19".into(),
        };
        assert!(!ext.validate(&bad));
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(b"\x00\x01\x0f\xff"), "00010fff");
        assert_eq!(hex_encode(b""), "");
    }

    #[test]
    fn get_decoder_properties_parses_attrs() {
        // First byte: cycles=19 (0x13), salt_len_hi=1, iv_len_hi=1 → 0x13 | 0x80 | 0x40 = 0xD3
        // Second byte: salt_len_lo=0 (→ total 1), iv_len_lo=0 (→ total 1) → 0x00
        // Then: 1 byte salt, 1 byte iv
        let attrs = vec![0xD3, 0x00, 0xAB, 0xCD];
        let props = get_decoder_properties(&attrs);
        assert_eq!(props.number_cycles_power, 19);
        assert_eq!(props.salt_len, 1);
        assert_eq!(props.salt, vec![0xAB]);
        assert_eq!(props.iv_len, 1);
        assert_eq!(props.iv[0], 0xCD);
    }

    #[test]
    fn codec_type_for_values() {
        assert_eq!(codec_type_for(0, 0), 0);
        assert_eq!(codec_type_for(1, 0), 1); // LZMA1
        assert_eq!(codec_type_for(2, 0), 2); // LZMA2
        assert_eq!(codec_type_for(0, 1), 0x10); // BCJ
    }
}

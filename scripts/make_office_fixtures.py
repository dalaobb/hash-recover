#!/usr/bin/env python3
"""Generate encrypted Office fixtures for office-extractor tests.

olefile is read-only, so this script embeds a minimal OLE compound-file
writer (version 3, no mini streams: every stream is padded to >= 4096 bytes).
Each fixture carries the exact record structures office2john.py inspects, so
the parser logic is exercised against a byte-accurate reference.

Reference hashes are produced by openwall's office2john.py (tools/).
"""

import base64
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "src-tauri" / "extractors" / "office" / "testdata"
REFERENCE_OUT_DIR = OUT_DIR / "reference"
TOOLS = ROOT / "tools"
USER_PW = "password123"

FIXTURES = [
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
]

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

SALT = bytes(range(16))
VERIFIER = bytes(range(16, 32))
VERIFIER_HASH = bytes(range(32, 52))
CSP_NAME = "Microsoft Enhanced Cryptographic Provider v1.0 ".encode("utf-16-le")  # 94 bytes
SECOND_BLOCK = b"\xbb" * 32


# ---------------------------------------------------------------------------
# Minimal OLE CFB writer
# ---------------------------------------------------------------------------

def stream_entry(name: str, obj_type: int, start_sector: int, size: int, child: int, right_sib: int = -1) -> bytes:
    name_bytes = name.encode("utf-16-le")
    if len(name_bytes) > 64:
        raise ValueError("stream name too long")
    entry = bytearray(128)
    entry[0 : len(name_bytes)] = name_bytes
    struct.pack_into("<H", entry, 64, len(name_bytes) + 2)
    entry[66] = obj_type  # 5 root, 2 stream, 1 storage
    entry[67] = 1  # black color
    struct.pack_into("<i", entry, 68, -1)  # left
    struct.pack_into("<i", entry, 72, right_sib)  # right
    struct.pack_into("<i", entry, 76, child)  # child
    struct.pack_into("<I", entry, 116, start_sector)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def write_cfb(path: Path, streams: dict):
    """streams: {name: bytes}. Every stream must be >= 4096 bytes."""
    # CFB directory entries must be ordered by uppercase name.
    ordered = sorted(streams.items(), key=lambda kv: kv[0].upper())
    names = [n for n, _ in ordered]
    contents = [c for _, c in ordered]
    for name, content in zip(names, contents):
        if len(content) < 4096:
            raise ValueError(f"stream {name} too small; pad to >= 4096")

    sector_size = 512
    # Split each stream into sectors; keep the real (unpadded) size per entry.
    data_sectors = []
    stream_sizes = []
    for content in contents:
        padded = content + b"\x00" * (-len(content) % sector_size)
        data_sectors.extend(
            padded[i : i + sector_size] for i in range(0, len(padded), sector_size)
        )
        stream_sizes.append(len(content))

    n_stream_sectors = len(data_sectors)
    n_dir_entries = 1 + len(names)
    n_dir_sectors = (n_dir_entries + 3) // 4
    n_fat_sectors = 1
    if n_stream_sectors + n_fat_sectors + n_dir_sectors > 128:
        raise ValueError("fixture too large for single-FAT layout")

    first_fat = n_stream_sectors
    first_dir = first_fat + n_fat_sectors
    total_sectors = n_stream_sectors + n_fat_sectors + n_dir_sectors

    # Build FAT entries.
    fat = [FREESECT] * (n_fat_sectors * 128)
    next_idx = 0
    for content in contents:
        padded = content + b"\x00" * (-len(content) % sector_size)
        count = len(padded) // sector_size
        for j in range(count):
            fat[next_idx + j] = ENDOFCHAIN if j == count - 1 else next_idx + j + 1
        next_idx += count
    fat[first_fat] = FATSECT
    fat[first_dir] = ENDOFCHAIN

    # Directory entries, linked through right-sibling pointers so tools that
    # walk the entry tree (olefile) can find every stream.
    start = 0
    entry_list = [stream_entry("Root Entry", 5, ENDOFCHAIN, 0, 1)]
    for i, name in enumerate(names):
        size = stream_sizes[i]
        right_sib = 2 + i if i + 1 < len(names) else -1
        entry_list.append(stream_entry(name, 2, start, size, -1, right_sib))
        start += len(contents[i]) // sector_size
    entries = b"".join(entry_list)
    entries += b"\x00" * (-len(entries) % sector_size)
    dir_sectors = [
        entries[i : i + sector_size] for i in range(0, len(entries), sector_size)
    ]
    if len(dir_sectors) != n_dir_sectors:
        raise ValueError("directory sector count mismatch")

    # Header.
    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 0x0003)  # major version
    struct.pack_into("<H", header, 28, 0xFFFE)  # byte order
    struct.pack_into("<H", header, 30, 9)  # sector shift
    struct.pack_into("<H", header, 32, 6)  # mini sector shift
    struct.pack_into("<I", header, 40, 0)  # number of directory sectors (v3)
    struct.pack_into("<I", header, 44, n_fat_sectors)
    struct.pack_into("<I", header, 48, first_dir)
    struct.pack_into("<I", header, 52, 0)  # transaction signature
    struct.pack_into("<I", header, 56, 0x1000)  # mini stream cutoff
    struct.pack_into("<I", header, 60, ENDOFCHAIN)  # first mini FAT (no mini streams)
    struct.pack_into("<I", header, 64, 0)  # number of mini FAT sectors
    struct.pack_into("<I", header, 68, NOSTREAM)  # first DIFAT
    struct.pack_into("<I", header, 72, 0)  # number of DIFAT sectors
    for i in range(109):
        struct.pack_into("<I", header, 76 + i * 4, first_fat if i < n_fat_sectors else FREESECT)

    blob = bytes(header)
    for s in data_sectors:
        blob += s
    for i in range(n_fat_sectors):
        blob += struct.pack("<128I", *fat[i * 128 : (i + 1) * 128])
    for s in dir_sectors:
        blob += s
    path.write_bytes(blob)


# ---------------------------------------------------------------------------
# Stream builders
# ---------------------------------------------------------------------------

def record(rec_type: int, data: bytes) -> bytes:
    return struct.pack("<HH", rec_type, len(data)) + data


def cryptoapi_header(key_size: int) -> bytes:
    csp = CSP_NAME
    header_length = 32 + len(csp)
    out = struct.pack("<I", 0)  # encryptionFlags
    out += struct.pack("<I", header_length)
    out += struct.pack("<II", 0, 0)  # skipFlags, sizeExtra
    out += struct.pack("<I", 0x6801)  # algId (RC4)
    out += struct.pack("<I", 0x8004)  # algHashId (SHA1)
    out += struct.pack("<I", key_size)
    out += struct.pack("<I", 1)  # providerType
    out += struct.pack("<II", 0, 0)  # unused, unused
    out += csp
    out += struct.pack("<I", 16)
    out += SALT
    out += VERIFIER
    out += struct.pack("<I", 20)
    out += VERIFIER_HASH
    return out


def pad_to(size: int, data: bytes, pattern: bytes = b"") -> bytes:
    out = bytearray(size)
    out[: len(data)] = data
    if pattern:
        for i in range(0, size, len(pattern)):
            out[i : i + len(pattern)] = pattern[: max(0, size - i)]
    return bytes(out)


def make_xls_rc4() -> bytes:
    data = b"\x01\x00\x01\x00\x01\x00" + SALT + VERIFIER + VERIFIER_HASH
    stream = record(0x2F, data)
    return pad_to(4096, stream)


def make_xls_cryptoapi(key_size: int) -> bytes:
    data = b"\x01\x00" + struct.pack("<HH", 2, 2) + cryptoapi_header(key_size)
    stream = record(0x2F, data)
    # RC4-40 needs a 32-byte window at absolute offset 1024 in the stream.
    if key_size == 40:
        body = bytearray(pad_to(4096, stream))
        body[1024:1056] = SECOND_BLOCK
        return bytes(body)
    return pad_to(4096, stream)


def make_doc_rc4() -> tuple:
    word = bytearray(pad_to(4096, b"\xec\xa5" + b"\x00" * 9 + b"\x01"))
    table = pad_to(4096, b"\x01\x00\x01\x00" + SALT + VERIFIER + VERIFIER_HASH)
    return {"WordDocument": word, "0Table": table}


def make_doc_cryptoapi(key_size: int) -> tuple:
    word = bytearray(pad_to(4096, b"\xec\xa5" + b"\x00" * 9 + b"\x01"))
    header = struct.pack("<HH", 2, 2) + cryptoapi_header(key_size)
    table = bytearray(pad_to(4096, header))
    if key_size == 40:
        table[512:544] = SECOND_BLOCK
    return {"WordDocument": word, "0Table": table}


def make_ppt_cryptoapi(key_size: int) -> dict:
    offset = 64
    current_user = bytearray(pad_to(4096, b"\x00" * 2 + struct.pack("<H", 0xF3D1) + struct.pack("<I", 0)))
    struct.pack_into("<I", current_user, 16, offset)

    persist_offset = offset + 8 + 30
    enc_header_offset = persist_offset + 8 + 4 + 4
    user_edit_atom = struct.pack("<I", 0)  # lastSlideRef
    user_edit_atom += struct.pack("<H", 0)  # version
    user_edit_atom += b"\x00\x00"  # minorVersion, majorVersion
    user_edit_atom += struct.pack("<I", 0)  # offsetLastEdit
    user_edit_atom += struct.pack("<I", persist_offset)
    user_edit_atom += struct.pack("<I", 1)  # docPersistIdRef
    user_edit_atom += struct.pack("<I", 2)  # persistIdSeed
    user_edit_atom += struct.pack("<HH", 0, 0)  # lastView, unused
    user_edit_atom += struct.pack("<H", 1)  # encryptSessionPersistIdRef

    doc = bytearray(pad_to(4096, b""))
    doc[0:32] = SECOND_BLOCK
    doc[offset : offset + 8] = b"\x00" * 2 + struct.pack("<H", 0x0FF5) + struct.pack("<I", 32)
    doc[offset + 8 : offset + 8 + 30] = user_edit_atom
    doc[persist_offset : persist_offset + 8] = b"\x00" * 2 + struct.pack("<H", 0xFFFF) + struct.pack("<I", 0)
    doc[persist_offset + 8 : persist_offset + 12] = b"\x00" * 4
    struct.pack_into("<I", doc, persist_offset + 12, enc_header_offset)
    enc = b"\x00" * 2 + struct.pack("<H", 0x0000) + struct.pack("<I", 0)
    enc += struct.pack("<HH", 2, 2) + cryptoapi_header(key_size)
    doc[enc_header_offset : enc_header_offset + len(enc)] = enc
    return {"Current User": current_user, "PowerPoint Document": doc}


def make_ooxml_2007() -> dict:
    header = struct.pack("<I", 32 + len(CSP_NAME))
    header += struct.pack("<II", 0, 0)  # skipFlags, sizeExtra
    header += struct.pack("<I", 0x660E)  # algId (AES-128)
    header += struct.pack("<I", 0x8004)  # algHashId (SHA1)
    header += struct.pack("<I", 128)  # keySize
    header += struct.pack("<I", 24)  # providerType
    header += struct.pack("<II", 0, 0)
    header += CSP_NAME
    header += struct.pack("<I", 16) + SALT + VERIFIER
    header += struct.pack("<I", 20) + VERIFIER_HASH
    stream = struct.pack("<HH", 4, 2) + struct.pack("<I", 0) + header
    return {"EncryptionInfo": pad_to(4096, stream)}


def make_ooxml_agile(hash_algo: str, key_bits: int) -> dict:
    salt = base64.b64encode(bytes(range(16))).decode()
    verifier_input = base64.b64encode(bytes(range(32))).decode()
    verifier_value = base64.b64encode(bytes(range(48))).decode()
    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
<keyData saltSize="16" blockSize="16" keyBits="{key_bits}" hashSize="{64 if hash_algo == 'SHA512' else 20}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{hash_algo}" saltValue="{salt}"/>
<dataIntegrity encryptedHmacKey="AA==" encryptedHmacValue="AA=="/>
<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="{key_bits}" hashSize="{64 if hash_algo == 'SHA512' else 20}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{hash_algo}" saltValue="{salt}" encryptedVerifierHashInput="{verifier_input}" encryptedVerifierHashValue="{verifier_value}"/></keyEncryptor></keyEncryptors>
</encryption>""".encode()
    stream = struct.pack("<HH", 4, 4) + struct.pack("<I", 0x40) + xml
    # Pad with XML-legal whitespace, not NULs: the reference parser feeds the
    # whole stream to an XML parser.
    stream += b" " * (4096 - len(stream))
    return {"EncryptionInfo": stream}


# ---------------------------------------------------------------------------
# Fixture assembly + reference capture
# ---------------------------------------------------------------------------

def make_fixtures():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_cfb(OUT_DIR / "xls_rc4.xls", {"Workbook": make_xls_rc4()})
    write_cfb(OUT_DIR / "xls_rc4_40.xls", {"Workbook": make_xls_cryptoapi(40)})
    write_cfb(OUT_DIR / "xls_rc4_128.xls", {"Workbook": make_xls_cryptoapi(128)})
    write_cfb(OUT_DIR / "doc_rc4.doc", make_doc_rc4())
    write_cfb(OUT_DIR / "doc_rc4_40.doc", make_doc_cryptoapi(40))
    write_cfb(OUT_DIR / "doc_rc4_128.doc", make_doc_cryptoapi(128))
    write_cfb(OUT_DIR / "ppt_rc4_40.ppt", make_ppt_cryptoapi(40))
    write_cfb(OUT_DIR / "ppt_rc4_128.ppt", make_ppt_cryptoapi(128))
    write_cfb(OUT_DIR / "docx_2007_aes128.docx", make_ooxml_2007())
    write_cfb(OUT_DIR / "xlsx_2010_sha1.xlsx", make_ooxml_agile("SHA1", 128))
    write_cfb(OUT_DIR / "pptx_2013_sha512.pptx", make_ooxml_agile("SHA512", 256))
    make_plain_docx(OUT_DIR / "plain.docx")


def make_plain_docx(path: Path):
    """A real, unencrypted docx (zip container) used to prove rejection."""
    import zipfile

    with zipfile.ZipFile(path, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/></Types>',
        )


def write_references():
    pdf2john = TOOLS / "office2john.py"
    if not pdf2john.exists():
        print("warning: office2john.py missing, skipping reference files", file=sys.stderr)
        return
    REFERENCE_OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in FIXTURES:
        pdf = OUT_DIR / name
        out = subprocess.run(
            [sys.executable, str(pdf2john), str(pdf)], capture_output=True, text=True
        )
        if out.returncode != 0:
            print(f"warning: office2john.py failed for {name}: {out.stderr}", file=sys.stderr)
            continue
        (REFERENCE_OUT_DIR / (name + ".hash")).write_text(out.stdout.strip())


def main():
    make_fixtures()
    write_references()
    print(f"fixtures written to {OUT_DIR}")


if __name__ == "__main__":
    sys.exit(main())

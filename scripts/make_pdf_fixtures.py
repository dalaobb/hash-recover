#!/usr/bin/env python3
"""Generate encrypted PDF fixtures for pdf-extractor tests.

Produces three PDFs covering the standard security handler revisions:
  - rc4.pdf        RC4-128   (R=3, V=2)
  - aes128.pdf     AES-128   (R=4, V=4)
  - aes256.pdf     AES-256   (R=6, V=5)
All use the same user password for predictable fixtures.
"""

import sys
from pathlib import Path

USER_PW = "password123"
OWNER_PW = "ownerpass"
OUT_DIR = Path(__file__).resolve().parent.parent / "src-tauri" / "extractors" / "pdf" / "testdata"
REFERENCE_OUT_DIR = OUT_DIR / "reference"
FIXTURES = ["rc4", "aes128", "aes256"]


def make_rc4(out: Path):
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.encrypt(user_password=USER_PW, owner_password=OWNER_PW, algorithm="RC4-128")
    with open(out, "wb") as f:
        w.write(f)


def make_aes128(out: Path):
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.encrypt(user_password=USER_PW, owner_password=OWNER_PW, algorithm="AES-128")
    with open(out, "wb") as f:
        w.write(f)


def make_aes256(out: Path):
    import pikepdf

    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    enc = pikepdf.Encryption(owner=OWNER_PW, user=USER_PW, R=6, aes=True)
    pdf.save(out, encryption=enc)


def make_plain(out: Path):
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    with open(out, "wb") as f:
        w.write(f)


def write_references():
    """Capture reference hashes from openwall pdf2john.py (pyhanko)."""
    import subprocess

    pdf2john = Path(__file__).resolve().parent.parent / "tools" / "pdf2john.py"
    if not pdf2john.exists():
        print("warning: reference tool missing, skipping reference files", file=sys.stderr)
        return
    REFERENCE_OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in FIXTURES:
        pdf = OUT_DIR / f"{name}.pdf"
        out = subprocess.run(
            [sys.executable, str(pdf2john), str(pdf)],
            capture_output=True,
            text=True,
        )
        if out.returncode != 0:
            print(f"warning: pdf2john.py failed for {name}: {out.stderr}", file=sys.stderr)
            continue
        (REFERENCE_OUT_DIR / f"{name}.hash").write_text(out.stdout.strip())


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    make_plain(OUT_DIR / "plain.pdf")
    make_rc4(OUT_DIR / "rc4.pdf")
    make_aes128(OUT_DIR / "aes128.pdf")
    make_aes256(OUT_DIR / "aes256.pdf")
    write_references()
    print(f"fixtures written to {OUT_DIR}")


if __name__ == "__main__":
    sys.exit(main())

# AGENTS.md

## Project Overview

HashRecover is a cross-platform desktop password recovery assistant.

The goal is to provide a user-friendly GUI workflow for:

1. Selecting encrypted files
2. Detecting file formats
3. Extracting password hashes
4. Selecting recovery strategies
5. Running recovery engines
6. Displaying progress and results

The application hides the complexity of:

- John the Ripper
- Hashcat
- Hash modes
- Attack modes
- Wordlists
- GPU configuration

Users should not need to understand command-line tools.

## Technology Stack

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Zustand for application state
- React Query for async operations

### Desktop Runtime

- Tauri 2.x
- Rust backend

### Recovery Engines

- John the Ripper
- Hashcat

### Supported Platforms

Primary:

- Windows
- Linux
- macOS

## Core Design Principles

### 1. User First

Never expose low-level concepts by default.

Avoid displaying:

- hash mode numbers
- attack mode numbers
- command arguments
- internal extractor names

Bad:

Hashcat -m 17200 -a 3

Good:

ZIP AES password recovery

### 2. Layer Separation

The project must maintain strict separation:

```
UI
 |
Application Logic
 |
Recovery Service
 |
Extractor Layer
 |
External Tools
```

Never call:

- hashcat
- john
- external binaries

directly from React components.

## Architecture

### Frontend Structure

### Rust Structure

## Data Flow

The correct workflow:

```
User selects file
    ↓
File Analyzer
    ↓
Format Detection
    ↓
Hash Extraction
    ↓
Hash Validation
    ↓
Recovery Strategy Selection
    ↓
Hashcat Execution
    ↓
Progress Streaming
    ↓
Result Display
```

## File Extraction Rules

### Never assume one extractor works for all files.

Every extractor must provide:

- detect()
- extract()
- validate()

Example:

ZipExtractor

- detect():
  check zip signature
- extract():
  call zip2john
- validate():
  check generated hash

### Supported Formats and Extractor Toolchain

| Format  | John extractor  | Type       | Runtime |
| ------- | --------------- | ---------- | ------- |
| ZIP     | zip2john        | Native C   | none    |
| RAR     | rar2john        | Native C   | none    |
| 7z      | 7z2john.pl      | Perl       | Perl    |
| PDF     | pdf2john.pl     | Perl       | Perl    |
| Office  | office2john.py  | Python     | Python  |

Do not assume every extractor is an executable. In John the Ripper jumbo:

- zip2john and rar2john are compiled C tools shipped inside the john binary (no runtime).
- 7z2john.pl and pdf2john.pl are Perl scripts.
- office2john.py is a Python script.

word (doc, docx), excel (xls, xlsx) and powerpoint (ppt, pptx) all share office2john.py as the John reference extractor.

Do not rely on the system having Perl or Python installed. See External Binary Management.

## External Binary Management

External tools are bundled with the application.

Never require users to install:

- Python
- Perl
- John
- Hashcat
- CUDA

The application must work after installation.

### Product Variants

HashRecover is released as multiple apps built from one codebase:

- HashRecover for ZIP
- HashRecover for RAR
- HashRecover for 7z
- HashRecover for PDF
- HashRecover for Word
- HashRecover for Excel
- HashRecover for PowerPoint
- HashRecover for Office (all Office formats)
- HashRecover All (all supported formats)

Each variant:

- Has its own product name and bundle identifier.
- Bundles only the engine programs required by its formats.
- Restricts the file picker to its supported formats.
- Hides unsupported formats from the UI.

Variant to formats:

| Variant                    | Formats                    |
| -------------------------- | -------------------------- |
| HashRecover for ZIP        | zip                        |
| HashRecover for RAR        | rar                        |
| HashRecover for 7z         | 7z                         |
| HashRecover for PDF        | pdf                        |
| HashRecover for Word       | word (doc, docx)           |
| HashRecover for Excel      | excel (xls, xlsx)          |
| HashRecover for PowerPoint | powerpoint (ppt, pptx)     |
| HashRecover for Office     | word, excel, powerpoint    |
| HashRecover All            | zip, rar, 7z, pdf, word, excel, powerpoint |

A format id maps to its extension filter and to its extractor program. word, excel and powerpoint share one extractor (office-extractor); the Office variant is their union.

### Engine Layout

Each supported format is backed by one self-contained native Rust extractor program. Extractors are internal components, not user-facing apps.

Per-format extractor programs:

- zip-extractor
- rar-extractor
- sevenz-extractor
- pdf-extractor
- office-extractor

word, excel and powerpoint share the single office-extractor; their variants only restrict the file picker and UI to their own extensions.

CLI contract:

- Read input file, run detect(), extract(), validate().
- Print John/Hashcat-compatible hash lines to stdout.
- Exit code and stdout/stderr must be machine-readable.

Bundling by variant:

- Single-format variant ships: 1 extractor + Hashcat + John.
- Office variant ships: 1 extractor (office) + Hashcat + John.
- All-format variant ships: 5 extractors + Hashcat + John.

The John jumbo scripts (7z2john.pl, pdf2john.pl, office2john.py) are reference implementations only. Port their logic into the Rust extractors and do not bundle Perl/Python runtimes.

### Build Profiles

A variant is a build-time profile. One codebase produces every variant.

- src-tauri/tauri.conf.json: shared base config.
- src-tauri/tauri.<variant>.json: per-variant overrides (productName, identifier, externalBin, resources).
- scripts/build-variant.mjs: runs `tauri build --config tauri.conf.json --config tauri.<variant>.json`.
- The Rust backend reads HASHRECOVER_VARIANT at compile time and exposes the active variant via get_app_config().
- The frontend derives supported formats, file picker filters, and visible format cards from get_app_config(). It never hardcodes the format list.

### File Type Restriction

The file picker and the analyzer both enforce the variant's format list.

- File picker: extension filter restricted to the variant's supported formats.
- Analyzer: content-signature detection (detect()); reject files outside the variant's formats with a friendly message.
- Never let the user select a format the variant does not support.

### Bundled Third-Party Binaries

Only two external binaries are bundled, next to the native extractor programs:

- Hashcat - recovery engine, GPU acceleration.
- John the Ripper - recovery engine, CPU fallback.

Both ship as official per-platform builds. Never build or install them on the user machine.

### Platform Bundles

| Component             | Windows          | macOS x64/arm64      | Linux                    |
| --------------------- | ---------------- | -------------------- | ------------------------ |
| Extractor programs    | Rust sidecar     | Rust sidecar         | Rust sidecar             |
| Hashcat               | official win pkg | official mac pkg     | official linux pkg       |
| John the Ripper       | official win zip | john-packages build  | self-built in CI (old glibc base image) |

### Tauri Bundling Rules

- Single-file binaries (extractors, hashcat, john) are bundled as Tauri sidecars (externalBin) with the platform triple suffix (e.g. hashcat-x86_64-pc-windows-msvc.exe).
- Directory-shaped payloads (wordlists, hashcat kernels, john config) are bundled as Tauri resources.
- On first run, resources are unpacked into app_data_dir, never Program Files (write permission).
- On startup the engine layer validates each sidecar: exists, executable bit set, self-check passes.
- A missing or broken engine degrades gracefully (hide that format), never crashes the app.

## Hash Normalization Layer

All extracted hashes must pass through:

HashNormalizer

Responsibilities:

- Validate format
- Check length
- Remove unsupported data
- Select compatible engine
- Detect Hashcat limitations

Example:

```
John output
    ↓
HashNormalizer
    ↓
Hashcat compatible hash
```

## Recovery Engine

The frontend should use friendly concepts.

Internal mapping:

| User Concept              | Internal          |
| ------------------------- | ----------------- |
| Common passwords          | Dictionary attack |
| Remember part of password | Mask/Hybrid       |
| Password habits           | Rule attack       |
| Unknown password          | Brute force       |

Never expose:

- -a 0
- -a 3
- -a 6
- -a 7

## Attack Strategy Model

Example:

```ts
interface RecoveryStrategy {
  type: "dictionary" | "partial" | "pattern" | "bruteforce";

  options: {
    minLength?: number;

    maxLength?: number;

    charset?: string;

    dictionary?: string;
  };
}
```

## GPU Handling

The application should automatically detect:

- NVIDIA GPU
- AMD GPU
- Apple Silicon
- CPU fallback

Do not require users to configure:

- CUDA
- OpenCL
- drivers

Display:

Detected GPU:

RTX 5070 Ti

Acceleration:

Enabled

## UI Guidelines

Visual Style

Theme:
Dark security dashboard

Colors:

Background: #0B0F14

Card: #151B23

Primary: #22C55E

Danger: #EF4444

## User Flow

Preferred flow:

```
Home

 ↓

Select File

 ↓

Analyze

 ↓

Choose Recovery Method

 ↓

Configure

 ↓

Run

 ↓

Result
```

Avoid complex wizard steps.

## Error Handling

Never show raw errors.

Bad:

- spawn hashcat ENOENT

Good:

- Recovery engine unavailable.
- Please reinstall HashRecover.

Log technical details internally.

## Logging

Use structured logs.

Example:

```
{
 timestamp,
 module,
 event,
 status
}
```

Do not log:

- recovered passwords
- user files
- sensitive content

## Security Rules

Never:

- Upload user files
- Send hashes remotely
- Store recovered passwords permanently
- Collect telemetry without consent

## Testing Requirements

Before committing:

Frontend:

```
pnpm run lint
pnpm run test
pnpm run build
```

Rust:

```
cargo fmt
cargo clippy
cargo test
```

## Git Commit Style

Use conventional commits.
Examples:

```
feat: add zip file analyzer

fix: handle invalid hash extraction

refactor: separate recovery engine

docs: update architecture guide
```

## AI Agent Rules

When modifying code:

1. Understand existing architecture first.
1. Do not create duplicate services.
1. Do not bypass Rust backend.
1. Do not add dependencies without justification.
1. Prefer simple solutions.
1. Keep UI beginner-friendly.
1. Preserve cross-platform compatibility.

Before implementing new features:

Explain:

- affected modules
- design approach
- possible risks

Then modify code.

## Product Direction

HashRecover is not a Hashcat GUI.

It is:

"A simple password recovery assistant powered by professional recovery engines."

The complexity belongs inside the engine layer.

The user experience belongs to HashRecover.

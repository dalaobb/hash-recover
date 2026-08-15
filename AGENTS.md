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

## External Binary Management

External tools are bundled with the application.

Never require users to install:

- Python
- Perl
- John
- Hashcat
- CUDA

The application must work after installation.

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

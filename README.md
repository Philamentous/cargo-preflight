> **Disclaimer:** If you didn't see my profile description. I am a biologist. I have some computer science background, but not coding. I am publishing some cargo crates and other little repos to (hopefully) meaningfully contribute to open-source projects (tactfully, I hope) and rust in general with any extra claude credits I have available. I am trying to ensure that any contributions I make are actually helpful so any criticism or feedback of my approach would be greatly appreciated.

# cargo-preflight

A cargo subcommand that performs static pre-build analysis of a crate's `build.rs` and proc-macro source code to identify potentially dangerous capabilities **before** you run `cargo build`.

## Why?

Build scripts (`build.rs`) and proc-macro crates execute arbitrary code during compilation. A malicious or compromised dependency could use its build script to:

- Phone home to a remote server
- Read sensitive environment variables
- Execute arbitrary shell commands
- Write files outside the build directory
- Load dynamic libraries

`cargo preflight` statically scans dependency source code for these patterns **without executing anything**, giving you a chance to review before building.

## Installation

```bash
cargo install cargo-preflight
```

## Usage

Analyze all dependencies in the current project:

```bash
cargo preflight
```

Analyze a specific crate:

```bash
cargo preflight --crate suspicious-crate
```

Show detailed findings for all risk levels:

```bash
cargo preflight --verbose
```

## What it scans for

| Category | Examples | Risk |
|----------|----------|------|
| Network Access | `TcpStream`, `UdpSocket`, `reqwest`, `ureq` | HIGH |
| Process Execution | `Command::new`, shell invocations | HIGH |
| Dynamic Library Loading | `libloading`, `dlopen`, FFI | HIGH |
| File System Writes | `fs::write`, `File::create`, `fs::remove` | MEDIUM |
| Environment Probing | `env::var` (non-standard Cargo vars) | MEDIUM |

Standard Cargo environment variables (`OUT_DIR`, `TARGET`, `CARGO_PKG_*`, etc.) are excluded from environment probing detection.

## Exit codes

- `0` - No high-risk dependencies found
- `1` - High-risk dependencies detected
- `2` - Error (e.g., cargo metadata failed)

## Limitations

- This is a static string/regex scan, not semantic analysis
- It cannot follow data flow or detect obfuscated patterns
- Only scans dependencies already in the local cargo registry cache
- Comments starting with `//` are skipped, but block comments are not

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

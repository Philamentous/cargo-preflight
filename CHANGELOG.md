# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-05

### Added

- Initial release of cargo-preflight
- Static analysis of `build.rs` files in dependencies
- Static analysis of proc-macro crate source files
- Detection categories: Network Access, File System Writes, Process Execution, Environment Probing, Dynamic Library Loading
- Risk level classification: LOW (pure codegen), MEDIUM (expected build activities), HIGH (network, process exec, suspicious ops)
- Colored terminal output grouped by risk level
- `--crate` flag to analyze a specific dependency
- `--verbose` flag for detailed findings at all risk levels
- Exit code 0 for no high-risk, 1 for high-risk detected, 2 for errors
- Standard Cargo environment variable allowlist (OUT_DIR, TARGET, etc. not flagged)
- Comment skipping (single-line `//` comments)

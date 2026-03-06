use std::fs;
use std::path::Path;

use crate::metadata::AnalyzablePackage;
use crate::patterns::{self, Category, Finding, RiskPattern};

/// Risk level for a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// What kind of source was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    BuildScript,
    ProcMacro,
}

/// Result of scanning a single package.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub package_name: String,
    pub version: String,
    pub risk_level: RiskLevel,
    pub scan_kind: ScanKind,
    pub findings: Vec<Finding>,
}

/// Scan all packages and return results.
pub fn scan_packages(packages: &[AnalyzablePackage]) -> Vec<ScanResult> {
    let patterns = patterns::build_patterns();
    let mut results = Vec::new();

    for pkg in packages {
        if pkg.has_build_script {
            if let Some(result) = scan_build_script(pkg, &patterns) {
                results.push(result);
            }
        }
        if pkg.is_proc_macro {
            if let Some(result) = scan_proc_macro(pkg, &patterns) {
                results.push(result);
            }
        }
    }

    // Sort by risk level (high first)
    results.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));
    results
}

/// Scan a package's build.rs file.
fn scan_build_script(pkg: &AnalyzablePackage, patterns: &[RiskPattern]) -> Option<ScanResult> {
    let build_rs_path = pkg.source_dir.join("build.rs");
    let content = fs::read_to_string(&build_rs_path).ok()?;
    let findings = patterns::scan_content(&content, patterns);
    let risk_level = determine_risk_level(&findings);

    Some(ScanResult {
        package_name: pkg.name.clone(),
        version: pkg.version.clone(),
        risk_level,
        scan_kind: ScanKind::BuildScript,
        findings,
    })
}

/// Scan a proc-macro crate's source files.
fn scan_proc_macro(pkg: &AnalyzablePackage, patterns: &[RiskPattern]) -> Option<ScanResult> {
    let src_dir = pkg.source_dir.join("src");
    let mut all_findings = Vec::new();

    // Scan all .rs files in the source directory
    if let Ok(entries) = collect_rs_files(&src_dir) {
        for path in entries {
            if let Ok(content) = fs::read_to_string(&path) {
                let mut findings = patterns::scan_content(&content, patterns);
                all_findings.append(&mut findings);
            }
        }
    }

    // Also try lib.rs at the crate root
    let lib_rs = pkg.source_dir.join("src").join("lib.rs");
    if !lib_rs.exists() {
        // Some proc-macro crates might have lib.rs at root
        let root_lib = pkg.source_dir.join("lib.rs");
        if let Ok(content) = fs::read_to_string(root_lib) {
            let mut findings = patterns::scan_content(&content, patterns);
            all_findings.append(&mut findings);
        }
    }

    let risk_level = determine_risk_level(&all_findings);

    Some(ScanResult {
        package_name: pkg.name.clone(),
        version: pkg.version.clone(),
        risk_level,
        scan_kind: ScanKind::ProcMacro,
        findings: all_findings,
    })
}

/// Recursively collect all .rs files in a directory.
fn collect_rs_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_rs_files(&path)?);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }

    Ok(files)
}

/// Determine the overall risk level based on findings.
fn determine_risk_level(findings: &[Finding]) -> RiskLevel {
    if findings.is_empty() {
        return RiskLevel::Low;
    }

    let has_high_risk = findings.iter().any(|f| f.category.is_high_risk());

    if has_high_risk {
        return RiskLevel::High;
    }

    // File system writes and env probing are medium risk
    let has_medium_indicators = findings
        .iter()
        .any(|f| matches!(f.category, Category::FileSystemWrite | Category::EnvironmentProbing));

    if has_medium_indicators {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    #[test]
    fn test_determine_risk_level_empty() {
        assert_eq!(determine_risk_level(&[]), RiskLevel::Low);
    }

    #[test]
    fn test_determine_risk_level_network() {
        let findings = vec![Finding {
            category: Category::NetworkAccess,
            line_number: 1,
            matched_text: "TcpStream::connect".to_string(),
        }];
        assert_eq!(determine_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_determine_risk_level_process() {
        let findings = vec![Finding {
            category: Category::ProcessExecution,
            line_number: 1,
            matched_text: "Command::new".to_string(),
        }];
        assert_eq!(determine_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_determine_risk_level_dynamic_lib() {
        let findings = vec![Finding {
            category: Category::DynamicLibraryLoading,
            line_number: 1,
            matched_text: "libloading::Library".to_string(),
        }];
        assert_eq!(determine_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_determine_risk_level_fs_write() {
        let findings = vec![Finding {
            category: Category::FileSystemWrite,
            line_number: 1,
            matched_text: "fs::write".to_string(),
        }];
        assert_eq!(determine_risk_level(&findings), RiskLevel::Medium);
    }

    #[test]
    fn test_determine_risk_level_env_probing() {
        let findings = vec![Finding {
            category: Category::EnvironmentProbing,
            line_number: 1,
            matched_text: "env::var".to_string(),
        }];
        assert_eq!(determine_risk_level(&findings), RiskLevel::Medium);
    }

    #[test]
    fn test_determine_risk_level_mixed_picks_highest() {
        let findings = vec![
            Finding {
                category: Category::FileSystemWrite,
                line_number: 1,
                matched_text: "fs::write".to_string(),
            },
            Finding {
                category: Category::NetworkAccess,
                line_number: 5,
                matched_text: "reqwest::get".to_string(),
            },
        ];
        assert_eq!(determine_risk_level(&findings), RiskLevel::High);
    }

    #[test]
    fn test_scan_result_struct() {
        let result = ScanResult {
            package_name: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            risk_level: RiskLevel::Low,
            scan_kind: ScanKind::BuildScript,
            findings: vec![],
        };
        assert_eq!(result.package_name, "test-crate");
        assert_eq!(result.scan_kind, ScanKind::BuildScript);
    }

    #[test]
    fn test_collect_rs_files_nonexistent_dir() {
        let files = collect_rs_files(Path::new("/nonexistent/path"));
        assert!(files.is_ok());
        assert!(files.unwrap().is_empty());
    }

    #[test]
    fn test_collect_rs_files_with_temp_dir() {
        let tmp = std::env::temp_dir().join("cargo-preflight-test-collect");
        let src = tmp.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("lib.rs"), "fn main() {}").unwrap();
        fs::write(src.join("util.rs"), "fn helper() {}").unwrap();
        fs::write(src.join("not_rust.txt"), "not rust").unwrap();

        let files = collect_rs_files(&src).unwrap();
        assert_eq!(files.len(), 2, "Should find exactly 2 .rs files");
        assert!(files.iter().all(|f| f.extension().unwrap() == "rs"));

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_scan_build_script_with_temp_file() {
        let tmp = std::env::temp_dir().join("cargo-preflight-test-scan");
        fs::create_dir_all(&tmp).unwrap();
        fs::write(
            tmp.join("build.rs"),
            r#"
use std::process::Command;
fn main() {
    let output = Command::new("gcc").arg("foo.c").output().unwrap();
    std::fs::write(std::env::var("OUT_DIR").unwrap().as_str(), "generated");
}
"#,
        )
        .unwrap();

        let pkg = AnalyzablePackage {
            name: "test-pkg".to_string(),
            version: "0.1.0".to_string(),
            source_dir: tmp.clone(),
            has_build_script: true,
            is_proc_macro: false,
        };

        let patterns = patterns::build_patterns();
        let result = scan_build_script(&pkg, &patterns).unwrap();

        assert_eq!(result.package_name, "test-pkg");
        assert_eq!(result.risk_level, RiskLevel::High); // Command::new is high risk
        assert!(!result.findings.is_empty());

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_scan_packages_sorts_by_risk() {
        let tmp = std::env::temp_dir().join("cargo-preflight-test-sort");
        let low_dir = tmp.join("low-pkg");
        let high_dir = tmp.join("high-pkg");
        fs::create_dir_all(&low_dir).unwrap();
        fs::create_dir_all(&high_dir).unwrap();

        // Low risk: clean build script
        fs::write(
            low_dir.join("build.rs"),
            r#"
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
        )
        .unwrap();

        // High risk: network access
        fs::write(
            high_dir.join("build.rs"),
            r#"
fn main() {
    let stream = std::net::TcpStream::connect("evil.com:1234").unwrap();
}
"#,
        )
        .unwrap();

        let packages = vec![
            AnalyzablePackage {
                name: "low-pkg".to_string(),
                version: "1.0.0".to_string(),
                source_dir: low_dir,
                has_build_script: true,
                is_proc_macro: false,
            },
            AnalyzablePackage {
                name: "high-pkg".to_string(),
                version: "1.0.0".to_string(),
                source_dir: high_dir,
                has_build_script: true,
                is_proc_macro: false,
            },
        ];

        let results = scan_packages(&packages);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].risk_level, RiskLevel::High);
        assert_eq!(results[0].package_name, "high-pkg");

        fs::remove_dir_all(&tmp).unwrap();
    }
}

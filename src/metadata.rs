use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A dependency package that has either a build script or is a proc-macro crate.
#[derive(Debug, Clone)]
pub struct AnalyzablePackage {
    pub name: String,
    pub version: String,
    pub source_dir: PathBuf,
    pub has_build_script: bool,
    pub is_proc_macro: bool,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
    manifest_path: String,
    source: Option<String>,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    kind: Vec<String>,
    #[allow(dead_code)]
    name: String,
}

/// Run `cargo metadata` and return packages that have build scripts or are proc-macros.
/// Only returns external dependencies (not workspace members).
pub fn get_dependency_packages(manifest_dir: &str) -> Result<Vec<AnalyzablePackage>, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest_dir)
        .output()
        .map_err(|e| format!("Failed to run cargo metadata: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cargo metadata failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let metadata: CargoMetadata =
        serde_json::from_str(&stdout).map_err(|e| format!("Failed to parse metadata: {}", e))?;

    let workspace_member_names: Vec<String> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| extract_name_from_id(id))
        .collect();

    let mut analyzable = Vec::new();

    for pkg in &metadata.packages {
        // Skip workspace members (the user's own code)
        if workspace_member_names.contains(&pkg.name) {
            continue;
        }

        // Only analyze registry dependencies (source is Some)
        if pkg.source.is_none() {
            continue;
        }

        let has_build_script = pkg
            .targets
            .iter()
            .any(|t| t.kind.contains(&"custom-build".to_string()));

        let is_proc_macro = pkg
            .targets
            .iter()
            .any(|t| t.kind.contains(&"proc-macro".to_string()));

        if has_build_script || is_proc_macro {
            let manifest_path = Path::new(&pkg.manifest_path);
            let source_dir = manifest_path
                .parent()
                .unwrap_or(Path::new("."))
                .to_path_buf();

            analyzable.push(AnalyzablePackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                source_dir,
                has_build_script,
                is_proc_macro,
            });
        }
    }

    Ok(analyzable)
}

/// Extract package name from a cargo metadata package ID.
/// IDs look like: "path+file:///some/path#name@0.1.0"
/// or: "registry+https://...#name@version"
fn extract_name_from_id(id: &str) -> Option<String> {
    // The name is after the '#' and before the '@'
    let after_hash = id.split('#').nth(1)?;
    let name = after_hash.split('@').next()?;
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_name_from_path_id() {
        let id = "path+file:///home/user/project#my-crate@0.1.0";
        assert_eq!(extract_name_from_id(id), Some("my-crate".to_string()));
    }

    #[test]
    fn test_extract_name_from_registry_id() {
        let id = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228";
        assert_eq!(extract_name_from_id(id), Some("serde".to_string()));
    }

    #[test]
    fn test_extract_name_from_invalid_id() {
        assert_eq!(extract_name_from_id("no-hash-here"), None);
    }

    #[test]
    fn test_metadata_deserialization() {
        let json = r#"{
            "packages": [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "manifest_path": "/tmp/test/Cargo.toml",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "targets": [
                        { "kind": ["lib"], "name": "test-pkg" },
                        { "kind": ["custom-build"], "name": "build-script-build" }
                    ]
                },
                {
                    "name": "my-app",
                    "version": "0.1.0",
                    "manifest_path": "/home/user/project/Cargo.toml",
                    "source": null,
                    "targets": [
                        { "kind": ["bin"], "name": "my-app" }
                    ]
                }
            ],
            "workspace_members": ["path+file:///home/user/project#my-app@0.1.0"]
        }"#;

        let metadata: CargoMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.packages.len(), 2);
        assert_eq!(metadata.workspace_members.len(), 1);

        // Check that filtering works
        let workspace_names: Vec<String> = metadata
            .workspace_members
            .iter()
            .filter_map(|id| extract_name_from_id(id))
            .collect();
        assert_eq!(workspace_names, vec!["my-app".to_string()]);

        // test-pkg should be analyzable (has build script, is registry dep, not workspace member)
        let pkg = &metadata.packages[0];
        assert!(pkg.source.is_some());
        assert!(!workspace_names.contains(&pkg.name));
        assert!(pkg
            .targets
            .iter()
            .any(|t| t.kind.contains(&"custom-build".to_string())));
    }
}

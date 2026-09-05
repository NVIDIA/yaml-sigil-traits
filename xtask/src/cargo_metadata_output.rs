// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Typed parsing for bounded Cargo metadata output.

use std::str;

use cargo_metadata::{Metadata, MetadataCommand};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};

pub(crate) fn parse_bounded(output: &[u8], invalid_context: &str) -> Result<Metadata, String> {
    bounded_process::require_within_limit(
        output,
        VALIDATION_OUTPUT_LIMITS.stdout,
        "Cargo metadata",
    )
    .map_err(|error| error.to_string())?;
    let output = str::from_utf8(output).map_err(|error| format!("{invalid_context}: {error}"))?;
    MetadataCommand::parse(output).map_err(|error| format!("{invalid_context}: {error}"))
}

pub(crate) fn publishes_to_crates_io(publish: Option<&[String]>) -> Result<bool, String> {
    match publish {
        None => Ok(true),
        Some([]) => Ok(false),
        Some(registries) if registries.iter().any(|registry| registry == "crates-io") => Ok(true),
        Some(_) => Err("a publishable release package excludes crates-io".to_string()),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    use serde_json::{Value, json};

    pub(crate) fn metadata(workspace_root: &Path, packages: Vec<Value>) -> Value {
        let workspace_members: Vec<_> = packages
            .iter()
            .filter(|package| package.get("source") == Some(&Value::Null))
            .filter_map(|package| package.get("id").cloned())
            .collect();
        let target_directory = workspace_root.join("target");
        json!({
            "packages": packages,
            "workspace_members": workspace_members,
            "workspace_default_members": workspace_members,
            "resolve": null,
            "workspace_root": fixture_path(workspace_root),
            "target_directory": fixture_path(&target_directory),
            "build_directory": fixture_path(&target_directory),
            "metadata": null,
            "version": 1
        })
    }

    pub(crate) fn package(
        name: &str,
        version: &str,
        source: Option<&str>,
        manifest_path: &Path,
        publish: Option<&[&str]>,
        dependencies: Vec<Value>,
        targets: Vec<Value>,
    ) -> Value {
        let package_root = manifest_path
            .parent()
            .expect("fixture manifest has a parent directory");
        let id = match source {
            Some(source) => format!("{source}#{name}@{version}"),
            None => format!(
                "path+file://{}#{name}@{version}",
                fixture_path(package_root)
            ),
        };
        json!({
            "name": name,
            "version": version,
            "authors": [],
            "id": id,
            "source": source,
            "description": null,
            "dependencies": dependencies,
            "license": "Apache-2.0",
            "license_file": null,
            "targets": targets,
            "features": {},
            "manifest_path": fixture_path(manifest_path),
            "categories": [],
            "keywords": [],
            "readme": null,
            "repository": null,
            "homepage": null,
            "documentation": null,
            "edition": "2024",
            "metadata": null,
            "links": null,
            "publish": publish,
            "default_run": null,
            "rust_version": "1.95"
        })
    }

    pub(crate) fn target(name: &str, kind: &str, src_path: &Path) -> Value {
        let crate_type = if kind == "lib" { "lib" } else { "bin" };
        json!({
            "name": name,
            "kind": [kind],
            "crate_types": [crate_type],
            "required-features": [],
            "src_path": fixture_path(src_path),
            "edition": "2024",
            "doctest": kind == "lib",
            "test": true,
            "doc": kind == "lib"
        })
    }

    pub(crate) fn dependency(
        name: &str,
        requirement: &str,
        source: Option<&str>,
        registry: Option<&str>,
        rename: Option<&str>,
        dependency_path: Option<&Path>,
    ) -> Value {
        json!({
            "name": name,
            "source": source,
            "req": requirement,
            "kind": null,
            "rename": rename,
            "optional": false,
            "uses_default_features": true,
            "features": [],
            "target": null,
            "registry": registry,
            "path": dependency_path.map(fixture_path)
        })
    }

    pub(crate) fn encoded(metadata: &Value) -> Vec<u8> {
        serde_json::to_vec(metadata).expect("serialize Cargo metadata fixture")
    }

    fn fixture_path(path: &Path) -> &str {
        path.to_str().expect("Cargo metadata fixture path is UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::cargo_metadata_output::test_support as fixture;

    #[test]
    fn complete_metadata_fixture_parses() {
        let root = Path::new("/workspace");
        let document = fixture::metadata(
            root,
            vec![fixture::package(
                "example",
                "1.2.3",
                None,
                &root.join("Cargo.toml"),
                Some(&["crates-io"]),
                vec![fixture::dependency(
                    "dependency",
                    "^1.0",
                    None,
                    None,
                    None,
                    Some(&root.join("dependency")),
                )],
                vec![fixture::target("example", "lib", &root.join("src/lib.rs"))],
            )],
        );
        let metadata = parse_bounded(&fixture::encoded(&document), "invalid fixture").unwrap();

        assert_eq!(metadata.packages.len(), 1);
        assert_eq!(metadata.packages[0].name.as_ref(), "example");
    }

    #[test]
    fn parser_rejects_unbounded_or_non_utf8_metadata() {
        let error = parse_bounded(
            &vec![b' '; VALIDATION_OUTPUT_LIMITS.stdout + 1],
            "invalid fixture",
        )
        .unwrap_err();
        assert_eq!(
            error,
            format!(
                "Cargo metadata exceeded its {}-byte limit",
                VALIDATION_OUTPUT_LIMITS.stdout
            )
        );

        let error = parse_bounded(&[0xff], "invalid fixture").unwrap_err();
        assert!(error.starts_with("invalid fixture:"), "{error}");
    }

    #[test]
    fn publication_policy_matches_cargo_metadata() {
        assert!(publishes_to_crates_io(None).unwrap());
        assert!(!publishes_to_crates_io(Some(&[])).unwrap());
        assert!(publishes_to_crates_io(Some(&["crates-io".to_string()])).unwrap());
        assert!(publishes_to_crates_io(Some(&["alternate".to_string()])).is_err());
    }
}

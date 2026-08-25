// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral package, tag, and changelog release policy.

use std::path::Path;
use std::process::Command;

use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseFamily {
    Traits,
    RustWorkspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackagePolicy {
    pub(crate) package: &'static str,
    pub(crate) tag_prefix: &'static str,
    pub(crate) changelog: &'static str,
    pub(crate) path_in_vcs: &'static str,
}

impl PackagePolicy {
    pub(crate) fn tag(&self, version: &str) -> String {
        format!("{}{version}", self.tag_prefix)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleasePolicy {
    pub(crate) family: ReleaseFamily,
    pub(crate) packages: &'static [PackagePolicy],
}

const TRAITS_PACKAGES: &[PackagePolicy] = &[PackagePolicy {
    package: "yaml-sigil-traits",
    tag_prefix: "v",
    changelog: "CHANGELOG.md",
    path_in_vcs: "",
}];

const RUST_PACKAGES: &[PackagePolicy] = &[
    PackagePolicy {
        package: "yaml-sigil-core",
        tag_prefix: "yaml-sigil-core-v",
        changelog: "crates/yaml-sigil-core/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-core",
    },
    PackagePolicy {
        package: "yaml-sigil-transcription",
        tag_prefix: "yaml-sigil-transcription-v",
        changelog: "crates/yaml-sigil-transcription/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-transcription",
    },
    PackagePolicy {
        package: "yaml-sigil-signing",
        tag_prefix: "yaml-sigil-signing-v",
        changelog: "crates/yaml-sigil-signing/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-signing",
    },
    PackagePolicy {
        package: "yaml-sigil-verification",
        tag_prefix: "yaml-sigil-verification-v",
        changelog: "crates/yaml-sigil-verification/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-verification",
    },
];

pub(crate) const TRAITS_POLICY: ReleasePolicy = ReleasePolicy {
    family: ReleaseFamily::Traits,
    packages: TRAITS_PACKAGES,
};

pub(crate) const RUST_POLICY: ReleasePolicy = ReleasePolicy {
    family: ReleaseFamily::RustWorkspace,
    packages: RUST_PACKAGES,
};

pub(crate) fn detect(root: &Path) -> Result<&'static ReleasePolicy, String> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(root)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .map_err(|error| format!("run Cargo metadata for release policy: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "Cargo metadata failed while selecting release policy: {detail}"
        ));
    }
    if output.stdout.len() > 4 * 1024 * 1024 {
        return Err("Cargo release metadata exceeded its bound".to_string());
    }
    let metadata: Metadata = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Cargo returned invalid release metadata: {error}"))?;
    detect_from_metadata(&metadata)
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    #[serde(default)]
    publish: Option<Value>,
}

fn detect_from_metadata(metadata: &Metadata) -> Result<&'static ReleasePolicy, String> {
    let mut publishable = Vec::new();
    for package in &metadata.packages {
        match publish_state(package.publish.as_ref())? {
            PublishState::Publishable => publishable.push(package.name.as_str()),
            PublishState::Disabled => {}
        }
    }
    let traits = exact_package_order(&publishable, TRAITS_POLICY.packages);
    let rust = exact_package_order(&publishable, RUST_POLICY.packages);
    match (traits, rust) {
        (true, false) => Ok(&TRAITS_POLICY),
        (false, true) => Ok(&RUST_POLICY),
        _ => Err(format!(
            "publishable package inventory does not select one release policy: [{}]",
            publishable.join(", ")
        )),
    }
}

fn exact_package_order(actual: &[&str], expected: &[PackagePolicy]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| *actual == expected.package)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishState {
    Publishable,
    Disabled,
}

fn publish_state(value: Option<&Value>) -> Result<PublishState, String> {
    match value {
        None | Some(Value::Null) => Ok(PublishState::Publishable),
        Some(Value::Array(registries)) if registries.is_empty() => Ok(PublishState::Disabled),
        Some(Value::Array(registries)) => {
            if !registries.iter().all(Value::is_string) {
                return Err("Cargo returned invalid publish registry metadata".to_string());
            }
            if registries
                .iter()
                .any(|registry| registry.as_str() == Some("crates-io"))
            {
                Ok(PublishState::Publishable)
            } else {
                Err("a publishable release package excludes crates-io".to_string())
            }
        }
        Some(_) => Err("Cargo returned invalid publish metadata".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_null_and_default_registry_metadata_are_publishable() {
        assert_eq!(publish_state(None).unwrap(), PublishState::Publishable);
        assert_eq!(
            publish_state(Some(&Value::Null)).unwrap(),
            PublishState::Publishable
        );
        assert_eq!(
            publish_state(Some(&json!(["crates-io"]))).unwrap(),
            PublishState::Publishable
        );
    }

    #[test]
    fn only_cargo_false_encoding_disables_publication() {
        assert_eq!(
            publish_state(Some(&json!([]))).unwrap(),
            PublishState::Disabled
        );
        assert!(publish_state(Some(&json!(["internal"]))).is_err());
        assert!(publish_state(Some(&json!(false))).is_err());
    }

    #[test]
    fn package_policy_is_central_and_ordered() {
        assert_eq!(TRAITS_POLICY.packages[0].tag("0.4.0"), "v0.4.0");
        assert_eq!(RUST_POLICY.packages.len(), 4);
    }
}

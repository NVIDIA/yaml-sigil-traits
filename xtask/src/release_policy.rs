// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral package, tag, and changelog release policy.

use std::path::Path;
use std::process::Command;

use cargo_metadata::Metadata;

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::cargo_metadata_output::{parse_bounded, publishes_to_crates_io};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseToolchain {
    pub(crate) cargo_binstall_version: &'static str,
    pub(crate) release_plz_version: &'static str,
    pub(crate) cargo_semver_checks_version: &'static str,
}

const REVIEWED_RELEASE_TOOLCHAIN: ReleaseToolchain = ReleaseToolchain {
    cargo_binstall_version: "1.20.1",
    release_plz_version: "0.3.160",
    cargo_semver_checks_version: "0.49.0",
};

pub(crate) const TRAITS_TOOLCHAIN: ReleaseToolchain = REVIEWED_RELEASE_TOOLCHAIN;
pub(crate) const RUST_TOOLCHAIN: ReleaseToolchain = REVIEWED_RELEASE_TOOLCHAIN;

impl PackagePolicy {
    pub(crate) fn tag(&self, version: &str) -> String {
        format!("{}{version}", self.tag_prefix)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleasePolicy {
    pub(crate) family: ReleaseFamily,
    pub(crate) packages: &'static [PackagePolicy],
    pub(crate) toolchain: ReleaseToolchain,
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
    toolchain: TRAITS_TOOLCHAIN,
};

pub(crate) const RUST_POLICY: ReleasePolicy = ReleasePolicy {
    family: ReleaseFamily::RustWorkspace,
    packages: RUST_PACKAGES,
    toolchain: RUST_TOOLCHAIN,
};

pub(crate) fn detect(root: &Path) -> Result<&'static ReleasePolicy, String> {
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .current_dir(root)
        .args(["metadata", "--no-deps", "--format-version", "1"]);
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run Cargo metadata for release policy: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "Cargo metadata failed while selecting release policy: {detail}"
        ));
    }
    let metadata = parse_bounded(&output.stdout, "Cargo returned invalid release metadata")?;
    detect_from_metadata(&metadata)
}

fn detect_from_metadata(metadata: &Metadata) -> Result<&'static ReleasePolicy, String> {
    let mut publishable = Vec::new();
    for package in &metadata.packages {
        if publishes_to_crates_io(package.publish.as_deref())? {
            publishable.push(package.name.as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_publish_policy_is_typed_and_fail_closed() {
        assert!(publishes_to_crates_io(None).unwrap());
        assert!(!publishes_to_crates_io(Some(&[])).unwrap());
        assert!(publishes_to_crates_io(Some(&["crates-io".to_string()])).unwrap());
        assert!(publishes_to_crates_io(Some(&["alternate".to_string()])).is_err());
    }

    #[test]
    fn package_policy_is_central_and_ordered() {
        assert_eq!(TRAITS_POLICY.packages[0].tag("0.4.0"), "v0.4.0");
        assert_eq!(RUST_POLICY.packages.len(), 4);
        assert_eq!(TRAITS_POLICY.toolchain, TRAITS_TOOLCHAIN);
        assert_eq!(RUST_POLICY.toolchain, RUST_TOOLCHAIN);
    }
}

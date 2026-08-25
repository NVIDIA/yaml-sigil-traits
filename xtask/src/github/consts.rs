// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! One repository-policy inventory shared by every GitHub release command.

use crate::release_policy::ReleaseFamily;

pub(crate) const APP_SLUG: &str = "nvidia-yamlsigil-release-pr";
pub(crate) const APP_LOGIN: &str = "nvidia-yamlsigil-release-pr[bot]";
pub(crate) const APP_ID: u64 = 318_780_254;
pub(crate) const APP_EMAIL: &str =
    "318780254+nvidia-yamlsigil-release-pr[bot]@users.noreply.github.com";
pub(crate) const WEB_FLOW_LOGIN: &str = "web-flow";
pub(crate) const WEB_FLOW_ID: u64 = 19_864_447;
pub(crate) const WEB_FLOW_NAME: &str = "GitHub";
pub(crate) const WEB_FLOW_EMAIL: &str = "noreply@github.com";
pub(crate) const RELEASE_BRANCH: &str = "release-plz-next";
pub(crate) const MAX_FILE_BYTES: u64 = 1_048_576;
pub(crate) const RELEASE_TITLE_PREFIX: &str = "chore(release): prepare";
pub(crate) const RELEASE_AUTHORIZATION_SENTENCE: &str = "Reviewing and merging this pull request authorizes the protected official publication workflow.";

pub(crate) const TRAITS_REPOSITORY: &str = "NVIDIA/yaml-sigil-traits";
pub(crate) const RUST_REPOSITORY: &str = "NVIDIA/yaml-sigil-rs";

const TRAITS_GENERATED_PATHS: &[&str] = &["CHANGELOG.md", "Cargo.toml"];
const RUST_GENERATED_PATHS: &[&str] = &[
    "Cargo.toml",
    "crates/yaml-sigil-core/CHANGELOG.md",
    "crates/yaml-sigil-signing/CHANGELOG.md",
    "crates/yaml-sigil-transcription/CHANGELOG.md",
    "crates/yaml-sigil-verification/CHANGELOG.md",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryKind {
    Traits,
    RustWorkspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryPolicy {
    pub(crate) full_name: &'static str,
    pub(crate) kind: RepositoryKind,
    pub(crate) generated_paths: &'static [&'static str],
    pub(crate) release_family: ReleaseFamily,
    pub(crate) title_subject: &'static str,
    pub(crate) release_subject: &'static str,
    pub(crate) release_object_sentence: &'static str,
}

pub(crate) const TRAITS_POLICY: RepositoryPolicy = RepositoryPolicy {
    full_name: TRAITS_REPOSITORY,
    kind: RepositoryKind::Traits,
    generated_paths: TRAITS_GENERATED_PATHS,
    release_family: ReleaseFamily::Traits,
    title_subject: "yaml-sigil-traits",
    release_subject: "yaml-sigil-traits",
    release_object_sentence: "The resulting official release is source-only and receives no executable assets.",
};

pub(crate) const RUST_POLICY: RepositoryPolicy = RepositoryPolicy {
    full_name: RUST_REPOSITORY,
    kind: RepositoryKind::RustWorkspace,
    generated_paths: RUST_GENERATED_PATHS,
    release_family: ReleaseFamily::RustWorkspace,
    title_subject: "YamlSigil",
    release_subject: "all four YamlSigil Rust crates",
    release_object_sentence: "The resulting official releases are source-only and receive no executable assets.",
};

pub(crate) fn repository_policy(repository: &str) -> Option<&'static RepositoryPolicy> {
    match repository {
        TRAITS_REPOSITORY => Some(&TRAITS_POLICY),
        RUST_REPOSITORY => Some(&RUST_POLICY),
        _ => None,
    }
}

pub(crate) fn repository_for_family(family: ReleaseFamily) -> Option<&'static RepositoryPolicy> {
    [TRAITS_POLICY, RUST_POLICY]
        .iter()
        .find(|policy| policy.release_family == family)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_identity_and_paths_have_one_inventory() {
        assert_eq!(repository_policy(TRAITS_REPOSITORY), Some(&TRAITS_POLICY));
        assert_eq!(
            repository_for_family(ReleaseFamily::Traits),
            Some(&TRAITS_POLICY)
        );
        assert!(TRAITS_POLICY.generated_paths.contains(&"Cargo.toml"));
        assert!(repository_policy("example.invalid/copied-workflow").is_none());
    }
}

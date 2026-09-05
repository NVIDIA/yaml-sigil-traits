// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Compile-time source-package and release-object policy.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackagePolicy {
    pub(crate) package: &'static str,
    pub(crate) tag_prefix: &'static str,
    pub(crate) changelog: &'static str,
    pub(crate) path_in_vcs: &'static str,
}

impl PackagePolicy {
    pub(crate) fn tag(self, version: &str) -> String {
        format!("{}{version}", self.tag_prefix)
    }
}

pub(crate) const TRAITS_PACKAGE: PackagePolicy = PackagePolicy {
    package: "yaml-sigil-traits",
    tag_prefix: "v",
    changelog: "CHANGELOG.md",
    path_in_vcs: "",
};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleasePolicy {
    pub(crate) packages: &'static [PackagePolicy],
}

#[cfg(test)]
pub(crate) const TRAITS_POLICY: ReleasePolicy = ReleasePolicy {
    packages: &[TRAITS_PACKAGE],
};

pub(crate) const RELEASE_PLZ_VERSION: &str = "0.3.160";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traits_policy_is_exact() {
        assert_eq!(TRAITS_PACKAGE.package, "yaml-sigil-traits");
        assert_eq!(TRAITS_POLICY.packages, &[TRAITS_PACKAGE]);
        assert_eq!(TRAITS_PACKAGE.tag("0.4.0-rc.3"), "v0.4.0-rc.3");
        assert_eq!(RELEASE_PLZ_VERSION, "0.3.160");
    }
}

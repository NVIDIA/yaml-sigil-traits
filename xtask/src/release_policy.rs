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

/// The source line is independent of protected-main execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseLine {
    Main,
    Support { major: u64, minor: u64 },
}

impl ReleaseLine {
    pub(crate) fn from_base_ref(value: &str) -> Result<Self, String> {
        if value == "refs/heads/main" {
            return Ok(Self::Main);
        }
        let line = value.strip_prefix("refs/heads/support/").ok_or_else(|| {
            "release base must be refs/heads/main or refs/heads/support/M.N".to_string()
        })?;
        let (major, minor) = line
            .split_once('.')
            .ok_or_else(|| "support base requires exactly two version components".to_string())?;
        fn component(value: &str) -> Result<u64, String> {
            if value.is_empty()
                || value.len() > 9
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err("support base has a noncanonical version component".into());
            }
            value
                .parse()
                .map_err(|_| "support version component overflows".into())
        }
        Ok(Self::Support {
            major: component(major)?,
            minor: component(minor)?,
        })
    }

    pub(crate) fn base_ref(self) -> String {
        match self {
            Self::Main => "refs/heads/main".into(),
            Self::Support { major, minor } => format!("refs/heads/support/{major}.{minor}"),
        }
    }

    pub(crate) fn tracking_ref(self) -> String {
        self.base_ref()
            .replacen("refs/heads/", "refs/remotes/origin/", 1)
    }

    pub(crate) fn make_latest(self, version: &semver::Version) -> bool {
        self == Self::Main && version.pre.is_empty()
    }

    pub(crate) fn admits(self, version: &semver::Version) -> bool {
        match self {
            Self::Main => true,
            Self::Support { major, minor } => version.major == major && version.minor == minor,
        }
    }

    pub(crate) fn require_version(self, version: &semver::Version) -> Result<(), String> {
        if !self.admits(version) {
            return Err(format!("version {version} is outside {}", self.base_ref()));
        }
        Ok(())
    }

    /// Only an actual stable publication on another main line establishes eligibility.
    pub(crate) fn require_successor(self, version: &semver::Version) -> Result<(), String> {
        let newer = matches!(self, Self::Support { major, minor } if (version.major, version.minor) > (major, minor));
        if !newer || !version.pre.is_empty() || !version.build.is_empty() {
            return Err(
                "support activation requires a published main stable outside the old line".into(),
            );
        }
        Ok(())
    }

    /// Validate advancement against published versions on this support line.
    /// Cargo/release-plz still derive and apply the release transaction.
    pub(crate) fn require_advancement(
        self,
        selected: &semver::Version,
        published: &[semver::Version],
    ) -> Result<(), String> {
        self.require_version(selected)?;
        if self == Self::Main {
            return Ok(());
        }
        if !selected.build.is_empty() {
            return Err("support releases cannot contain build metadata".into());
        }
        let stable = published
            .iter()
            .filter(|v| self.admits(v) && v.pre.is_empty() && v.build.is_empty())
            .max()
            .ok_or_else(|| "support line has no published stable baseline".to_string())?;
        if stable.patch.checked_add(1) != Some(selected.patch) {
            return Err("support release must use the next patch after its last stable".into());
        }
        if published.contains(selected) {
            return Err("support release version is already published".into());
        }
        let ordinal = |v: &semver::Version| -> Result<u64, String> {
            let value = v
                .pre
                .as_str()
                .strip_prefix("rc.")
                .ok_or_else(|| "support prerelease must be rc.N".to_string())?;
            let number: u64 = value
                .parse()
                .map_err(|_| "invalid support RC ordinal".to_string())?;
            if number == 0 || number.to_string() != value {
                return Err("support RC ordinal must be canonical and positive".into());
            }
            Ok(number)
        };
        if !selected.pre.is_empty() {
            let next = ordinal(selected)?;
            if let Some(last) = published
                .iter()
                .filter(|v| self.admits(v) && v.patch == selected.patch)
                .max()
                && ordinal(last)?.checked_add(1) != Some(next)
            {
                return Err("support RC must advance by exactly one ordinal".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod release_line_tests {
    use super::ReleaseLine;
    use semver::Version;

    #[test]
    fn latest_intent_is_main_stable_only() {
        let stable = Version::parse("0.5.2").unwrap();
        let rc = Version::parse("0.5.2-rc.1").unwrap();
        let support = ReleaseLine::Support { major: 0, minor: 5 };
        assert!(ReleaseLine::Main.make_latest(&stable));
        assert!(!ReleaseLine::Main.make_latest(&rc));
        assert!(!support.make_latest(&stable));
        assert!(!support.make_latest(&rc));
    }

    #[test]
    fn canonical_support_bases_and_line_versions() {
        let line = ReleaseLine::from_base_ref("refs/heads/support/0.5").unwrap();
        assert_eq!(line.base_ref(), "refs/heads/support/0.5");
        assert_eq!(line.tracking_ref(), "refs/remotes/origin/support/0.5");
        assert!(line.admits(&Version::parse("0.5.2-rc.1").unwrap()));
        assert!(!line.admits(&Version::parse("0.6.0").unwrap()));
        for bad in [
            "support/0.5",
            "refs/heads/support/00.5",
            "refs/heads/support/0.05",
            "refs/heads/support/0",
            "refs/heads/support/0.5.1",
            "refs/heads/dev/0.6.0",
            "refs/heads/support/+1.2",
            "refs/heads/support/18446744073709551616.2",
            "refs/heads/support/1000000000.5",
        ] {
            assert!(ReleaseLine::from_base_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn support_progression_keeps_rc_and_stable_reachable() {
        let line = ReleaseLine::Support { major: 0, minor: 5 };
        let v = |s| Version::parse(s).unwrap();
        let stable = vec![v("0.5.1")];
        for allowed in ["0.5.2", "0.5.2-rc.1"] {
            assert!(line.require_advancement(&v(allowed), &stable).is_ok());
        }
        for bad in [
            "0.5.1",
            "0.5.3",
            "0.6.0",
            "0.5.2-rc.0",
            "0.5.2-beta.1",
            "0.5.2+build",
        ] {
            assert!(line.require_advancement(&v(bad), &stable).is_err(), "{bad}");
        }
        let rc = vec![v("0.5.1"), v("0.5.2-rc.1")];
        assert!(line.require_advancement(&v("0.5.2-rc.2"), &rc).is_ok());
        assert!(line.require_advancement(&v("0.5.2"), &rc).is_ok());
        assert!(line.require_advancement(&v("0.5.2-rc.1"), &rc).is_err());
        assert!(line.require_advancement(&v("0.5.2-rc.3"), &rc).is_err());
        assert!(line.require_successor(&v("0.4.9")).is_err());
        assert!(line.require_successor(&v("0.6.0-rc.1")).is_err());
        assert!(line.require_successor(&v("0.5.3")).is_err());
        assert!(line.require_successor(&v("0.6.0")).is_ok());
    }
}

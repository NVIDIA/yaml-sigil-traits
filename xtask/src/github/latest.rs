// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit Latest selection and readback around immutable Release creation.

use semver::Version;
use serde::Deserialize;

use super::REPOSITORY;
use super::transport::Transport;
use crate::release_policy::ReleaseLine;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct Latest {
    id: u64,
    tag_name: String,
}

pub(super) struct Guard {
    before: Option<Latest>,
    target: String,
    advance: bool,
}

impl Guard {
    pub(super) fn capture(
        github: &mut impl Transport,
        line: ReleaseLine,
        tag: &str,
    ) -> Result<Self, String> {
        let target = release_order(tag)?;
        let before = read(github)?;
        if line != ReleaseLine::Main && before.as_ref().is_some_and(|latest| latest.tag_name == tag)
        {
            return Err(
                "support release already holds Latest; reconcile that state before retrying".into(),
            );
        }
        // The package ordinal preserves deterministic multi-package ordering
        // when a retry encounters a partially finalized version. An earlier
        // package must not displace a later package of the same version.
        let advance = line.make_latest(&target.0)
            && match &before {
                Some(latest) => target > release_order(&latest.tag_name)?,
                None => true,
            };
        Ok(Self {
            before,
            target: tag.into(),
            advance,
        })
    }

    pub(super) fn request_value(&self) -> &'static str {
        if self.advance { "true" } else { "false" }
    }

    pub(super) fn require_unchanged(&self, github: &mut impl Transport) -> Result<(), String> {
        if read(github)? != self.before {
            return Err(
                "Latest changed before Release creation; requalify without mutation".into(),
            );
        }
        Ok(())
    }

    pub(super) fn verify(&self, github: &mut impl Transport) -> Result<(), String> {
        let after = read(github)?;
        let matches = if self.advance {
            after
                .as_ref()
                .is_some_and(|latest| latest.tag_name == self.target)
        } else {
            after == self.before
        };
        if !matches {
            return Err("Latest readback differs from the intended Release outcome".into());
        }
        Ok(())
    }
}

fn read(github: &mut impl Transport) -> Result<Option<Latest>, String> {
    let observed: Option<Latest> =
        github.get_optional(&format!("repos/{REPOSITORY}/releases/latest"))?;
    if let Some(latest) = &observed {
        let (version, _) = release_order(&latest.tag_name)?;
        if latest.id == 0 || !version.pre.is_empty() || !version.build.is_empty() {
            return Err("Latest is not one canonical stable repository Release".into());
        }
    }
    Ok(observed)
}

fn release_order(tag: &str) -> Result<(Version, usize), String> {
    for (ordinal, prefix) in package_prefixes().iter().enumerate() {
        if let Some(raw) = tag.strip_prefix(prefix) {
            let version = Version::parse(raw).map_err(|_| "Latest tag has an invalid version")?;
            if version.to_string() != raw || !version.build.is_empty() {
                return Err("Latest tag has a noncanonical version".into());
            }
            return Ok((version, ordinal));
        }
    }
    Err("Latest tag is outside the compiled package family".into())
}

fn package_prefixes() -> Vec<&'static str> {
    vec![crate::release_policy::TRAITS_PACKAGE.tag_prefix]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    struct Fake {
        latest: Option<Latest>,
    }

    impl Transport for Fake {
        fn get<T: serde::de::DeserializeOwned>(&mut self, _path: &str) -> Result<T, String> {
            panic!("unexpected read")
        }
        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            assert_eq!(path, format!("repos/{REPOSITORY}/releases/latest"));
            self.latest
                .as_ref()
                .map(|latest| {
                    serde_json::from_value(
                        serde_json::json!({"id":latest.id,"tag_name":latest.tag_name}),
                    )
                    .map_err(|e| e.to_string())
                })
                .transpose()
        }
        fn mutate<T: serde::de::DeserializeOwned, P: Serialize>(
            &mut self,
            _method: &str,
            _path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            panic!("unexpected mutation")
        }
    }

    fn latest(version: &str, ordinal: usize) -> Option<Latest> {
        Some(Latest {
            id: ordinal as u64 + 1,
            tag_name: format!("{}{version}", package_prefixes()[ordinal]),
        })
    }

    #[test]
    fn support_prerelease_and_older_main_recovery_preserve_latest() {
        for (line, version) in [
            (ReleaseLine::Support { major: 0, minor: 5 }, "0.5.2"),
            (ReleaseLine::Main, "0.7.0-rc.1"),
            (ReleaseLine::Main, "0.5.2"),
        ] {
            let mut github = Fake {
                latest: latest("0.6.0", 0),
            };
            let guard = Guard::capture(
                &mut github,
                line,
                &format!("{}{version}", package_prefixes()[0]),
            )
            .unwrap();
            assert_eq!(guard.request_value(), "false");
            guard.require_unchanged(&mut github).unwrap();
            guard.verify(&mut github).unwrap();
            github.latest = latest("0.7.0", 0);
            assert!(guard.require_unchanged(&mut github).is_err());
            assert!(guard.verify(&mut github).is_err());
        }
    }

    #[test]
    fn fresh_and_newer_main_recovery_advance_and_verify_latest() {
        for before in [None, latest("0.5.1", 0)] {
            let mut github = Fake { latest: before };
            let guard = Guard::capture(
                &mut github,
                ReleaseLine::Main,
                &format!("{}0.6.0", package_prefixes()[0]),
            )
            .unwrap();
            assert_eq!(guard.request_value(), "true");
            guard.require_unchanged(&mut github).unwrap();
            assert!(guard.verify(&mut github).is_err());
            github.latest = latest("0.6.0", 0);
            guard.verify(&mut github).unwrap();
        }
    }

    #[test]
    fn replay_preserves_deterministic_package_order_and_identity() {
        let last = package_prefixes().len() - 1;
        let mut github = Fake {
            latest: latest("0.6.0", last),
        };
        let guard = Guard::capture(
            &mut github,
            ReleaseLine::Main,
            &format!("{}0.6.0", package_prefixes()[0]),
        )
        .unwrap();
        assert_eq!(guard.request_value(), "false");
        guard.verify(&mut github).unwrap();
        github.latest.as_mut().unwrap().id += 1;
        assert!(guard.verify(&mut github).is_err());
        let mut github = Fake {
            latest: Some(Latest {
                id: 1,
                tag_name: "foreign-v9.0.0".into(),
            }),
        };
        assert!(
            Guard::capture(
                &mut github,
                ReleaseLine::Main,
                &format!("{}0.6.0", package_prefixes()[0])
            )
            .is_err()
        );
    }
}

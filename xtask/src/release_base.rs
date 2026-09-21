// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral Git base selection for local release transactions.

use std::path::Path;
use std::process::Command;

use semver::Version;

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::release_policy::ReleaseLine;

pub(crate) fn resolve(root: &Path, explicit: Option<&str>) -> Result<ReleaseLine, String> {
    if let Some(base) = explicit {
        return ReleaseLine::from_base_ref(base);
    }
    let branch = git(root, &["symbolic-ref", "--quiet", "HEAD"])
        .map_err(|_| "detached release checkout requires --base-ref".to_string())?;
    if branch == "refs/heads/main" || branch.starts_with("refs/heads/support/") {
        return ReleaseLine::from_base_ref(&branch);
    }
    // Preserve the ordinary named main-release branch convenience. An older
    // support source cannot silently inherit main when its base is ambiguous.
    git(
        root,
        &[
            "merge-base",
            "--is-ancestor",
            "refs/remotes/origin/main",
            "HEAD",
        ],
    )
    .map_err(|_| "release base is ambiguous; supply --base-ref".to_string())?;
    Ok(ReleaseLine::Main)
}

pub(crate) fn validate_version(
    root: &Path,
    line: ReleaseLine,
    version: &Version,
    tag_prefix: &str,
) -> Result<(), String> {
    line.require_version(version)?;
    if line == ReleaseLine::Main {
        return Ok(());
    }
    let tags = git(
        root,
        &[
            "tag",
            "--merged",
            &line.tracking_ref(),
            "--list",
            &format!("{tag_prefix}*"),
        ],
    )?;
    let mut versions = Vec::new();
    for tag in tags.lines() {
        let value = tag
            .strip_prefix(tag_prefix)
            .ok_or_else(|| "unexpected release tag prefix".to_string())?;
        // Early repository history includes non-SemVer tags such as v1alpha1.
        // Those names cannot establish a typed release progression baseline.
        if let Ok(parsed) = Version::parse(value)
            && parsed.to_string() == value
        {
            versions.push(parsed);
        }
    }
    line.require_advancement(version, &versions)
}

pub(crate) fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = bounded_process::output(
        Command::new("git").current_dir(root).args(args),
        VALIDATION_OUTPUT_LIMITS,
    )
    .map_err(|error| format!("read release Git state: {error}"))?;
    if !output.status.success() {
        return Err(format!("git {} failed", args.join(" ")));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("decode release Git state: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_source_never_guesses_its_line() {
        let dir = tempfile::tempdir().unwrap();
        for args in [
            vec!["init", "--quiet", "--initial-branch=main"],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            ],
            vec!["checkout", "--detach"],
        ] {
            git(dir.path(), &args).unwrap();
        }
        assert!(
            resolve(dir.path(), None)
                .unwrap_err()
                .contains("--base-ref")
        );
        assert_eq!(
            resolve(dir.path(), Some("refs/heads/main")).unwrap(),
            ReleaseLine::Main
        );
        assert_eq!(
            resolve(dir.path(), Some("refs/heads/support/0.5")).unwrap(),
            ReleaseLine::Support { major: 0, minor: 5 }
        );
    }

    #[test]
    fn support_progression_uses_only_tags_reachable_from_selected_base() {
        for tag_prefix in ["v", "yaml-sigil-core-v"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            git(root, &["init", "--quiet", "--initial-branch=main"]).unwrap();
            let commit = |message: &str| {
                git(
                    root,
                    &[
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=fixture@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "--allow-empty",
                        "--quiet",
                        "-m",
                        message,
                    ],
                )
                .unwrap();
                git(root, &["rev-parse", "HEAD"]).unwrap()
            };
            let tag = |version: &str| {
                git(
                    root,
                    &[
                        "-c",
                        "tag.gpgsign=false",
                        "tag",
                        &format!("{tag_prefix}{version}"),
                    ],
                )
                .unwrap();
            };
            let line = ReleaseLine::Support { major: 0, minor: 5 };
            let version = |value: &str| Version::parse(value).unwrap();

            let baseline = commit("stable support baseline");
            tag("0.5.1");
            tag("1alpha1");
            git(root, &["update-ref", &line.tracking_ref(), &baseline]).unwrap();

            // Main's newer release tags are outside the selected support
            // history, even while HEAD and origin/main point to that commit.
            let main = commit("later main releases");
            tag("0.5.2");
            tag("0.6.0");
            git(root, &["update-ref", "refs/remotes/origin/main", &main]).unwrap();
            for selected in ["0.5.2", "0.5.2-rc.1"] {
                validate_version(root, line, &version(selected), tag_prefix).unwrap();
            }

            git(
                root,
                &[
                    "checkout",
                    "--quiet",
                    "-b",
                    "release-plz-manual-0.5.2",
                    &baseline,
                ],
            )
            .unwrap();
            assert!(resolve(root, None).unwrap_err().contains("--base-ref"));
            assert_eq!(resolve(root, Some(&line.base_ref())).unwrap(), line);

            // Only moving the selected tracking ref makes the RC part of
            // the progression baseline; a tag on the local head is not enough.
            let release_candidate = commit("support release candidate");
            tag("0.5.2-rc.1");
            validate_version(root, line, &version("0.5.2-rc.1"), tag_prefix).unwrap();
            git(
                root,
                &["update-ref", &line.tracking_ref(), &release_candidate],
            )
            .unwrap();
            for selected in ["0.5.2-rc.2", "0.5.2"] {
                validate_version(root, line, &version(selected), tag_prefix).unwrap();
            }
            for rejected in [
                "0.5.1",
                "0.5.2-rc.0",
                "0.5.2-rc.1",
                "0.5.2-rc.3",
                "0.5.2+build",
                "0.5.3",
                "0.6.0",
            ] {
                assert!(
                    validate_version(root, line, &version(rejected), tag_prefix).is_err(),
                    "{tag_prefix}{rejected}"
                );
            }
            assert_eq!(
                git(root, &["rev-parse", "refs/remotes/origin/main"]).unwrap(),
                main
            );
            assert_eq!(
                git(root, &["rev-parse", &line.tracking_ref()]).unwrap(),
                release_candidate
            );
            assert!(git(root, &["status", "--porcelain"]).unwrap().is_empty());
        }
    }
}

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
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral preparation and validation for a manual release PR.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output};

use cargo_metadata::Metadata;
use clap::{Args, Subcommand};
use semver::Version;
use toml_edit::DocumentMut;

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::release_policy::{RELEASE_PLZ_VERSION, TRAITS_PACKAGE};
use crate::{cargo_metadata_output, package_content, safe_file};

const BRANCH_PREFIX: &str = "release-plz-manual-";
const RELEASE_CONFIG: &str = ".release-plz.toml";
const RELEASE_CREDENTIAL_ENV: &[&str] = &[
    "ACTIONS_CACHE_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GIT_TOKEN",
];
const DCO_TRAILER: &str =
    "Signed-off-by: ddurst <267424412+ddurst-nvidia@users.noreply.github.com>";
const RELEASE_PATHS: &[&str] = &["CHANGELOG.md", "Cargo.toml"];

#[derive(Args)]
pub(crate) struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Run pinned release-plz update on an exact clean manual branch.
    Prepare {
        /// Exact version selected by the maintainer.
        #[arg(long)]
        version: Version,
    },
    /// Validate a prepared release transaction without publishing it.
    Check {
        /// Exact version selected by the maintainer.
        #[arg(long)]
        version: Version,
    },
}

pub(crate) fn run(root: &Path, args: ReleaseArgs) -> Result<(), String> {
    match args.command {
        ReleaseCommand::Prepare { version } => prepare(root, &version),
        ReleaseCommand::Check { version } => check(root, &version),
    }
}

fn prepare(root: &Path, version: &Version) -> Result<(), String> {
    validate_version(version)?;
    require_branch(root, version)?;
    require_exact_git_state(root, true)?;
    require_release_plz(root)?;

    // Pinned release-plz is the sole authority that edits the version and
    // changelog; this command never publishes, tags, or creates a Release.
    let status = release_plz_command(root)
        .args([
            "update",
            "--config",
            RELEASE_CONFIG,
            "--manifest-path",
            "Cargo.toml",
        ])
        .status()
        .map_err(|error| format!("run release-plz update: {error}"))?;
    if !status.success() {
        return Err(format!("release-plz update failed with {status}"));
    }

    require_release_changes(root, false)?;
    validate_release_content(root, version)?;
    eprintln!("release: prepared source changes for {version}");
    Ok(())
}

fn check(root: &Path, version: &Version) -> Result<(), String> {
    validate_version(version)?;
    require_branch(root, version)?;
    require_release_changes(root, true)?;
    validate_release_content(root, version)?;
    package_content::run(root).map_err(|error| error.to_string())?;
    eprintln!("release: validated the {version} source-only release transaction");
    Ok(())
}

pub(crate) fn check_manifest(root: &Path) -> Result<(), String> {
    validate_release_config(root)?;
    let metadata = metadata(root)?;
    validate_metadata(&metadata, None)
}

pub(crate) fn manifest_version(root: &Path) -> Result<Version, String> {
    let body = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .map_err(|error| format!("read Cargo.toml: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse Cargo.toml: {error}"))?;
    let value = document
        .get("package")
        .and_then(|item| item.get("version"))
        .and_then(toml_edit::Item::as_str)
        .ok_or_else(|| "Cargo.toml lacks package.version".to_string())?;
    let version = Version::parse(value)
        .map_err(|error| format!("Cargo.toml package.version is invalid: {error}"))?;
    validate_version(&version)?;
    Ok(version)
}

fn validate_release_content(root: &Path, version: &Version) -> Result<(), String> {
    check_manifest(root)?;
    let actual = manifest_version(root)?;
    if &actual != version {
        return Err(format!(
            "release version differs: expected {version}, found {actual}"
        ));
    }
    validate_changelog(root, version)
}

fn validate_version(version: &Version) -> Result<(), String> {
    if !version.build.is_empty() {
        return Err("release version may not contain build metadata".to_string());
    }
    Ok(())
}

fn require_release_plz(root: &Path) -> Result<(), String> {
    let mut command = release_plz_command(root);
    command.arg("--version");
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run release-plz: {error}"))?;
    require_success(&output, "release-plz --version")?;
    let actual = one_line(&output.stdout, "release-plz --version")?;
    let expected = format!("release-plz {RELEASE_PLZ_VERSION}");
    if actual != expected {
        return Err(format!("expected {expected}; found {actual}"));
    }
    Ok(())
}

fn release_plz_command(root: &Path) -> Command {
    let mut command = Command::new("release-plz");
    command.current_dir(root);
    for name in RELEASE_CREDENTIAL_ENV {
        command.env_remove(name);
    }
    command
}

fn require_branch(root: &Path, version: &Version) -> Result<(), String> {
    let expected = format!("{BRANCH_PREFIX}{version}");
    let current = git_optional_line(root, &["symbolic-ref", "--short", "HEAD"])?;
    let observed = std::env::var("YAML_SIGIL_RELEASE_PR_BRANCH")
        .ok()
        .filter(|value| !value.is_empty())
        .or(current)
        .ok_or_else(|| "release branch identity is unavailable".to_string())?;
    if observed != expected {
        return Err(format!(
            "release branch differs: expected {expected}, found {observed}"
        ));
    }
    Ok(())
}

fn require_exact_git_state(root: &Path, clean_start: bool) -> Result<(), String> {
    let head = git_line(root, &["rev-parse", "HEAD"])?;
    let main = git_line(root, &["rev-parse", "origin/main"])?;
    if head != main {
        return Err("release preparation must start at exact origin/main".to_string());
    }
    if clean_start && !git_line(root, &["status", "--porcelain"])?.is_empty() {
        return Err("release preparation requires a clean worktree".to_string());
    }
    Ok(())
}

fn require_release_changes(root: &Path, accept_committed: bool) -> Result<(), String> {
    let status = git_line(root, &["status", "--porcelain"])?;
    let dirty = !status.is_empty();
    if accept_committed && dirty {
        return Err("release check requires the sole release commit".to_string());
    }
    if !accept_committed && dirty {
        require_exact_git_state(root, false)?;
    } else if accept_committed {
        require_one_signed_commit(root)?;
    } else {
        return Err("release-plz did not produce source changes".to_string());
    }

    let mut actual = git_paths(
        root,
        &["diff", "--name-only", "--no-renames", "-z", "origin/main"],
    )?;
    actual.extend(git_paths(
        root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?);
    let expected: BTreeSet<String> = RELEASE_PATHS
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    if actual != expected {
        return Err(format!(
            "release paths differ: expected [{}], found [{}]",
            expected.into_iter().collect::<Vec<_>>().join(", "),
            actual.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(())
}

fn require_one_signed_commit(root: &Path) -> Result<(), String> {
    let main = git_line(root, &["rev-parse", "origin/main"])?;
    let count = git_line(root, &["rev-list", "--count", "origin/main..HEAD"])?;
    let parent = git_line(root, &["rev-parse", "HEAD^"])?;
    if count != "1" || parent != main {
        return Err("release PR must contain one commit current with origin/main".to_string());
    }
    let raw = git_line(root, &["cat-file", "commit", "HEAD"])?;
    if !raw.contains("gpgsig -----BEGIN SSH SIGNATURE-----") {
        return Err("release PR commit lacks an SSH signature".to_string());
    }
    let message = git_line(root, &["show", "-s", "--format=%B", "HEAD"])?;
    if !message.lines().any(|line| line == DCO_TRAILER) {
        return Err("release PR commit lacks the required DCO sign-off".to_string());
    }
    Ok(())
}

fn validate_release_config(root: &Path) -> Result<(), String> {
    let body = safe_file::read_manifest(root, Path::new(RELEASE_CONFIG))
        .map_err(|error| format!("read {RELEASE_CONFIG}: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse {RELEASE_CONFIG}: {error}"))?;
    let workspace = document
        .get("workspace")
        .and_then(toml_edit::Item::as_table)
        .ok_or_else(|| "release-plz config lacks [workspace]".to_string())?;
    let workspace_keys: BTreeSet<_> = workspace.iter().map(|(key, _)| key).collect();
    let expected_workspace_keys: BTreeSet<_> = [
        "changelog_update",
        "git_release_enable",
        "git_release_type",
        "git_tag_enable",
        "pr_branch_prefix",
        "publish_allow_dirty",
        "publish_no_verify",
        "publish_timeout",
        "release",
        "release_always",
        "semver_check",
    ]
    .into_iter()
    .collect();
    if workspace_keys != expected_workspace_keys {
        return Err("release-plz workspace keys differ from exact policy".to_string());
    }
    for (key, expected) in [
        ("release", false),
        ("release_always", false),
        ("git_tag_enable", false),
        ("git_release_enable", false),
        ("publish_allow_dirty", false),
        ("publish_no_verify", false),
        ("semver_check", false),
    ] {
        if workspace.get(key).and_then(toml_edit::Item::as_bool) != Some(expected) {
            return Err(format!("release-plz workspace.{key} must be {expected}"));
        }
    }
    if workspace
        .get("pr_branch_prefix")
        .and_then(toml_edit::Item::as_str)
        != Some(BRANCH_PREFIX)
    {
        return Err(format!(
            "release-plz workspace.pr_branch_prefix must be {BRANCH_PREFIX}"
        ));
    }
    for (key, expected) in [("git_release_type", "auto"), ("publish_timeout", "5m")] {
        if workspace.get(key).and_then(toml_edit::Item::as_str) != Some(expected) {
            return Err(format!("release-plz workspace.{key} must be {expected}"));
        }
    }
    if workspace
        .get("changelog_update")
        .and_then(toml_edit::Item::as_bool)
        != Some(true)
    {
        return Err("release-plz workspace.changelog_update must be true".to_string());
    }

    let packages = document
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(|| "release-plz config lacks [[package]]".to_string())?;
    if packages.len() != 1 {
        return Err("release-plz config must contain one package policy".to_string());
    }
    let package = packages
        .get(0)
        .ok_or_else(|| "release-plz config lacks its package policy".to_string())?;
    let package_keys: BTreeSet<_> = package.iter().map(|(key, _)| key).collect();
    let expected_package_keys: BTreeSet<_> = [
        "changelog_path",
        "changelog_update",
        "git_release_body",
        "git_release_enable",
        "git_release_name",
        "git_release_type",
        "git_tag_enable",
        "git_tag_name",
        "name",
        "publish",
        "release",
    ]
    .into_iter()
    .collect();
    if package_keys != expected_package_keys {
        return Err("release-plz package keys differ from exact policy".to_string());
    }
    if package.get("name").and_then(toml_edit::Item::as_str) != Some(TRAITS_PACKAGE.package)
        || package.get("release").and_then(toml_edit::Item::as_bool) != Some(true)
        || package.get("publish").and_then(toml_edit::Item::as_bool) != Some(true)
        || package
            .get("changelog_update")
            .and_then(toml_edit::Item::as_bool)
            != Some(true)
        || package
            .get("changelog_path")
            .and_then(toml_edit::Item::as_str)
            != Some("CHANGELOG.md")
        || package
            .get("git_tag_enable")
            .and_then(toml_edit::Item::as_bool)
            != Some(false)
        || package
            .get("git_tag_name")
            .and_then(toml_edit::Item::as_str)
            != Some("v{{ version }}")
        || package
            .get("git_release_enable")
            .and_then(toml_edit::Item::as_bool)
            != Some(false)
        || package
            .get("git_release_name")
            .and_then(toml_edit::Item::as_str)
            != Some("v{{ version }}")
        || package
            .get("git_release_body")
            .and_then(toml_edit::Item::as_str)
            != Some("{{ changelog }}")
        || package
            .get("git_release_type")
            .and_then(toml_edit::Item::as_str)
            != Some("auto")
    {
        return Err("release-plz package policy is not exact".to_string());
    }
    Ok(())
}

fn validate_changelog(root: &Path, version: &Version) -> Result<(), String> {
    let body = safe_file::read_manifest(root, Path::new(TRAITS_PACKAGE.changelog))
        .map_err(|error| format!("read changelog: {error}"))?;
    let heading = format!("## [{version}]");
    let matches = body
        .lines()
        .filter(|line| is_version_heading(line, &heading))
        .count();
    if matches != 1 {
        return Err(format!(
            "changelog must contain one exact {version} release heading"
        ));
    }
    Ok(())
}

fn is_version_heading(line: &str, heading: &str) -> bool {
    line.strip_prefix(heading).is_some_and(|suffix| {
        suffix.is_empty() || suffix.starts_with('(') || suffix.starts_with(" - ")
    })
}

fn metadata(root: &Path) -> Result<Metadata, String> {
    let output = command_output(
        root,
        std::env::var("CARGO").as_deref().unwrap_or("cargo"),
        &["metadata", "--no-deps", "--format-version", "1"],
    )?;
    require_success(&output, "cargo metadata")?;
    cargo_metadata_output::parse_bounded(&output.stdout, "Cargo returned invalid metadata")
}

fn validate_metadata(metadata: &Metadata, version: Option<&Version>) -> Result<(), String> {
    let mut publishable = Vec::new();
    for package in &metadata.packages {
        if cargo_metadata_output::publishes_to_crates_io(package.publish.as_deref())? {
            publishable.push(package);
        }
    }
    if publishable.len() != 1 || publishable[0].name.as_ref() != TRAITS_PACKAGE.package {
        return Err("publishable package set is not exactly yaml-sigil-traits".to_string());
    }
    let package = publishable[0];
    if version.is_some_and(|expected| &package.version != expected) {
        return Err("Cargo metadata release version differs".to_string());
    }
    if package
        .targets
        .iter()
        .any(|target| target.is_bin() || target.is_custom_build())
        || package
            .targets
            .iter()
            .filter(|target| target.is_lib())
            .count()
            != 1
    {
        return Err(
            "release package must contain one library and no executable target".to_string(),
        );
    }
    Ok(())
}

fn command_output(root: &Path, program: &str, args: &[&str]) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.current_dir(root).args(args);
    bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run {program}: {error}"))
}

fn require_success(output: &Output, label: &str) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("{label} failed with {}: {detail}", output.status))
    }
}

fn git_line(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = command_output(root, "git", args)?;
    require_success(&output, "git")?;
    one_line(&output.stdout, "git")
}

fn git_optional_line(root: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = command_output(root, "git", args)?;
    if output.status.success() {
        one_line(&output.stdout, "git").map(Some)
    } else {
        Ok(None)
    }
}

fn git_paths(root: &Path, args: &[&str]) -> Result<BTreeSet<String>, String> {
    let output = command_output(root, "git", args)?;
    require_success(&output, "git")?;
    if output.stdout.is_empty() {
        return Ok(BTreeSet::new());
    }
    if !output.stdout.ends_with(&[0]) {
        return Err("git path inventory lacks its NUL terminator".to_string());
    }
    output.stdout[..output.stdout.len() - 1]
        .split(|byte| *byte == 0)
        .map(|path| {
            if path.is_empty() {
                return Err("git path inventory contains an empty path".to_string());
            }
            std::str::from_utf8(path)
                .map(str::to_string)
                .map_err(|_| "git path inventory contains non-UTF-8".to_string())
        })
        .collect()
}

fn one_line(bytes: &[u8], label: &str) -> Result<String, String> {
    let value = std::str::from_utf8(bytes).map_err(|_| format!("{label} returned non-UTF-8"))?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.contains('\0') {
        return Err(format!("{label} returned NUL"));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_fixture() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().unwrap();
        for args in [
            vec!["init", "--quiet", "--initial-branch=main", "."],
            vec!["config", "user.name", "Fixture Author"],
            vec!["config", "user.email", "fixture@example.invalid"],
        ] {
            assert!(
                Command::new("git")
                    .current_dir(temporary.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        std::fs::write(temporary.path().join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(temporary.path().join("CHANGELOG.md"), "# Changelog\n").unwrap();
        std::fs::write(temporary.path().join("README.md"), "fixture\n").unwrap();
        for args in [
            vec!["add", "Cargo.toml", "CHANGELOG.md", "README.md"],
            vec!["commit", "--quiet", "-m", "fixture"],
            vec!["update-ref", "refs/remotes/origin/main", "HEAD"],
        ] {
            assert!(
                Command::new("git")
                    .current_dir(temporary.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        std::fs::write(
            temporary.path().join("Cargo.toml"),
            "[package]\nname='changed'\n",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("CHANGELOG.md"),
            "# Changelog\nchanged\n",
        )
        .unwrap();
        temporary
    }

    #[test]
    fn versions_and_release_paths_are_bounded() {
        assert!(validate_version(&Version::parse("1.2.3-rc.4").unwrap()).is_ok());
        assert!(validate_version(&Version::parse("1.2.3+local").unwrap()).is_err());
        assert_eq!(RELEASE_PATHS, ["CHANGELOG.md", "Cargo.toml"]);
        assert!(is_version_heading(
            "## [1.2.3](https://example.invalid) - 2026-09-04",
            "## [1.2.3]"
        ));
        assert!(!is_version_heading(
            "## [1.2.30](https://example.invalid)",
            "## [1.2.3]"
        ));
    }

    #[test]
    fn committed_configuration_disables_native_release_objects() {
        validate_release_config(&crate::workspace_root()).unwrap();
    }

    #[test]
    fn release_paths_include_tracked_deletions_and_untracked_files() {
        let deleted = git_fixture();
        std::fs::remove_file(deleted.path().join("README.md")).unwrap();
        assert!(require_release_changes(deleted.path(), false).is_err());

        let untracked = git_fixture();
        std::fs::write(untracked.path().join("untracked.txt"), "unexpected\n").unwrap();
        assert!(require_release_changes(untracked.path(), false).is_err());

        let renamed = git_fixture();
        std::fs::remove_file(renamed.path().join("Cargo.toml")).unwrap();
        std::fs::rename(
            renamed.path().join("README.md"),
            renamed.path().join("Cargo.toml"),
        )
        .unwrap();
        assert!(require_release_changes(renamed.path(), false).is_err());

        let uncommitted = git_fixture();
        assert!(require_release_changes(uncommitted.path(), true).is_err());
    }

    #[test]
    fn provider_neutral_release_preparation_removes_ambient_credentials() {
        let command = release_plz_command(Path::new("."));
        let removed: BTreeSet<_> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect();
        let expected: BTreeSet<_> = [
            "ACTIONS_CACHE_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_RESULTS_URL",
            "ACTIONS_RUNTIME_TOKEN",
            "CARGO_REGISTRIES_CRATES_IO_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GIT_TOKEN",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(removed, expected);
    }
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository maintenance tasks. Invoke from the repository root with
//! `cargo xtask <COMMAND>`.

mod bounded_process;
mod cargo_metadata_output;
mod ci;
mod crate_archive;
mod github;
mod package_content;
mod package_content_policy;
mod release;
mod release_baseline;
mod release_policy;
mod release_proposal;
mod release_version;
mod safe_file;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo xtask", bin_name = "cargo xtask")]
#[command(about = "Repository maintenance tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Run the complete provider-neutral validation sequence.
    Ci {
        /// Validate another checkout instead of this repository root.
        #[arg(long)]
        candidate_root: Option<PathBuf>,
    },
    /// Compare Cargo's source list with the committed inventory.
    PackageContent,
    /// Manage provider-neutral release version transactions.
    ReleaseVersion(release_version::ReleaseVersionArgs),
    /// Run provider-neutral release preparation and verification.
    Release(release::ReleaseArgs),
    /// Run bounded GitHub release-automation operations.
    Github(github::GithubArgs),
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Task::Ci { candidate_root } => {
            match resolve_ci_root(candidate_root)
                .and_then(|root| ci::run(&root).map_err(|error| error.to_string()))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("ci failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Task::PackageContent => match package_content::run(&workspace_root()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("package-content failed: {error}");
                ExitCode::FAILURE
            }
        },
        Task::ReleaseVersion(args) => match release_version::run(&workspace_root(), args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("release-version failed: {error}");
                ExitCode::FAILURE
            }
        },
        Task::Release(args) => match release::run(&workspace_root(), args) {
            Ok(outcome) => ExitCode::from(release_exit_code(outcome)),
            Err(error) => {
                eprintln!("release failed: {error}");
                ExitCode::FAILURE
            }
        },
        Task::Github(args) => match github::run(&workspace_root(), args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("github failed: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn release_exit_code(outcome: release::Outcome) -> u8 {
    match outcome {
        release::Outcome::Success => 0,
        release::Outcome::RegistryUnavailable => 3,
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest lives in xtask/")
        .to_path_buf()
}

fn resolve_ci_root(candidate_root: Option<PathBuf>) -> Result<PathBuf, String> {
    require_alternate_candidate_support(candidate_root.is_some())?;
    let candidate = candidate_root.unwrap_or_else(workspace_root);
    let candidate = candidate.canonicalize().map_err(|error| {
        format!(
            "cannot resolve candidate root {}: {error}",
            candidate.display()
        )
    })?;
    if !candidate.join("Cargo.toml").is_file() {
        return Err(format!(
            "candidate root {} lacks Cargo.toml",
            candidate.display()
        ));
    }
    Ok(candidate)
}

fn require_alternate_candidate_support(explicit: bool) -> Result<(), &'static str> {
    if explicit && cfg!(all(unix, not(target_os = "linux"))) {
        return Err("alternate --candidate-root validation is unsupported on non-Linux Unix hosts");
    }
    Ok(())
}

fn resolve_validation_root(
    default_root: &Path,
    validation_root: Option<PathBuf>,
    validation_head: Option<String>,
) -> Result<PathBuf, String> {
    let (validation_root, validation_head) = match (validation_root, validation_head) {
        (None, None) => return Ok(default_root.to_path_buf()),
        (Some(root), Some(head)) => (root, head),
        _ => {
            return Err(
                "--validation-root and --validation-head must be provided together".to_string(),
            );
        }
    };
    if validation_head.len() != 40
        || !validation_head
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("--validation-head must be a lowercase full commit SHA".to_string());
    }
    let root = validation_root.canonicalize().map_err(|error| {
        format!(
            "cannot resolve validation root {}: {error}",
            validation_root.display()
        )
    })?;
    if !root.join("Cargo.toml").is_file() {
        return Err(format!(
            "validation root {} lacks Cargo.toml",
            root.display()
        ));
    }
    let top = validation_git_line(&root, &["rev-parse", "--show-toplevel"])?;
    let top = PathBuf::from(top)
        .canonicalize()
        .map_err(|error| format!("resolve validation Git root: {error}"))?;
    if top != root || validation_git_line(&root, &["rev-parse", "HEAD"])? != validation_head {
        return Err("validation root is not the exact selected commit".to_string());
    }
    if !validation_git_output(&root, &["status", "--porcelain", "--untracked-files=no"])?.is_empty()
    {
        return Err("validation root contains tracked changes".to_string());
    }
    Ok(root)
}

fn validation_git_line(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = validation_git_output(root, arguments)?;
    let text = std::str::from_utf8(&output)
        .map_err(|_| "validation Git output is not UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err("validation Git output is not one line".to_string());
    }
    Ok(line.to_string())
}

fn validation_git_output(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            &format!("core.hooksPath={null_device}"),
        ])
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device);
    let output = bounded_process::output(&mut command, bounded_process::VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run validation Git command: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "validation Git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validation_fixture(version: &str) -> (tempfile::TempDir, String) {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(
            temporary.path().join("Cargo.toml"),
            format!("[package]\nname = \"fixture\"\nversion = \"{version}\"\n"),
        )
        .unwrap();
        for arguments in [
            vec!["init", "--quiet"],
            vec!["config", "user.name", "Fixture"],
            vec!["config", "user.email", "fixture@example.invalid"],
            vec!["add", "Cargo.toml"],
            vec!["commit", "--quiet", "-m", "fixture"],
        ] {
            assert!(
                Command::new("git")
                    .current_dir(temporary.path())
                    .args(arguments)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let head = validation_git_line(temporary.path(), &["rev-parse", "HEAD"]).unwrap();
        (temporary, head)
    }

    #[test]
    fn ci_candidate_root_is_repository_scoped_and_platform_bounded() {
        let root = workspace_root();
        assert_eq!(resolve_ci_root(None).unwrap(), root.canonicalize().unwrap());
        let alternate = resolve_ci_root(Some(root));
        if cfg!(all(unix, not(target_os = "linux"))) {
            assert_eq!(
                alternate.unwrap_err(),
                "alternate --candidate-root validation is unsupported on non-Linux Unix hosts"
            );
        } else {
            assert!(alternate.is_ok());
        }
        assert!(Cli::try_parse_from(["xtask", "ci", "--candidate-root"]).is_err());
        assert!(Cli::try_parse_from(["xtask", "ci", "--unknown", "value"]).is_err());
    }

    #[test]
    fn registry_unavailable_retains_the_ordered_wait_status() {
        assert_eq!(release_exit_code(release::Outcome::Success), 0);
        assert_eq!(release_exit_code(release::Outcome::RegistryUnavailable), 3);
    }

    #[test]
    fn release_version_validation_uses_only_the_exact_selected_checkout() {
        let (selected, head) = validation_fixture("0.4.0");
        let (unused_build, _) = validation_fixture("not-semver");
        let cli = Cli::try_parse_from([
            "xtask",
            "release-version",
            "--validation-root",
            selected.path().to_str().unwrap(),
            "--validation-head",
            &head,
            "show",
        ])
        .unwrap();
        let Task::ReleaseVersion(args) = cli.command else {
            panic!("parsed the wrong command")
        };
        release_version::run(unused_build.path(), args).unwrap();

        assert!(
            resolve_validation_root(
                unused_build.path(),
                Some(selected.path().to_path_buf()),
                Some("b".repeat(40)),
            )
            .unwrap_err()
            .contains("exact selected commit")
        );
        std::fs::write(
            selected.path().join("Cargo.toml"),
            "[package]\nname = \"dirty\"\nversion = \"0.4.0\"\n",
        )
        .unwrap();
        assert!(
            resolve_validation_root(
                unused_build.path(),
                Some(selected.path().to_path_buf()),
                Some(head),
            )
            .unwrap_err()
            .contains("tracked changes")
        );

        let (selected, head) = validation_fixture("not-semver");
        let (unused_build, _) = validation_fixture("0.4.0");
        let cli = Cli::try_parse_from([
            "xtask",
            "release-version",
            "--validation-root",
            selected.path().to_str().unwrap(),
            "--validation-head",
            &head,
            "show",
        ])
        .unwrap();
        let Task::ReleaseVersion(args) = cli.command else {
            panic!("parsed the wrong command")
        };
        assert!(release_version::run(unused_build.path(), args).is_err());
    }
}

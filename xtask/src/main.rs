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

use std::path::PathBuf;
use std::process::ExitCode;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}

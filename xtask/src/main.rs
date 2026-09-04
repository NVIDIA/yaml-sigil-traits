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
mod release_policy;
mod safe_file;

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(test)]
use clap::CommandFactory as _;
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
    Ci,
    /// Compare Cargo's source list with the committed inventory.
    PackageContent,
    /// Prepare or validate a locally owned release pull request.
    Release(release::ReleaseArgs),
    /// Run the two typed GitHub release operations.
    Github(github::GithubArgs),
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Task::Ci => ci::run(&workspace_root()).map_err(|error| error.to_string()),
        Task::PackageContent => {
            package_content::run(&workspace_root()).map_err(|error| error.to_string())
        }
        Task::Release(args) => release::run(&workspace_root(), args),
        Task::Github(args) => github::run(&workspace_root(), args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest lives in xtask/")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_contract_is_valid() {
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["xtask", "ci", "--candidate-root", "."]).is_err());
        assert!(Cli::try_parse_from(["xtask", "github", "api"]).is_err());
    }
}

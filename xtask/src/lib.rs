// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository maintenance tasks. Invoke from the repository root with
//! `cargo xtask <COMMAND>`.

mod bounded_process;
mod cargo_metadata_output;
mod ci;
mod coverage;
mod crate_archive;
mod features;
mod github;
mod package_content;
mod package_content_policy;
mod process;
mod release;
mod release_base;
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
    #[command(visible_alias = "ci")]
    Check(ci::CheckArgs),
    /// Generate an HTML coverage report for the public crate.
    Coverage(coverage::CoverageArgs),
    /// Generate a fresh coverage report and open it in the browser.
    CoverageOpen(coverage::CoverageOptions),
    /// Compare Cargo's source list with the committed inventory.
    PackageContent,
    /// Prepare or validate a locally owned release pull request.
    Release(release::ReleaseArgs),
    /// Run typed GitHub release operations.
    Github(github::GithubArgs),
}

/// Parse and run the repository maintenance command.
pub fn run() -> ExitCode {
    let result = match Cli::parse().command {
        Task::Check(args) => ci::run(&workspace_root(), &args).map_err(|error| error.to_string()),
        Task::Coverage(args) => coverage::run(&workspace_root(), &args.options, args.open)
            .map_err(|error| error.to_string()),
        Task::CoverageOpen(args) => {
            coverage::run(&workspace_root(), &args, true).map_err(|error| error.to_string())
        }
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

    #[test]
    fn check_and_ci_share_selection_and_feature_options() {
        for command in ["check", "ci"] {
            let cli = Cli::try_parse_from([
                "xtask",
                command,
                "--only=test,fmt,test",
                "--features=first,second",
                "--no-default-features",
            ])
            .unwrap();
            let Task::Check(args) = cli.command else {
                panic!("expected check")
            };
            assert_eq!(
                args.selected().unwrap(),
                [ci::CheckStep::Fmt, ci::CheckStep::Test]
            );
            assert_eq!(
                args.features.cargo_args(),
                ["--features", "first,second", "--no-default-features"]
            );
            for invalid in [
                "--only=",
                "--only=all",
                "--only=fmt,",
                "--exclude=",
                "--only=unknown",
            ] {
                assert!(Cli::try_parse_from(["xtask", command, invalid]).is_err());
            }
            assert!(
                Cli::try_parse_from(["xtask", command, "--only=fmt", "--exclude=test"]).is_err()
            );
        }
    }

    #[test]
    fn coverage_open_and_coverage_accept_the_same_engine_and_features() {
        for command in ["coverage", "coverage-open"] {
            let cli = Cli::try_parse_from([
                "xtask",
                command,
                "--engine=tarpaulin",
                "--features=example",
                "--no-default-features",
            ])
            .unwrap();
            let options = match cli.command {
                Task::Coverage(args) => args.options,
                Task::CoverageOpen(options) => options,
                _ => panic!("expected coverage"),
            };
            assert_eq!(options.engine, coverage::CoverageEngine::Tarpaulin);
            assert_eq!(
                options.features.cargo_args(),
                ["--features", "example", "--no-default-features"]
            );
            assert!(Cli::try_parse_from(["xtask", command, "--engine=unknown"]).is_err());
        }
        assert!(matches!(
            Cli::try_parse_from(["xtask", "coverage", "--open"])
                .unwrap()
                .command,
            Task::Coverage(coverage::CoverageArgs { open: true, .. })
        ));
        for command in ["check", "ci", "coverage", "coverage-open"] {
            assert!(
                Cli::try_parse_from(["xtask", command, "--all-features", "--features=example"])
                    .is_err()
            );
            assert!(
                Cli::try_parse_from(["xtask", command, "--all-features", "--no-default-features"])
                    .is_err()
            );
            assert!(Cli::try_parse_from(["xtask", command, "--features="]).is_err());
        }
        for omitted in ["image", "profile", "profile-open", "mcp"] {
            assert!(Cli::try_parse_from(["xtask", omitted]).is_err());
        }
    }
}

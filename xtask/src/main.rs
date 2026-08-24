// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository maintenance tasks. Invoke from the repository root with
//! `cargo xtask <COMMAND>`.

mod ci;
mod package_content;
mod release_version;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let remaining: Vec<_> = args.collect();

    match command.as_str() {
        "ci" if !is_help_request(&remaining) => {
            match parse_ci_root(&remaining)
                .and_then(|root| ci::run(&root).map_err(|error| error.to_string()))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("ci failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "package-content" if remaining.is_empty() => {
            match package_content::run(&workspace_root()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("package-content failed: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "release-version" => match release_version::run(&workspace_root(), &remaining) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("release-version failed: {error}");
                ExitCode::FAILURE
            }
        },
        "" | "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "ci" | "package-content" if is_help_request(&remaining) => {
            print_usage();
            ExitCode::SUCCESS
        }
        "package-content" => {
            eprintln!("{command} does not accept arguments");
            print_usage();
            ExitCode::FAILURE
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage();
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

fn parse_ci_root(args: &[String]) -> Result<PathBuf, String> {
    let candidate = match args {
        [] => workspace_root(),
        [flag, value] if flag == "--candidate-root" && !value.is_empty() => PathBuf::from(value),
        [flag, _] if flag == "--candidate-root" => {
            return Err("--candidate-root needs a nonempty path".to_string());
        }
        _ => return Err("ci accepts only --candidate-root PATH".to_string()),
    };
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

fn is_help_request(args: &[String]) -> bool {
    matches!(args, [arg] if matches!(arg.as_str(), "help" | "--help" | "-h"))
}

fn print_usage() {
    eprintln!(
        "usage:\n  cargo xtask ci [--candidate-root PATH]\n  cargo xtask package-content\n  \
         cargo xtask release-version <COMMAND>\n\n\
         commands:\n  ci               Run the complete non-release validation sequence.\n  \
                            --candidate-root validates another checkout.\n  \
         package-content  Compare Cargo's source list with the committed inventory.\n  \
         release-version  Manage provider-neutral release version transactions."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_candidate_root_is_repository_scoped() {
        let root = workspace_root();
        assert_eq!(
            parse_ci_root(&["--candidate-root".to_string(), root.display().to_string(),]).unwrap(),
            root.canonicalize().unwrap()
        );
        assert!(parse_ci_root(&["--candidate-root".to_string()]).is_err());
        assert!(parse_ci_root(&["--unknown".to_string(), "value".to_string()]).is_err());
    }
}

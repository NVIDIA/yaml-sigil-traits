// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository maintenance tasks. Invoke from the repository root with
//! `cargo xtask <COMMAND>`.

mod ci;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let remaining: Vec<_> = args.collect();

    match command.as_str() {
        "ci" if remaining.is_empty() => match ci::run(&workspace_root()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ci failed: {error}");
                ExitCode::FAILURE
            }
        },
        "" | "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "ci" if is_help_request(&remaining) => {
            print_usage();
            ExitCode::SUCCESS
        }
        "ci" => {
            eprintln!("ci does not accept arguments");
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

fn is_help_request(args: &[String]) -> bool {
    matches!(args, [arg] if matches!(arg.as_str(), "help" | "--help" | "-h"))
}

fn print_usage() {
    eprintln!(
        "usage:\n  cargo xtask ci\n\n\
         Runs the repository's complete non-release validation sequence."
    );
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral local validation.

use std::io;
use std::path::Path;
use std::process::Command;

use crate::{package_content, release};

const REQUIRED_TOOLS: &[(&str, &str)] = &[
    (
        "cargo-machete",
        "cargo install --locked cargo-machete --version 0.9.2",
    ),
    (
        "cargo-deny",
        "cargo install --locked cargo-deny --version 0.20.2",
    ),
    (
        "cargo-audit",
        "cargo +1.98.0 install --locked cargo-audit --version 0.22.2",
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Step {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

const PRE_PACKAGE_STEPS: &[Step] = &[
    Step {
        label: "Markdown lint",
        program: "rumdl",
        args: &["check", "."],
    },
    Step {
        label: "Rust formatting",
        program: "cargo",
        args: &["fmt", "--all", "--check"],
    },
    Step {
        label: "xtask formatting",
        program: "cargo",
        args: &[
            "fmt",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--all",
            "--check",
        ],
    },
];

const POST_PACKAGE_STEPS: &[Step] = &[
    Step {
        label: "Rust lint",
        program: "cargo",
        args: &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    },
    Step {
        label: "xtask lint",
        program: "cargo",
        args: &[
            "clippy",
            "--locked",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    },
    Step {
        label: "Rust tests",
        program: "cargo",
        args: &["test", "--all-features"],
    },
    Step {
        label: "xtask tests",
        program: "cargo",
        args: &["test", "--locked", "--manifest-path", "xtask/Cargo.toml"],
    },
    Step {
        label: "Unused Rust dependencies",
        program: "cargo-machete",
        args: &["--with-metadata"],
    },
    Step {
        label: "Rust dependency policy",
        program: "cargo-deny",
        args: &["check", "bans", "licenses", "sources", "-D", "warnings"],
    },
    Step {
        label: "xtask dependency policy",
        program: "cargo-deny",
        args: &[
            "--manifest-path",
            "xtask/Cargo.toml",
            "--locked",
            "check",
            "bans",
            "licenses",
            "sources",
            "-D",
            "warnings",
        ],
    },
    Step {
        label: "Rust dependency audit",
        program: "cargo",
        args: &["audit"],
    },
    Step {
        label: "xtask dependency audit",
        program: "cargo",
        args: &["audit", "--file", "xtask/Cargo.lock"],
    },
];

pub(crate) fn run(root: &Path) -> io::Result<()> {
    for (program, install) in REQUIRED_TOOLS {
        require_tool(program, install)?;
    }
    for step in PRE_PACKAGE_STEPS {
        run_step(root, *step)?;
    }
    release::check_manifest(root).map_err(io::Error::other)?;
    package_content::run(root)?;
    for step in POST_PACKAGE_STEPS {
        run_step(root, *step)?;
    }
    Ok(())
}

fn require_tool(program: &str, install: &str) -> io::Result<()> {
    match Command::new(program).arg("--version").status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::other(format!(
            "{program} --version failed with {status}; install with `{install}`"
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{program} is required; install with `{install}`"),
        )),
        Err(error) => Err(error),
    }
}

fn run_step(root: &Path, step: Step) -> io::Result<()> {
    eprintln!(
        "+ {} {} (cwd {})",
        step.program,
        step.args.join(" "),
        root.display()
    );
    let status = Command::new(step.program)
        .args(step.args)
        .current_dir(root)
        .status()
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", step.label)))?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{} failed with {status}",
            step.label
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_sequence_keeps_release_mutation_out() {
        let commands: Vec<_> = PRE_PACKAGE_STEPS
            .iter()
            .chain(POST_PACKAGE_STEPS)
            .map(|step| {
                std::iter::once(step.program)
                    .chain(step.args.iter().copied())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        assert!(
            commands
                .iter()
                .any(|line| line == "cargo test --all-features")
        );
        assert!(commands.iter().any(|line| line == "cargo audit"));
        assert!(commands.iter().all(|line| !line.contains("publish")));
        assert!(commands.iter().all(|line| !line.contains("release-plz")));
    }
}

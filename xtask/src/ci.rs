// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local entry point for the repository's non-release validation sequence.

use std::io;
use std::path::Path;
use std::process::Command;

use crate::{package_content, release_version};

const CARGO_MACHETE_INSTALL_COMMAND: &str = "cargo install --locked cargo-machete --version 0.9.2";

#[derive(Clone, Copy, Debug)]
struct Step {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

impl Step {
    fn command_line(self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    }
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
    // A Cargo-launched xtask must invoke this binary directly. In cargo-machete
    // 0.9.2, inherited Cargo package variables otherwise make `cargo machete`
    // parse its subcommand name as an input path.
    Step {
        label: "Unused Rust dependencies",
        program: "cargo-machete",
        args: &["--with-metadata"],
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
    require_cargo_machete()?;
    for step in PRE_PACKAGE_STEPS {
        run_step(root, *step)?;
    }
    release_version::check(root).map_err(io::Error::other)?;
    package_content::run(root)?;
    for step in POST_PACKAGE_STEPS {
        run_step(root, *step)?;
    }
    Ok(())
}

fn run_step(root: &Path, step: Step) -> io::Result<()> {
    eprintln!("+ {} (cwd {})", step.command_line(), root.display());
    let status = Command::new(step.program)
        .args(step.args)
        .current_dir(root)
        .status()
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", step.label)))?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "{} failed with {status}",
            step.label
        )));
    }
    Ok(())
}

fn require_cargo_machete() -> io::Result<()> {
    let output = Command::new("cargo-machete")
        .arg("--version")
        .output()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "cargo-machete is required but was not found.\n\n\
                         Install it with:\n    {CARGO_MACHETE_INSTALL_COMMAND}"
                    ),
                )
            } else {
                io::Error::new(
                    error.kind(),
                    format!("failed to run cargo-machete: {error}"),
                )
            }
        })?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "cargo-machete --version failed with {}.\n\n{}",
            output.status, CARGO_MACHETE_INSTALL_COMMAND
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CARGO_MACHETE_INSTALL_COMMAND, POST_PACKAGE_STEPS};

    const AGENT_GUIDANCE: &str = include_str!("../../AGENTS.md");
    const GITMODULES: &str = include_str!("../../.gitmodules");

    #[test]
    fn git_dependencies_skip_the_non_build_spec_submodule() {
        const SOURCE_SPEC: &str = "[submodule \"source-spec\"]\n\
\tpath = source-spec\n\
\turl = https://github.com/NVIDIA/yaml-sigil-spec.git\n\
\tupdate = none";
        let gitmodules = GITMODULES.replace("\r\n", "\n");

        assert!(
            gitmodules.contains(SOURCE_SPEC),
            "source-spec must remain excluded from automatic submodule updates"
        );
    }

    #[test]
    fn cargo_machete_guidance_is_aligned_and_actionable() {
        assert_eq!(
            CARGO_MACHETE_INSTALL_COMMAND,
            "cargo install --locked cargo-machete --version 0.9.2"
        );
        assert!(AGENT_GUIDANCE.contains(CARGO_MACHETE_INSTALL_COMMAND));
        assert!(AGENT_GUIDANCE.contains("cargo-machete --with-metadata"));
    }

    #[test]
    fn dependency_audits_cover_root_and_xtask_locks() {
        let commands = POST_PACKAGE_STEPS
            .iter()
            .map(|step| step.command_line())
            .collect::<Vec<_>>();

        assert!(commands.iter().any(|command| command == "cargo audit"));
        assert!(
            commands
                .iter()
                .any(|command| command == "cargo audit --file xtask/Cargo.lock")
        );
        assert!(AGENT_GUIDANCE.contains("cargo audit --file xtask/Cargo.lock"));
    }
}

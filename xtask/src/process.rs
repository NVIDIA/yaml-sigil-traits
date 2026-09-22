// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Argument-vector execution and selected-tool prerequisite checks.

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandSpec {
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
    pub(crate) env: Vec<(OsString, OsString)>,
}

impl CommandSpec {
    pub(crate) fn new(program: impl Into<OsString>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(OsString::from).collect(),
            env: Vec::new(),
        }
    }

    pub(crate) fn cargo(args: &[&str]) -> Self {
        Self::new(cargo_program(), args)
    }

    pub(crate) fn env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    pub(crate) fn run(&self, root: &Path) -> io::Result<()> {
        eprintln!(
            "+ {:?} {:?} (cwd {})",
            self.program,
            self.args,
            root.display()
        );
        let status = self.command(root).status().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to run {:?}: {error}", self.program),
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{:?} failed with {status}",
                self.program
            )))
        }
    }

    fn command(&self, root: &Path) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .current_dir(root);
        command
    }
}

fn cargo_program() -> OsString {
    std::env::var_os("CARGO")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cargo".into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Probe {
    pub(crate) name: &'static str,
    pub(crate) command: CommandSpec,
    pub(crate) install: &'static str,
}

impl Probe {
    pub(crate) fn tool(name: &'static str, install: &'static str) -> Self {
        Self {
            name,
            command: CommandSpec::new(name, &["--version"]),
            install,
        }
    }

    pub(crate) fn cargo_tool(
        name: &'static str,
        subcommand: &'static str,
        install: &'static str,
    ) -> Self {
        Self {
            name,
            command: CommandSpec::new(format!("cargo-{subcommand}"), &[subcommand, "--version"]),
            install,
        }
    }

    pub(crate) fn cargo() -> Self {
        Self {
            name: "Cargo",
            command: CommandSpec::cargo(&["--version"]),
            install: "Install Rust with rustup: https://rustup.rs/",
        }
    }

    pub(crate) fn require(&self, root: &Path) -> io::Result<()> {
        let result = self
            .command
            .command(root)
            .output()
            .map(|output| ProbeResult {
                success: output.status.success(),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        self.validate(result)
    }

    fn validate(&self, result: io::Result<ProbeResult>) -> io::Result<()> {
        match result {
            Ok(result) if result.success => Ok(()),
            Ok(result) => Err(io::Error::other(format!(
                "{} is installed but unusable ({}): {}\n{}",
                self.name, result.status, result.stderr, self.install
            ))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} was not found.\n{}", self.name, self.install),
            )),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("{} could not launch: {error}\n{}", self.name, self.install),
            )),
        }
    }
}

struct ProbeResult {
    success: bool,
    status: String,
    stderr: String,
}

pub(crate) fn require_unique(
    root: &Path,
    probes: impl IntoIterator<Item = Probe>,
) -> io::Result<()> {
    let mut checked = Vec::new();
    for probe in probes {
        if !checked.contains(&probe) {
            probe.require(root)?;
            checked.push(probe);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prerequisites_distinguish_missing_and_unusable_tools() {
        let probe = Probe::tool("cargo-tarpaulin", "cargo install --locked cargo-tarpaulin");
        let missing = probe
            .validate(Err(io::Error::from(io::ErrorKind::NotFound)))
            .unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(missing.to_string().contains("was not found"));
        let unusable = probe
            .validate(Ok(ProbeResult {
                success: false,
                status: "exit status: 127".into(),
                stderr: "libssl.so.1.1 is missing".into(),
            }))
            .unwrap_err();
        assert!(unusable.to_string().contains("installed but unusable"));
        assert!(unusable.to_string().contains("libssl.so.1.1 is missing"));
        for error in [missing, unusable] {
            assert!(error.to_string().contains(probe.install));
        }
    }

    #[test]
    fn arguments_remain_separate_os_values() {
        let command = CommandSpec::new("tool", &["a path with spaces", "$(literal)"]);
        assert_eq!(command.args, ["a path with spaces", "$(literal)"]);
    }
}

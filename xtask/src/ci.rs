// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral checks for the crate and the isolated developer workspace.

use std::io;
use std::path::Path;

use clap::{Args, ValueEnum};

use crate::features::FeatureArgs;
use crate::process::{self, CommandSpec, Probe};
use crate::{package_content, release};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CheckStep {
    Markdown,
    Fmt,
    PackageContent,
    Check,
    Clippy,
    Test,
    Machete,
    Deny,
    Audit,
}

const REGISTRY: &[CheckStep] = &[
    CheckStep::Markdown,
    CheckStep::Fmt,
    CheckStep::PackageContent,
    CheckStep::Check,
    CheckStep::Clippy,
    CheckStep::Test,
    CheckStep::Machete,
    CheckStep::Deny,
    CheckStep::Audit,
];

#[derive(Args, Debug, Default)]
pub(crate) struct CheckArgs {
    /// Run only these checks, in registry order.
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "STEP,...",
        conflicts_with = "exclude"
    )]
    pub(crate) only: Vec<CheckStep>,
    /// Run every check except these.
    #[arg(long, value_delimiter = ',', value_name = "STEP,...")]
    pub(crate) exclude: Vec<CheckStep>,
    #[command(flatten)]
    pub(crate) features: FeatureArgs,
}

impl CheckArgs {
    pub(crate) fn selected(&self) -> io::Result<Vec<CheckStep>> {
        let selected: Vec<_> = REGISTRY
            .iter()
            .copied()
            .filter(|step| self.only.is_empty() || self.only.contains(step))
            .filter(|step| !self.exclude.contains(step))
            .collect();
        if selected.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selection contains no checks",
            ));
        }
        Ok(selected)
    }
}

impl CheckStep {
    fn probes(self) -> Vec<Probe> {
        match self {
            Self::Markdown => vec![Probe::tool("rumdl", "cargo install rumdl")],
            Self::Fmt => vec![Probe::cargo_tool(
                "rustfmt",
                "fmt",
                "rustup component add rustfmt",
            )],
            Self::Clippy => vec![Probe::cargo_tool(
                "Clippy",
                "clippy",
                "rustup component add clippy",
            )],
            Self::PackageContent | Self::Check | Self::Test => vec![Probe::cargo()],
            Self::Machete => vec![Probe::tool(
                "cargo-machete",
                "cargo install --locked cargo-machete --version 0.9.2",
            )],
            Self::Deny => vec![Probe::tool(
                "cargo-deny",
                "cargo install --locked cargo-deny --version 0.20.2",
            )],
            Self::Audit => vec![
                Probe::cargo(),
                Probe::tool(
                    "cargo-audit",
                    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2",
                ),
            ],
        }
    }

    fn commands(self, features: &FeatureArgs) -> Vec<CommandSpec> {
        match self {
            Self::Markdown => vec![CommandSpec::new("rumdl", &["check", "."])],
            Self::Fmt => vec![
                CommandSpec::cargo(&["fmt", "--all", "--check"]),
                CommandSpec::cargo(&[
                    "fmt",
                    "--manifest-path",
                    "xtask/Cargo.toml",
                    "--all",
                    "--check",
                ]),
            ],
            Self::Check | Self::Clippy | Self::Test => {
                let subcommand = match self {
                    Self::Check => "check",
                    Self::Clippy => "clippy",
                    Self::Test => "test",
                    _ => unreachable!(),
                };
                let mut root = CommandSpec::cargo(&[subcommand]);
                let mut xtask = CommandSpec::cargo(&[
                    subcommand,
                    "--locked",
                    "--manifest-path",
                    "xtask/Cargo.toml",
                ]);
                for command in [&mut root, &mut xtask] {
                    if self != Self::Test {
                        command.args.push("--all-targets".into());
                    }
                }
                root.args.extend(features.cargo_args());
                xtask.args.push("--all-features".into());
                for command in [&mut root, &mut xtask] {
                    if self == Self::Clippy {
                        command
                            .args
                            .extend(["--", "-D", "warnings"].map(Into::into));
                    }
                }
                vec![root, xtask]
            }
            Self::Machete => vec![CommandSpec::new("cargo-machete", &["--with-metadata"])],
            Self::Deny => {
                let mut root = CommandSpec::new("cargo-deny", &[]);
                root.args.extend(features.cargo_args());
                root.args.extend(
                    ["check", "bans", "licenses", "sources", "-D", "warnings"].map(Into::into),
                );
                vec![
                    root,
                    CommandSpec::new(
                        "cargo-deny",
                        &[
                            "--manifest-path",
                            "xtask/Cargo.toml",
                            "--locked",
                            "--all-features",
                            "check",
                            "bans",
                            "licenses",
                            "sources",
                            "-D",
                            "warnings",
                        ],
                    ),
                ]
            }
            Self::Audit => vec![
                CommandSpec::cargo(&["audit"]),
                CommandSpec::cargo(&["audit", "--file", "xtask/Cargo.lock"]),
            ],
            Self::PackageContent => Vec::new(),
        }
    }
}

pub(crate) fn run(root: &Path, args: &CheckArgs) -> io::Result<()> {
    let selected = args.selected()?;
    process::require_unique(root, selected.iter().flat_map(|step| step.probes()))?;
    for step in selected {
        if step == CheckStep::PackageContent {
            release::check_manifest(root).map_err(io::Error::other)?;
            package_content::run(root)?;
        }
        if step == CheckStep::Audit && !root.join("Cargo.lock").try_exists()? {
            // The public library deliberately has no committed lockfile. A
            // standalone audit needs the same resolved graph as a normal build.
            CommandSpec::cargo(&["generate-lockfile"]).run(root)?;
        }
        for command in step.commands(&args.features) {
            command.run(root)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_is_deduplicated_and_ordered() {
        assert_eq!(CheckArgs::default().selected().unwrap(), REGISTRY);
        let args = CheckArgs {
            only: vec![CheckStep::Test, CheckStep::Fmt, CheckStep::Test],
            ..CheckArgs::default()
        };
        assert_eq!(args.selected().unwrap(), [CheckStep::Fmt, CheckStep::Test]);
        assert!(
            CheckArgs {
                exclude: REGISTRY.to_vec(),
                ..CheckArgs::default()
            }
            .selected()
            .is_err()
        );
    }

    #[test]
    fn both_workspaces_keep_their_lockfile_and_feature_policy() {
        let features = FeatureArgs {
            features: vec!["product-feature".into()],
            no_default_features: true,
            ..FeatureArgs::default()
        };
        for step in [
            CheckStep::Check,
            CheckStep::Clippy,
            CheckStep::Test,
            CheckStep::Deny,
        ] {
            let commands = step.commands(&features);
            assert_eq!(commands.len(), 2);
            assert!(!commands[0].args.contains(&"--locked".into()));
            assert!(commands[1].args.contains(&"--locked".into()));
            assert!(commands[1].args.contains(&"xtask/Cargo.toml".into()));
            assert!(commands[0].args.contains(&"--no-default-features".into()));
            assert!(commands[0].args.contains(&"product-feature".into()));
            assert!(!commands[0].args.contains(&"--all-features".into()));
            assert!(commands[1].args.contains(&"--all-features".into()));
            assert!(!commands[1].args.contains(&"product-feature".into()));
            assert!(!commands[1].args.contains(&"--no-default-features".into()));
        }
        for command in CheckStep::Fmt.commands(&features) {
            assert!(!command.args.contains(&"--no-default-features".into()));
        }
    }

    #[test]
    fn default_checks_preserve_both_dependency_graphs_and_denied_warnings() {
        assert_eq!(CheckStep::Deny.commands(&FeatureArgs::default()).len(), 2);
        let audits = CheckStep::Audit.commands(&FeatureArgs::default());
        assert_eq!(audits[0].args, ["audit"]);
        assert_eq!(audits[1].args, ["audit", "--file", "xtask/Cargo.lock"]);
        for command in CheckStep::Clippy.commands(&FeatureArgs::default()) {
            assert!(command.args.contains(&"--all-targets".into()));
            assert!(command.args.contains(&"--all-features".into()));
            assert!(
                command
                    .args
                    .ends_with(&["--".into(), "-D".into(), "warnings".into()])
            );
        }
        assert_eq!(
            CheckStep::Machete.commands(&FeatureArgs::default())[0].program,
            "cargo-machete"
        );
    }

    #[test]
    fn narrow_checks_do_not_require_unselected_tools() {
        let args = CheckArgs {
            only: vec![CheckStep::Fmt],
            ..CheckArgs::default()
        };
        let probes: Vec<_> = args
            .selected()
            .unwrap()
            .into_iter()
            .flat_map(CheckStep::probes)
            .collect();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].name, "rustfmt");
    }
}

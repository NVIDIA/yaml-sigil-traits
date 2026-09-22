// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Cargo feature selection shared by checks and coverage.

use std::ffi::OsString;

use clap::Args;

#[derive(Args, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FeatureArgs {
    /// Enable every feature (the default when no feature option is supplied).
    #[arg(long, conflicts_with_all = ["features", "no_default_features"])]
    pub(crate) all_features: bool,
    /// Enable the named Cargo features.
    #[arg(long, value_delimiter = ',', value_name = "FEATURE,...", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub(crate) features: Vec<String>,
    /// Disable the default features; may be combined with --features.
    #[arg(long)]
    pub(crate) no_default_features: bool,
}

impl FeatureArgs {
    pub(crate) fn cargo_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if self.all_features || (self.features.is_empty() && !self.no_default_features) {
            args.push("--all-features".into());
        }
        if !self.features.is_empty() {
            args.extend(["--features".into(), self.features.join(",").into()]);
        }
        if self.no_default_features {
            args.push("--no-default-features".into());
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_features_replace_the_all_features_default() {
        assert_eq!(FeatureArgs::default().cargo_args(), ["--all-features"]);
        let explicit = FeatureArgs {
            features: vec!["first".into(), "second".into()],
            no_default_features: true,
            ..FeatureArgs::default()
        };
        assert_eq!(
            explicit.cargo_args(),
            ["--features", "first,second", "--no-default-features"]
        );
        assert_eq!(
            FeatureArgs {
                no_default_features: true,
                ..FeatureArgs::default()
            }
            .cargo_args(),
            ["--no-default-features"]
        );
    }
}

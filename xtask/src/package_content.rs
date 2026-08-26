// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Static source-package inventory validation without archive assembly.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::process::Command;

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::package_content_policy::PACKAGE_SPECS;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PackageSpec {
    pub(crate) name: &'static str,
    pub(crate) inventory_path: &'static str,
    pub(crate) inventory: &'static str,
}

const SYNTHETIC_LOCKFILE: &str = "Cargo.lock";

#[derive(Debug, Eq, PartialEq)]
struct InventoryDifference {
    missing: Vec<String>,
    unexpected: Vec<String>,
}

/// Compare Cargo's modeled package paths with the committed exact inventories.
///
/// `cargo package --list` is deliberately run with `--exclude-lockfile` so a
/// root lockfile does not trigger dependency resolution for the unpublished
/// workspace. Cargo would generate a package-local lockfile during real
/// package assembly, so this validator adds that one path to the observed set.
pub(crate) fn run(root: &Path) -> io::Result<()> {
    let mut failures = Vec::new();

    for package in PACKAGE_SPECS {
        match check_package(root, *package) {
            Ok(count) => eprintln!("{}: package contents match ({count} paths)", package.name),
            Err(error) => failures.push(format!("{}: {error}", package.name)),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "package content validation failed:\n\n{}",
            failures.join("\n\n")
        )))
    }
}

fn check_package(root: &Path, package: PackageSpec) -> io::Result<usize> {
    let expected = parse_inventory(package.inventory, package.inventory_path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let args = package_list_args(package.name);
    eprintln!("+ cargo {} (cwd {})", args.join(" "), root.display());

    let mut command = Command::new("cargo");
    command.current_dir(root).args(args);
    let output =
        bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to run cargo package --list: {error}"),
            )
        })?;

    if !output.stderr.is_empty() {
        io::stderr().lock().write_all(&output.stderr)?;
    }
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "cargo package --list failed with {}",
            output.status
        )));
    }

    let stdout = std::str::from_utf8(&output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cargo package --list returned non-UTF-8 output: {error}"),
        )
    })?;
    let mut actual = parse_cargo_list(stdout)?;
    actual.insert(SYNTHETIC_LOCKFILE.to_owned());

    let difference = compare_inventories(&expected, &actual);
    if difference.missing.is_empty() && difference.unexpected.is_empty() {
        Ok(actual.len())
    } else {
        Err(io::Error::other(format_difference(&difference)))
    }
}

#[cfg(all(test, windows))]
pub(crate) fn check_test_package(root: &Path) -> io::Result<usize> {
    check_package(
        root,
        PackageSpec {
            name: "candidate-package",
            inventory_path: "test package inventory",
            inventory: "Cargo.lock\nCargo.toml\nCargo.toml.orig\nsrc/lib.rs\n",
        },
    )
}

fn package_list_args(package: &str) -> [&str; 6] {
    [
        "package",
        "--list",
        "--allow-dirty",
        "--exclude-lockfile",
        "--package",
        package,
    ]
}

fn parse_inventory(text: &str, label: &str) -> Result<BTreeSet<String>, String> {
    if text.is_empty() {
        return Err(format!("{label} is empty"));
    }
    if !text.ends_with('\n') {
        return Err(format!("{label} must end with a line feed"));
    }
    if text.contains('\r') {
        return Err(format!("{label} must use line-feed terminators"));
    }

    let mut paths = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for (index, path) in text.lines().enumerate() {
        let line = index + 1;
        validate_inventory_path(path, label, line)?;

        if let Some(prior) = previous {
            match prior.as_bytes().cmp(path.as_bytes()) {
                std::cmp::Ordering::Greater => {
                    return Err(format!(
                        "{label}:{line}: paths are not bytewise sorted: {path} follows {prior}"
                    ));
                }
                std::cmp::Ordering::Equal => {
                    return Err(format!("{label}:{line}: duplicate path: {path}"));
                }
                std::cmp::Ordering::Less => {}
            }
        }

        paths.insert(path.to_owned());
        previous = Some(path);
    }
    Ok(paths)
}

fn parse_cargo_list(text: &str) -> io::Result<BTreeSet<String>> {
    let normalized = normalize_platform_separators(text, std::path::MAIN_SEPARATOR);
    parse_inventory(&normalized, "cargo package --list output")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn normalize_platform_separators(text: &str, separator: char) -> String {
    text.replace(separator, "/")
}

fn validate_inventory_path(path: &str, label: &str, line: usize) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{label}:{line}: blank path"));
    }
    if path.starts_with('#') {
        return Err(format!("{label}:{line}: comments are not allowed"));
    }
    if path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || !Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{label}:{line}: path must be a normalized crate-relative path: {path}"
        ));
    }
    Ok(())
}

fn compare_inventories(
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
) -> InventoryDifference {
    InventoryDifference {
        missing: expected.difference(actual).cloned().collect(),
        unexpected: actual.difference(expected).cloned().collect(),
    }
}

fn format_difference(difference: &InventoryDifference) -> String {
    let mut message = String::from("package contents differ");
    if !difference.missing.is_empty() {
        message.push_str("\n  missing from package:");
        for path in &difference.missing {
            message.push_str("\n    ");
            message.push_str(path);
        }
    }
    if !difference.unexpected.is_empty() {
        message.push_str("\n  unexpected in package:");
        for path in &difference.unexpected {
            message.push_str("\n    ");
            message.push_str(path);
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_policy_is_nonempty_and_unique() {
        assert!(!PACKAGE_SPECS.is_empty());

        let names = PACKAGE_SPECS
            .iter()
            .map(|package| package.name)
            .collect::<BTreeSet<_>>();
        let inventories = PACKAGE_SPECS
            .iter()
            .map(|package| package.inventory_path)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), PACKAGE_SPECS.len());
        assert_eq!(inventories.len(), PACKAGE_SPECS.len());
    }

    #[test]
    fn package_list_flags_are_exact() {
        assert_eq!(
            package_list_args("example"),
            [
                "package",
                "--list",
                "--allow-dirty",
                "--exclude-lockfile",
                "--package",
                "example",
            ]
        );
    }

    #[test]
    fn committed_inventories_are_canonical() {
        for package in PACKAGE_SPECS {
            parse_inventory(package.inventory, package.inventory_path)
                .unwrap_or_else(|error| panic!("{}: {error}", package.name));
        }
    }

    #[test]
    fn parser_rejects_noncanonical_inventory_text() {
        for (text, message) in [
            ("", "is empty"),
            ("src/lib.rs", "must end with a line feed"),
            ("src/lib.rs\r\n", "must use line-feed terminators"),
            ("src/lib.rs\n\n", "blank path"),
            ("# note\n", "comments are not allowed"),
            ("/src/lib.rs\n", "normalized crate-relative path"),
            ("../src/lib.rs\n", "normalized crate-relative path"),
            ("src//lib.rs\n", "normalized crate-relative path"),
            ("src/./lib.rs\n", "normalized crate-relative path"),
            ("src/\n", "normalized crate-relative path"),
            ("src\\lib.rs\n", "normalized crate-relative path"),
            ("src/z.rs\nsrc/a.rs\n", "not bytewise sorted"),
            ("src/lib.rs\nsrc/lib.rs\n", "duplicate path"),
        ] {
            let error = parse_inventory(text, "test inventory")
                .expect_err("noncanonical inventory must fail");
            assert!(error.contains(message), "unexpected error: {error}");
        }
    }

    #[test]
    fn cargo_output_normalizes_only_the_platform_separator() {
        assert_eq!(
            normalize_platform_separators("src\\lib.rs\n", '\\'),
            "src/lib.rs\n"
        );
        assert_eq!(
            normalize_platform_separators("src\\lib.rs\n", '/'),
            "src\\lib.rs\n"
        );
    }

    #[test]
    fn differences_name_missing_and_unexpected_paths_deterministically() {
        let expected = paths(&["README.md", "src/lib.rs"]);
        let actual = paths(&["README.md", "src/new.rs"]);
        let difference = compare_inventories(&expected, &actual);
        assert_eq!(
            format_difference(&difference),
            concat!(
                "package contents differ\n",
                "  missing from package:\n",
                "    src/lib.rs\n",
                "  unexpected in package:\n",
                "    src/new.rs"
            )
        );
        assert_eq!(
            compare_inventories(&expected, &expected),
            InventoryDifference {
                missing: Vec::new(),
                unexpected: Vec::new(),
            }
        );
    }

    fn paths(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Static validation of the crate source-package inventory.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::process::Command;

#[derive(Clone, Copy, Debug)]
struct PackageSpec {
    name: &'static str,
    inventory_path: &'static str,
    inventory: &'static str,
}

const PACKAGE_SPECS: &[PackageSpec] = &[PackageSpec {
    name: "yaml-sigil-traits",
    inventory_path: "xtask/package-contents/yaml-sigil-traits.txt",
    inventory: include_str!("../package-contents/yaml-sigil-traits.txt"),
}];

#[derive(Debug, Eq, PartialEq)]
struct InventoryDifference {
    missing: Vec<String>,
    unexpected: Vec<String>,
}

pub(crate) fn run(root: &Path) -> io::Result<()> {
    let mut failures = Vec::new();

    for spec in PACKAGE_SPECS {
        match check_package(root, *spec) {
            Ok(path_count) => {
                eprintln!("{}: package contents match ({path_count} paths)", spec.name);
            }
            Err(error) => failures.push(format!("{}: {error}", spec.name)),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("\n\n")))
    }
}

fn check_package(root: &Path, spec: PackageSpec) -> io::Result<usize> {
    let expected = parse_inventory(spec.inventory).map_err(|message| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {message}", spec.inventory_path),
        )
    })?;

    let args = cargo_package_list_args(spec.name);
    eprintln!("+ cargo {} (cwd {})", args.join(" "), root.display());
    let output = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to run cargo package --list: {error}"),
            )
        })?;

    io::stderr().write_all(&output.stderr)?;
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

    // `--exclude-lockfile` prevents an ignored root lockfile from changing
    // Cargo's dependency-resolution behavior. Cargo source archives still
    // synthesize Cargo.lock, so model that generated entry before comparison.
    actual.insert("Cargo.lock".to_owned());

    let difference = compare_inventories(&expected, &actual);
    if difference.missing.is_empty() && difference.unexpected.is_empty() {
        Ok(actual.len())
    } else {
        Err(io::Error::other(format_difference(&difference)))
    }
}

fn cargo_package_list_args(package: &str) -> [&str; 6] {
    [
        "package",
        "--list",
        "--allow-dirty",
        "--exclude-lockfile",
        "--package",
        package,
    ]
}

fn parse_inventory(contents: &str) -> Result<BTreeSet<String>, String> {
    if !contents.ends_with('\n') {
        return Err("inventory must end with a newline".to_owned());
    }
    if contents.contains('\r') {
        return Err("inventory must use line-feed terminators".to_owned());
    }

    let mut paths = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for (index, path) in contents.lines().enumerate() {
        let line_number = index + 1;
        validate_inventory_path(path, line_number)?;

        if let Some(previous_path) = previous {
            if path == previous_path {
                return Err(format!("line {line_number} duplicates `{path}`"));
            }
            if path < previous_path {
                return Err(format!(
                    "line {line_number} is not bytewise sorted: `{path}` follows `{previous_path}`"
                ));
            }
        }

        paths.insert(path.to_owned());
        previous = Some(path);
    }

    if paths.is_empty() {
        return Err("inventory must contain at least one path".to_owned());
    }

    Ok(paths)
}

fn parse_cargo_list(contents: &str) -> io::Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    let normalized_contents = normalize_platform_separators(contents, std::path::MAIN_SEPARATOR);
    for (index, path) in normalized_contents.lines().enumerate() {
        validate_inventory_path(path, index + 1).map_err(|message| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid cargo package --list output: {message}"),
            )
        })?;
        if !paths.insert(path.to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cargo package --list returned duplicate path `{path}`"),
            ));
        }
    }
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cargo package --list returned no paths",
        ));
    }
    Ok(paths)
}

fn normalize_platform_separators(contents: &str, separator: char) -> String {
    contents.replace(separator, "/")
}

fn validate_inventory_path(path: &str, line_number: usize) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("line {line_number} is blank"));
    }
    if path.starts_with('#') {
        return Err(format!(
            "line {line_number} is a comment; comments are not allowed"
        ));
    }
    if path.contains('\\') {
        return Err(format!(
            "line {line_number} uses a backslash; paths must use `/` separators"
        ));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(format!(
            "line {line_number} is not a normalized crate-relative path: `{path}`"
        ));
    }
    if Path::new(path).components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::CurDir | Component::ParentDir
        )
    }) {
        return Err(format!(
            "line {line_number} is not a normalized crate-relative path: `{path}`"
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
    use super::{
        InventoryDifference, PACKAGE_SPECS, cargo_package_list_args, compare_inventories,
        format_difference, normalize_platform_separators, parse_inventory,
    };
    use std::collections::BTreeSet;

    #[test]
    fn package_scope_and_order_are_explicit() {
        let names: Vec<_> = PACKAGE_SPECS.iter().map(|spec| spec.name).collect();
        assert_eq!(names, ["yaml-sigil-traits"]);
    }

    #[test]
    fn package_list_flags_are_exact() {
        assert_eq!(
            cargo_package_list_args("example"),
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
            parse_inventory(package.inventory)
                .unwrap_or_else(|error| panic!("{}: {error}", package.inventory_path));
        }
    }

    #[test]
    fn parser_rejects_noncanonical_inventory_text() {
        let cases = [
            ("a", "inventory must end with a newline"),
            ("a\r\n", "inventory must use line-feed terminators"),
            ("\n", "line 1 is blank"),
            ("# comment\n", "comments are not allowed"),
            ("/absolute\n", "not a normalized crate-relative path"),
            ("../parent\n", "not a normalized crate-relative path"),
            ("src//lib.rs\n", "not a normalized crate-relative path"),
            ("src/./lib.rs\n", "not a normalized crate-relative path"),
            ("src/\n", "not a normalized crate-relative path"),
            ("a\\b\n", "paths must use `/` separators"),
            ("a\na\n", "duplicates `a`"),
            ("b\na\n", "is not bytewise sorted"),
        ];

        for (contents, expected_message) in cases {
            let error = parse_inventory(contents).unwrap_err();
            assert!(
                error.contains(expected_message),
                "expected `{expected_message}` in `{error}`"
            );
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
        let cases = [
            (
                ["a", "b"].into_iter().map(String::from).collect(),
                ["b"].into_iter().map(String::from).collect(),
                "package contents differ\n  missing from package:\n    a",
            ),
            (
                ["b"].into_iter().map(String::from).collect(),
                ["a", "b"].into_iter().map(String::from).collect(),
                "package contents differ\n  unexpected in package:\n    a",
            ),
            (
                ["b", "c"].into_iter().map(String::from).collect(),
                ["a", "c", "d"].into_iter().map(String::from).collect(),
                "package contents differ\n  missing from package:\n    b\n  unexpected in package:\n    a\n    d",
            ),
        ];

        for (expected, actual, diagnostic) in cases {
            let difference = compare_inventories(&expected, &actual);
            assert_eq!(format_difference(&difference), diagnostic);
        }
        let paths: BTreeSet<_> = ["a", "b"].into_iter().map(String::from).collect();
        assert_eq!(
            compare_inventories(&paths, &paths),
            InventoryDifference {
                missing: Vec::new(),
                unexpected: Vec::new(),
            }
        );
    }
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral release proposal generation.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use semver::Version;
use serde::Serialize;

use crate::release_policy::{ReleaseFamily, ReleasePolicy, detect};

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [command, remaining @ ..] if command == "generate" => generate_command(root, remaining),
        [arg] if matches!(arg.as_str(), "help" | "--help" | "-h") => {
            eprintln!("{}", usage());
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    [
        "usage: cargo xtask release proposal generate \\",
        "    --mode next-candidate|promote-stable --bump patch|minor|major \\",
        "    --published-version VERSION --registry-manifest PATH --date YYYY-MM-DD \\",
        "    --result PATH",
    ]
    .join("\n")
}

fn generate_command(root: &Path, args: &[String]) -> Result<(), String> {
    let values = parse_flags(
        args,
        &[
            "--mode",
            "--bump",
            "--published-version",
            "--registry-manifest",
            "--date",
            "--result",
        ],
    )?;
    let required = |flag: &str| {
        values
            .get(flag)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {flag}"))
    };
    let mode = required("--mode")?;
    let bump = required("--bump")?;
    let published = required("--published-version")?;
    let registry_manifest = PathBuf::from(required("--registry-manifest")?);
    let date = required("--date")?;
    let result_file = PathBuf::from(required("--result")?);
    if !matches!(mode, "next-candidate" | "promote-stable")
        || !matches!(bump, "patch" | "minor" | "major")
        || (mode == "promote-stable" && bump != "patch")
    {
        return Err("release proposal mode or bump is unsupported".to_string());
    }
    parse_release_version(published)?;
    validate_date(date)?;
    let registry_manifest = registry_manifest
        .canonicalize()
        .map_err(|error| format!("resolve registry baseline manifest: {error}"))?;
    if !registry_manifest.is_file() {
        return Err("official registry baseline manifest is missing".to_string());
    }
    let policy = detect(root)?;
    let result = generate(
        root,
        policy,
        mode,
        bump,
        published,
        &registry_manifest,
        date,
    )?;
    write_new_json(&result_file, &result)?;
    eprintln!("release: generated validated {} proposal", result.target);
    Ok(())
}

#[derive(Debug, Serialize)]
struct ProposalResult {
    target: String,
    substantive: bool,
}

fn generate(
    root: &Path,
    policy: &ReleasePolicy,
    mode: &str,
    bump: &str,
    published: &str,
    registry_manifest: &Path,
    date: &str,
) -> Result<ProposalResult, String> {
    let (target, substantive) = if mode == "promote-stable" {
        let head = command_line(root, "git", &["rev-parse", "HEAD"])?;
        for package in policy.packages {
            let tag = package.tag(published);
            let commit = command_line(root, "git", &["rev-parse", &format!("{tag}^{{commit}}")])?;
            if commit != head {
                return Err("stable promotion requires exact published RC source".to_string());
            }
        }
        (
            run_xtask_line(root, &["release-version", "promote-stable", "--date", date])?,
            true,
        )
    } else {
        let baseline = path_text(registry_manifest)?;
        require_success(
            root,
            "release-plz",
            &[
                "update",
                "--config",
                ".release-plz.toml",
                "--registry-manifest-path",
                baseline,
            ],
        )?;
        let substantive = policy
            .packages
            .iter()
            .map(|package| package.changelog)
            .try_fold(false, |changed, path| {
                path_changed(root, path).map(|path_changed| changed || path_changed)
            })?;
        let mut args = vec![
            "release-version",
            "candidate",
            "--published",
            published,
            "--bump",
            bump,
            "--date",
            date,
        ];
        if substantive {
            args.push("--release-notes");
        }
        (run_xtask_line(root, &args)?, substantive)
    };

    if policy.family == ReleaseFamily::RustWorkspace {
        run_xtask(root, &["sync-workspace-versions"])?;
        run_xtask(root, &["sync-workspace-versions", "--check"])?;
    }
    run_xtask(root, &["release-version", "check"])?;
    require_success(
        root,
        cargo_program(),
        &["metadata", "--no-deps", "--format-version", "1"],
    )?;
    let mut compatibility = vec![
        "release-version",
        "check-compatibility",
        "--baseline-manifest",
        path_text(registry_manifest)?,
        "--current-manifest",
        "Cargo.toml",
    ];
    if policy.family == ReleaseFamily::Traits {
        compatibility.extend(["--package", policy.packages[0].package]);
    }
    compatibility.extend([
        "--expected-baseline-version",
        published,
        "--expected-current-version",
        &target,
        "--intent",
        bump,
    ]);
    run_xtask(root, &compatibility)?;
    require_success(root, "git", &["diff", "--check"])?;

    Ok(ProposalResult {
        target,
        substantive,
    })
}

fn run_xtask(root: &Path, args: &[&str]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve current xtask executable: {error}"))?;
    let executable = path_text(&executable)?;
    require_success(root, executable, args)
}

fn run_xtask_line(root: &Path, args: &[&str]) -> Result<String, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve current xtask executable: {error}"))?;
    command_line(root, path_text(&executable)?, args)
}

fn path_changed(root: &Path, path: &str) -> Result<bool, String> {
    let output = run_output(root, "git", &["diff", "--quiet", "--", path])?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(format!("git diff failed for {path}: {}", detail(&output))),
    }
}

fn require_success(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    let output = run_output(root, program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            detail(&output)
        ))
    }
}

fn command_line(root: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let output = run_output(root, program, args)?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            detail(&output)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("{program} returned non-UTF-8 output"))?;
    let line = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(&stdout);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err(format!("{program} did not return one exact line"));
    }
    Ok(line.to_string())
}

fn run_output(root: &Path, program: &str, args: &[&str]) -> Result<Output, String> {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(format!("{program} output exceeded its bound"));
    }
    Ok(output)
}

fn detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn parse_flags(args: &[String], allowed: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !allowed.contains(&flag) {
            return Err(format!("unexpected argument: {flag}"));
        }
        index += 1;
        if index >= args.len() || args[index].starts_with("--") {
            return Err(format!("missing value for {flag}"));
        }
        if values
            .insert(flag.to_string(), args[index].clone())
            .is_some()
        {
            return Err(format!("duplicate {flag}"));
        }
        index += 1;
    }
    Ok(values)
}

fn parse_release_version(value: &str) -> Result<Version, String> {
    let version = Version::parse(value)
        .map_err(|error| format!("invalid published version {value}: {error}"))?;
    if !version.build.is_empty() {
        return Err("published version contains build metadata".to_string());
    }
    Ok(version)
}

fn validate_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return Err("--date must use YYYY-MM-DD".to_string());
    }
    let year = value[0..4].parse::<u32>().unwrap_or_default();
    let month = value[5..7].parse::<u32>().unwrap_or_default();
    let day = value[8..10].parse::<u32>().unwrap_or_default();
    if year < 2000 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err("--date is outside the supported calendar range".to_string());
    }
    Ok(())
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut body = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize proposal result: {error}"))?;
    body.push(b'\n');
    write_new(path, &body)
}

fn write_new(path: &Path, body: &[u8]) -> Result<(), String> {
    let path = absolute(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create proposal output parent {}: {error}",
                parent.display()
            )
        })?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create proposal output {}: {error}", path.display()))?;
    output
        .write_all(body)
        .map_err(|error| format!("write proposal output {}: {error}", path.display()))
}

fn cargo_program() -> &'static str {
    "cargo"
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|root| root.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_arguments_are_explicit_and_unique() {
        let args = vec!["--mode".to_string(), "next-candidate".to_string()];
        assert_eq!(
            parse_flags(&args, &["--mode"]).unwrap()["--mode"],
            "next-candidate"
        );
        let duplicate = vec![
            "--mode".to_string(),
            "next-candidate".to_string(),
            "--mode".to_string(),
            "promote-stable".to_string(),
        ];
        assert!(parse_flags(&duplicate, &["--mode"]).is_err());
    }

    #[test]
    fn proposal_date_is_strictly_shaped() {
        assert!(validate_date("2026-08-25").is_ok());
        assert!(validate_date("2026-8-25").is_err());
        assert!(validate_date("2026-13-01").is_err());
    }
}

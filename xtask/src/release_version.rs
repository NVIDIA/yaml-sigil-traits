// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral release version transactions.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Subcommand, ValueEnum};
use semver::{Prerelease, Version};
use toml_edit::DocumentMut;

use crate::release::exact_output_line;
use crate::release_policy::TRAITS_TOOLCHAIN;

const CHANGELOG: &str = "CHANGELOG.md";

#[derive(Args)]
pub struct ReleaseVersionArgs {
    #[command(subcommand)]
    command: ReleaseVersionCommand,
}

#[derive(Subcommand)]
enum ReleaseVersionCommand {
    /// Print the exact release version.
    Show,
    /// Validate the current release version.
    Check,
    /// Check one exact registry baseline against the proposed API.
    CheckCompatibility {
        #[arg(long)]
        baseline_manifest: PathBuf,
        #[arg(long)]
        current_manifest: PathBuf,
        #[arg(long)]
        package: String,
        #[arg(long)]
        expected_baseline_version: Version,
        #[arg(long)]
        expected_current_version: Version,
        #[arg(long, value_enum)]
        intent: ReleaseBump,
    },
    /// Resolve the release intent from published and current versions.
    Intent {
        #[arg(long)]
        published: Version,
    },
    /// Prepare the next release candidate version.
    Candidate {
        #[arg(long)]
        published: Version,
        #[arg(long, value_enum)]
        bump: ReleaseBump,
        #[arg(long)]
        date: String,
        #[arg(long)]
        release_notes: bool,
    },
    /// Promote the current release candidate to its stable version.
    PromoteStable {
        #[arg(long)]
        date: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ReleaseBump {
    Patch,
    Minor,
    Major,
}

impl ReleaseBump {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

pub fn run(root: &Path, args: ReleaseVersionArgs) -> Result<(), String> {
    match args.command {
        ReleaseVersionCommand::Show => {
            println!("{}", read_version(root)?);
            Ok(())
        }
        ReleaseVersionCommand::Check => {
            let version = read_version(root)?;
            eprintln!("release-version: manifest version is {version}");
            Ok(())
        }
        ReleaseVersionCommand::CheckCompatibility {
            baseline_manifest,
            current_manifest,
            package,
            expected_baseline_version,
            expected_current_version,
            intent,
        } => check_api_compatibility(
            root,
            &baseline_manifest,
            &current_manifest,
            &package,
            &expected_baseline_version,
            &expected_current_version,
            intent.as_str(),
        ),
        ReleaseVersionCommand::Intent { published } => {
            println!("{}", release_intent(&published, &read_version(root)?)?);
            Ok(())
        }
        ReleaseVersionCommand::Candidate {
            published,
            bump,
            date,
            release_notes,
        } => {
            validate_date(&date)?;
            let current = read_version(root)?;
            let target = candidate_version(&published, &current, bump.as_str())?;
            write_version(root, &target)?;
            if release_notes {
                ensure_candidate_changelog(root, &current, &target, &date)?;
            }
            println!("{target}");
            Ok(())
        }
        ReleaseVersionCommand::PromoteStable { date } => {
            validate_date(&date)?;
            let current = read_version(root)?;
            let stable = stable_version(&current)?;
            promote_changelog(root, &current, &stable, &date)?;
            write_version(root, &stable)?;
            println!("{stable}");
            Ok(())
        }
    }
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let version = read_version(root)?;
    eprintln!("release-version: manifest version is {version}");
    Ok(())
}

fn validate_date(date: &str) -> Result<(), String> {
    let bytes = date.as_bytes();
    if bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err("--date must use YYYY-MM-DD".to_string())
    }
}

fn read_version(root: &Path) -> Result<Version, String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("read Cargo.toml: {error}"))?;
    let value = section_version(&manifest, "[package]")?
        .ok_or_else(|| "missing [package] version in Cargo.toml".to_string())?;
    let version = Version::parse(&value)
        .map_err(|error| format!("invalid package version {value}: {error}"))?;
    release_rc(&version)?;
    Ok(version)
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn output_detail(output: &CargoOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[derive(Debug)]
struct ManifestPath {
    argument: PathBuf,
    identity: PathBuf,
}

fn resolve_manifest(root: &Path, path: &Path, label: &str) -> Result<ManifestPath, String> {
    let argument = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let identity = argument
        .canonicalize()
        .map_err(|error| format!("resolve {label} manifest {}: {error}", argument.display()))?;
    if !identity.is_file()
        || identity.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
    {
        return Err(format!(
            "{label} manifest is not an exact Cargo.toml file: {}",
            identity.display()
        ));
    }
    Ok(ManifestPath { argument, identity })
}

#[derive(Debug)]
struct CargoOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct CargoStatus {
    success: bool,
    code: Option<i32>,
}

trait CargoRunner {
    fn output(
        &mut self,
        root: &Path,
        program: &OsStr,
        args: &[OsString],
    ) -> Result<CargoOutput, String>;
    fn status(
        &mut self,
        root: &Path,
        program: &OsStr,
        args: &[OsString],
    ) -> Result<CargoStatus, String>;
}

struct SystemCargoRunner;

impl CargoRunner for SystemCargoRunner {
    fn output(
        &mut self,
        root: &Path,
        program: &OsStr,
        args: &[OsString],
    ) -> Result<CargoOutput, String> {
        let output = Command::new(program)
            .current_dir(root)
            .args(args)
            .output()
            .map_err(|error| format!("run {}: {error}", program.to_string_lossy()))?;
        Ok(CargoOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn status(
        &mut self,
        root: &Path,
        program: &OsStr,
        args: &[OsString],
    ) -> Result<CargoStatus, String> {
        let status = Command::new(program)
            .current_dir(root)
            .args(args)
            .status()
            .map_err(|error| format!("run {}: {error}", program.to_string_lossy()))?;
        Ok(CargoStatus {
            success: status.success(),
            code: status.code(),
        })
    }
}

fn metadata_version(
    root: &Path,
    manifest: &ManifestPath,
    package: &str,
    runner: &mut impl CargoRunner,
) -> Result<Version, String> {
    let mut args: Vec<OsString> = [
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--manifest-path",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(manifest.argument.as_os_str().to_owned());
    let output = runner
        .output(root, &cargo_program(), &args)
        .map_err(|error| {
            format!(
                "run Cargo metadata for {}: {error}",
                manifest.argument.display()
            )
        })?;
    if !output.success {
        return Err(format!(
            "Cargo metadata failed for {}: {}",
            manifest.argument.display(),
            output_detail(&output)
        ));
    }
    metadata_version_from_json(&output.stdout, &manifest.identity, package)
}

fn metadata_version_from_json(
    output: &[u8],
    manifest: &Path,
    package: &str,
) -> Result<Version, String> {
    let metadata: serde_json::Value = serde_json::from_slice(output)
        .map_err(|error| format!("Cargo returned invalid metadata: {error}"))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Cargo returned invalid package metadata".to_string())?;
    let mut matches = Vec::new();
    for item in packages {
        if item.get("name").and_then(serde_json::Value::as_str) != Some(package) {
            continue;
        }
        let path = item
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("metadata did not contain a manifest path for {package}"))?;
        let identity = Path::new(path)
            .canonicalize()
            .map_err(|error| format!("resolve Cargo metadata manifest {path}: {error}"))?;
        if identity == manifest {
            matches.push(item);
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "metadata did not contain exactly one {package} package at {}",
            manifest.display()
        ));
    }
    let value = matches[0]
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("metadata did not contain a version for {package}"))?;
    let version = Version::parse(value)
        .map_err(|error| format!("metadata returned invalid version {value}: {error}"))?;
    release_rc(&version)?;
    Ok(version)
}

fn checker_release_type(intent: &str, current: &Version) -> Result<&'static str, String> {
    match intent {
        "major" => Ok("major"),
        "minor" if current.major == 0 => Ok("major"),
        "minor" => Ok("minor"),
        "patch" if current.major != 0 => Ok("patch"),
        "patch" if current.minor == 0 => Ok("major"),
        "patch" => Ok("minor"),
        _ => Err("--intent must be patch, minor, or major".to_string()),
    }
}

fn require_semver_checks_version(value: &[u8]) -> Result<(), String> {
    let expected = format!(
        "cargo-semver-checks {}",
        TRAITS_TOOLCHAIN.cargo_semver_checks_version
    );
    let actual = exact_output_line(value, "cargo-semver-checks version")?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {expected}; found {actual}"))
    }
}

fn check_api_compatibility(
    root: &Path,
    baseline_manifest: &Path,
    current_manifest: &Path,
    package: &str,
    expected_baseline: &Version,
    expected_current: &Version,
    expected_intent: &str,
) -> Result<(), String> {
    let mut runner = SystemCargoRunner;
    check_api_compatibility_with_runner(
        root,
        baseline_manifest,
        current_manifest,
        package,
        expected_baseline,
        expected_current,
        expected_intent,
        &mut runner,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_api_compatibility_with_runner(
    root: &Path,
    baseline_manifest: &Path,
    current_manifest: &Path,
    package: &str,
    expected_baseline: &Version,
    expected_current: &Version,
    expected_intent: &str,
    runner: &mut impl CargoRunner,
) -> Result<(), String> {
    if package.is_empty() || package.starts_with('-') {
        return Err("--package must be a nonempty Cargo package name".to_string());
    }
    release_rc(expected_baseline)?;
    release_rc(expected_current)?;

    // Address the installed analyzer directly so Cargo aliases cannot replace it.
    let tool = runner
        .output(
            root,
            OsStr::new("cargo-semver-checks"),
            &[OsString::from("semver-checks"), OsString::from("--version")],
        )
        .map_err(|error| format!("cargo-semver-checks is unavailable: {error}"))?;
    if !tool.success {
        return Err(format!(
            "cargo-semver-checks is unavailable: {}",
            output_detail(&tool)
        ));
    }
    require_semver_checks_version(&tool.stdout)?;

    let baseline_manifest = resolve_manifest(root, baseline_manifest, "baseline")?;
    let current_manifest = resolve_manifest(root, current_manifest, "current")?;
    let repository_manifest = resolve_manifest(root, &root.join("Cargo.toml"), "repository")?;
    if current_manifest.identity != repository_manifest.identity {
        return Err("the current manifest is not the repository root Cargo.toml".to_string());
    }
    let baseline = metadata_version(root, &baseline_manifest, package, runner)?;
    let current = metadata_version(root, &current_manifest, package, runner)?;
    if baseline != *expected_baseline {
        return Err(format!(
            "baseline manifest version {baseline} does not match {expected_baseline}"
        ));
    }
    if current != *expected_current {
        return Err(format!(
            "candidate manifest version {current} does not match {expected_current}"
        ));
    }
    let intent = release_intent(&baseline, &current)?;
    if intent != expected_intent {
        return Err(format!(
            "candidate represents a {intent} bump, not requested {expected_intent}"
        ));
    }
    let release_type = checker_release_type(intent, &current)?;
    let baseline_root = baseline_manifest
        .argument
        .parent()
        .ok_or_else(|| "the baseline manifest has no parent directory".to_string())?;
    let args = [
        OsString::from("semver-checks"),
        OsString::from("check-release"),
        OsString::from("--manifest-path"),
        current_manifest.argument.as_os_str().to_owned(),
        OsString::from("--package"),
        OsString::from(package),
        OsString::from("--baseline-root"),
        baseline_root.as_os_str().to_owned(),
        OsString::from("--release-type"),
        OsString::from(release_type),
        OsString::from("--all-features"),
        OsString::from("--color"),
        OsString::from("never"),
    ];
    // Keep analysis on the same alias-resistant executable verified above.
    let status = runner
        .status(root, OsStr::new("cargo-semver-checks"), &args)
        .map_err(|error| format!("run cargo-semver-checks: {error}"))?;
    if !status.success {
        return Err(format!(
            "cargo-semver-checks failed with status {}",
            status
                .code
                .map_or_else(|| "signal".to_string(), |code| code.to_string())
        ));
    }
    eprintln!(
        "release-version: API compatibility passed with {intent} intent \
         ({release_type} Cargo release type)"
    );
    Ok(())
}

fn write_version(root: &Path, version: &Version) -> Result<(), String> {
    let path = root.join("Cargo.toml");
    let manifest =
        fs::read_to_string(&path).map_err(|error| format!("read Cargo.toml: {error}"))?;
    let updated = replace_section_version(&manifest, "[package]", &version.to_string())?;
    if updated != manifest {
        fs::write(path, updated).map_err(|error| format!("write Cargo.toml: {error}"))?;
    }
    Ok(())
}

fn section_version(manifest: &str, section: &str) -> Result<Option<String>, String> {
    let mut in_section = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == section {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            break;
        }
        if in_section && trimmed.starts_with("version = ") {
            let value = trimmed
                .strip_prefix("version = ")
                .and_then(|value| value.strip_prefix('"'))
                .and_then(|value| value.split('"').next())
                .ok_or_else(|| format!("invalid version line: {line}"))?;
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn replace_section_version(manifest: &str, section: &str, version: &str) -> Result<String, String> {
    let mut in_section = false;
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == section {
            in_section = true;
        } else if in_section && trimmed.starts_with('[') {
            in_section = false;
        }

        if in_section && trimmed.starts_with("version = ") {
            if replaced {
                return Err(format!("multiple version entries in {section}"));
            }
            let prefix_end = line
                .find('"')
                .ok_or_else(|| format!("invalid version line: {line}"))?
                + 1;
            let suffix_start = prefix_end
                + line[prefix_end..]
                    .find('"')
                    .ok_or_else(|| format!("invalid version line: {line}"))?;
            lines.push(format!(
                "{}{}{}",
                &line[..prefix_end],
                version,
                &line[suffix_start..]
            ));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        return Err(format!("missing version entry in {section}"));
    }
    let mut output = lines.join("\n");
    output.push('\n');
    Ok(output)
}

fn candidate_version(
    published: &Version,
    _current: &Version,
    bump: &str,
) -> Result<Version, String> {
    let published_rc = release_rc(published)?;
    let mut target = match bump {
        "patch" => match published_rc {
            None => bumped_core(published, "patch")?,
            Some(rc) => with_rc(published, rc.checked_add(1).ok_or("rc number overflow")?)?,
        },
        "minor" | "major" => bumped_core(published, bump)?,
        _ => return Err("--bump must be patch, minor, or major".to_string()),
    };
    target.build = semver::BuildMetadata::EMPTY;
    Ok(target)
}

fn release_intent(published: &Version, current: &Version) -> Result<&'static str, String> {
    let published_rc = release_rc(published)?;
    let current_rc = release_rc(current)?;
    let same_core = current.major == published.major
        && current.minor == published.minor
        && current.patch == published.patch;
    if same_core {
        return match (published_rc, current_rc) {
            (Some(_), None) => Ok("patch"),
            (Some(published), Some(current)) if Some(current) == published.checked_add(1) => {
                Ok("patch")
            }
            _ => Err(
                "the release version does not exactly advance or promote the current RC"
                    .to_string(),
            ),
        };
    }

    let intent = if current.major != published.major {
        if current.major
            == published
                .major
                .checked_add(1)
                .ok_or("major version overflow")?
            && current.minor == 0
            && current.patch == 0
        {
            "major"
        } else {
            return Err(
                "the release version does not represent one patch, minor, or major line"
                    .to_string(),
            );
        }
    } else if current.minor != published.minor {
        if current.minor
            == published
                .minor
                .checked_add(1)
                .ok_or("minor version overflow")?
            && current.patch == 0
        {
            "minor"
        } else {
            return Err(
                "the release version does not represent one patch, minor, or major line"
                    .to_string(),
            );
        }
    } else if current.patch
        == published
            .patch
            .checked_add(1)
            .ok_or("patch version overflow")?
    {
        if published_rc.is_some() {
            return Err("a patch intent must advance the current RC core".to_string());
        }
        "patch"
    } else {
        return Err(
            "the release version does not represent one patch, minor, or major line".to_string(),
        );
    };

    if current_rc != Some(1) {
        return Err("a new release version line must start at rc.1".to_string());
    }
    Ok(intent)
}

fn bumped_core(version: &Version, bump: &str) -> Result<Version, String> {
    let (major, minor, patch) = match bump {
        "patch" => (
            version.major,
            version.minor,
            version
                .patch
                .checked_add(1)
                .ok_or("patch version overflow")?,
        ),
        "minor" => (
            version.major,
            version
                .minor
                .checked_add(1)
                .ok_or("minor version overflow")?,
            0,
        ),
        "major" => (
            version
                .major
                .checked_add(1)
                .ok_or("major version overflow")?,
            0,
            0,
        ),
        _ => return Err(format!("unsupported bump: {bump}")),
    };
    with_rc(&Version::new(major, minor, patch), 1)
}

fn require_rc(version: &Version) -> Result<u64, String> {
    let value = version.pre.as_str();
    let number = value
        .strip_prefix("rc.")
        .ok_or_else(|| format!("expected an rc.N prerelease, found {version}"))?;
    let rc = number
        .parse::<u64>()
        .map_err(|_| format!("expected an rc.N prerelease, found {version}"))?;
    if rc == 0 {
        return Err(format!("expected rc.N with N at least 1, found {version}"));
    }
    Ok(rc)
}

fn release_rc(version: &Version) -> Result<Option<u64>, String> {
    if !version.build.is_empty() {
        return Err(format!(
            "release versions cannot contain build metadata: {version}"
        ));
    }
    if version.pre.is_empty() {
        Ok(None)
    } else {
        require_rc(version).map(Some)
    }
}

fn with_rc(version: &Version, rc: u64) -> Result<Version, String> {
    let mut version = Version::new(version.major, version.minor, version.patch);
    version.pre = Prerelease::new(&format!("rc.{rc}"))
        .map_err(|error| format!("construct rc prerelease: {error}"))?;
    Ok(version)
}

fn stable_version(version: &Version) -> Result<Version, String> {
    release_rc(version)?.ok_or_else(|| format!("expected an rc.N prerelease, found {version}"))?;
    Ok(Version::new(version.major, version.minor, version.patch))
}

fn ensure_candidate_changelog(
    root: &Path,
    generated: &Version,
    target: &Version,
    date: &str,
) -> Result<(), String> {
    let path = root.join(CHANGELOG);
    let body = fs::read_to_string(&path).map_err(|error| format!("read {CHANGELOG}: {error}"))?;
    let generated_prefix = format!("## [{generated}](");
    let target_prefix = format!("## [{target}](");
    let mut changed = false;
    let mut output = Vec::new();
    for line in body.lines() {
        if line.starts_with(&generated_prefix) && generated != target {
            output.push(line.replacen(&generated.to_string(), &target.to_string(), 2));
            changed = true;
        } else {
            output.push(line.to_string());
        }
    }
    let mut updated = output.join("\n");
    updated.push('\n');
    if !updated.lines().any(|line| line.starts_with(&target_prefix)) {
        let release_url = release_tag_url(root, target)?;
        updated = insert_after_unreleased(
            &updated,
            &format!(
                "## [{target}]({release_url}) - {date}\n\n### Other\n\n- No crate-specific changes."
            ),
        )?;
        changed = true;
    }
    if changed {
        fs::write(path, updated).map_err(|error| format!("write {CHANGELOG}: {error}"))?;
    }
    Ok(())
}

fn promote_changelog(
    root: &Path,
    rc: &Version,
    stable: &Version,
    date: &str,
) -> Result<(), String> {
    let path = root.join(CHANGELOG);
    let body = fs::read_to_string(&path).map_err(|error| format!("read {CHANGELOG}: {error}"))?;
    let section = changelog_section(&body, rc)?;
    let release_url = release_tag_url(root, stable)?;
    let promoted = format!("## [{stable}]({release_url}) - {date}\n{section}");
    let updated = insert_after_unreleased(&body, &promoted)?;
    fs::write(path, updated).map_err(|error| format!("write {CHANGELOG}: {error}"))
}

fn release_tag_url(root: &Path, version: &Version) -> Result<String, String> {
    let path = root.join("Cargo.toml");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("read Cargo.toml metadata: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        return Err("Cargo.toml is missing, indirect, or oversized".to_string());
    }
    let body = fs::read_to_string(&path).map_err(|error| format!("read Cargo.toml: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse Cargo.toml: {error}"))?;
    let repository = document
        .get("package")
        .and_then(|item| item.get("repository"))
        .and_then(toml_edit::Item::as_str)
        .or_else(|| {
            document
                .get("workspace")
                .and_then(|item| item.get("package"))
                .and_then(|item| item.get("repository"))
                .and_then(toml_edit::Item::as_str)
        })
        .ok_or_else(|| "Cargo.toml has no package repository URL".to_string())?;
    if repository.len() > 2048
        || !repository.starts_with("https://")
        || repository.ends_with('/')
        || repository.contains(['\0', '\r', '\n', '?', '#'])
    {
        return Err("Cargo.toml has an unsupported package repository URL".to_string());
    }
    Ok(format!("{repository}/releases/tag/v{version}"))
}

fn changelog_section(body: &str, version: &Version) -> Result<String, String> {
    let lines: Vec<_> = body.lines().collect();
    let prefix = format!("## [{version}](");
    let start = lines
        .iter()
        .position(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("missing changelog section for {version}"))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.starts_with("## ["))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let section = lines[start + 1..end].join("\n");
    Ok(format!("{}\n", section.trim_end()))
}

fn insert_after_unreleased(body: &str, section: &str) -> Result<String, String> {
    let marker = "## [Unreleased]";
    let start = body
        .find(marker)
        .ok_or_else(|| "missing [Unreleased] changelog heading".to_string())?;
    let insert_at = start + marker.len();
    let mut output = String::with_capacity(body.len() + section.len() + 3);
    output.push_str(&body[..insert_at]);
    output.push_str("\n\n");
    output.push_str(section.trim());
    output.push_str("\n\n");
    output.push_str(body[insert_at..].trim_start_matches('\n'));
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::release_policy::TRAITS_POLICY;

    const TRAITS_PACKAGE: &str = TRAITS_POLICY.packages[0].package;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        release_version: ReleaseVersionArgs,
    }

    const FIXTURE_REPOSITORY_URL: &str = "https://example.invalid/repository";

    #[derive(Debug, Eq, PartialEq)]
    enum Invocation {
        Output(OsString, Vec<OsString>),
        Status(OsString, Vec<OsString>),
    }

    #[derive(Default)]
    struct FakeCargoRunner {
        outputs: VecDeque<Result<CargoOutput, String>>,
        statuses: VecDeque<Result<CargoStatus, String>>,
        invocations: Vec<Invocation>,
    }

    impl CargoRunner for FakeCargoRunner {
        fn output(
            &mut self,
            _root: &Path,
            program: &OsStr,
            args: &[OsString],
        ) -> Result<CargoOutput, String> {
            self.invocations
                .push(Invocation::Output(program.to_owned(), args.to_vec()));
            self.outputs
                .pop_front()
                .expect("unexpected fake Cargo output command")
        }

        fn status(
            &mut self,
            _root: &Path,
            program: &OsStr,
            args: &[OsString],
        ) -> Result<CargoStatus, String> {
            self.invocations
                .push(Invocation::Status(program.to_owned(), args.to_vec()));
            self.statuses
                .pop_front()
                .expect("unexpected fake Cargo status command")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "yaml-sigil-release-version-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cargo_output(stdout: impl Into<Vec<u8>>) -> Result<CargoOutput, String> {
        Ok(CargoOutput {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
        })
    }

    fn metadata_output(
        package: &str,
        manifest: &Path,
        version: &str,
    ) -> Result<CargoOutput, String> {
        cargo_output(
            serde_json::to_vec(&serde_json::json!({
                "packages": [{
                    "name": package,
                    "manifest_path": manifest,
                    "version": version
                }]
            }))
            .unwrap(),
        )
    }

    fn compatibility_fixture(
        status: Result<CargoStatus, String>,
    ) -> (TestDirectory, PathBuf, PathBuf, FakeCargoRunner) {
        let temporary = TestDirectory::new("compatibility");
        let baseline_root = temporary.0.join("baseline");
        let repository_root = temporary.0.join("repository");
        fs::create_dir(&baseline_root).unwrap();
        fs::create_dir(&repository_root).unwrap();
        let baseline = baseline_root.join("Cargo.toml");
        fs::write(
            &baseline,
            format!("[package]\nname = \"{TRAITS_PACKAGE}\"\nversion = \"0.3.0-rc.1\"\n"),
        )
        .unwrap();
        let baseline = baseline.canonicalize().unwrap();
        let current = repository_root.join("Cargo.toml");
        fs::write(
            &current,
            format!("[package]\nname = \"{TRAITS_PACKAGE}\"\nversion = \"0.4.0-rc.1\"\n"),
        )
        .unwrap();
        let current = current.canonicalize().unwrap();
        let runner = FakeCargoRunner {
            outputs: [
                cargo_output(
                    format!(
                        "cargo-semver-checks {}\n",
                        TRAITS_TOOLCHAIN.cargo_semver_checks_version
                    )
                    .into_bytes(),
                ),
                metadata_output(TRAITS_PACKAGE, &baseline, "0.3.0-rc.1"),
                metadata_output(TRAITS_PACKAGE, &current, "0.4.0-rc.1"),
            ]
            .into(),
            statuses: [status].into(),
            invocations: Vec::new(),
        };
        (temporary, baseline, current, runner)
    }

    #[test]
    fn patch_advances_rc_on_the_same_core() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&current, &current, "patch").unwrap(),
            Version::parse("0.4.0-rc.4").unwrap()
        );
    }

    #[test]
    fn patch_starts_next_patch_rc_after_stable() {
        let current = Version::parse("0.4.0").unwrap();
        assert_eq!(
            candidate_version(&current, &current, "patch").unwrap(),
            Version::parse("0.4.1-rc.1").unwrap()
        );
    }

    #[test]
    fn patch_ignores_analyzer_core_drift_and_advances_the_published_rc() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        let generated = Version::parse("0.4.1-rc.1").unwrap();
        assert_eq!(
            candidate_version(&published, &generated, "patch").unwrap(),
            Version::parse("0.4.0-rc.4").unwrap()
        );
    }

    #[test]
    fn explicit_minor_starts_new_rc_train() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&published, &published, "minor").unwrap(),
            Version::parse("0.5.0-rc.1").unwrap()
        );
    }

    #[test]
    fn explicit_major_starts_new_rc_train() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&published, &published, "major").unwrap(),
            Version::parse("1.0.0-rc.1").unwrap()
        );
    }

    #[test]
    fn automatic_bump_is_rejected() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        assert!(candidate_version(&published, &published, "auto").is_err());
    }

    #[test]
    fn concrete_intent_is_derived_for_merged_release_validation() {
        let baseline = Version::parse("0.4.0-rc.1").unwrap();
        assert_eq!(
            release_intent(&baseline, &Version::parse("0.4.0-rc.2").unwrap()).unwrap(),
            "patch"
        );
        assert_eq!(
            release_intent(&baseline, &Version::parse("0.5.0-rc.1").unwrap()).unwrap(),
            "minor"
        );
        assert_eq!(
            release_intent(&baseline, &Version::parse("1.0.0-rc.1").unwrap()).unwrap(),
            "major"
        );
        assert_eq!(
            release_intent(&baseline, &Version::parse("0.4.0").unwrap()).unwrap(),
            "patch"
        );
        assert_eq!(
            release_intent(
                &Version::parse("0.4.0").unwrap(),
                &Version::parse("0.4.1-rc.1").unwrap(),
            )
            .unwrap(),
            "patch"
        );
    }

    #[test]
    fn release_intent_rejects_non_monotonic_or_non_rc_transitions() {
        for (published, current) in [
            ("0.4.0-rc.2", "0.4.0-rc.1"),
            ("0.4.0-rc.1", "0.4.0-rc.1"),
            ("0.4.0-rc.1", "0.4.0-rc.3"),
            ("0.4.0-rc.1", "0.4.1-rc.1"),
            ("0.4.0", "0.4.1"),
            ("0.4.0-rc.1", "0.5.0"),
            ("0.4.0", "0.5.0"),
            ("0.4.0-beta.1", "0.4.0-rc.1"),
            ("0.4.0-rc.1", "0.4.0-beta.2"),
            ("0.4.0-rc.0", "0.4.0-rc.1"),
            ("0.4.0+build.1", "0.4.1-rc.1"),
        ] {
            assert!(
                release_intent(
                    &Version::parse(published).unwrap(),
                    &Version::parse(current).unwrap(),
                )
                .is_err(),
                "accepted {published} -> {current}",
            );
        }
    }

    #[test]
    fn compatibility_uses_cargo_pre_one_release_types() {
        for (intent, current, expected) in [
            ("major", "0.5.0-rc.1", "major"),
            ("minor", "0.5.0-rc.1", "major"),
            ("patch", "0.5.0-rc.2", "minor"),
            ("patch", "0.0.1-rc.1", "major"),
            ("minor", "1.1.0-rc.1", "minor"),
            ("patch", "1.0.1-rc.1", "patch"),
        ] {
            assert_eq!(
                checker_release_type(intent, &Version::parse(current).unwrap()).unwrap(),
                expected
            );
        }
        assert!(checker_release_type("auto", &Version::parse("0.5.0-rc.1").unwrap()).is_err());
    }

    #[test]
    fn compatibility_metadata_binds_exact_package_manifest_and_version() {
        let temporary = TestDirectory::new("metadata-paths");
        let release = temporary.0.join("release");
        let other = temporary.0.join("other");
        fs::create_dir(&release).unwrap();
        fs::create_dir(&other).unwrap();
        fs::write(release.join("Cargo.toml"), "[package]\n").unwrap();
        fs::write(other.join("Cargo.toml"), "[package]\n").unwrap();
        let manifest = release.join("Cargo.toml").canonicalize().unwrap();
        let equivalent_spelling = release.join("..").join("release").join("Cargo.toml");
        let exact = serde_json::json!({
            "packages": [{
                "name": TRAITS_PACKAGE,
                "version": "0.4.0-rc.1",
                "manifest_path": equivalent_spelling
            }]
        });
        assert_eq!(
            metadata_version_from_json(
                &serde_json::to_vec(&exact).unwrap(),
                &manifest,
                TRAITS_PACKAGE
            )
            .unwrap(),
            Version::parse("0.4.0-rc.1").unwrap()
        );

        let wrong_manifest = other.join("Cargo.toml").canonicalize().unwrap();
        assert!(
            metadata_version_from_json(
                &serde_json::to_vec(&exact).unwrap(),
                &wrong_manifest,
                TRAITS_PACKAGE
            )
            .is_err()
        );
        assert!(
            metadata_version_from_json(br#"{"packages":[]}"#, &manifest, TRAITS_PACKAGE).is_err()
        );
    }

    #[test]
    fn compatibility_requires_the_exact_analyzer_version() {
        let expected = format!(
            "cargo-semver-checks {}",
            TRAITS_TOOLCHAIN.cargo_semver_checks_version
        );
        for suffix in ["", "\n", "\r\n"] {
            assert!(
                require_semver_checks_version(format!("{expected}{suffix}").as_bytes()).is_ok()
            );
        }
        for output in [
            b"cargo-semver-checks 0.48.0".to_vec(),
            format!(" {expected}\n").into_bytes(),
            format!("{expected} \n").into_bytes(),
            format!("{expected}\n\n").into_bytes(),
            vec![0xff],
            Vec::new(),
        ] {
            assert!(require_semver_checks_version(&output).is_err());
        }
    }

    #[test]
    fn compatibility_rejects_duplicate_flags() {
        let package = TRAITS_PACKAGE;
        let parsed = TestCli::try_parse_from([
            "test",
            "check-compatibility",
            "--baseline-manifest",
            "baseline/Cargo.toml",
            "--current-manifest",
            "Cargo.toml",
            "--package",
            package,
            "--package",
            "lookalike",
            "--expected-baseline-version",
            "0.3.0-rc.1",
            "--expected-current-version",
            "0.4.0-rc.1",
            "--intent",
            "minor",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn compatibility_runner_binds_exact_commands_and_paths() {
        let (_temporary, baseline, current, mut runner) = compatibility_fixture(Ok(CargoStatus {
            success: true,
            code: Some(0),
        }));
        let root = current.parent().unwrap();
        check_api_compatibility_with_runner(
            root,
            &baseline,
            &current,
            TRAITS_PACKAGE,
            &Version::parse("0.3.0-rc.1").unwrap(),
            &Version::parse("0.4.0-rc.1").unwrap(),
            "minor",
            &mut runner,
        )
        .unwrap();
        assert!(runner.outputs.is_empty());
        assert!(runner.statuses.is_empty());
        assert_eq!(
            runner.invocations,
            [
                Invocation::Output(
                    "cargo-semver-checks".into(),
                    vec!["semver-checks".into(), "--version".into()],
                ),
                Invocation::Output(
                    cargo_program(),
                    vec![
                        "metadata".into(),
                        "--no-deps".into(),
                        "--format-version".into(),
                        "1".into(),
                        "--manifest-path".into(),
                        baseline.as_os_str().to_owned(),
                    ],
                ),
                Invocation::Output(
                    cargo_program(),
                    vec![
                        "metadata".into(),
                        "--no-deps".into(),
                        "--format-version".into(),
                        "1".into(),
                        "--manifest-path".into(),
                        current.as_os_str().to_owned(),
                    ],
                ),
                Invocation::Status(
                    "cargo-semver-checks".into(),
                    vec![
                        "semver-checks".into(),
                        "check-release".into(),
                        "--manifest-path".into(),
                        current.as_os_str().to_owned(),
                        "--package".into(),
                        TRAITS_PACKAGE.into(),
                        "--baseline-root".into(),
                        baseline.parent().unwrap().as_os_str().to_owned(),
                        "--release-type".into(),
                        "major".into(),
                        "--all-features".into(),
                        "--color".into(),
                        "never".into(),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn compatibility_runner_fails_closed_on_analyzer_status_or_spawn_error() {
        for (status, expected) in [
            (
                Ok(CargoStatus {
                    success: false,
                    code: Some(101),
                }),
                "101",
            ),
            (
                Ok(CargoStatus {
                    success: false,
                    code: None,
                }),
                "signal",
            ),
            (
                Err("fixture spawn failure".to_string()),
                "fixture spawn failure",
            ),
        ] {
            let (_temporary, baseline, current, mut runner) = compatibility_fixture(status);
            let error = check_api_compatibility_with_runner(
                current.parent().unwrap(),
                &baseline,
                &current,
                TRAITS_PACKAGE,
                &Version::parse("0.3.0-rc.1").unwrap(),
                &Version::parse("0.4.0-rc.1").unwrap(),
                "minor",
                &mut runner,
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn compatibility_runner_fails_before_analysis_on_tool_or_metadata_ambiguity() {
        let (_temporary, baseline, current, mut wrong_tool) =
            compatibility_fixture(Ok(CargoStatus {
                success: true,
                code: Some(0),
            }));
        wrong_tool.outputs[0] = cargo_output(b"cargo-semver-checks 0.48.0\n".to_vec());
        assert!(
            check_api_compatibility_with_runner(
                current.parent().unwrap(),
                &baseline,
                &current,
                TRAITS_PACKAGE,
                &Version::parse("0.3.0-rc.1").unwrap(),
                &Version::parse("0.4.0-rc.1").unwrap(),
                "minor",
                &mut wrong_tool,
            )
            .is_err()
        );
        assert_eq!(wrong_tool.invocations.len(), 1);

        let (_temporary, baseline, current, mut malformed) =
            compatibility_fixture(Ok(CargoStatus {
                success: true,
                code: Some(0),
            }));
        malformed.outputs[1] = cargo_output(b"not-json".to_vec());
        assert!(
            check_api_compatibility_with_runner(
                current.parent().unwrap(),
                &baseline,
                &current,
                TRAITS_PACKAGE,
                &Version::parse("0.3.0-rc.1").unwrap(),
                &Version::parse("0.4.0-rc.1").unwrap(),
                "minor",
                &mut malformed,
            )
            .is_err()
        );
        assert_eq!(malformed.invocations.len(), 2);

        let (_temporary, baseline, current, mut mismatch) =
            compatibility_fixture(Ok(CargoStatus {
                success: true,
                code: Some(0),
            }));
        assert!(
            check_api_compatibility_with_runner(
                current.parent().unwrap(),
                &baseline,
                &current,
                TRAITS_PACKAGE,
                &Version::parse("0.3.0-rc.2").unwrap(),
                &Version::parse("0.4.0-rc.1").unwrap(),
                "minor",
                &mut mismatch,
            )
            .is_err()
        );
        assert!(!mismatch.statuses.is_empty());
    }

    #[test]
    fn candidate_rejects_unsupported_published_prereleases() {
        for published in ["0.4.0-beta.1", "0.4.0-rc.0", "0.4.0+build.1"] {
            let published = Version::parse(published).unwrap();
            assert!(candidate_version(&published, &published, "minor").is_err());
        }
    }

    #[test]
    fn inserted_changelog_sections_remain_separated() {
        let body = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n";
        let section = "## [0.2.0](new) - 2026-08-19\n\n- New.";

        assert_eq!(
            insert_after_unreleased(body, section).unwrap(),
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0](new) - 2026-08-19\n\n- New.\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n"
        );
    }

    #[test]
    fn release_links_follow_reviewed_package_metadata() {
        let temporary = TestDirectory::new("repository-url");
        let version = Version::parse("1.2.3-rc.1").unwrap();
        fs::write(
            temporary.0.join("Cargo.toml"),
            format!("[package]\nrepository = {FIXTURE_REPOSITORY_URL:?}\n"),
        )
        .unwrap();
        assert_eq!(
            release_tag_url(&temporary.0, &version).unwrap(),
            format!("{FIXTURE_REPOSITORY_URL}/releases/tag/v{version}")
        );

        fs::write(
            temporary.0.join("Cargo.toml"),
            format!("[workspace.package]\nrepository = {FIXTURE_REPOSITORY_URL:?}\n"),
        )
        .unwrap();
        assert_eq!(
            release_tag_url(&temporary.0, &version).unwrap(),
            format!("{FIXTURE_REPOSITORY_URL}/releases/tag/v{version}")
        );
    }
}

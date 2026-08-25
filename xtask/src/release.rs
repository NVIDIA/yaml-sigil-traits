// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral release preparation and verification tasks.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand};
use semver::Version;
use serde_json::Value;
use toml_edit::DocumentMut;

use crate::release_policy::TRAITS_POLICY;

const REGISTRY_USER_AGENT: &str = "yaml-sigil-release-workflow/1.0";
const REGISTRY_ATTEMPTS: usize = 30;
const REGISTRY_RETRY_SECONDS: u64 = 10;
const TRAITS_PACKAGE: &str = TRAITS_POLICY.packages[0].package;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    RegistryUnavailable,
}

#[derive(Args)]
pub struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Install and verify the exact release analyzers.
    InstallTools,
    /// Require the exact library-only crates.io package order.
    CheckPackages {
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Verify exact non-yanked crates.io versions.
    VerifyRegistry {
        #[arg(long)]
        check_version: Option<Version>,
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Bind a release mutation to exact current remote main.
    RequireCurrentMain {
        #[arg(long)]
        head: String,
        #[arg(long)]
        fetch_url: String,
    },
    /// Prepare a checkout-bound release-plz publication config.
    PreparePublicationConfig {
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare or verify an archive-bound official baseline.
    Baseline(crate::release_baseline::BaselineArgs),
    /// Generate a provider-neutral release proposal transaction.
    Proposal(crate::release_proposal::ProposalArgs),
}

pub fn run(root: &Path, args: ReleaseArgs) -> Result<Outcome, String> {
    match args.command {
        ReleaseCommand::InstallTools => {
            install_tools(root)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::CheckPackages { packages } => {
            validate_package_arguments(&packages)?;
            check_packages(root, &packages)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::VerifyRegistry {
            check_version,
            packages,
        } => {
            validate_package_arguments(&packages)?;
            verify_registry(root, check_version.as_ref(), &packages)
        }
        ReleaseCommand::RequireCurrentMain { head, fetch_url } => {
            require_current_main(root, &head, &fetch_url)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::PreparePublicationConfig { source, output } => {
            let source = source.unwrap_or_else(|| root.join(".release-plz.toml"));
            prepare_publication_config(root, &source, &output)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::Baseline(args) => {
            crate::release_baseline::run(root, args)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::Proposal(args) => {
            crate::release_proposal::run(root, args)?;
            Ok(Outcome::Success)
        }
    }
}

fn validate_package_arguments(packages: &[String]) -> Result<(), String> {
    for package in packages {
        validate_crate_name(package)?;
    }
    for (index, package) in packages.iter().enumerate() {
        if packages[..index].contains(package) {
            return Err(format!("duplicate crate name: {package}"));
        }
    }
    Ok(())
}

fn validate_crate_name(package: &str) -> Result<(), String> {
    let mut bytes = package.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    });
    if valid_start && valid_rest {
        Ok(())
    } else {
        Err(format!("invalid crate name: {package}"))
    }
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

#[derive(Debug)]
struct CommandResult {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct CommandStatus {
    success: bool,
    code: Option<i32>,
}

trait Runner {
    fn output(
        &mut self,
        program: &OsStr,
        args: &[OsString],
        root: &Path,
    ) -> Result<CommandResult, String>;

    fn status(
        &mut self,
        program: &OsStr,
        args: &[OsString],
        root: &Path,
    ) -> Result<CommandStatus, String>;

    fn sleep(&mut self, duration: Duration);
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn output(
        &mut self,
        program: &OsStr,
        args: &[OsString],
        root: &Path,
    ) -> Result<CommandResult, String> {
        let output = Command::new(program)
            .current_dir(root)
            .args(args)
            .output()
            .map_err(|error| format!("run {}: {error}", program.to_string_lossy()))?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }

    fn status(
        &mut self,
        program: &OsStr,
        args: &[OsString],
        root: &Path,
    ) -> Result<CommandStatus, String> {
        let status = Command::new(program)
            .current_dir(root)
            .args(args)
            .status()
            .map_err(|error| format!("run {}: {error}", program.to_string_lossy()))?;
        Ok(CommandStatus {
            success: status.success(),
            code: status.code(),
        })
    }
}

fn output_detail(output: &CommandResult) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn process_output_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn install_tools(root: &Path) -> Result<(), String> {
    let toolchain = crate::release_policy::detect(root)?.toolchain;
    let mut runner = SystemRunner;
    install_tools_with(root, toolchain, &mut runner)
}

fn install_tools_with(
    root: &Path,
    toolchain: crate::release_policy::ReleaseToolchain,
    runner: &mut impl Runner,
) -> Result<(), String> {
    require_command_version(
        root,
        runner,
        OsStr::new("cargo-binstall"),
        &[OsString::from("--version")],
        &format!("cargo-binstall {}", toolchain.cargo_binstall_version),
    )?;
    let install_args = [
        OsString::from("--force"),
        OsString::from("--locked"),
        OsString::from("--no-confirm"),
        OsString::from("--strategies=crate-meta-data,compile"),
        OsString::from(format!("release-plz@{}", toolchain.release_plz_version)),
        OsString::from(format!(
            "cargo-semver-checks@{}",
            toolchain.cargo_semver_checks_version
        )),
    ];
    // Invoke the verified binary directly so a Cargo alias cannot replace it.
    let status = runner.status(OsStr::new("cargo-binstall"), &install_args, root)?;
    if !status.success {
        return Err(format!(
            "Cargo binstall failed with status {}",
            status
                .code
                .map_or_else(|| "signal".to_string(), |code| code.to_string())
        ));
    }
    // Verify the analyzer binary directly for the same alias-resistant boundary.
    require_command_version(
        root,
        runner,
        OsStr::new("release-plz"),
        &[OsString::from("--version")],
        &format!("release-plz {}", toolchain.release_plz_version),
    )?;
    require_command_version(
        root,
        runner,
        OsStr::new("cargo-semver-checks"),
        &[OsString::from("semver-checks"), OsString::from("--version")],
        &format!(
            "cargo-semver-checks {}",
            toolchain.cargo_semver_checks_version
        ),
    )?;
    eprintln!("release: installed and verified the exact release analyzers");
    Ok(())
}

fn require_command_version(
    root: &Path,
    runner: &mut impl Runner,
    program: &OsStr,
    args: &[OsString],
    expected: &str,
) -> Result<(), String> {
    let output = runner.output(program, args, root)?;
    if !output.success {
        return Err(format!(
            "{} version check failed: {}",
            program.to_string_lossy(),
            output_detail(&output)
        ));
    }
    let actual = exact_output_line(
        &output.stdout,
        &format!("{} version", program.to_string_lossy()),
    )?;
    if actual != expected {
        return Err(format!("expected {expected}; found {actual}"));
    }
    Ok(())
}

fn is_lowercase_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_current_main(root: &Path, head: &str, fetch_url: &str) -> Result<(), String> {
    if !is_lowercase_sha(head) {
        return Err("--head must be a lowercase full 40-character SHA".to_string());
    }
    if fetch_url.is_empty() || fetch_url.starts_with('-') || fetch_url.contains(['\0', '\r', '\n'])
    {
        return Err("--fetch-url must be one non-option Git URL".to_string());
    }
    let mut runner = SystemRunner;
    require_current_main_with(root, head, fetch_url, &mut runner)
}

fn require_current_main_with(
    root: &Path,
    head: &str,
    fetch_url: &str,
    runner: &mut impl Runner,
) -> Result<(), String> {
    let checkout = git_line(root, runner, &["rev-parse", "HEAD"])?;
    if checkout != head {
        return Err("the release checkout is not at the triggering main commit".to_string());
    }
    let origin = git_line(root, runner, &["remote", "get-url", "origin"])?;
    if origin != fetch_url {
        return Err("origin does not use the expected release fetch URL".to_string());
    }
    let remote_args = [
        OsString::from("ls-remote"),
        OsString::from("--exit-code"),
        OsString::from(fetch_url),
        OsString::from("refs/heads/main"),
    ];
    let output = runner.output(OsStr::new("git"), &remote_args, root)?;
    if !output.success {
        return Err(format!("git ls-remote failed: {}", output_detail(&output)));
    }
    let remote = exact_output_line(&output.stdout, "remote main")?;
    let (remote_head, remote_ref) = remote
        .split_once('\t')
        .ok_or_else(|| "origin returned an invalid main ref".to_string())?;
    if remote_ref.contains('\t')
        || !is_lowercase_sha(remote_head)
        || remote_ref != "refs/heads/main"
        || remote_head != head
    {
        return Err("remote main changed before the release mutation".to_string());
    }
    eprintln!("release: verified exact current remote main {head}");
    Ok(())
}

fn git_line(root: &Path, runner: &mut impl Runner, args: &[&str]) -> Result<String, String> {
    let args: Vec<_> = args.iter().map(OsString::from).collect();
    let output = runner.output(OsStr::new("git"), &args, root)?;
    if !output.success {
        return Err(format!("Git command failed: {}", output_detail(&output)));
    }
    exact_output_line(&output.stdout, "Git command")
}

pub(crate) fn exact_output_line(output: &[u8], label: &str) -> Result<String, String> {
    let output =
        std::str::from_utf8(output).map_err(|_| format!("{label} returned non-UTF-8 output"))?;
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err(format!("{label} did not return one exact line"));
    }
    Ok(line.to_string())
}

fn cargo_metadata(root: &Path, runner: &mut impl Runner) -> Result<Value, String> {
    let args = [
        OsString::from("metadata"),
        OsString::from("--no-deps"),
        OsString::from("--format-version"),
        OsString::from("1"),
    ];
    let output = runner.output(&cargo_program(), &args, root)?;
    if !output.success {
        return Err(format!("Cargo metadata failed: {}", output_detail(&output)));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Cargo returned invalid metadata: {error}"))
}

fn metadata_packages(metadata: &Value) -> Result<&[Value], String> {
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "Cargo returned invalid package metadata".to_string())
}

fn check_packages(root: &Path, expected: &[String]) -> Result<(), String> {
    let mut runner = SystemRunner;
    let metadata = cargo_metadata(root, &mut runner)?;
    check_packages_in_metadata(&metadata, expected)?;
    eprintln!(
        "release: validated library-only crates.io package order: {}",
        expected.join(" ")
    );
    Ok(())
}

fn check_packages_in_metadata(metadata: &Value, expected: &[String]) -> Result<(), String> {
    let mut actual = Vec::new();
    for package in metadata_packages(metadata)? {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "Cargo returned a package without a valid name".to_string())?;
        let publishes_to_crates_io = match package.get("publish") {
            // Cargo permits publication to its default registry when the
            // manifest omits an explicit publish allowlist.
            None | Some(Value::Null) | Some(Value::Bool(true)) => true,
            Some(Value::Bool(false)) => false,
            Some(Value::Array(registries)) => {
                if registries.is_empty() {
                    false
                } else {
                    let mut publishes = false;
                    for registry in registries {
                        let registry = registry.as_str().ok_or_else(|| {
                            format!("Cargo returned invalid publish registries for {name}")
                        })?;
                        publishes |= registry == "crates-io";
                    }
                    if !publishes {
                        return Err(format!("publishable package {name} excludes crates-io"));
                    }
                    true
                }
            }
            Some(_) => {
                return Err(format!(
                    "Cargo returned invalid publish metadata for {name}"
                ));
            }
        };
        if !publishes_to_crates_io {
            continue;
        }
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("Cargo returned invalid targets for {name}"))?;
        validate_publishable_package_identity(metadata, name, package, targets)?;
        let mut has_binary = false;
        let mut has_build_script = false;
        for target in targets {
            let kinds = target
                .get("kind")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("Cargo returned invalid target kinds for {name}"))?;
            if !kinds.iter().all(Value::is_string) {
                return Err(format!("Cargo returned invalid target kinds for {name}"));
            }
            has_binary |= kinds.iter().any(|kind| kind.as_str() == Some("bin"));
            has_build_script |= kinds
                .iter()
                .any(|kind| kind.as_str() == Some("custom-build"));
        }
        if has_binary {
            return Err(format!("crates.io package {name} contains a binary target"));
        }
        if has_build_script {
            return Err(format!(
                "crates.io package {name} contains an unexpected build script"
            ));
        }
        actual.push(name.to_string());
    }
    if actual != expected {
        return Err(format!(
            "crates.io package order differs: expected [{}], found [{}]",
            expected.join(", "),
            actual.join(", ")
        ));
    }
    Ok(())
}

fn validate_publishable_package_identity(
    metadata: &Value,
    package_name: &str,
    package: &Value,
    targets: &[Value],
) -> Result<(), String> {
    if package_name != TRAITS_PACKAGE {
        return Err(format!(
            "crates.io package {package_name} has no approved workspace identity"
        ));
    }
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "Cargo returned no workspace root for package validation".to_string())?;
    let expected_manifest = Path::new(workspace_root).join("Cargo.toml");
    let manifest = package
        .get("manifest_path")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Cargo returned no manifest path for {package_name}"))?;
    if Path::new(manifest) != expected_manifest {
        return Err(format!(
            "crates.io package {package_name} manifest differs from {}",
            expected_manifest.display()
        ));
    }

    let expected_library = Path::new(workspace_root).join("src/lib.rs");
    let libraries: Vec<_> = targets
        .iter()
        .filter(|target| {
            target
                .get("kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.len() == 1 && kinds[0].as_str() == Some("lib"))
        })
        .collect();
    if libraries.len() != 1 {
        return Err(format!(
            "crates.io package {package_name} must contain one exact primary library target"
        ));
    }
    let source = libraries[0]
        .get("src_path")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Cargo returned no library source path for {package_name}"))?;
    if Path::new(source) != expected_library {
        return Err(format!(
            "crates.io package {package_name} library differs from {}",
            expected_library.display()
        ));
    }
    Ok(())
}

fn verify_registry(
    root: &Path,
    requested_version: Option<&Version>,
    packages: &[String],
) -> Result<Outcome, String> {
    let mut runner = SystemRunner;
    verify_registry_with(root, requested_version, packages, &mut runner)
}

fn verify_registry_with(
    root: &Path,
    requested_version: Option<&Version>,
    packages: &[String],
    runner: &mut impl Runner,
) -> Result<Outcome, String> {
    let metadata = requested_version
        .is_none()
        .then(|| cargo_metadata(root, runner))
        .transpose()?;
    let mut unavailable = false;

    for package in packages {
        let version = match requested_version {
            Some(version) => version.clone(),
            None => metadata_package_version(
                metadata
                    .as_ref()
                    .expect("metadata is present in publication verification mode"),
                package,
            )?,
        };
        let attempts = if requested_version.is_some() {
            1
        } else {
            REGISTRY_ATTEMPTS
        };
        let mut available = false;
        for attempt in 1..=attempts {
            match query_registry(root, package, &version, runner)? {
                RegistryState::Available => {
                    available = true;
                    break;
                }
                RegistryState::Missing if requested_version.is_some() => {
                    unavailable = true;
                    break;
                }
                RegistryState::Missing if attempt == attempts => {
                    return Err(format!(
                        "crates.io did not expose {package} {version} as non-yanked"
                    ));
                }
                RegistryState::Missing => {
                    runner.sleep(Duration::from_secs(REGISTRY_RETRY_SECONDS));
                }
            }
        }

        if requested_version.is_none() {
            if !available {
                return Err(format!("crates.io did not expose {package} {version}"));
            }
            verify_cargo_resolution(root, package, &version, runner)?;
            eprintln!("release: verified {package} {version} on crates.io");
        }
    }

    Ok(if unavailable {
        Outcome::RegistryUnavailable
    } else {
        Outcome::Success
    })
}

fn metadata_package_version(metadata: &Value, package: &str) -> Result<Version, String> {
    let matches: Vec<_> = metadata_packages(metadata)?
        .iter()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(package))
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "expected one workspace package named {package}; found {}",
            matches.len()
        ));
    }
    let value = matches[0]
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Cargo returned no version for {package}"))?;
    Version::parse(value).map_err(|error| format!("invalid version for {package}: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryState {
    Available,
    Missing,
}

fn query_registry(
    root: &Path,
    package: &str,
    version: &Version,
    runner: &mut impl Runner,
) -> Result<RegistryState, String> {
    let url = format!("https://crates.io/api/v1/crates/{package}/{version}");
    let args = [
        OsString::from("--silent"),
        OsString::from("--show-error"),
        OsString::from("--write-out"),
        OsString::from("\n%{http_code}"),
        OsString::from("--user-agent"),
        OsString::from(REGISTRY_USER_AGENT),
        OsString::from(url),
    ];
    let output = runner.output(OsStr::new("curl"), &args, root)?;
    if !output.success {
        return Err(format!(
            "crates.io request failed: {}",
            output_detail(&output)
        ));
    }
    parse_registry_response(package, version, &output.stdout)
}

fn parse_registry_response(
    package: &str,
    version: &Version,
    output: &[u8],
) -> Result<RegistryState, String> {
    let output = std::str::from_utf8(output)
        .map_err(|_| "crates.io returned a non-UTF-8 response".to_string())?;
    let (body, status) = output
        .rsplit_once('\n')
        .ok_or_else(|| "crates.io response lacked an HTTP status".to_string())?;
    match status {
        "404" => Ok(RegistryState::Missing),
        "200" => {
            let value: Value = serde_json::from_str(body)
                .map_err(|error| format!("crates.io returned invalid JSON: {error}"))?;
            let record = value
                .get("version")
                .and_then(Value::as_object)
                .ok_or_else(|| "crates.io returned no exact version record".to_string())?;
            let exact = record.get("num").and_then(Value::as_str) == Some(&version.to_string());
            let non_yanked = record.get("yanked").and_then(Value::as_bool) == Some(false);
            if exact && non_yanked {
                Ok(RegistryState::Available)
            } else {
                Err(format!(
                    "crates.io did not report {package} {version} as non-yanked"
                ))
            }
        }
        other => Err(format!(
            "crates.io returned HTTP {other} for {package} {version}"
        )),
    }
}

fn verify_cargo_resolution(
    root: &Path,
    package: &str,
    version: &Version,
    runner: &mut impl Runner,
) -> Result<(), String> {
    let args = [
        OsString::from("info"),
        OsString::from("--quiet"),
        OsString::from("--registry"),
        OsString::from("crates-io"),
        OsString::from(format!("{package}@{version}")),
    ];
    let output = runner.output(&cargo_program(), &args, root)?;
    if output.success {
        Ok(())
    } else {
        Err(format!(
            "Cargo could not resolve {package} {version} from crates-io: {}",
            output_detail(&output)
        ))
    }
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn require_publication_fields(
    document: &DocumentMut,
    release_always: bool,
    branch_prefix: Option<&str>,
) -> Result<(), String> {
    let workspace = document
        .get("workspace")
        .and_then(toml_edit::Item::as_table)
        .ok_or_else(|| "release config has no workspace table".to_string())?;
    if workspace
        .get("release_always")
        .and_then(toml_edit::Item::as_bool)
        != Some(release_always)
    {
        return Err(format!(
            "reviewed config must set release_always = {release_always}"
        ));
    }
    match (workspace.get("pr_branch_prefix"), branch_prefix) {
        (None, None) => Ok(()),
        (Some(value), Some(expected)) if value.as_str() == Some(expected) => Ok(()),
        (Some(_), None) => Err("reviewed config already selects a PR branch prefix".to_string()),
        _ => Err("publication config has an invalid PR branch prefix".to_string()),
    }
}

fn source_newline(body: &str) -> Result<&'static str, String> {
    if body.contains("\r\n") {
        let without_crlf = body.replace("\r\n", "");
        if without_crlf.contains(['\r', '\n']) {
            return Err("release config uses mixed line endings".to_string());
        }
        Ok("\r\n")
    } else if body.contains('\r') {
        Err("release config uses an unsupported line ending".to_string())
    } else {
        Ok("\n")
    }
}

fn prepare_publication_config(root: &Path, source: &Path, output: &Path) -> Result<(), String> {
    let source = resolve_path(root, source).canonicalize().map_err(|error| {
        format!(
            "could not resolve release config {}: {error}",
            source.display()
        )
    })?;
    let output = resolve_path(root, output);
    if output.exists() {
        return Err(format!(
            "publication config already exists: {}",
            output.display()
        ));
    }
    let body = fs::read_to_string(&source).map_err(|error| {
        format!(
            "could not read release config {}: {error}",
            source.display()
        )
    })?;
    let original: DocumentMut = body.parse().map_err(|error| {
        format!(
            "could not parse release config {}: {error}",
            source.display()
        )
    })?;
    require_publication_fields(&original, false, None)?;

    let valid_ref_check = Command::new("git")
        .current_dir(root)
        .args(["check-ref-format", "--branch", "release-plz-publication"])
        .output()
        .map_err(|error| format!("run git check-ref-format: {error}"))?;
    if !valid_ref_check.status.success() {
        return Err(format!(
            "git could not validate a known-good publication branch: {}",
            process_output_detail(&valid_ref_check)
        ));
    }
    let invalid_ref_check = Command::new("git")
        .current_dir(root)
        .args(["check-ref-format", "--branch", ":release-plz-publication"])
        .output()
        .map_err(|error| format!("run git check-ref-format: {error}"))?;
    if invalid_ref_check.status.success() {
        return Err("the publication branch prefix is a valid Git ref".to_string());
    }
    let newline = source_newline(&body)?;
    let workspace_marker = format!("[workspace]{newline}");
    if body.matches(&workspace_marker).count() != 1 {
        return Err("reviewed config has an ambiguous workspace table".to_string());
    }
    if body.matches("release_always = false").count() != 1 {
        return Err("reviewed config has an ambiguous release_always field".to_string());
    }
    let updated = body
        .replacen(
            &workspace_marker,
            &format!("{workspace_marker}pr_branch_prefix = \":\"{newline}"),
            1,
        )
        .replacen("release_always = false", "release_always = true", 1);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create publication config directory: {error}"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .map_err(|error| format!("create publication config {}: {error}", output.display()))?;
    if let Err(error) = file
        .write_all(updated.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&output);
        return Err(format!(
            "write publication config {}: {error}",
            output.display()
        ));
    }
    drop(file);
    let verify_result = (|| {
        let actual_bytes = fs::read(&output).map_err(|error| {
            format!(
                "read generated publication config {}: {error}",
                output.display()
            )
        })?;
        if actual_bytes != updated.as_bytes() {
            return Err("publication config bytes changed while writing".to_string());
        }
        let actual_text = std::str::from_utf8(&actual_bytes)
            .map_err(|_| "generated publication config is not UTF-8".to_string())?;
        let actual: DocumentMut = actual_text
            .parse()
            .map_err(|error| format!("generated publication config is invalid: {error}"))?;
        require_publication_fields(&actual, true, Some(":"))?;
        Ok(())
    })();
    if let Err(error) = verify_result {
        let _ = fs::remove_file(&output);
        return Err(error);
    }
    eprintln!(
        "release: prepared checkout-bound publication config at {}",
        output.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_policy::{TRAITS_POLICY, TRAITS_TOOLCHAIN};
    use clap::Parser;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    const FIXTURE_FETCH_URL: &str = "https://example.invalid/repository";

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        release: ReleaseArgs,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum CallMode {
        Output,
        Status,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Call {
        mode: CallMode,
        program: String,
        args: Vec<String>,
    }

    #[derive(Default)]
    struct FakeRunner {
        responses: VecDeque<Result<CommandResult, String>>,
        status_responses: VecDeque<Result<CommandStatus, String>>,
        calls: Vec<Call>,
        sleeps: Vec<Duration>,
    }

    impl FakeRunner {
        fn with_responses(responses: Vec<Result<CommandResult, String>>) -> Self {
            Self {
                responses: responses.into(),
                ..Self::default()
            }
        }

        fn assert_consumed(&self) {
            assert!(self.responses.is_empty(), "unused fake command responses");
            assert!(
                self.status_responses.is_empty(),
                "unused fake status responses"
            );
        }
    }

    impl Runner for FakeRunner {
        fn output(
            &mut self,
            program: &OsStr,
            args: &[OsString],
            _root: &Path,
        ) -> Result<CommandResult, String> {
            self.calls.push(Call {
                mode: CallMode::Output,
                program: program.to_string_lossy().into_owned(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            });
            self.responses
                .pop_front()
                .expect("fake runner received an unexpected command")
        }

        fn status(
            &mut self,
            program: &OsStr,
            args: &[OsString],
            _root: &Path,
        ) -> Result<CommandStatus, String> {
            self.calls.push(Call {
                mode: CallMode::Status,
                program: program.to_string_lossy().into_owned(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            });
            self.status_responses
                .pop_front()
                .expect("fake runner received an unexpected status command")
        }

        fn sleep(&mut self, duration: Duration) {
            self.sleeps.push(duration);
        }
    }

    fn success(stdout: impl Into<Vec<u8>>) -> Result<CommandResult, String> {
        Ok(CommandResult {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
        })
    }

    fn failure(stderr: &str) -> Result<CommandResult, String> {
        Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn status(success: bool, code: Option<i32>) -> Result<CommandStatus, String> {
        Ok(CommandStatus { success, code })
    }

    fn run_git(root: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "yaml-sigil-xtask-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tool_installation_binds_exact_versions_and_argv() {
        let mut runner = FakeRunner {
            responses: [
                success(
                    format!(
                        "cargo-binstall {}\n",
                        TRAITS_TOOLCHAIN.cargo_binstall_version
                    )
                    .into_bytes(),
                ),
                success(
                    format!("release-plz {}\n", TRAITS_TOOLCHAIN.release_plz_version).into_bytes(),
                ),
                success(
                    format!(
                        "cargo-semver-checks {}\n",
                        TRAITS_TOOLCHAIN.cargo_semver_checks_version
                    )
                    .into_bytes(),
                ),
            ]
            .into(),
            status_responses: [status(true, Some(0))].into(),
            ..FakeRunner::default()
        };
        install_tools_with(Path::new("."), TRAITS_TOOLCHAIN, &mut runner).unwrap();
        runner.assert_consumed();
        assert_eq!(runner.calls.len(), 4);
        assert_eq!(runner.calls[0].mode, CallMode::Output);
        assert_eq!(runner.calls[0].program, "cargo-binstall");
        assert_eq!(runner.calls[0].args, ["--version"]);
        assert_eq!(runner.calls[1].mode, CallMode::Status);
        assert_eq!(runner.calls[1].program, "cargo-binstall");
        assert_eq!(
            runner.calls[1].args,
            vec![
                "--force".to_string(),
                "--locked".to_string(),
                "--no-confirm".to_string(),
                "--strategies=crate-meta-data,compile".to_string(),
                format!("release-plz@{}", TRAITS_TOOLCHAIN.release_plz_version),
                format!(
                    "cargo-semver-checks@{}",
                    TRAITS_TOOLCHAIN.cargo_semver_checks_version
                ),
            ]
        );
        assert_eq!(runner.calls[2].program, "release-plz");
        assert_eq!(runner.calls[2].args, ["--version"]);
        assert_eq!(runner.calls[3].program, "cargo-semver-checks");
        assert_eq!(runner.calls[3].args, ["semver-checks", "--version"]);
    }

    #[test]
    fn tool_installation_fails_closed_on_versions_status_and_spawn() {
        let mut wrong_bootstrap =
            FakeRunner::with_responses(vec![success(b"cargo-binstall 1.20.0\n".to_vec())]);
        assert!(
            install_tools_with(Path::new("."), TRAITS_TOOLCHAIN, &mut wrong_bootstrap).is_err()
        );
        wrong_bootstrap.assert_consumed();
        assert_eq!(wrong_bootstrap.calls.len(), 1);

        for (install_status, expected) in [
            (status(false, Some(101)), "101"),
            (status(false, None), "signal"),
            (
                Err("fixture spawn failure".to_string()),
                "fixture spawn failure",
            ),
        ] {
            let mut runner = FakeRunner {
                responses: [success(
                    format!(
                        "cargo-binstall {}\n",
                        TRAITS_TOOLCHAIN.cargo_binstall_version
                    )
                    .into_bytes(),
                )]
                .into(),
                status_responses: [install_status].into(),
                ..FakeRunner::default()
            };
            let error =
                install_tools_with(Path::new("."), TRAITS_TOOLCHAIN, &mut runner).unwrap_err();
            assert!(error.contains(expected), "{error}");
            runner.assert_consumed();
        }

        for responses in [
            vec![
                success(
                    format!(
                        "cargo-binstall {}\n",
                        TRAITS_TOOLCHAIN.cargo_binstall_version
                    )
                    .into_bytes(),
                ),
                success(b"release-plz 0.3.159\n".to_vec()),
            ],
            vec![
                success(
                    format!(
                        "cargo-binstall {}\n",
                        TRAITS_TOOLCHAIN.cargo_binstall_version
                    )
                    .into_bytes(),
                ),
                success(
                    format!("release-plz {}\n", TRAITS_TOOLCHAIN.release_plz_version).into_bytes(),
                ),
                success(b"cargo-semver-checks 0.48.0\n".to_vec()),
            ],
        ] {
            let mut runner = FakeRunner {
                responses: responses.into(),
                status_responses: [status(true, Some(0))].into(),
                ..FakeRunner::default()
            };
            assert!(install_tools_with(Path::new("."), TRAITS_TOOLCHAIN, &mut runner).is_err());
            runner.assert_consumed();
        }
    }

    #[test]
    fn tool_versions_require_one_exact_line() {
        let expected = format!("cargo-binstall {}", TRAITS_TOOLCHAIN.cargo_binstall_version);
        for output in [
            format!(" {expected}\n").into_bytes(),
            format!("{expected} \n").into_bytes(),
            format!("\n{expected}\n").into_bytes(),
            format!("{expected}\n\n").into_bytes(),
            format!("{expected}\nother\n").into_bytes(),
            format!("{expected}\r").into_bytes(),
            vec![0xff],
        ] {
            let mut runner = FakeRunner::with_responses(vec![success(output)]);
            assert!(
                require_command_version(
                    Path::new("."),
                    &mut runner,
                    OsStr::new("cargo-binstall"),
                    &[OsString::from("--version")],
                    &expected,
                )
                .is_err()
            );
            runner.assert_consumed();
        }

        for suffix in ["", "\n", "\r\n"] {
            let mut runner = FakeRunner::with_responses(vec![success(
                format!("{expected}{suffix}").into_bytes(),
            )]);
            require_command_version(
                Path::new("."),
                &mut runner,
                OsStr::new("cargo-binstall"),
                &[OsString::from("--version")],
                &expected,
            )
            .unwrap();
            runner.assert_consumed();
        }
    }

    #[test]
    fn current_main_gate_binds_exact_git_commands_and_state() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let fetch_url = FIXTURE_FETCH_URL;
        let mut runner = FakeRunner::with_responses(vec![
            success(format!("{head}\n").into_bytes()),
            success(format!("{fetch_url}\n").into_bytes()),
            success(format!("{head}\trefs/heads/main\n").into_bytes()),
        ]);
        require_current_main_with(Path::new("."), head, fetch_url, &mut runner).unwrap();
        runner.assert_consumed();
        assert_eq!(runner.calls.len(), 3);
        assert_eq!(runner.calls[0].program, "git");
        assert_eq!(runner.calls[0].args, ["rev-parse", "HEAD"]);
        assert_eq!(runner.calls[1].args, ["remote", "get-url", "origin"]);
        assert_eq!(
            runner.calls[2].args,
            ["ls-remote", "--exit-code", fetch_url, "refs/heads/main"]
        );
    }

    #[test]
    fn current_main_gate_uses_real_git_and_detects_a_stale_remote() {
        let temporary = TestDirectory::new("current main");
        let remote = temporary.path().join("remote repository.git");
        let checkout = temporary.path().join("checkout");
        let remote_arg = remote.to_str().unwrap();
        let checkout_arg = checkout.to_str().unwrap();

        run_git(temporary.path(), &["init", "--bare", remote_arg]);
        run_git(temporary.path(), &["init", checkout_arg]);
        fs::write(checkout.join("fixture.txt"), "first\n").unwrap();
        run_git(&checkout, &["add", "fixture.txt"]);
        run_git(
            &checkout,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Release fixture",
                "-c",
                "user.email=release-fixture@example.invalid",
                "commit",
                "-m",
                "first",
            ],
        );
        run_git(&checkout, &["branch", "-M", "main"]);
        run_git(&checkout, &["remote", "add", "origin", remote_arg]);
        run_git(&checkout, &["push", "--set-upstream", "origin", "main"]);
        let head = exact_output_line(&run_git(&checkout, &["rev-parse", "HEAD"]), "HEAD").unwrap();
        require_current_main(&checkout, &head, remote_arg).unwrap();

        fs::write(checkout.join("fixture.txt"), "second\n").unwrap();
        run_git(&checkout, &["add", "fixture.txt"]);
        run_git(
            &checkout,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Release fixture",
                "-c",
                "user.email=release-fixture@example.invalid",
                "commit",
                "-m",
                "second",
            ],
        );
        run_git(&checkout, &["push", "origin", "main"]);
        run_git(&checkout, &["reset", "--hard", &head]);
        let error = require_current_main(&checkout, &head, remote_arg).unwrap_err();
        assert!(error.contains("remote main changed"), "{error}");
    }

    #[test]
    fn current_main_gate_rejects_invalid_or_ambiguous_state() {
        assert!(is_lowercase_sha("0123456789abcdef0123456789abcdef01234567"));
        for invalid in [
            "",
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef0123456G",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(!is_lowercase_sha(invalid));
        }
        let head = "0123456789abcdef0123456789abcdef01234567";
        for invalid in ["", "-option", "bad\nurl", "bad\rurl", "bad\0url"] {
            assert!(require_current_main(Path::new("."), head, invalid).is_err());
        }
        let stale = "1123456789abcdef0123456789abcdef01234567";
        let fetch_url = FIXTURE_FETCH_URL;
        let cases = [
            vec![success(format!("{stale}\n").into_bytes())],
            vec![
                success(format!("{head}\n").into_bytes()),
                success(b"https://github.com/lookalike/repository\n".to_vec()),
            ],
            vec![
                success(format!("{head}\n").into_bytes()),
                success(format!("{fetch_url}\n").into_bytes()),
                success(format!("{stale}\trefs/heads/main\n").into_bytes()),
            ],
            vec![
                success(format!("{head}\n").into_bytes()),
                success(format!("{fetch_url}\n").into_bytes()),
                success(format!("{head}\trefs/heads/main\n{head}\trefs/heads/main\n").into_bytes()),
            ],
            vec![
                success(format!("{head}\n").into_bytes()),
                success(format!("{fetch_url}\n").into_bytes()),
                success(format!("{head} refs/heads/main\n").into_bytes()),
            ],
        ];
        for responses in cases {
            let mut runner = FakeRunner::with_responses(responses);
            assert!(
                require_current_main_with(Path::new("."), head, fetch_url, &mut runner).is_err()
            );
            runner.assert_consumed();
        }
    }

    #[test]
    fn current_main_gate_fails_on_git_status_or_spawn_error() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let fetch_url = FIXTURE_FETCH_URL;
        for response in [failure("git failed"), Err("git spawn failed".to_string())] {
            let mut runner = FakeRunner::with_responses(vec![response]);
            assert!(
                require_current_main_with(Path::new("."), head, fetch_url, &mut runner).is_err()
            );
            runner.assert_consumed();
        }
        let mut remote_failure = FakeRunner::with_responses(vec![
            success(format!("{head}\n").into_bytes()),
            success(format!("{fetch_url}\n").into_bytes()),
            failure("remote failed"),
        ]);
        assert!(
            require_current_main_with(Path::new("."), head, fetch_url, &mut remote_failure)
                .is_err()
        );
        remote_failure.assert_consumed();
    }

    #[test]
    fn crate_names_and_duplicates_are_rejected() {
        assert!(
            validate_package_arguments(&[TRAITS_POLICY.packages[0].package.to_string()]).is_ok()
        );
        for invalid in ["", "Yaml", "-yaml", "yaml.sig"] {
            assert!(validate_package_arguments(&[invalid.to_string()]).is_err());
        }
        assert!(validate_package_arguments(&["yaml".to_string(), "yaml".to_string()]).is_err());
    }

    #[test]
    fn package_policy_requires_exact_order_and_no_binary_targets() {
        let metadata = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [
                {
                    "name": "private-helper",
                    "publish": [],
                    "targets": [{"kind": ["lib"]}]
                },
                {
                    "name": TRAITS_PACKAGE,
                    "publish": ["crates-io"],
                    "manifest_path": "/workspace/Cargo.toml",
                    "targets": [{
                        "kind": ["lib"],
                        "src_path": "/workspace/src/lib.rs"
                    }]
                }
            ]
        });
        assert!(check_packages_in_metadata(&metadata, &[TRAITS_PACKAGE.to_string()]).is_ok());
        assert!(check_packages_in_metadata(&metadata, &["wrong".to_string()]).is_err());

        let mut alternate = metadata.clone();
        alternate["packages"].as_array_mut().unwrap().insert(
            1,
            serde_json::json!({
                "name": "alternate-registry-helper",
                "publish": ["alternate"],
                "targets": [{"kind": ["lib"]}]
            }),
        );
        assert!(check_packages_in_metadata(&alternate, &[TRAITS_PACKAGE.to_string()]).is_err());

        let binary = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": ["crates-io"],
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [
                    {"kind": ["lib"], "src_path": "/workspace/src/lib.rs"},
                    {"kind": ["bin"]}
                ]
            }]
        });
        assert!(check_packages_in_metadata(&binary, &[TRAITS_PACKAGE.to_string()]).is_err());
        let build_script = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": ["crates-io"],
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [
                    {"kind": ["lib"], "src_path": "/workspace/src/lib.rs"},
                    {"kind": ["custom-build"]}
                ]
            }]
        });
        assert!(check_packages_in_metadata(&build_script, &[TRAITS_PACKAGE.to_string()]).is_err());
        let malformed = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": ["crates-io"],
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [{}]
            }]
        });
        assert!(check_packages_in_metadata(&malformed, &[TRAITS_PACKAGE.to_string()]).is_err());
    }

    #[test]
    fn package_policy_includes_cargo_default_publication() {
        let default_publish = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": null,
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [{
                    "kind": ["lib"],
                    "src_path": "/workspace/src/lib.rs"
                }]
            }]
        });
        assert!(
            check_packages_in_metadata(&default_publish, &[TRAITS_PACKAGE.to_string()]).is_ok()
        );

        let mut absent_publish = default_publish.clone();
        absent_publish["packages"][0]
            .as_object_mut()
            .unwrap()
            .remove("publish");
        assert!(check_packages_in_metadata(&absent_publish, &[TRAITS_PACKAGE.to_string()]).is_ok());

        let unexpected = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [
                {
                    "name": TRAITS_PACKAGE,
                    "publish": ["crates-io"],
                    "manifest_path": "/workspace/Cargo.toml",
                    "targets": [{
                        "kind": ["lib"],
                        "src_path": "/workspace/src/lib.rs"
                    }]
                },
                {
                    "name": "unexpected-default-package",
                    "publish": null,
                    "manifest_path": "/workspace/unexpected/Cargo.toml",
                    "targets": [{
                        "kind": ["lib"],
                        "src_path": "/workspace/unexpected/src/lib.rs"
                    }]
                }
            ]
        });
        assert!(check_packages_in_metadata(&unexpected, &[TRAITS_PACKAGE.to_string()]).is_err());

        let default_binary = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": null,
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [
                    {"kind": ["lib"], "src_path": "/workspace/src/lib.rs"},
                    {"kind": ["bin"]}
                ]
            }]
        });
        assert!(
            check_packages_in_metadata(&default_binary, &[TRAITS_PACKAGE.to_string()]).is_err()
        );
    }

    #[test]
    fn package_policy_binds_the_root_manifest_and_primary_library() {
        let expected = [TRAITS_PACKAGE.to_string()];
        let valid = serde_json::json!({
            "workspace_root": "/workspace",
            "packages": [{
                "name": TRAITS_PACKAGE,
                "publish": ["crates-io"],
                "manifest_path": "/workspace/Cargo.toml",
                "targets": [{
                    "kind": ["lib"],
                    "src_path": "/workspace/src/lib.rs"
                }]
            }]
        });
        assert!(check_packages_in_metadata(&valid, &expected).is_ok());

        let mut relocated_manifest = valid.clone();
        relocated_manifest["packages"][0]["manifest_path"] =
            Value::String("/workspace/relocated/Cargo.toml".to_string());
        assert!(check_packages_in_metadata(&relocated_manifest, &expected).is_err());

        let mut relocated_library = valid.clone();
        relocated_library["packages"][0]["targets"][0]["src_path"] =
            Value::String("/workspace/src/other.rs".to_string());
        assert!(check_packages_in_metadata(&relocated_library, &expected).is_err());

        let mut missing_library = valid.clone();
        missing_library["packages"][0]["targets"] =
            serde_json::json!([{"kind": ["test"], "src_path": "/workspace/tests/api.rs"}]);
        assert!(check_packages_in_metadata(&missing_library, &expected).is_err());

        let mut duplicate_library = valid;
        duplicate_library["packages"][0]["targets"] = serde_json::json!([
            {"kind": ["lib"], "src_path": "/workspace/src/lib.rs"},
            {"kind": ["lib"], "src_path": "/workspace/src/lib.rs"}
        ]);
        assert!(check_packages_in_metadata(&duplicate_library, &expected).is_err());
    }

    #[test]
    fn package_policy_rejects_ambiguous_publish_metadata() {
        for publish in [serde_json::json!(true), serde_json::json!(["crates-io", 1])] {
            let metadata = serde_json::json!({
                "packages": [{
                    "name": TRAITS_PACKAGE,
                    "publish": publish,
                    "targets": [{"kind": ["lib"]}]
                }]
            });
            assert!(check_packages_in_metadata(&metadata, &[TRAITS_PACKAGE.to_string()]).is_err());
        }

        let missing = serde_json::json!({
            "packages": [{
                "name": TRAITS_PACKAGE,
                "targets": [{"kind": ["lib"]}]
            }]
        });
        assert!(check_packages_in_metadata(&missing, &[TRAITS_PACKAGE.to_string()]).is_err());
    }

    #[test]
    fn registry_response_requires_exact_non_yanked_version() {
        let version = Version::parse("0.4.0-rc.1").unwrap();
        let available = br#"{"version":{"num":"0.4.0-rc.1","yanked":false}}
200"#;
        assert_eq!(
            parse_registry_response(TRAITS_PACKAGE, &version, available).unwrap(),
            RegistryState::Available
        );
        assert_eq!(
            parse_registry_response(TRAITS_PACKAGE, &version, b"missing\n404").unwrap(),
            RegistryState::Missing
        );
        for invalid in [
            br#"{"version":{"num":"0.4.0-rc.2","yanked":false}}
200"#
                .as_slice(),
            br#"{"version":{"num":"0.4.0-rc.1","yanked":true}}
200"#
                .as_slice(),
            b"error\n500".as_slice(),
            b"no-status".as_slice(),
        ] {
            assert!(parse_registry_response(TRAITS_PACKAGE, &version, invalid).is_err());
        }
    }

    #[test]
    fn readiness_distinguishes_available_missing_yanked_and_process_failure() {
        let version = Version::parse("1.2.3").unwrap();
        let packages = ["yaml-sigil-test".to_string()];
        let cases = [
            (
                success(b"{\"version\":{\"num\":\"1.2.3\",\"yanked\":false}}\n200".to_vec()),
                Ok(Outcome::Success),
            ),
            (
                success(b"missing\n404".to_vec()),
                Ok(Outcome::RegistryUnavailable),
            ),
            (
                success(b"{\"version\":{\"num\":\"1.2.3\",\"yanked\":true}}\n200".to_vec()),
                Err("non-yanked"),
            ),
            (
                Err("could not start curl".to_string()),
                Err("could not start curl"),
            ),
            (failure("curl failed"), Err("curl failed")),
        ];

        for (response, expected) in cases {
            let mut runner = FakeRunner::with_responses(vec![response]);
            let result =
                verify_registry_with(Path::new("."), Some(&version), &packages, &mut runner);
            match expected {
                Ok(outcome) => assert_eq!(result.unwrap(), outcome),
                Err(fragment) => assert!(result.unwrap_err().contains(fragment)),
            }
            runner.assert_consumed();
            assert_eq!(runner.calls.len(), 1);
            assert_eq!(runner.calls[0].program, "curl");
            assert_eq!(
                runner.calls[0].args,
                [
                    "--silent",
                    "--show-error",
                    "--write-out",
                    "\n%{http_code}",
                    "--user-agent",
                    REGISTRY_USER_AGENT,
                    "https://crates.io/api/v1/crates/yaml-sigil-test/1.2.3",
                ]
            );
            assert!(runner.sleeps.is_empty());
        }
    }

    #[test]
    fn publication_verification_uses_metadata_polling_and_named_registry() {
        let metadata = serde_json::to_vec(&serde_json::json!({
            "packages": [{"name": TRAITS_PACKAGE, "version": "0.4.0-rc.1"}]
        }))
        .unwrap();
        let mut runner = FakeRunner::with_responses(vec![
            success(metadata),
            success(b"missing\n404".to_vec()),
            success(b"{\"version\":{\"num\":\"0.4.0-rc.1\",\"yanked\":false}}\n200".to_vec()),
            success(Vec::new()),
        ]);
        let result = verify_registry_with(
            Path::new("."),
            None,
            &[TRAITS_PACKAGE.to_string()],
            &mut runner,
        );
        assert_eq!(result.unwrap(), Outcome::Success);
        runner.assert_consumed();
        assert_eq!(runner.sleeps, [Duration::from_secs(10)]);
        assert_eq!(runner.calls.len(), 4);
        assert!(
            Path::new(&runner.calls[0].program)
                .file_name()
                .is_some_and(|name| name == "cargo" || name == "cargo.exe")
        );
        assert_eq!(
            runner.calls[0].args,
            ["metadata", "--no-deps", "--format-version", "1"]
        );
        assert_eq!(runner.calls[1].program, "curl");
        assert_eq!(runner.calls[2].program, "curl");
        assert!(
            Path::new(&runner.calls[3].program)
                .file_name()
                .is_some_and(|name| name == "cargo" || name == "cargo.exe")
        );
        assert_eq!(
            runner.calls[3].args,
            vec![
                "info".to_string(),
                "--quiet".to_string(),
                "--registry".to_string(),
                "crates-io".to_string(),
                format!("{TRAITS_PACKAGE}@0.4.0-rc.1"),
            ]
        );
    }

    #[test]
    fn cargo_metadata_errors_fail_before_registry_access() {
        for response in [
            failure("metadata failed"),
            success(b"not-json".to_vec()),
            success(br#"{"packages":[]}"#.to_vec()),
        ] {
            let mut runner = FakeRunner::with_responses(vec![response]);
            assert!(
                verify_registry_with(
                    Path::new("."),
                    None,
                    &[TRAITS_PACKAGE.to_string()],
                    &mut runner,
                )
                .is_err()
            );
            runner.assert_consumed();
            assert_eq!(runner.calls.len(), 1);
        }
    }

    #[test]
    fn publication_verification_fails_on_resolution_or_bounded_absence() {
        let metadata = serde_json::to_vec(&serde_json::json!({
            "packages": [{"name": TRAITS_PACKAGE, "version": "0.4.0-rc.1"}]
        }))
        .unwrap();
        let available = b"{\"version\":{\"num\":\"0.4.0-rc.1\",\"yanked\":false}}\n200";
        let mut resolution_failure = FakeRunner::with_responses(vec![
            success(metadata.clone()),
            success(available.to_vec()),
            failure("cargo info failed"),
        ]);
        let error = verify_registry_with(
            Path::new("."),
            None,
            &[TRAITS_PACKAGE.to_string()],
            &mut resolution_failure,
        )
        .unwrap_err();
        assert!(error.contains("cargo info failed"));

        let mut responses = vec![success(metadata)];
        responses.extend((0..REGISTRY_ATTEMPTS).map(|_| success(b"missing\n404".to_vec())));
        let mut bounded = FakeRunner::with_responses(responses);
        let error = verify_registry_with(
            Path::new("."),
            None,
            &[TRAITS_PACKAGE.to_string()],
            &mut bounded,
        )
        .unwrap_err();
        assert!(error.contains("did not expose"));
        assert_eq!(bounded.sleeps.len(), REGISTRY_ATTEMPTS - 1);
        bounded.assert_consumed();
    }

    #[test]
    fn metadata_version_requires_one_exact_workspace_package() {
        let metadata = serde_json::json!({
            "packages": [{"name": TRAITS_PACKAGE, "version": "0.4.0-rc.1"}]
        });
        assert_eq!(
            metadata_package_version(&metadata, TRAITS_PACKAGE).unwrap(),
            Version::parse("0.4.0-rc.1").unwrap()
        );
        assert!(metadata_package_version(&metadata, "missing").is_err());
        let duplicate = serde_json::json!({
            "packages": [
                {"name": TRAITS_PACKAGE, "version": "0.4.0-rc.1"},
                {"name": TRAITS_PACKAGE, "version": "0.4.0-rc.1"}
            ]
        });
        assert!(metadata_package_version(&duplicate, TRAITS_PACKAGE).is_err());
    }

    #[test]
    fn value_flags_reject_duplicates_and_stray_arguments() {
        assert!(
            TestCli::try_parse_from(["test", "prepare-publication-config", "--output", "file"])
                .is_ok()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "prepare-publication-config",
                "--output",
                "one",
                "--output",
                "two",
            ])
            .is_err()
        );
        assert!(TestCli::try_parse_from(["test", "prepare-publication-config", "stray"]).is_err());
    }

    #[test]
    fn publication_config_changes_exactly_two_source_spans() {
        for (label, newline) in [("lf", "\n"), ("crlf", "\r\n")] {
            let temporary = TestDirectory::new(label);
            let source = temporary.path().join("release-plz.toml");
            let output = temporary.path().join("publication.toml");
            let body = [
                "[workspace]",
                "# Retain this comment and all surrounding bytes.",
                "release = false",
                "release_always = false",
                "",
                "[[package]]",
                "name = \"fixture\"",
                "release = true",
                "",
            ]
            .join(newline);
            fs::write(&source, &body).unwrap();

            prepare_publication_config(temporary.path(), &source, &output).unwrap();
            let marker = format!("[workspace]{newline}");
            let expected = body
                .replacen(
                    &marker,
                    &format!("{marker}pr_branch_prefix = \":\"{newline}"),
                    1,
                )
                .replacen("release_always = false", "release_always = true", 1);
            assert_eq!(fs::read_to_string(&output).unwrap(), expected);
            assert!(prepare_publication_config(temporary.path(), &source, &output).is_err());
            assert_eq!(fs::read_to_string(&output).unwrap(), expected);
        }
    }

    #[test]
    fn publication_config_rejects_unreviewed_or_ambiguous_sources() {
        for (label, body) in [
            ("true", "[workspace]\nrelease_always = true\n"),
            ("string", "[workspace]\nrelease_always = \"false\"\n"),
            (
                "prefix",
                "[workspace]\nrelease_always = false\npr_branch_prefix = \"release-plz\"\n",
            ),
            (
                "duplicate-field",
                "[workspace]\nrelease_always = false\nrelease_always = false\n",
            ),
            (
                "duplicate-table",
                "[workspace]\nrelease_always = false\n[workspace]\n",
            ),
            (
                "mixed-line-endings",
                "[workspace]\r\nrelease_always = false\n",
            ),
        ] {
            let temporary = TestDirectory::new(label);
            let source = temporary.path().join("release-plz.toml");
            let output = temporary.path().join("publication.toml");
            fs::write(&source, body).unwrap();
            assert!(prepare_publication_config(temporary.path(), &source, &output).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn publication_config_rejects_output_path_collisions_and_io_failures() {
        let temporary = TestDirectory::new("publication-collisions");
        let source = temporary.path().join("release-plz.toml");
        fs::write(&source, "[workspace]\nrelease_always = false\n").unwrap();

        assert!(prepare_publication_config(temporary.path(), &source, &source).is_err());
        let blocking_file = temporary.path().join("blocking-file");
        fs::write(&blocking_file, "preserve\n").unwrap();
        let impossible_output = blocking_file.join("publication.toml");
        assert!(prepare_publication_config(temporary.path(), &source, &impossible_output).is_err());
        assert_eq!(fs::read_to_string(&blocking_file).unwrap(), "preserve\n");
    }

    #[cfg(unix)]
    #[test]
    fn publication_config_never_follows_an_output_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = TestDirectory::new("publication-symlink");
        let source = temporary.path().join("release-plz.toml");
        let target = temporary.path().join("target.toml");
        let output = temporary.path().join("publication.toml");
        fs::write(&source, "[workspace]\nrelease_always = false\n").unwrap();
        fs::write(&target, "preserve\n").unwrap();
        symlink(&target, &output).unwrap();

        assert!(prepare_publication_config(temporary.path(), &source, &output).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "preserve\n");
    }
}

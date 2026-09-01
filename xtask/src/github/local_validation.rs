// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Maintained local integration harness for the validation-only release path.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::safe_file;

use super::{consts, git_line, output_detail, repository_policy_for_root};

const MANIFEST_SCHEMA: u64 = 1;
const MANIFEST_LIMIT: usize = 64 * 1024;
const MAX_VALIDATOR_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u64,
    repository: String,
    current_sha: String,
    historical_sha: String,
    release_plz: PathBuf,
}

pub(super) fn run(root: &Path, manifest_path: &Path) -> Result<(), String> {
    let manifest = read_manifest(root, manifest_path)?;
    let provider = repository_policy_for_root(root, &manifest.repository)?;
    require_closed_manifest(&manifest, provider.full_name)?;
    require_exact_source(root, &manifest)?;
    require_release_plz(&manifest.release_plz, provider.release_family)?;
    let forge_token = release_plz_forge_token()?;

    let current_executable = std::env::current_exe()
        .map_err(|error| format!("resolve current release validator: {error}"))?;
    let validator_digest = digest_file(&current_executable)?;
    let staging = tempfile::tempdir()
        .map_err(|error| format!("create validator staging directory: {error}"))?;
    let staged_validator = staging.path().join("yaml-sigil-release-xtask");
    fs::copy(&current_executable, &staged_validator)
        .map_err(|error| format!("stage current release validator: {error}"))?;
    set_executable(&staged_validator)?;
    if digest_file(&staged_validator)? != validator_digest {
        return Err("staged release validator bytes changed".to_string());
    }

    validate_source(
        root,
        &manifest,
        "current",
        &manifest.current_sha,
        &staged_validator,
        provider.release_family,
        &forge_token,
    )?;
    validate_source(
        root,
        &manifest,
        "historical",
        &manifest.historical_sha,
        &staged_validator,
        provider.release_family,
        &forge_token,
    )?;
    if digest_file(&staged_validator)? != validator_digest {
        return Err("staged release validator changed during validation".to_string());
    }
    println!("local_release_validation=valid\nvalidator_sha256={validator_digest}");
    Ok(())
}

fn require_closed_manifest(manifest: &Manifest, repository: &str) -> Result<(), String> {
    if manifest.schema_version != MANIFEST_SCHEMA
        || repository != manifest.repository
        || !super::is_sha(&manifest.current_sha)
        || !super::is_sha(&manifest.historical_sha)
        || manifest.current_sha == manifest.historical_sha
    {
        return Err("local validation manifest is outside the closed policy".to_string());
    }
    Ok(())
}

fn read_manifest(root: &Path, path: &Path) -> Result<Manifest, String> {
    let body = safe_file::TrustedRoot::open(root)
        .and_then(|trusted| trusted.read_utf8(path, MANIFEST_LIMIT))
        .map_err(|error| format!("read local validation manifest: {error}"))?;
    serde_json::from_str(&body)
        .map_err(|error| format!("local validation manifest is invalid: {error}"))
}

fn require_exact_source(root: &Path, manifest: &Manifest) -> Result<(), String> {
    if git_line(root, &["rev-parse", "HEAD"])? != manifest.current_sha {
        return Err("current checkout does not match the validation manifest".to_string());
    }
    let tracked = checked_output(
        root,
        "git",
        &["status", "--porcelain", "--untracked-files=no"],
    )?;
    require_no_tracked_changes(&tracked.stdout)?;
    checked_output(
        root,
        "git",
        &[
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", manifest.historical_sha),
        ],
    )?;
    checked_output(
        root,
        "git",
        &[
            "merge-base",
            "--is-ancestor",
            &manifest.historical_sha,
            &manifest.current_sha,
        ],
    )?;
    Ok(())
}

fn require_no_tracked_changes(status: &[u8]) -> Result<(), String> {
    if status.is_empty() {
        Ok(())
    } else {
        Err("current checkout contains tracked changes".to_string())
    }
}

fn require_release_plz(
    release_plz: &Path,
    family: crate::release_policy::ReleaseFamily,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(release_plz)
        .map_err(|error| format!("inspect pinned release-plz: {error}"))?;
    if !release_plz.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("pinned release-plz is not one regular non-link file".to_string());
    }
    let policy = consts::repository_for_family(family)
        .ok_or_else(|| "release family has no GitHub repository policy".to_string())?;
    let release = release_policy(policy.release_family);
    let expected = release.toolchain.release_plz_version;
    let output = checked_output(
        Path::new("."),
        release_plz
            .to_str()
            .ok_or_else(|| "release-plz path is not UTF-8".to_string())?,
        &["--version"],
    )?;
    require_release_plz_version(&output.stdout, expected)
}

fn require_release_plz_version(output: &[u8], expected: &str) -> Result<(), String> {
    let actual = one_line(output, "release-plz version")?;
    if actual != format!("release-plz {expected}") {
        return Err("release-plz version differs from compiled policy".to_string());
    }
    Ok(())
}

fn validate_source(
    source: &Path,
    manifest: &Manifest,
    label: &str,
    sha: &str,
    validator: &Path,
    family: crate::release_policy::ReleaseFamily,
    forge_token: &str,
) -> Result<(), String> {
    let temporary = tempfile::tempdir()
        .map_err(|error| format!("create {label} validation directory: {error}"))?;
    let checkout = temporary.path().join("checkout");
    checked_output(
        source,
        "git",
        &[
            "clone",
            "--quiet",
            "--no-hardlinks",
            source
                .to_str()
                .ok_or_else(|| "source path is not UTF-8".to_string())?,
            checkout
                .to_str()
                .ok_or_else(|| "checkout path is not UTF-8".to_string())?,
        ],
    )?;
    checked_output(
        &checkout,
        "git",
        &[
            "update-ref",
            "refs/remotes/origin/main",
            &manifest.current_sha,
        ],
    )?;
    let branch = format!("release-plz-local-{label}");
    checked_output(
        &checkout,
        "git",
        &["switch", "--quiet", "--force-create", &branch, sha],
    )?;
    checked_output(
        &checkout,
        "git",
        &["branch", "--set-upstream-to=origin/main", &branch],
    )?;
    if git_line(&checkout, &["rev-parse", "HEAD"])? != sha
        || git_line(
            &checkout,
            &[
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ],
        )? != "origin/main"
    {
        return Err(format!("{label} fixture branch attachment is invalid"));
    }

    let before_refs = checked_output(
        &checkout,
        "git",
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
    )?
    .stdout;
    require_clean(&checkout, label)?;
    run_validator(&checkout, validator, &["release-version", "check"])?;
    run_validator(&checkout, validator, &["release-version", "show"])?;
    let release = release_policy(family);
    let mut package_args = vec!["release".to_string(), "check-packages".to_string()];
    package_args.extend(
        release
            .packages
            .iter()
            .map(|package| package.package.to_string()),
    );
    run_validator_owned(&checkout, validator, &package_args)?;

    let config = temporary.path().join(format!("{label}-publication.toml"));
    run_validator_owned(
        &checkout,
        validator,
        &[
            "release".to_string(),
            "prepare-publication-config".to_string(),
            "--output".to_string(),
            config.display().to_string(),
        ],
    )?;
    run_release_plz(&checkout, manifest, &config, forge_token)?;
    require_clean(&checkout, label)?;
    let after_refs = checked_output(
        &checkout,
        "git",
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
    )?
    .stdout;
    let after_head = git_line(&checkout, &["rev-parse", "HEAD"])?;
    require_unchanged_source_state(label, &before_refs, &after_refs, sha, &after_head)?;
    Ok(())
}

fn require_unchanged_source_state(
    label: &str,
    before_refs: &[u8],
    after_refs: &[u8],
    expected_head: &str,
    after_head: &str,
) -> Result<(), String> {
    if after_refs != before_refs || after_head != expected_head {
        return Err(format!("{label} validation changed Git refs or HEAD"));
    }
    Ok(())
}

fn run_validator(root: &Path, validator: &Path, args: &[&str]) -> Result<(), String> {
    let owned = args
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    run_validator_owned(root, validator, &owned)
}

fn run_validator_owned(root: &Path, validator: &Path, args: &[String]) -> Result<(), String> {
    let mut command = Command::new(validator);
    command.current_dir(root).args(args);
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run staged release validator: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "staged release validator failed: {}",
            output_detail(&output)
        ))
    }
}

fn run_release_plz(
    root: &Path,
    manifest: &Manifest,
    config: &Path,
    forge_token: &str,
) -> Result<(), String> {
    let mut command = release_plz_command(root, manifest, config, forge_token);
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run pinned release-plz dry run: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "pinned release-plz dry run failed: {}",
            output_detail(&output)
        ))
    }
}

fn release_plz_command(
    root: &Path,
    manifest: &Manifest,
    config: &Path,
    forge_token: &str,
) -> Command {
    let mut command = Command::new(&manifest.release_plz);
    command
        .current_dir(root)
        .args([
            "release",
            "--dry-run",
            "--forge",
            "github",
            "--repo-url",
            &format!("https://github.com/{}", manifest.repository),
            "--config",
            &config.display().to_string(),
            "--manifest-path",
            "Cargo.toml",
        ])
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "remote.origin.pushurl")
        .env(
            "GIT_CONFIG_VALUE_0",
            "disabled://yaml-sigil-local-validation",
        )
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env("GIT_TOKEN", forge_token)
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN");
    command
}

fn release_plz_forge_token() -> Result<String, String> {
    match std::env::var("GIT_TOKEN") {
        Ok(value) if !value.is_empty() && !value.contains(['\0', '\r', '\n']) => Ok(value),
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
            Err("GIT_TOKEN is not one valid token value".to_string())
        }
        Err(std::env::VarError::NotPresent) => {
            Err("GIT_TOKEN is required for release-plz dry-run forge reads".to_string())
        }
    }
}

fn require_clean(root: &Path, label: &str) -> Result<(), String> {
    let output = checked_output(root, "git", &["status", "--porcelain"])?;
    if output.stdout.is_empty() {
        Ok(())
    } else {
        Err(format!("{label} validation fixture is not clean"))
    }
}

fn release_policy(
    family: crate::release_policy::ReleaseFamily,
) -> &'static crate::release_policy::ReleasePolicy {
    match family {
        crate::release_policy::ReleaseFamily::Traits => &crate::release_policy::TRAITS_POLICY,
        crate::release_policy::ReleaseFamily::RustWorkspace => &crate::release_policy::RUST_POLICY,
    }
}

fn checked_output(
    root: &Path,
    program: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let mut command = Command::new(program);
    command.current_dir(root).args(args);
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("{program} failed: {}", output_detail(&output)))
    }
}

fn one_line(bytes: &[u8], label: &str) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8"))?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains(['\r', '\n']) {
        Err(format!("{label} is not one line"))
    } else {
        Ok(line.to_string())
    }
}

fn digest_file(path: &Path) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_VALIDATOR_BYTES {
        return Err(format!(
            "{} is not one bounded regular file",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("make staged validator executable: {error}"))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA,
            repository: "NVIDIA/yaml-sigil-traits".to_string(),
            current_sha: "a".repeat(40),
            historical_sha: "b".repeat(40),
            release_plz: if cfg!(windows) {
                PathBuf::from(r"C:\release-plz.exe")
            } else {
                PathBuf::from("/release-plz")
            },
        }
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_symlinked_paths() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(
            temporary.path().join("manifest.json"),
            r#"{"schema_version":1,"repository":"NVIDIA/yaml-sigil-traits","current_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","historical_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","release_plz":"/bin/false","extra":true}"#,
        )
        .unwrap();
        assert!(read_manifest(temporary.path(), Path::new("manifest.json")).is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                temporary.path().join("manifest.json"),
                temporary.path().join("linked.json"),
            )
            .unwrap();
            assert!(read_manifest(temporary.path(), Path::new("linked.json")).is_err());
        }
    }

    #[test]
    fn closed_manifest_rejects_wrong_shas() {
        let mut value = manifest();
        assert!(require_closed_manifest(&value, &value.repository).is_ok());

        value.current_sha = "a".repeat(39);
        assert!(require_closed_manifest(&value, &value.repository).is_err());
        value.current_sha = "a".repeat(40);
        value.historical_sha = "z".repeat(40);
        assert!(require_closed_manifest(&value, &value.repository).is_err());
        value.historical_sha = value.current_sha.clone();
        assert!(require_closed_manifest(&value, &value.repository).is_err());
    }

    #[test]
    fn tracked_changes_fail_closed() {
        assert!(require_no_tracked_changes(b"").is_ok());
        assert!(require_no_tracked_changes(b" M AGENTS.md\n").is_err());
    }

    #[test]
    fn wrong_release_plz_version_fails_closed() {
        assert!(require_release_plz_version(b"release-plz 0.3.160\n", "0.3.160").is_ok());
        assert!(require_release_plz_version(b"release-plz 0.3.159\n", "0.3.160").is_err());
    }

    #[test]
    fn ref_or_head_mutation_fails_closed() {
        let head = "a".repeat(40);
        assert!(require_unchanged_source_state("current", b"refs", b"refs", &head, &head).is_ok());
        assert!(
            require_unchanged_source_state("current", b"refs", b"changed", &head, &head).is_err()
        );
        assert!(
            require_unchanged_source_state("current", b"refs", b"refs", &head, &"b".repeat(40))
                .is_err()
        );
    }

    #[test]
    fn release_plz_command_is_dry_run_and_strips_publish_credentials() {
        let temporary = tempfile::tempdir().unwrap();
        let value = manifest();
        let config = temporary.path().join("publication.toml");
        let command = release_plz_command(temporary.path(), &value, &config, "test-forge-token");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "release",
                "--dry-run",
                "--forge",
                "github",
                "--repo-url",
                "https://github.com/NVIDIA/yaml-sigil-traits",
                "--config",
                &config.display().to_string(),
                "--manifest-path",
                "Cargo.toml",
            ]
        );
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|item| item.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(environment["GIT_CONFIG_COUNT"].as_deref(), Some("1"));
        assert_eq!(
            environment["GIT_CONFIG_KEY_0"].as_deref(),
            Some("remote.origin.pushurl")
        );
        assert_eq!(
            environment["GIT_CONFIG_VALUE_0"].as_deref(),
            Some("disabled://yaml-sigil-local-validation")
        );
        assert_eq!(
            environment["GIT_TOKEN"].as_deref(),
            Some("test-forge-token")
        );
        for removed in [
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        ] {
            assert_eq!(environment.get(removed), Some(&None));
        }
    }
}

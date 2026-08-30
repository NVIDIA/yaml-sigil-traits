// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verify or recover annotated tags and source-only GitHub Releases.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::Builder;
use toml_edit::DocumentMut;

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::crate_archive::{
    CratesIo, Registry, inspect_archive_entries, require_archive, require_clean_source,
};
use crate::github::consts::{APP_EMAIL, APP_ID, APP_LOGIN, RepositoryKind};
use crate::github::identity::token_signature;
use crate::github::models::{GitObject, GitRef, Signature};
use crate::github::release_train::{
    ReleaseObjectIntent, ReleaseObjectPackageIntent, release_object_intent,
};
use crate::github::transport::{Transport, percent_encode};
use crate::github::{ReconcileMode, git_line, is_sha, repository_policy_for_root};
use crate::release_policy::{PackagePolicy, ReleasePolicy, detect};
use crate::safe_file;

pub(super) fn reconcile_command(
    root: &Path,
    mode: ReconcileMode,
    repository: &str,
    version: &str,
    commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    if !is_sha(commit) {
        return Err("release object mode, repository, or commit is unsupported".to_string());
    }
    parse_version(version)?;
    let repository_policy = repository_policy_for_root(root, repository)?;
    let release_policy = detect(root)?;
    require_clean_source(root, commit)?;
    if manifest_version(root, repository_policy.kind)? != version {
        return Err("release source manifest version is unexpected".to_string());
    }
    require_main(github, repository, commit)?;
    let identity = token_identity(root, github)?;
    let specs = release_specs(root, release_policy, version)?;
    let attestation = if mode == ReconcileMode::Recover {
        let intent = release_object_intent(github, repository, commit)?;
        intent.require_specs(repository, commit, &specs)?;
        Some(intent)
    } else {
        None
    };
    let mut registry = CratesIo::new();
    reconcile(
        root,
        github,
        &mut registry,
        repository,
        &specs,
        commit,
        mode.as_str(),
        &identity,
        attestation.as_ref(),
    )?;
    eprintln!(
        "github: release objects passed {} reconciliation for {version}",
        mode.as_str()
    );
    Ok(())
}

#[derive(Debug)]
struct TokenIdentity {
    signature: Signature,
}

fn token_identity(root: &Path, github: &mut impl Transport) -> Result<TokenIdentity, String> {
    let signature = token_signature(github)?;
    if signature.name != APP_LOGIN
        || signature.email != APP_EMAIL
        || git_line(root, &["config", "--local", "user.name"])? != signature.name
        || git_line(root, &["config", "--local", "user.email"])? != signature.email
    {
        return Err(
            "release-object recovery identity is not the configured Release App".to_string(),
        );
    }
    Ok(TokenIdentity { signature })
}

#[derive(Clone, Debug)]
pub(super) struct ReleaseSpec<'a> {
    pub(super) policy: &'a PackagePolicy,
    pub(super) version: String,
    pub(super) tag: String,
    pub(super) body: String,
    pub(super) prerelease: bool,
}

impl ReleaseSpec<'_> {
    fn tag_message(&self) -> String {
        format!(
            "chore: Release package {} version {}",
            self.policy.package, self.version
        )
    }
}

pub(super) fn release_specs<'a>(
    root: &Path,
    policy: &'a ReleasePolicy,
    version: &str,
) -> Result<Vec<ReleaseSpec<'a>>, String> {
    let prerelease = !parse_version(version)?.pre.is_empty();
    policy
        .packages
        .iter()
        .map(|package| {
            Ok(ReleaseSpec {
                policy: package,
                version: version.to_string(),
                tag: package.tag(version),
                body: changelog_body(&root.join(package.changelog), version)?,
                prerelease,
            })
        })
        .collect()
}

fn changelog_body(path: &Path, version: &str) -> Result<String, String> {
    let body = fs::read_to_string(path)
        .map_err(|error| format!("read release changelog {}: {error}", path.display()))?;
    let lines: Vec<_> = body.lines().collect();
    let matches: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| release_heading(line, version))
        .map(|(index, _)| index)
        .collect();
    if matches.len() != 1 {
        return Err(format!(
            "changelog {} does not contain one exact {version} release",
            path.display()
        ));
    }
    let start = matches[0] + 1;
    let end = (start..lines.len())
        .find(|index| lines[*index].starts_with("## "))
        .unwrap_or(lines.len());
    let release = lines[start..end].join("\n").trim().to_string();
    if release.is_empty() {
        return Err(format!("changelog {} has an empty release", path.display()));
    }
    Ok(release)
}

fn release_heading(line: &str, version: &str) -> bool {
    let prefix = format!("## [{version}]");
    let Some(rest) = line.strip_prefix(&prefix) else {
        return false;
    };
    let date = if let Some(rest) = rest.strip_prefix(" - ") {
        rest
    } else if let Some(link) = rest.strip_prefix('(') {
        let Some((_, date)) = link.split_once(") - ") else {
            return false;
        };
        date
    } else {
        return false;
    };
    valid_date(date)
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().unwrap_or_default();
    let month = value[5..7].parse::<u32>().unwrap_or_default();
    let day = value[8..10].parse::<u32>().unwrap_or_default();
    year >= 2000 && (1..=12).contains(&month) && (1..=31).contains(&day)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectState {
    tag: bool,
    release: bool,
}

#[allow(clippy::too_many_arguments)]
fn reconcile(
    root: &Path,
    github: &mut impl Transport,
    registry: &mut impl Registry,
    repository: &str,
    specs: &[ReleaseSpec<'_>],
    commit: &str,
    mode: &str,
    identity: &TokenIdentity,
    attestation: Option<&ReleaseObjectIntent>,
) -> Result<(), String> {
    let states = inspect_objects(github, repository, specs, commit, identity, attestation)?;
    if mode == "prepublish" {
        require_prepublish_state(root, registry, specs, &states, commit)?;
        require_main(github, repository, commit)?;
        return Ok(());
    }

    let attestation =
        attestation.ok_or_else(|| "release-object recovery lacks an App intent".to_string())?;
    let checksums = require_registry_publication(root, registry, specs, commit)?;
    for (spec, state) in specs.iter().zip(&states) {
        if !state.tag {
            require_main(github, repository, commit)?;
            create_tag(github, repository, spec, commit, identity, attestation)?;
            require_main(github, repository, commit)?;
        }
    }
    for (spec, state) in specs.iter().zip(&states) {
        if !state.release {
            require_main(github, repository, commit)?;
            attestation.revalidate(github, repository)?;
            create_release(github, repository, spec, commit)?;
            if !inspect_tag(
                github,
                repository,
                spec,
                commit,
                identity,
                Some(attestation.package(spec.policy.package)?),
            )? {
                return Err(format!(
                    "annotated tag {} disappeared during Release creation",
                    spec.tag
                ));
            }
            require_main(github, repository, commit)?;
        }
    }
    let final_state = inspect_objects(
        github,
        repository,
        specs,
        commit,
        identity,
        Some(attestation),
    )?;
    if final_state.iter().any(|state| !state.tag || !state.release) {
        return Err("official release objects remain incomplete".to_string());
    }
    recheck_registry(registry, specs, &checksums)?;
    Ok(())
}

fn require_prepublish_state(
    root: &Path,
    registry: &mut impl Registry,
    specs: &[ReleaseSpec<'_>],
    states: &[ObjectState],
    commit: &str,
) -> Result<(), String> {
    if specs.len() != states.len() {
        return Err("release object inventory is incomplete".to_string());
    }
    let mut missing_seen = false;
    for (spec, state) in specs.iter().zip(states) {
        let record = registry.exact_version(spec.policy.package, &spec.version)?;
        if record.is_none() {
            missing_seen = true;
            if state.tag || state.release {
                return Err(format!(
                    "unpublished crate {} already has official release objects",
                    spec.policy.package
                ));
            }
            continue;
        }
        if missing_seen {
            return Err(
                "published crates do not form the exact dependency-order prefix".to_string(),
            );
        }
        require_reproduced_archive(root, registry, spec, commit)?;
    }
    Ok(())
}

fn require_registry_publication(
    root: &Path,
    registry: &mut impl Registry,
    specs: &[ReleaseSpec<'_>],
    commit: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut checksums = BTreeMap::new();
    for spec in specs {
        let checksum = require_reproduced_archive(root, registry, spec, commit)?;
        checksums.insert(spec.policy.package.to_string(), checksum);
    }
    Ok(checksums)
}

pub(super) fn require_reproduced_archive(
    root: &Path,
    registry: &mut impl Registry,
    spec: &ReleaseSpec<'_>,
    commit: &str,
) -> Result<String, String> {
    let (checksum, published_archive, published) =
        require_archive(registry, spec.policy, &spec.version, commit)?;
    let archive = package_source(root, spec)?;
    let reproduced = inspect_archive_entries(&archive, spec.policy, &spec.version, commit)?;
    require_matching_archive_entries(&published, &reproduced, spec)?;
    if published_archive != archive {
        return Err(format!(
            "complete compressed archive differs from published {} {}",
            spec.policy.package, spec.version
        ));
    }
    Ok(checksum)
}

fn require_matching_archive_entries<T: Eq>(
    published: &BTreeMap<String, T>,
    reproduced: &BTreeMap<String, T>,
    spec: &ReleaseSpec<'_>,
) -> Result<(), String> {
    if published != reproduced {
        if published.get("Cargo.lock") != reproduced.get("Cargo.lock") {
            return Err(format!(
                "exact Cargo.lock entry differs between published and reproduced {} {} archives",
                spec.policy.package, spec.version
            ));
        }
        return Err(format!(
            "local source content or Cargo archive metadata differs from {} {}",
            spec.policy.package, spec.version
        ));
    }
    Ok(())
}

pub(super) fn package_source(root: &Path, spec: &ReleaseSpec<'_>) -> Result<Vec<u8>, String> {
    let cargo = select_archive_cargo(
        env::var_os("YAML_SIGIL_ARCHIVE_CARGO"),
        env::var_os("CARGO"),
    );
    let mut version_command = Command::new(&cargo);
    version_command.current_dir(root).arg("--version");
    let version = bounded_process::output(&mut version_command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("read Cargo version: {error}"))?;
    let version_line = String::from_utf8_lossy(&version.stdout);
    if !version.status.success() || !version_line.starts_with("cargo 1.95.0 ") {
        return Err("source recovery requires exact Cargo 1.95.0".to_string());
    }
    let temporary = Builder::new()
        .prefix("yaml-sigil-release-source-")
        .tempdir()
        .map_err(|error| format!("create source-package directory: {error}"))?;
    let target = temporary.path().join("target");
    let mut package_command = Command::new(&cargo);
    package_command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args(["package", "--no-verify", "--package", spec.policy.package]);
    let output = bounded_process::output(&mut package_command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("package {}: {error}", spec.policy.package))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "Cargo could not reproduce {}: {detail}",
            spec.policy.package
        ));
    }
    let archive = target
        .join("package")
        .join(format!("{}-{}.crate", spec.policy.package, spec.version));
    let metadata = fs::metadata(&archive)
        .map_err(|error| format!("read reproduced archive metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > crate::crate_archive::MAX_CRATE_BYTES as u64 {
        return Err("Cargo reproduced archive is missing or oversized".to_string());
    }
    fs::read(&archive).map_err(|error| format!("read reproduced source archive: {error}"))
}

fn select_archive_cargo(archive: Option<OsString>, build: Option<OsString>) -> OsString {
    archive.or(build).unwrap_or_else(|| "cargo".into())
}

fn recheck_registry(
    registry: &mut impl Registry,
    specs: &[ReleaseSpec<'_>],
    checksums: &BTreeMap<String, String>,
) -> Result<(), String> {
    for spec in specs {
        let record = registry
            .exact_version(spec.policy.package, &spec.version)?
            .ok_or_else(|| format!("crates.io lost {} {}", spec.policy.package, spec.version))?;
        if record.num != spec.version
            || record.yanked
            || checksums.get(spec.policy.package) != Some(&record.checksum)
        {
            return Err(format!(
                "crates.io changed {} {} during recovery",
                spec.policy.package, spec.version
            ));
        }
    }
    Ok(())
}

fn inspect_objects(
    github: &mut impl Transport,
    repository: &str,
    specs: &[ReleaseSpec<'_>],
    commit: &str,
    identity: &TokenIdentity,
    attestation: Option<&ReleaseObjectIntent>,
) -> Result<Vec<ObjectState>, String> {
    specs
        .iter()
        .map(|spec| {
            Ok(ObjectState {
                tag: inspect_tag(
                    github,
                    repository,
                    spec,
                    commit,
                    identity,
                    attestation
                        .map(|intent| intent.package(spec.policy.package))
                        .transpose()?,
                )?,
                release: inspect_release(github, repository, spec, commit)?,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct AnnotatedTag {
    sha: String,
    tag: String,
    message: String,
    tagger: TaggerSignature,
    object: GitObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct TaggerSignature {
    name: String,
    email: String,
    date: String,
}

fn inspect_tag(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    identity: &TokenIdentity,
    attested: Option<&ReleaseObjectPackageIntent>,
) -> Result<bool, String> {
    let path = format!(
        "repos/{repository}/git/ref/tags/{}",
        percent_encode(&spec.tag)
    );
    let Some(reference): Option<GitRef> = github.get_optional(&path)? else {
        return Ok(false);
    };
    if reference.name != format!("refs/tags/{}", spec.tag)
        || reference.object.kind != "tag"
        || !is_sha(&reference.object.sha)
        || attested.is_some_and(|intent| reference.object.sha != intent.tag_object_id)
    {
        return Err(format!("tag ref {} is not exact and annotated", spec.tag));
    }
    let object: AnnotatedTag = github.get(&format!(
        "repos/{repository}/git/tags/{}",
        reference.object.sha
    ))?;
    validate_tag(
        &object,
        spec,
        commit,
        &reference.object.sha,
        identity,
        attested,
    )?;
    Ok(true)
}

fn validate_tag(
    object: &AnnotatedTag,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    object_sha: &str,
    identity: &TokenIdentity,
    attested: Option<&ReleaseObjectPackageIntent>,
) -> Result<(), String> {
    let identity_matches = if let Some(intent) = attested {
        object.sha == intent.tag_object_id
            && object.message == intent.tag_message
            && object.tagger.name == APP_LOGIN
            && object.tagger.email == APP_EMAIL
            && object.tagger.date == intent.tagger_date
    } else {
        object.message == spec.tag_message()
            && object.tagger.name == identity.signature.name
            && object.tagger.email == identity.signature.email
    };
    if object.sha != object_sha
        || object.tag != spec.tag
        || object.object.kind != "commit"
        || object.object.sha != commit
        || !identity_matches
    {
        return Err(format!("annotated tag {} has conflicting state", spec.tag));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    target_commitish: String,
    name: String,
    body: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    author: ReleaseAuthor,
    assets: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAuthor {
    login: String,
    id: u64,
    #[serde(rename = "type")]
    kind: String,
}

fn inspect_release(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
) -> Result<bool, String> {
    let path = format!(
        "repos/{repository}/releases/tags/{}",
        percent_encode(&spec.tag)
    );
    let Some(release): Option<Release> = github.get_optional(&path)? else {
        return Ok(false);
    };
    validate_release(&release, spec, commit)?;
    Ok(true)
}

fn validate_release(release: &Release, spec: &ReleaseSpec<'_>, commit: &str) -> Result<(), String> {
    if release.id == 0
        || release.tag_name != spec.tag
        || release.name != spec.tag
        || release.body != spec.body
        || release.draft
        || release.prerelease != spec.prerelease
        || !release.immutable
        || release.author.login != APP_LOGIN
        || release.author.id != APP_ID
        || release.author.kind != "Bot"
        || !release.assets.is_empty()
        || release.target_commitish != commit
    {
        return Err(format!(
            "GitHub Release {} is not exact, immutable, and App-authored",
            spec.tag
        ));
    }
    Ok(())
}

fn create_tag(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    identity: &TokenIdentity,
    attestation: &ReleaseObjectIntent,
) -> Result<(), String> {
    let attested = attestation.package(spec.policy.package)?;
    if inspect_tag(github, repository, spec, commit, identity, Some(attested))? {
        return Err(format!(
            "annotated tag {} appeared before creation",
            spec.tag
        ));
    }
    let object_path = format!("repos/{repository}/git/tags/{}", attested.tag_object_id);
    if let Some(object) = github.get_optional::<AnnotatedTag>(&object_path)? {
        validate_tag(
            &object,
            spec,
            commit,
            &attested.tag_object_id,
            identity,
            Some(attested),
        )?;
    } else {
        attestation.revalidate(github, repository)?;
        create_attested_tag_object(github, repository, spec, commit, identity, attested)?;
    }
    attestation.revalidate(github, repository)?;
    let mutation: Result<GitRef, String> = github.mutate(
        "POST",
        &format!("repos/{repository}/git/refs"),
        &json!({
            "ref": format!("refs/tags/{}", spec.tag),
            "sha": attested.tag_object_id,
        }),
    );
    if mutation.is_err()
        && !inspect_tag(github, repository, spec, commit, identity, Some(attested))?
    {
        return Err(mutation.expect_err("checked tag-ref error"));
    }
    if !inspect_tag(github, repository, spec, commit, identity, Some(attested))? {
        return Err(format!(
            "GitHub did not retain exact annotated tag {}",
            spec.tag
        ));
    }
    Ok(())
}

fn create_attested_tag_object(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    identity: &TokenIdentity,
    attested: &ReleaseObjectPackageIntent,
) -> Result<(), String> {
    let object_path = format!("repos/{repository}/git/tags/{}", attested.tag_object_id);
    let mutation: Result<AnnotatedTag, String> = github.mutate(
        "POST",
        &format!("repos/{repository}/git/tags"),
        &json!({
            "tag": spec.tag,
            "message": attested.tag_message,
            "object": commit,
            "type": "commit",
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": attested.tagger_date,
            },
        }),
    );
    let object = match mutation {
        Ok(object) => object,
        Err(error) => github
            .get_optional::<AnnotatedTag>(&object_path)?
            .ok_or(error)?,
    };
    validate_tag(
        &object,
        spec,
        commit,
        &attested.tag_object_id,
        identity,
        Some(attested),
    )?;
    let readback: AnnotatedTag = github.get(&object_path)?;
    validate_tag(
        &readback,
        spec,
        commit,
        &attested.tag_object_id,
        identity,
        Some(attested),
    )
}

fn create_release(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
) -> Result<(), String> {
    if inspect_release(github, repository, spec, commit)? {
        return Err(format!(
            "GitHub Release {} appeared before creation",
            spec.tag
        ));
    }
    let mutation: Result<Release, String> = github.mutate(
        "POST",
        &format!("repos/{repository}/releases"),
        &json!({
            "tag_name": spec.tag,
            "target_commitish": commit,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": spec.prerelease,
        }),
    );
    match mutation {
        Ok(release) => validate_release(&release, spec, commit)?,
        Err(error) => {
            if !inspect_release(github, repository, spec, commit)? {
                return Err(error);
            }
        }
    }
    if !inspect_release(github, repository, spec, commit)? {
        return Err(format!(
            "GitHub did not retain exact source-only Release {}",
            spec.tag
        ));
    }
    Ok(())
}

fn require_main(github: &mut impl Transport, repository: &str, commit: &str) -> Result<(), String> {
    let reference: GitRef = github.get(&format!("repos/{repository}/git/ref/heads/main"))?;
    if reference.name != "refs/heads/main"
        || reference.object.kind != "commit"
        || reference.object.sha != commit
    {
        return Err("protected main changed during release-object reconciliation".to_string());
    }
    Ok(())
}

pub(super) fn manifest_version(root: &Path, kind: RepositoryKind) -> Result<String, String> {
    let body = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .map_err(|error| format!("read release manifest: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse release manifest: {error}"))?;
    let value = match kind {
        RepositoryKind::Traits => document
            .get("package")
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
        RepositoryKind::RustWorkspace => document
            .get("workspace")
            .and_then(|item| item.get("package"))
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
    }
    .ok_or_else(|| "release manifest has no exact version".to_string())?;
    parse_version(value)?;
    Ok(value.to_string())
}

pub(super) fn parse_version(value: &str) -> Result<Version, String> {
    let version = Version::parse(value)
        .map_err(|error| format!("unsupported release version {value}: {error}"))?;
    if !version.build.is_empty() {
        return Err("release version contains build metadata".to_string());
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::crate_archive::RegistryVersion;
    use crate::github::consts::{APP_EMAIL, APP_ID, APP_LOGIN, TRAITS_REPOSITORY};
    use crate::github::transport::fake::{Expected, FakeTransport};

    #[test]
    fn changelog_body_is_exact_and_nonempty() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("CHANGELOG.md");
        fs::write(
            &path,
            "# Changelog\n\n## [0.4.0](https://example.invalid/v0.4.0) - 2026-08-25\n\n- Fixed.\n\n## [0.3.0] - 2026-08-01\n\n- Older.\n",
        )
        .unwrap();
        assert_eq!(changelog_body(&path, "0.4.0").unwrap(), "- Fixed.");
        assert!(changelog_body(&path, "0.5.0").is_err());
    }

    #[test]
    fn release_heading_requires_an_exact_date() {
        assert!(release_heading("## [0.4.0] - 2026-08-25", "0.4.0"));
        assert!(!release_heading("## [0.4.0] - someday", "0.4.0"));
    }

    #[test]
    fn release_object_identity_uses_the_graphql_viewer() {
        let root = tempfile::tempdir().unwrap();
        crate::github::git_output(root.path(), &["init", "--quiet"]).unwrap();
        crate::github::git_output(root.path(), &["config", "--local", "user.name", APP_LOGIN])
            .unwrap();
        crate::github::git_output(root.path(), &["config", "--local", "user.email", APP_EMAIL])
            .unwrap();
        let payload = json!({
            "query": "query { viewer { name login databaseId } }",
        });
        let response = json!({
            "data": {
                "viewer": {
                    "login": APP_LOGIN,
                    "databaseId": APP_ID,
                    "name": null,
                }
            }
        });
        let mut github = FakeTransport::new([Expected::mutation(
            "GRAPHQL",
            "graphql",
            payload,
            Ok(response),
        )]);

        let identity = token_identity(root.path(), &mut github).unwrap();

        assert_eq!(identity.signature.name, APP_LOGIN);
        assert_eq!(identity.signature.email, APP_EMAIL);
        github.finish();
    }

    #[test]
    fn releases_reject_assets_and_review_state_drift() {
        let policy = &crate::release_policy::TRAITS_POLICY.packages[0];
        let spec = ReleaseSpec {
            policy,
            version: "0.4.0".to_string(),
            tag: "v0.4.0".to_string(),
            body: "notes".to_string(),
            prerelease: false,
        };
        let mut release = Release {
            id: 100,
            tag_name: spec.tag.clone(),
            target_commitish: "a".repeat(40),
            name: spec.tag.clone(),
            body: spec.body.clone(),
            draft: false,
            prerelease: false,
            immutable: true,
            author: ReleaseAuthor {
                login: APP_LOGIN.to_string(),
                id: APP_ID,
                kind: "Bot".to_string(),
            },
            assets: vec![],
        };
        let commit = "a".repeat(40);
        assert!(validate_release(&release, &spec, &commit).is_ok());
        release.assets.push(json!({"name": "binary"}));
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.assets.clear();
        release.target_commitish = "main".to_string();
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.target_commitish = commit.clone();
        release.immutable = false;
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.immutable = true;
        release.id = 0;
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.id = 100;
        release.author.id += 1;
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.author.id = APP_ID;
        release.author.login = "writer".to_string();
        assert!(validate_release(&release, &spec, &commit).is_err());
        release.author.login = APP_LOGIN.to_string();
        release.author.kind = "User".to_string();
        assert!(validate_release(&release, &spec, &commit).is_err());
    }

    #[test]
    fn uncertain_release_creation_is_resolved_by_exact_reread() {
        let commit = "a".repeat(40);
        let spec = ReleaseSpec {
            policy: &crate::release_policy::TRAITS_POLICY.packages[0],
            version: "0.4.0".to_string(),
            tag: "v0.4.0".to_string(),
            body: "- Fixed.".to_string(),
            prerelease: false,
        };
        let path = format!(
            "repos/{TRAITS_REPOSITORY}/releases/tags/{}",
            percent_encode(&spec.tag)
        );
        let payload = json!({
            "tag_name": spec.tag,
            "target_commitish": commit,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": false,
        });
        let exact = json!({
            "id": 100,
            "tag_name": spec.tag,
            "target_commitish": commit,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": false,
            "immutable": true,
            "author": {"login": APP_LOGIN, "id": APP_ID, "type": "Bot"},
            "assets": [],
        });
        let mut github = FakeTransport::new([
            Expected::missing(&path),
            Expected::mutation(
                "POST",
                &format!("repos/{TRAITS_REPOSITORY}/releases"),
                payload,
                Err("connection lost"),
            ),
            Expected::optional(&path, exact.clone()),
            Expected::optional(&path, exact),
        ]);
        assert!(create_release(&mut github, TRAITS_REPOSITORY, &spec, &commit).is_ok());
        github.finish();
    }

    #[test]
    fn missing_attested_tag_object_is_created_and_reread_exactly() {
        let commit = "a".repeat(40);
        let object_id = "b".repeat(40);
        let spec = ReleaseSpec {
            policy: &crate::release_policy::TRAITS_POLICY.packages[0],
            version: "0.4.0".to_string(),
            tag: "v0.4.0".to_string(),
            body: "- Fixed.".to_string(),
            prerelease: false,
        };
        let attested = ReleaseObjectPackageIntent {
            package: spec.policy.package.to_string(),
            version: spec.version.clone(),
            tag: spec.tag.clone(),
            prerelease: spec.prerelease,
            release_body: spec.body.clone(),
            tag_object_id: object_id.clone(),
            tag_message: spec.tag_message(),
            tagger_date: "2026-08-29T00:00:00+00:00".to_string(),
        };
        let identity = TokenIdentity {
            signature: Signature {
                name: APP_LOGIN.to_string(),
                email: APP_EMAIL.to_string(),
            },
        };
        let payload = json!({
            "tag": spec.tag,
            "message": attested.tag_message,
            "object": commit,
            "type": "commit",
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": attested.tagger_date,
            },
        });
        let object = json!({
            "sha": object_id,
            "tag": spec.tag,
            "message": attested.tag_message,
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": attested.tagger_date,
            },
            "object": {"type": "commit", "sha": commit},
        });
        let object_path = format!("repos/{TRAITS_REPOSITORY}/git/tags/{object_id}");
        let mut github = FakeTransport::new([
            Expected::mutation(
                "POST",
                &format!("repos/{TRAITS_REPOSITORY}/git/tags"),
                payload,
                Ok(object.clone()),
            ),
            Expected::json("GET", &object_path, object),
        ]);
        create_attested_tag_object(
            &mut github,
            TRAITS_REPOSITORY,
            &spec,
            &commit,
            &identity,
            &attested,
        )
        .unwrap();
        github.finish();
    }

    #[test]
    fn release_family_type_remains_provider_neutral() {
        assert_eq!(
            crate::release_policy::TRAITS_POLICY.family,
            crate::release_policy::ReleaseFamily::Traits
        );
    }

    #[derive(Default)]
    struct FakeRegistry {
        versions: BTreeMap<String, Option<RegistryVersion>>,
    }

    impl Registry for FakeRegistry {
        fn exact_version(
            &mut self,
            package: &str,
            _version: &str,
        ) -> Result<Option<RegistryVersion>, String> {
            Ok(self.versions.get(package).cloned().flatten())
        }

        fn download(&mut self, _package: &str, _version: &str) -> Result<Vec<u8>, String> {
            Err("unexpected archive download".to_string())
        }
    }

    fn spec(policy: &'static PackagePolicy) -> ReleaseSpec<'static> {
        ReleaseSpec {
            policy,
            version: "0.4.0".to_string(),
            tag: policy.tag("0.4.0"),
            body: "- Fixed.".to_string(),
            prerelease: false,
        }
    }

    #[test]
    fn prepublish_rejects_objects_ahead_of_registry_and_nonprefix_state() {
        let traits = vec![spec(&crate::release_policy::TRAITS_POLICY.packages[0])];
        let mut registry = FakeRegistry::default();
        assert!(
            require_prepublish_state(
                Path::new("."),
                &mut registry,
                &traits,
                &[ObjectState {
                    tag: true,
                    release: false,
                }],
                &"a".repeat(40),
            )
            .is_err()
        );

        let policies = &crate::release_policy::RUST_POLICY.packages[..2];
        let specs: Vec<_> = policies.iter().map(spec).collect();
        registry.versions.insert(
            policies[1].package.to_string(),
            Some(RegistryVersion {
                num: "0.4.0".to_string(),
                yanked: false,
                checksum: "a".repeat(64),
            }),
        );
        assert!(
            require_prepublish_state(
                Path::new("."),
                &mut registry,
                &specs,
                &[
                    ObjectState {
                        tag: false,
                        release: false,
                    },
                    ObjectState {
                        tag: false,
                        release: false,
                    },
                ],
                &"a".repeat(40),
            )
            .is_err()
        );
    }

    #[test]
    fn published_archive_comparison_includes_generated_cargo_lock() {
        let release = spec(&crate::release_policy::TRAITS_POLICY.packages[0]);
        let published = BTreeMap::from([
            ("Cargo.lock".to_string(), b"published lock".to_vec()),
            ("Cargo.toml".to_string(), b"manifest".to_vec()),
        ]);
        let mut reproduced = published.clone();
        assert!(require_matching_archive_entries(&published, &reproduced, &release).is_ok());

        reproduced.insert("Cargo.lock".to_string(), b"different lock".to_vec());
        let error =
            require_matching_archive_entries(&published, &reproduced, &release).unwrap_err();
        assert!(error.contains("exact Cargo.lock entry differs"));
    }

    #[test]
    fn archive_cargo_is_independent_from_the_trusted_build_toolchain() {
        assert_eq!(
            select_archive_cargo(Some("archive-cargo".into()), Some("build-cargo".into())),
            OsString::from("archive-cargo")
        );
        assert_eq!(
            select_archive_cargo(None, Some("build-cargo".into())),
            OsString::from("build-cargo")
        );
    }
}

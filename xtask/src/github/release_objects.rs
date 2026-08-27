// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verify or recover annotated tags and source-only GitHub Releases.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::Builder;
use toml_edit::DocumentMut;

use crate::crate_archive::{CratesIo, Registry, require_archive, require_clean_source};
use crate::github::consts::RepositoryKind;
use crate::github::identity::token_signature;
use crate::github::models::{GitObject, GitRef, Signature};
use crate::github::transport::{Transport, percent_encode};
use crate::github::{ReconcileMode, git_line, is_sha, repository_policy_for_root};
use crate::release_policy::{PackagePolicy, ReleasePolicy, detect};

const MAX_COMMAND_OUTPUT: usize = 4 * 1024 * 1024;

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
    if git_line(root, &["config", "--local", "user.name"])? != signature.name
        || git_line(root, &["config", "--local", "user.email"])? != signature.email
    {
        return Err("local release identity is not bound to the current GitHub token".to_string());
    }
    Ok(TokenIdentity { signature })
}

#[derive(Clone, Debug)]
struct ReleaseSpec<'a> {
    policy: &'a PackagePolicy,
    version: String,
    tag: String,
    body: String,
    prerelease: bool,
}

impl ReleaseSpec<'_> {
    fn tag_message(&self) -> String {
        format!(
            "chore: Release package {} version {}",
            self.policy.package, self.version
        )
    }
}

fn release_specs<'a>(
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
) -> Result<(), String> {
    let states = inspect_objects(github, repository, specs, commit, identity)?;
    if mode == "prepublish" {
        require_prepublish_state(root, registry, specs, &states, commit)?;
        require_main(github, repository, commit)?;
        return Ok(());
    }

    let checksums = require_registry_publication(root, registry, specs, commit)?;
    for (spec, state) in specs.iter().zip(&states) {
        if !state.tag {
            require_main(github, repository, commit)?;
            create_tag(github, repository, spec, commit, identity)?;
            require_main(github, repository, commit)?;
        }
    }
    for (spec, state) in specs.iter().zip(&states) {
        if !state.release {
            require_main(github, repository, commit)?;
            create_release(github, repository, spec, commit)?;
            require_main(github, repository, commit)?;
        }
    }
    let final_state = inspect_objects(github, repository, specs, commit, identity)?;
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

fn require_reproduced_archive(
    root: &Path,
    registry: &mut impl Registry,
    spec: &ReleaseSpec<'_>,
    commit: &str,
) -> Result<String, String> {
    let (checksum, mut published) = require_archive(registry, spec.policy, &spec.version, commit)?;
    let archive = package_source(root, spec)?;
    let mut reproduced =
        crate::crate_archive::inspect_archive(&archive, spec.policy, &spec.version, commit)?;
    require_generated_lock(&published, spec)?;
    require_generated_lock(&reproduced, spec)?;
    published.remove("Cargo.lock");
    reproduced.remove("Cargo.lock");
    if published != reproduced {
        return Err(format!(
            "local source content differs from {} {}",
            spec.policy.package, spec.version
        ));
    }
    Ok(checksum)
}

fn package_source(root: &Path, spec: &ReleaseSpec<'_>) -> Result<Vec<u8>, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let version = Command::new(&cargo)
        .current_dir(root)
        .arg("--version")
        .output()
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
    let output = Command::new(&cargo)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target)
        .args(["package", "--no-verify", "--package", spec.policy.package])
        .output()
        .map_err(|error| format!("package {}: {error}", spec.policy.package))?;
    if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
        return Err("Cargo package output exceeded its bound".to_string());
    }
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

fn require_generated_lock(
    files: &BTreeMap<String, Vec<u8>>,
    spec: &ReleaseSpec<'_>,
) -> Result<(), String> {
    let lock = files.get("Cargo.lock").ok_or_else(|| {
        format!(
            "{} source package lacks generated Cargo.lock",
            spec.policy.package
        )
    })?;
    let body = std::str::from_utf8(lock).map_err(|_| {
        format!(
            "{} source package has non-UTF-8 Cargo.lock",
            spec.policy.package
        )
    })?;
    let document = body.parse::<DocumentMut>().map_err(|error| {
        format!(
            "{} source package has invalid Cargo.lock: {error}",
            spec.policy.package
        )
    })?;
    let packages = document
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(|| {
            format!(
                "{} source package has no lock packages",
                spec.policy.package
            )
        })?;
    let matches: Vec<_> = packages
        .iter()
        .filter(|package| {
            package.get("name").and_then(toml_edit::Item::as_str) == Some(spec.policy.package)
                && package.get("version").and_then(toml_edit::Item::as_str)
                    == Some(spec.version.as_str())
        })
        .collect();
    if matches.len() != 1
        || matches[0].contains_key("source")
        || matches[0].contains_key("checksum")
    {
        return Err(format!(
            "{} source package has an unbound generated Cargo.lock",
            spec.policy.package
        ));
    }
    Ok(())
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
) -> Result<Vec<ObjectState>, String> {
    specs
        .iter()
        .map(|spec| {
            Ok(ObjectState {
                tag: inspect_tag(github, repository, spec, commit, identity)?,
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
    tagger: Signature,
    object: GitObject,
}

fn inspect_tag(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    identity: &TokenIdentity,
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
    {
        return Err(format!("tag ref {} is not exact and annotated", spec.tag));
    }
    let object: AnnotatedTag = github.get(&format!(
        "repos/{repository}/git/tags/{}",
        reference.object.sha
    ))?;
    validate_tag(&object, spec, commit, &reference.object.sha, identity)?;
    Ok(true)
}

fn validate_tag(
    object: &AnnotatedTag,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    object_sha: &str,
    identity: &TokenIdentity,
) -> Result<(), String> {
    if object.sha != object_sha
        || object.tag != spec.tag
        || object.message != spec.tag_message()
        || object.object.kind != "commit"
        || object.object.sha != commit
        || object.tagger != identity.signature
    {
        return Err(format!("annotated tag {} has conflicting state", spec.tag));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct Release {
    tag_name: String,
    target_commitish: String,
    name: String,
    body: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Value>,
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
    if release.tag_name != spec.tag
        || release.name != spec.tag
        || release.body != spec.body
        || release.draft
        || release.prerelease != spec.prerelease
        || !release.assets.is_empty()
        || (release.target_commitish != commit && release.target_commitish != "main")
    {
        return Err(format!("GitHub Release {} has conflicting state", spec.tag));
    }
    Ok(())
}

fn create_tag(
    github: &mut impl Transport,
    repository: &str,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    identity: &TokenIdentity,
) -> Result<(), String> {
    if inspect_tag(github, repository, spec, commit, identity)? {
        return Err(format!(
            "annotated tag {} appeared before creation",
            spec.tag
        ));
    }
    let object: AnnotatedTag = github.mutate(
        "POST",
        &format!("repos/{repository}/git/tags"),
        &json!({
            "tag": spec.tag,
            "message": spec.tag_message(),
            "object": commit,
            "type": "commit",
            "tagger": {
                "name": identity.signature.name,
                "email": identity.signature.email,
            },
        }),
    )?;
    if !is_sha(&object.sha) {
        return Err(format!(
            "GitHub did not create an exact tag object for {}",
            spec.tag
        ));
    }
    validate_tag(&object, spec, commit, &object.sha, identity)?;
    let mutation: Result<GitRef, String> = github.mutate(
        "POST",
        &format!("repos/{repository}/git/refs"),
        &json!({"ref": format!("refs/tags/{}", spec.tag), "sha": object.sha}),
    );
    if mutation.is_err() && !inspect_tag(github, repository, spec, commit, identity)? {
        return Err(mutation.expect_err("checked tag-ref error"));
    }
    if !inspect_tag(github, repository, spec, commit, identity)? {
        return Err(format!(
            "GitHub did not retain exact annotated tag {}",
            spec.tag
        ));
    }
    Ok(())
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

fn manifest_version(root: &Path, kind: RepositoryKind) -> Result<String, String> {
    let body = fs::read_to_string(root.join("Cargo.toml"))
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

fn parse_version(value: &str) -> Result<Version, String> {
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
            tag_name: spec.tag.clone(),
            target_commitish: "a".repeat(40),
            name: spec.tag.clone(),
            body: spec.body.clone(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let commit = "a".repeat(40);
        assert!(validate_release(&release, &spec, &commit).is_ok());
        release.assets.push(json!({"name": "binary"}));
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
            "tag_name": spec.tag,
            "target_commitish": commit,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": false,
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
}

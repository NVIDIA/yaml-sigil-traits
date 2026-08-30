// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Captured release plans, durable App intent, and source-only finalization.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::crate_archive::{CratesIo, Registry, archive_inventory_sha256};
use crate::github::consts::{APP_EMAIL, APP_ID, APP_LOGIN, APP_SLUG};
use crate::github::release_objects::{
    ReleaseSpec, manifest_version, package_source, release_specs, require_reproduced_archive,
};
use crate::github::source::{SourceAuthorization, authorize_source};
use crate::github::transport::{Transport, percent_encode};
use crate::github::{
    append_outputs, git_output, is_positive_integer, is_sha, repository_policy_for_root,
};
use crate::release_policy::detect;
use crate::safe_file::TrustedRoot;

const PLAN_SCHEMA: u64 = 1;
const INTENT_SCHEMA: u64 = 1;
const NOTIFICATION_SCHEMA: u64 = 1;
const MAX_PLAN_BYTES: usize = 48 * 1024;
const MAX_INTENT_BYTES: usize = 64 * 1024;
const MAX_NOTIFICATION_BYTES: usize = 8 * 1024;
const MAX_RELEASE_PACKAGES: usize = 8;
const MAX_RELEASE_BODY_BYTES: usize = 16 * 1024;
const REGISTRY_POLL_COUNT: usize = 60;
const REGISTRY_POLL_SECONDS: u64 = 20;
const APP_PUBLIC_ID: u64 = 4_653_064;
const INTENT_NAME: &str = "Release finalization intent";
const RELEASE_PLZ_VERSION: &str = "0.3.160";

pub(super) struct PrepareIntentInput<'a> {
    pub(super) plan: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) origin_run_id: &'a str,
    pub(super) origin_run_attempt: &'a str,
    pub(super) ruleset_evidence_sha256: &'a str,
}

pub(super) struct CreateIntentInput<'a> {
    pub(super) repository: &'a str,
    pub(super) plan: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) intent: &'a str,
    pub(super) expected_app_slug: &'a str,
    pub(super) expected_installation_id: &'a str,
}

pub(super) struct FinalizeInput<'a> {
    pub(super) repository: &'a str,
    pub(super) plan: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) intent: &'a str,
    pub(super) intent_check_id: &'a str,
    pub(super) expected_app_slug: &'a str,
    pub(super) expected_installation_id: &'a str,
}

pub(super) struct NotifyInput<'a> {
    pub(super) repository: &'a str,
    pub(super) plan: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) intent: &'a str,
    pub(super) intent_check_id: &'a str,
    pub(super) finalized_entries: &'a str,
    pub(super) expected_app_slug: &'a str,
    pub(super) expected_installation_id: &'a str,
}

pub(super) fn discover_command(
    root: &Path,
    repository: &str,
    current_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    if !is_sha(current_commit) {
        return Err("current release source must be one lowercase full SHA".to_string());
    }
    repository_policy_for_root(root, repository)?;
    let policy = detect(root)?;
    let version = manifest_version(
        root,
        crate::github::consts::repository_policy(repository)
            .ok_or_else(|| "release discovery repository lacks compiled policy".to_string())?
            .kind,
    )?;
    let specs = release_specs(root, policy, &version)?;
    let mut registry = CratesIo::new();
    let mut discovered = None;
    let mut present = 0usize;
    for spec in &specs {
        let Some(record) = registry.exact_version(spec.policy.package, &spec.version)? else {
            break;
        };
        if record.num != spec.version
            || record.yanked
            || !crate::crate_archive::is_checksum(&record.checksum)
        {
            return Err(format!(
                "{} registry state is not one exact non-yanked version",
                spec.policy.package
            ));
        }
        let archive = registry.download(spec.policy.package, &spec.version)?;
        if sha256(&archive) != record.checksum {
            return Err(format!(
                "{} registry archive checksum changed during discovery",
                spec.policy.package
            ));
        }
        let commit =
            crate::crate_archive::archive_vcs_commit(&archive, spec.policy, &spec.version)?;
        if discovered
            .as_ref()
            .is_some_and(|expected| expected != &commit)
        {
            return Err("published release prefix identifies multiple source commits".to_string());
        }
        discovered = Some(commit);
        present += 1;
    }
    for spec in specs.iter().skip(present) {
        if registry
            .exact_version(spec.policy.package, &spec.version)?
            .is_some()
        {
            return Err("registry packages do not form the release dependency prefix".to_string());
        }
    }
    let release_sha = discovered.unwrap_or_else(|| current_commit.to_string());
    require_captured_ancestry(github, repository, &release_sha)?;
    let state = if present == 0 {
        "absent"
    } else if present == specs.len() {
        "complete"
    } else {
        "partial"
    };
    append_outputs(&[
        ("captured_release_sha", &release_sha),
        ("registry_state", state),
    ])
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleasePlan {
    schema_version: u64,
    repository: String,
    release_sha: String,
    authorization: PlanAuthorization,
    release_plz_version: String,
    release_config_sha256: String,
    publish_workflow_sha256: String,
    proposal_workflow_sha256: String,
    tagger_epoch: u64,
    tagger_date: String,
    packages: Vec<PlanPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanAuthorization {
    pull_request: u64,
    proposal_commit: String,
    base_commit: String,
    owner_id: u64,
    merger_id: u64,
}

impl From<SourceAuthorization> for PlanAuthorization {
    fn from(value: SourceAuthorization) -> Self {
        Self {
            pull_request: value.pull_request,
            proposal_commit: value.proposal_commit,
            base_commit: value.base_commit,
            owner_id: value.owner_id,
            merger_id: value.merger_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanPackage {
    package: String,
    version: String,
    tag: String,
    prerelease: bool,
    source_archive_sha256: String,
    package_inventory_sha256: String,
    release_body: String,
    release_body_sha256: String,
    registry: RegistryBaseline,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryBaseline {
    state: RegistryState,
    checksum: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RegistryState {
    Absent,
    Present,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IntentRecord {
    schema_version: u64,
    repository: String,
    release_sha: String,
    plan_digest: String,
    external_id: String,
    origin_run_id: u64,
    origin_run_attempt: u64,
    ruleset_evidence_sha256: String,
    plan: ReleasePlan,
    tags: Vec<TagIntent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TagIntent {
    package: String,
    tag: String,
    tag_object_id: String,
    tag_message: String,
    release_body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinalizedEntry {
    package: String,
    version: String,
    release_id: u64,
    tag: String,
    tag_object_id: String,
    release_body_sha256: String,
}

pub(super) fn capture_command(
    root: &Path,
    repository: &str,
    commit: &str,
    baseline_version: &str,
    baseline_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    let mut registry = CratesIo::new();
    let observed = capture_plan(
        root,
        repository,
        commit,
        baseline_version,
        baseline_commit,
        github,
        &mut registry,
    )?;
    let recovered = recover_existing_intent(github, repository, &observed)?;
    if recovered.is_none() {
        require_new_train_objects_absent(github, repository, &observed)?;
    }
    let plan = if let Some((_, _, record)) = &recovered {
        require_static_plan_match(&record.plan, &observed)?;
        require_registry_transition(&record.plan, &observed)?;
        record.plan.clone()
    } else {
        observed.clone()
    };
    let (body, digest) = encode_plan(&plan)?;
    let registry_state = if observed
        .packages
        .iter()
        .all(|package| package.registry.state == RegistryState::Present)
    {
        "complete"
    } else if observed
        .packages
        .iter()
        .all(|package| package.registry.state == RegistryState::Absent)
    {
        "absent"
    } else {
        "partial"
    };
    let (existing_intent, existing_intent_check_id, existing_intent_digest) = recovered
        .as_ref()
        .map(|(check, body, _)| (body.as_str(), check.id.to_string(), sha256(body.as_bytes())))
        .unwrap_or(("", String::new(), String::new()));
    append_outputs(&[
        ("captured_release_sha", &plan.release_sha),
        ("plan", &body),
        ("plan_digest", &digest),
        ("registry_state", registry_state),
        ("existing_intent", existing_intent),
        ("existing_intent_check_id", &existing_intent_check_id),
        ("existing_intent_digest", &existing_intent_digest),
    ])
}

fn require_new_train_objects_absent(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
) -> Result<(), String> {
    for package in &plan.packages {
        let reference = github.get_optional::<crate::github::models::GitRef>(&format!(
            "repos/{repository}/git/ref/tags/{}",
            percent_encode(&package.tag)
        ))?;
        let release = github.get_optional::<Release>(&format!(
            "repos/{repository}/releases/tags/{}",
            percent_encode(&package.tag)
        ))?;
        if reference.is_some() || release.is_some() {
            return Err(format!(
                "new release train tag or Release {} already exists without App intent",
                package.tag
            ));
        }
    }
    Ok(())
}

fn recover_existing_intent(
    github: &mut impl Transport,
    repository: &str,
    observed: &ReleasePlan,
) -> Result<Option<(CheckRun, String, IntentRecord)>, String> {
    let path = format!(
        "repos/{repository}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
        observed.release_sha,
        percent_encode(INTENT_NAME)
    );
    let checks: CheckRuns = github.get(&path)?;
    if checks.total_count != checks.check_runs.len() as u64 || checks.total_count > 100 {
        return Err("intent Check inventory is incomplete or oversized".to_string());
    }
    let mut recovered = Vec::new();
    for check in checks.check_runs {
        if check.name != INTENT_NAME
            || check.head_sha != observed.release_sha
            || check.app.id != APP_PUBLIC_ID
            || check.app.slug != APP_SLUG
        {
            continue;
        }
        let body = check
            .output
            .summary
            .clone()
            .ok_or_else(|| "App-owned release intent Check lacks its summary".to_string())?;
        let record: IntentRecord = serde_json::from_str(&body)
            .map_err(|error| format!("existing release intent schema is invalid: {error}"))?;
        let (plan_body, plan_digest) = encode_plan(&record.plan)?;
        if plan_digest != record.plan_digest
            || decode_plan(&plan_body, &plan_digest)? != record.plan
        {
            return Err("existing release intent embeds a noncanonical plan".to_string());
        }
        let record = decode_intent(&body, &record.plan, &record.plan_digest)?;
        validate_intent_check(&check, &record, &body)?;
        require_static_plan_match(&record.plan, observed)?;
        require_registry_transition(&record.plan, observed)?;
        recovered.push((check, body, record));
    }
    if recovered.len() > 1 {
        return Err("multiple App-owned release intents claim one train".to_string());
    }
    Ok(recovered.pop())
}

pub(super) fn verify_command(
    root: &Path,
    repository: &str,
    plan_text: &str,
    plan_digest: &str,
    baseline_version: &str,
    baseline_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    let expected = decode_plan(plan_text, plan_digest)?;
    let mut registry = CratesIo::new();
    let actual = capture_plan(
        root,
        repository,
        &expected.release_sha,
        baseline_version,
        baseline_commit,
        github,
        &mut registry,
    )?;
    require_static_plan_match(&expected, &actual)?;
    require_registry_transition(&expected, &actual)?;
    append_outputs(&[("captured_release_sha", &expected.release_sha)])
}

pub(super) fn wait_command(
    repository: &str,
    plan_text: &str,
    plan_digest: &str,
) -> Result<(), String> {
    let plan = decode_plan(plan_text, plan_digest)?;
    if plan.repository != repository {
        return Err("registry wait repository differs from the release plan".to_string());
    }
    let policy = release_policy_for_repository(repository)?;
    let mut registry = CratesIo::new();
    wait_for_registry(&plan, policy, &mut registry, REGISTRY_POLL_COUNT, || {
        thread::sleep(Duration::from_secs(REGISTRY_POLL_SECONDS))
    })?;
    append_outputs(&[("complete", "true")])
}

fn wait_for_registry(
    plan: &ReleasePlan,
    policy: &crate::release_policy::ReleasePolicy,
    registry: &mut impl Registry,
    poll_count: usize,
    mut pause: impl FnMut(),
) -> Result<(), String> {
    if policy.packages.len() != plan.packages.len() {
        return Err("registry wait package family is incomplete".to_string());
    }
    let mut inspected = vec![false; plan.packages.len()];
    if observe_registry(plan, policy, registry, &mut inspected, false)? {
        observe_registry(plan, policy, registry, &mut inspected, true)?;
        return Ok(());
    }
    for _ in 0..poll_count {
        pause();
        if observe_registry(plan, policy, registry, &mut inspected, false)? {
            observe_registry(plan, policy, registry, &mut inspected, true)?;
            return Ok(());
        }
    }
    Err("crates.io did not expose the complete release train within 20 minutes".to_string())
}

fn observe_registry(
    plan: &ReleasePlan,
    policy: &crate::release_policy::ReleasePolicy,
    registry: &mut impl Registry,
    inspected: &mut [bool],
    final_confirmation: bool,
) -> Result<bool, String> {
    let mut missing = false;
    for (index, (package, package_policy)) in plan.packages.iter().zip(policy.packages).enumerate()
    {
        let record = registry.exact_version(&package.package, &package.version)?;
        let Some(record) = record else {
            if inspected[index] {
                return Err("a previously observed registry package disappeared".to_string());
            }
            missing = true;
            continue;
        };
        if missing {
            return Err("registry packages do not form the planned dependency prefix".to_string());
        }
        if package.package != package_policy.package
            || record.num != package.version
            || record.yanked
            || record.checksum != package.source_archive_sha256
        {
            return Err(format!(
                "{} registry state differs from the release plan",
                package.package
            ));
        }
        if !inspected[index] || final_confirmation {
            let archive = registry.download(&package.package, &package.version)?;
            if sha256(&archive) != package.source_archive_sha256 {
                return Err(format!(
                    "{} registry archive differs from the release plan",
                    package.package
                ));
            }
            let entries = crate::crate_archive::inspect_archive_entries(
                &archive,
                package_policy,
                &package.version,
                &plan.release_sha,
            )?;
            if archive_inventory_sha256(&entries) != package.package_inventory_sha256 {
                return Err(format!(
                    "{} registry archive inventory differs from the release plan",
                    package.package
                ));
            }
            inspected[index] = true;
        }
    }
    Ok(!missing && inspected.iter().all(|value| *value))
}

fn capture_plan(
    root: &Path,
    repository: &str,
    commit: &str,
    baseline_version: &str,
    baseline_commit: &str,
    github: &mut impl Transport,
    registry: &mut impl Registry,
) -> Result<ReleasePlan, String> {
    if !is_sha(commit) {
        return Err("release plan commit must be one lowercase full SHA".to_string());
    }
    let repository_policy = repository_policy_for_root(root, repository)?;
    crate::crate_archive::require_clean_source(root, commit)?;
    let version = manifest_version(root, repository_policy.kind)?;
    let authorization = authorize_source(
        github,
        repository,
        commit,
        root,
        baseline_version,
        baseline_commit,
    )?;
    let policy = detect(root)?;
    let specs = release_specs(root, policy, &version)?;
    if specs.is_empty() || specs.len() > MAX_RELEASE_PACKAGES {
        return Err("release plan package count is outside its bound".to_string());
    }
    let trusted = TrustedRoot::open(root).map_err(|error| format!("open release root: {error}"))?;
    let config = trusted
        .read_manifest(Path::new(".release-plz.toml"))
        .map_err(|error| format!("read release-plz config: {error}"))?;
    require_source_only_config(&config, &specs)?;
    let publish = trusted
        .read_manifest(Path::new(".github/workflows/publish.yml"))
        .map_err(|error| format!("read publication workflow: {error}"))?;
    let proposal = trusted
        .read_manifest(Path::new(".github/workflows/release-proposal.yml"))
        .map_err(|error| format!("read proposal workflow: {error}"))?;
    let (tagger_epoch, tagger_date) = commit_timestamp(root, commit)?;
    let mut packages = Vec::with_capacity(specs.len());
    for spec in &specs {
        let archive = package_source(root, spec)?;
        let source_archive_sha256 = sha256(&archive);
        let archive_entries = crate::crate_archive::inspect_archive_entries(
            &archive,
            spec.policy,
            &spec.version,
            commit,
        )?;
        let package_inventory_sha256 = archive_inventory_sha256(&archive_entries);
        let record = registry.exact_version(spec.policy.package, &spec.version)?;
        let registry = match record {
            None => RegistryBaseline {
                state: RegistryState::Absent,
                checksum: None,
            },
            Some(record) => {
                let checksum = require_reproduced_archive(root, registry, spec, commit)?;
                if checksum != record.checksum {
                    return Err(format!(
                        "{} registry checksum changed during plan capture",
                        spec.policy.package
                    ));
                }
                RegistryBaseline {
                    state: RegistryState::Present,
                    checksum: Some(checksum),
                }
            }
        };
        packages.push(PlanPackage {
            package: spec.policy.package.to_string(),
            version: spec.version.clone(),
            tag: spec.tag.clone(),
            prerelease: spec.prerelease,
            source_archive_sha256,
            package_inventory_sha256,
            release_body: spec.body.clone(),
            release_body_sha256: sha256(spec.body.as_bytes()),
            registry,
        });
    }
    require_registry_prefix(&packages)?;
    Ok(ReleasePlan {
        schema_version: PLAN_SCHEMA,
        repository: repository.to_string(),
        release_sha: commit.to_string(),
        authorization: authorization.into(),
        release_plz_version: RELEASE_PLZ_VERSION.to_string(),
        release_config_sha256: sha256(config.as_bytes()),
        publish_workflow_sha256: sha256(publish.as_bytes()),
        proposal_workflow_sha256: sha256(proposal.as_bytes()),
        tagger_epoch,
        tagger_date,
        packages,
    })
}

fn require_source_only_config(config: &str, specs: &[ReleaseSpec<'_>]) -> Result<(), String> {
    let document = config
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("parse release-plz config: {error}"))?;
    let workspace = document
        .get("workspace")
        .and_then(toml_edit::Item::as_table)
        .ok_or_else(|| "release-plz config lacks workspace policy".to_string())?;
    if workspace
        .get("release_always")
        .and_then(toml_edit::Item::as_bool)
        != Some(false)
        || workspace
            .get("git_tag_enable")
            .and_then(toml_edit::Item::as_bool)
            != Some(false)
        || workspace
            .get("git_release_enable")
            .and_then(toml_edit::Item::as_bool)
            != Some(false)
        || workspace.contains_key("pr_branch_prefix")
    {
        return Err("tracked release-plz workspace policy is not proposal-safe".to_string());
    }
    let packages = document
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(|| "release-plz config lacks package overrides".to_string())?;
    if packages.len() != specs.len() {
        return Err("release-plz package override set is incomplete".to_string());
    }
    for (package, spec) in packages.iter().zip(specs) {
        if package.get("name").and_then(toml_edit::Item::as_str) != Some(spec.policy.package)
            || package
                .get("git_tag_enable")
                .and_then(toml_edit::Item::as_bool)
                != Some(false)
            || package
                .get("git_release_enable")
                .and_then(toml_edit::Item::as_bool)
                != Some(false)
        {
            return Err("release-plz package source-only policy is not exact".to_string());
        }
    }
    Ok(())
}

fn commit_timestamp(root: &Path, commit: &str) -> Result<(u64, String), String> {
    let output = git_output(root, &["show", "-s", "--format=%ct%n%cI", commit])?;
    let lines: Vec<_> = output.lines().collect();
    if lines.len() != 2
        || lines[0].starts_with('0')
        || !lines[0].bytes().all(|byte| byte.is_ascii_digit())
        || lines[1].len() > 64
        || lines[1].contains(['\0', '\r', '\n'])
    {
        return Err("release commit has a noncanonical timestamp".to_string());
    }
    let epoch = lines[0]
        .parse::<u64>()
        .map_err(|_| "release commit timestamp is invalid".to_string())?;
    Ok((epoch, lines[1].to_string()))
}

fn encode_plan(plan: &ReleasePlan) -> Result<(String, String), String> {
    let body =
        serde_json::to_string(plan).map_err(|error| format!("encode release plan: {error}"))?;
    if body.len() > MAX_PLAN_BYTES {
        return Err("release plan exceeds its byte bound".to_string());
    }
    Ok((body.clone(), sha256(body.as_bytes())))
}

fn decode_plan(body: &str, digest: &str) -> Result<ReleasePlan, String> {
    if body.is_empty() || body.len() > MAX_PLAN_BYTES || !is_digest(digest) {
        return Err("release plan input is empty, oversized, or has an invalid digest".to_string());
    }
    if sha256(body.as_bytes()) != digest {
        return Err("release plan digest does not match its exact bytes".to_string());
    }
    let plan: ReleasePlan = serde_json::from_str(body)
        .map_err(|error| format!("release plan schema is invalid: {error}"))?;
    let (canonical, canonical_digest) = encode_plan(&plan)?;
    if canonical != body || canonical_digest != digest {
        return Err("release plan is not canonical".to_string());
    }
    validate_plan(&plan)?;
    Ok(plan)
}

fn validate_plan(plan: &ReleasePlan) -> Result<(), String> {
    if plan.schema_version != PLAN_SCHEMA
        || !is_sha(&plan.release_sha)
        || plan.repository.is_empty()
        || plan.release_plz_version != RELEASE_PLZ_VERSION
        || !is_digest(&plan.release_config_sha256)
        || !is_digest(&plan.publish_workflow_sha256)
        || !is_digest(&plan.proposal_workflow_sha256)
        || plan.tagger_epoch == 0
        || plan.tagger_date.is_empty()
        || plan.tagger_date.len() > 64
        || plan.packages.is_empty()
        || plan.packages.len() > MAX_RELEASE_PACKAGES
        || plan.authorization.pull_request == 0
        || !is_sha(&plan.authorization.proposal_commit)
        || !is_sha(&plan.authorization.base_commit)
        || plan.authorization.owner_id == 0
        || plan.authorization.merger_id == 0
    {
        return Err("release plan binding is invalid".to_string());
    }
    let mut names = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for package in &plan.packages {
        if package.package.is_empty()
            || package.version.is_empty()
            || package.tag.is_empty()
            || !is_digest(&package.source_archive_sha256)
            || !is_digest(&package.package_inventory_sha256)
            || !is_digest(&package.release_body_sha256)
            || package.release_body.is_empty()
            || package.release_body.len() > MAX_RELEASE_BODY_BYTES
            || sha256(package.release_body.as_bytes()) != package.release_body_sha256
            || !names.insert(&package.package)
            || !tags.insert(&package.tag)
            || (package.registry.state == RegistryState::Absent
                && package.registry.checksum.is_some())
            || (package.registry.state == RegistryState::Present
                && package
                    .registry
                    .checksum
                    .as_deref()
                    .is_none_or(|checksum| !is_digest(checksum)))
        {
            return Err("release plan package binding is invalid".to_string());
        }
    }
    require_registry_prefix(&plan.packages)
}

fn require_registry_prefix(packages: &[PlanPackage]) -> Result<(), String> {
    let mut absent = false;
    for package in packages {
        match package.registry.state {
            RegistryState::Present if absent => {
                return Err("published packages do not form a dependency-order prefix".to_string());
            }
            RegistryState::Absent => absent = true,
            RegistryState::Present => {}
        }
    }
    Ok(())
}

fn require_static_plan_match(expected: &ReleasePlan, actual: &ReleasePlan) -> Result<(), String> {
    let mut expected = expected.clone();
    let mut actual = actual.clone();
    for package in &mut expected.packages {
        package.registry = RegistryBaseline {
            state: RegistryState::Absent,
            checksum: None,
        };
    }
    for package in &mut actual.packages {
        package.registry = RegistryBaseline {
            state: RegistryState::Absent,
            checksum: None,
        };
    }
    if expected != actual {
        return Err("release plan source or authorization changed".to_string());
    }
    Ok(())
}

fn require_registry_transition(expected: &ReleasePlan, actual: &ReleasePlan) -> Result<(), String> {
    for (old, new) in expected.packages.iter().zip(&actual.packages) {
        match (old.registry.state, new.registry.state) {
            (RegistryState::Absent, RegistryState::Absent)
            | (RegistryState::Absent, RegistryState::Present) => {}
            (RegistryState::Present, RegistryState::Present)
                if old.registry.checksum == new.registry.checksum => {}
            _ => return Err("registry state is not a valid release-plan progression".to_string()),
        }
    }
    require_registry_prefix(&actual.packages)
}

pub(super) fn prepare_intent_command(
    root: &Path,
    input: PrepareIntentInput<'_>,
) -> Result<(), String> {
    let plan = decode_plan(input.plan, input.plan_digest)?;
    let record = build_intent(
        root,
        &plan,
        input.plan_digest,
        positive(input.origin_run_id, "origin run ID")?,
        positive(input.origin_run_attempt, "origin run attempt")?,
        input.ruleset_evidence_sha256,
    )?;
    let record_body = canonical_intent(&record)?;
    let record_digest = sha256(record_body.as_bytes());
    append_outputs(&[
        ("intent", &record_body),
        ("intent_digest", &record_digest),
        ("intent_external_id", &record.external_id),
    ])
}

pub(super) fn create_intent_command(
    input: CreateIntentInput<'_>,
    github: &mut impl Transport,
) -> Result<(), String> {
    let plan = decode_plan(input.plan, input.plan_digest)?;
    let record = decode_intent(input.intent, &plan, input.plan_digest)?;
    if plan.repository != input.repository {
        return Err("intent repository differs from the release plan".to_string());
    }
    validate_app_token(
        github,
        input.repository,
        input.expected_app_slug,
        input.expected_installation_id,
    )?;
    let record_body = canonical_intent(&record)?;
    let check = create_or_require_intent(github, input.repository, &record, &record_body)?;
    let check_id = check.id.to_string();
    let record_digest = sha256(record_body.as_bytes());
    append_outputs(&[
        ("intent", &record_body),
        ("intent_digest", &record_digest),
        ("intent_check_id", &check_id),
        ("intent_external_id", &record.external_id),
    ])
}

fn build_intent(
    root: &Path,
    plan: &ReleasePlan,
    plan_digest: &str,
    origin_run_id: u64,
    origin_run_attempt: u64,
    ruleset_evidence_sha256: &str,
) -> Result<IntentRecord, String> {
    if !is_digest(ruleset_evidence_sha256) {
        return Err("ruleset evidence must be one SHA-256 digest".to_string());
    }
    let external_id = sha256(
        format!(
            "release-intent-v{INTENT_SCHEMA}\0{}\0{}\0{plan_digest}",
            plan.repository, plan.release_sha
        )
        .as_bytes(),
    );
    let mut tags = Vec::with_capacity(plan.packages.len());
    for package in &plan.packages {
        let tag_message = format!(
            "chore: Release package {} version {}",
            package.package, package.version
        );
        let payload = annotated_tag_payload(plan, &package.tag, &tag_message)?;
        let object_id = hash_git_object(root, "tag", payload.as_bytes())?;
        tags.push(TagIntent {
            package: package.package.clone(),
            tag: package.tag.clone(),
            tag_object_id: object_id,
            tag_message,
            release_body_sha256: package.release_body_sha256.clone(),
        });
    }
    Ok(IntentRecord {
        schema_version: INTENT_SCHEMA,
        repository: plan.repository.clone(),
        release_sha: plan.release_sha.clone(),
        plan_digest: plan_digest.to_string(),
        external_id,
        origin_run_id,
        origin_run_attempt,
        ruleset_evidence_sha256: ruleset_evidence_sha256.to_string(),
        plan: plan.clone(),
        tags,
    })
}

fn annotated_tag_payload(plan: &ReleasePlan, tag: &str, message: &str) -> Result<String, String> {
    if tag.contains(['\0', '\r', '\n']) || message.contains(['\0', '\r']) {
        return Err("tag intent contains an invalid line".to_string());
    }
    let offset = plan
        .tagger_date
        .get(plan.tagger_date.len().saturating_sub(6)..)
        .ok_or_else(|| "tagger date lacks an offset".to_string())?;
    if offset.as_bytes().get(3) != Some(&b':')
        || !matches!(offset.as_bytes().first(), Some(b'+') | Some(b'-'))
    {
        return Err("tagger date has a noncanonical offset".to_string());
    }
    let git_offset = format!("{}{}", &offset[..3], &offset[4..]);
    Ok(format!(
        "object {}\ntype commit\ntag {tag}\ntagger {APP_LOGIN} <{APP_EMAIL}> {} {git_offset}\n\n{message}\n",
        plan.release_sha, plan.tagger_epoch
    ))
}

fn hash_git_object(root: &Path, kind: &str, body: &[u8]) -> Result<String, String> {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args(["hash-object", "--stdin", "-t", kind]);
    let output = bounded_process::output_with_input(&mut command, body, VALIDATION_OUTPUT_LIMITS)
        .map_err(|error| format!("hash Git {kind} object: {error}"))?;
    if !output.status.success() {
        return Err("Git could not hash the release intent object".to_string());
    }
    let value =
        String::from_utf8(output.stdout).map_err(|_| "Git object ID is not UTF-8".to_string())?;
    let value = value.trim_end_matches(['\r', '\n']);
    if !is_sha(value) {
        return Err("Git returned an invalid intent object ID".to_string());
    }
    Ok(value.to_string())
}

fn canonical_intent(record: &IntentRecord) -> Result<String, String> {
    let body = serde_json::to_string(record).map_err(|error| format!("encode intent: {error}"))?;
    if body.len() > MAX_INTENT_BYTES {
        return Err("release intent exceeds its byte bound".to_string());
    }
    Ok(body)
}

#[derive(Debug, Deserialize)]
struct CheckRuns {
    total_count: u64,
    check_runs: Vec<CheckRun>,
}

#[derive(Debug, Deserialize)]
struct CheckRun {
    id: u64,
    name: String,
    head_sha: String,
    external_id: String,
    status: String,
    conclusion: Option<String>,
    app: CheckApp,
    output: CheckOutput,
}

#[derive(Debug, Deserialize)]
struct CheckApp {
    id: u64,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct CheckOutput {
    title: Option<String>,
    summary: Option<String>,
}

fn create_or_require_intent(
    github: &mut impl Transport,
    repository: &str,
    record: &IntentRecord,
    body: &str,
) -> Result<CheckRun, String> {
    let path = format!(
        "repos/{repository}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
        record.release_sha,
        percent_encode(INTENT_NAME)
    );
    let checks: CheckRuns = github.get(&path)?;
    if checks.total_count != checks.check_runs.len() as u64 || checks.total_count > 100 {
        return Err("intent Check inventory is incomplete or oversized".to_string());
    }
    let mut matching = Vec::new();
    for check in checks.check_runs {
        if check.app.id == APP_PUBLIC_ID && check.app.slug == APP_SLUG {
            if check.external_id != record.external_id {
                return Err(
                    "conflicting App-owned release intent exists for this train".to_string()
                );
            }
            matching.push(check);
        }
    }
    if matching.len() > 1 {
        return Err("duplicate release intent Checks claim one external ID".to_string());
    }
    if let Some(check) = matching.pop() {
        validate_intent_check(&check, record, body)?;
        return Ok(check);
    }
    let check: CheckRun = github.mutate(
        "POST",
        &format!("repos/{repository}/check-runs"),
        &json!({
            "name": INTENT_NAME,
            "head_sha": record.release_sha,
            "status": "completed",
            "conclusion": "success",
            "external_id": record.external_id,
            "output": {
                "title": "Attested source-only release train",
                "summary": body,
            },
        }),
    )?;
    validate_intent_check(&check, record, body)?;
    Ok(check)
}

fn validate_intent_check(
    check: &CheckRun,
    record: &IntentRecord,
    body: &str,
) -> Result<(), String> {
    if check.id == 0
        || check.name != INTENT_NAME
        || check.head_sha != record.release_sha
        || check.external_id != record.external_id
        || check.status != "completed"
        || check.conclusion.as_deref() != Some("success")
        || check.app.id != APP_PUBLIC_ID
        || check.app.slug != APP_SLUG
        || check.output.title.as_deref() != Some("Attested source-only release train")
        || check.output.summary.as_deref() != Some(body)
    {
        return Err("release intent Check does not match the exact App attestation".to_string());
    }
    Ok(())
}

pub(super) fn verify_intent_command(
    repository: &str,
    plan_text: &str,
    plan_digest: &str,
    intent_text: &str,
    check_id: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    let plan = decode_plan(plan_text, plan_digest)?;
    let intent = decode_intent(intent_text, &plan, plan_digest)?;
    let check_id = positive(check_id, "intent Check ID")?;
    let check: CheckRun = github.get(&format!("repos/{repository}/check-runs/{check_id}"))?;
    validate_intent_check(&check, &intent, intent_text)?;
    let check_id = check_id.to_string();
    let intent_digest = sha256(intent_text.as_bytes());
    append_outputs(&[
        ("intent", intent_text),
        ("intent_digest", &intent_digest),
        ("intent_check_id", &check_id),
    ])
}

fn decode_intent(
    body: &str,
    plan: &ReleasePlan,
    plan_digest: &str,
) -> Result<IntentRecord, String> {
    if body.is_empty() || body.len() > MAX_INTENT_BYTES {
        return Err("release intent is empty or oversized".to_string());
    }
    let record: IntentRecord = serde_json::from_str(body)
        .map_err(|error| format!("release intent schema is invalid: {error}"))?;
    if canonical_intent(&record)? != body
        || record.schema_version != INTENT_SCHEMA
        || record.repository != plan.repository
        || record.release_sha != plan.release_sha
        || record.plan_digest != plan_digest
        || !is_digest(&record.external_id)
        || !is_digest(&record.ruleset_evidence_sha256)
        || record.origin_run_id == 0
        || record.origin_run_attempt == 0
        || record.plan != *plan
        || record.tags.len() != plan.packages.len()
    {
        return Err("release intent binding is invalid".to_string());
    }
    for ((tag, package), index) in record.tags.iter().zip(&plan.packages).zip(0..) {
        if tag.package != package.package
            || tag.tag != package.tag
            || !is_sha(&tag.tag_object_id)
            || tag.release_body_sha256 != package.release_body_sha256
            || tag.tag_message
                != format!(
                    "chore: Release package {} version {}",
                    package.package, package.version
                )
        {
            return Err(format!("release intent tag {index} is not canonical"));
        }
    }
    Ok(record)
}

pub(super) fn finalize_command(
    input: FinalizeInput<'_>,
    github: &mut impl Transport,
) -> Result<(), String> {
    let plan = decode_plan(input.plan, input.plan_digest)?;
    let intent = decode_intent(input.intent, &plan, input.plan_digest)?;
    let intent_check_id = positive(input.intent_check_id, "intent Check ID")?;
    if plan.repository != input.repository {
        return Err("finalizer repository differs from the release plan".to_string());
    }
    validate_app_token(
        github,
        input.repository,
        input.expected_app_slug,
        input.expected_installation_id,
    )?;
    require_captured_ancestry(github, input.repository, &plan.release_sha)?;
    let policy = release_policy_for_repository(input.repository)?;
    if policy.packages.len() != plan.packages.len() {
        return Err("release plan package family is incomplete".to_string());
    }
    let mut registry = CratesIo::new();
    let mut present = 0usize;
    for (package, package_policy) in plan.packages.iter().zip(policy.packages) {
        if let Some(record) = registry.exact_version(&package.package, &package.version)? {
            if package.package != package_policy.package
                || record.num != package.version
                || record.yanked
                || record.checksum != package.source_archive_sha256
            {
                return Err(format!(
                    "{} registry state differs from the release plan",
                    package.package
                ));
            }
            let archive = registry.download(&package.package, &package.version)?;
            if sha256(&archive) != package.source_archive_sha256 {
                return Err(format!(
                    "{} registry archive differs from the release plan",
                    package.package
                ));
            }
            let entries = crate::crate_archive::inspect_archive_entries(
                &archive,
                package_policy,
                &package.version,
                &plan.release_sha,
            )?;
            if archive_inventory_sha256(&entries) != package.package_inventory_sha256 {
                return Err(format!(
                    "{} registry archive inventory differs from the release plan",
                    package.package
                ));
            }
            present += 1;
        } else {
            break;
        }
    }
    for package in plan.packages.iter().skip(present) {
        if registry
            .exact_version(&package.package, &package.version)?
            .is_some()
        {
            return Err("registry packages do not form the planned dependency prefix".to_string());
        }
    }
    require_finalizer_intent(
        github,
        input.repository,
        intent_check_id,
        &intent,
        input.intent,
    )?;
    let finalizer_intent = FinalizerIntent {
        check_id: intent_check_id,
        record: &intent,
        body: input.intent,
    };
    let mut entries = Vec::with_capacity(present);
    for (package, tag_intent) in plan.packages.iter().zip(&intent.tags).take(present) {
        let tag_object_id = reconcile_tag(
            github,
            input.repository,
            &plan,
            package,
            tag_intent,
            &finalizer_intent,
        )?;
        let release = reconcile_release(
            github,
            input.repository,
            &plan,
            package,
            tag_intent,
            &finalizer_intent,
        )?;
        entries.push(FinalizedEntry {
            package: package.package.clone(),
            version: package.version.clone(),
            release_id: release.id,
            tag: package.tag.clone(),
            tag_object_id,
            release_body_sha256: package.release_body_sha256.clone(),
        });
    }
    let entries_text = serde_json::to_string(&entries)
        .map_err(|error| format!("encode finalization entries: {error}"))?;
    append_outputs(&[
        (
            "complete",
            if present == plan.packages.len() {
                "true"
            } else {
                "false"
            },
        ),
        ("finalized_entries", &entries_text),
    ])
}

fn require_finalizer_intent(
    github: &mut impl Transport,
    repository: &str,
    check_id: u64,
    intent: &IntentRecord,
    intent_body: &str,
) -> Result<(), String> {
    let path = format!(
        "repos/{repository}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
        intent.release_sha,
        percent_encode(INTENT_NAME)
    );
    let inventory: CheckRuns = github.get(&path)?;
    if inventory.total_count != 1
        || inventory.check_runs.len() != 1
        || inventory.check_runs[0].id != check_id
    {
        return Err("finalizer intent Check is missing, duplicated, or incomplete".to_string());
    }
    validate_intent_check(&inventory.check_runs[0], intent, intent_body)?;
    let check: CheckRun = github.get(&format!("repos/{repository}/check-runs/{check_id}"))?;
    if check.id != check_id {
        return Err("finalizer intent Check ID changed during re-read".to_string());
    }
    validate_intent_check(&check, intent, intent_body)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReleaseObjectPackageIntent {
    pub(super) package: String,
    pub(super) version: String,
    pub(super) tag: String,
    pub(super) prerelease: bool,
    pub(super) release_body: String,
    pub(super) tag_object_id: String,
    pub(super) tag_message: String,
    pub(super) tagger_date: String,
}

pub(super) struct ReleaseObjectIntent {
    check_id: u64,
    record: IntentRecord,
    body: String,
    packages: Vec<ReleaseObjectPackageIntent>,
}

impl ReleaseObjectIntent {
    pub(super) fn require_specs(
        &self,
        repository: &str,
        release_sha: &str,
        specs: &[ReleaseSpec<'_>],
    ) -> Result<(), String> {
        if self.record.repository != repository
            || self.record.release_sha != release_sha
            || self.packages.len() != specs.len()
        {
            return Err("release-object recovery differs from the App intent".to_string());
        }
        for (expected, spec) in self.packages.iter().zip(specs) {
            if expected.package != spec.policy.package
                || expected.version != spec.version
                || expected.tag != spec.tag
                || expected.prerelease != spec.prerelease
                || expected.release_body != spec.body
            {
                return Err(format!(
                    "release-object recovery for {} differs from the App intent",
                    spec.policy.package
                ));
            }
        }
        Ok(())
    }

    pub(super) fn package(&self, package: &str) -> Result<&ReleaseObjectPackageIntent, String> {
        self.packages
            .iter()
            .find(|item| item.package == package)
            .ok_or_else(|| format!("release App intent lacks package {package}"))
    }

    pub(super) fn revalidate(
        &self,
        github: &mut impl Transport,
        repository: &str,
    ) -> Result<(), String> {
        require_finalizer_intent(github, repository, self.check_id, &self.record, &self.body)
    }
}

pub(super) fn release_object_intent(
    github: &mut impl Transport,
    repository: &str,
    release_sha: &str,
) -> Result<ReleaseObjectIntent, String> {
    let path = format!(
        "repos/{repository}/commits/{release_sha}/check-runs?check_name={}&filter=all&per_page=100",
        percent_encode(INTENT_NAME)
    );
    let inventory: CheckRuns = github.get(&path)?;
    if inventory.total_count != 1 || inventory.check_runs.len() != 1 {
        return Err("release-object recovery requires one exact App intent Check".to_string());
    }
    let listed = inventory
        .check_runs
        .into_iter()
        .next()
        .ok_or_else(|| "release-object recovery intent inventory is empty".to_string())?;
    let check: CheckRun = github.get(&format!("repos/{repository}/check-runs/{}", listed.id))?;
    if check.id != listed.id {
        return Err("release-object recovery intent Check ID changed".to_string());
    }
    let body = check
        .output
        .summary
        .clone()
        .ok_or_else(|| "release-object recovery intent body is absent".to_string())?;
    if body.is_empty() || body.len() > MAX_INTENT_BYTES {
        return Err("release-object recovery intent body is empty or oversized".to_string());
    }
    let preliminary: IntentRecord = serde_json::from_str(&body)
        .map_err(|error| format!("release-object recovery intent is invalid: {error}"))?;
    let (plan_body, plan_digest) = encode_plan(&preliminary.plan)?;
    let plan = decode_plan(&plan_body, &plan_digest)?;
    let record = decode_intent(&body, &plan, &plan_digest)?;
    if record.repository != repository || record.release_sha != release_sha {
        return Err("release-object recovery intent source is wrong".to_string());
    }
    validate_intent_check(&listed, &record, &body)?;
    validate_intent_check(&check, &record, &body)?;
    let packages = plan
        .packages
        .iter()
        .zip(&record.tags)
        .map(|(package, tag)| ReleaseObjectPackageIntent {
            package: package.package.clone(),
            version: package.version.clone(),
            tag: package.tag.clone(),
            prerelease: package.prerelease,
            release_body: package.release_body.clone(),
            tag_object_id: tag.tag_object_id.clone(),
            tag_message: tag.tag_message.clone(),
            tagger_date: plan.tagger_date.clone(),
        })
        .collect();
    Ok(ReleaseObjectIntent {
        check_id: check.id,
        record,
        body,
        packages,
    })
}

fn release_policy_for_repository(
    repository: &str,
) -> Result<&'static crate::release_policy::ReleasePolicy, String> {
    let policy = crate::github::consts::repository_policy(repository)
        .ok_or_else(|| "finalizer repository lacks compiled policy".to_string())?;
    match policy.release_family {
        crate::release_policy::ReleaseFamily::Traits => Ok(&crate::release_policy::TRAITS_POLICY),
        crate::release_policy::ReleaseFamily::RustWorkspace => {
            Ok(&crate::release_policy::RUST_POLICY)
        }
    }
}

fn require_captured_ancestry(
    github: &mut impl Transport,
    repository: &str,
    release_sha: &str,
) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Comparison {
        status: String,
        base_commit: CommitIdentity,
        merge_base_commit: CommitIdentity,
    }
    #[derive(Deserialize)]
    struct CommitIdentity {
        sha: String,
    }
    let comparison: Comparison =
        github.get(&format!("repos/{repository}/compare/{release_sha}...main"))?;
    if !matches!(comparison.status.as_str(), "ahead" | "identical")
        || comparison.base_commit.sha != release_sha
        || comparison.merge_base_commit.sha != release_sha
    {
        return Err("captured release SHA is no longer protected-main ancestry".to_string());
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AnnotatedTag {
    sha: String,
    tag: String,
    message: String,
    tagger: Tagger,
    object: TagTarget,
}

#[derive(Debug, Deserialize)]
struct Tagger {
    name: String,
    email: String,
    date: String,
}

#[derive(Debug, Deserialize)]
struct TagTarget {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}

struct FinalizerIntent<'a> {
    check_id: u64,
    record: &'a IntentRecord,
    body: &'a str,
}

fn reconcile_tag(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
    package: &PlanPackage,
    intent: &TagIntent,
    finalizer: &FinalizerIntent<'_>,
) -> Result<String, String> {
    let object_path = format!("repos/{repository}/git/tags/{}", intent.tag_object_id);
    let object = github.get_optional::<AnnotatedTag>(&object_path)?;
    if let Some(object) = &object {
        validate_tag_object(object, plan, package, intent)?;
    }
    let ref_path = format!(
        "repos/{repository}/git/ref/tags/{}",
        percent_encode(&package.tag)
    );
    let reference = github.get_optional::<crate::github::models::GitRef>(&ref_path)?;
    if let Some(reference) = reference {
        if reference.name != format!("refs/tags/{}", package.tag)
            || reference.object.kind != "tag"
            || reference.object.sha != intent.tag_object_id
            || object.is_none()
        {
            return Err(format!("tag {} conflicts with its App intent", package.tag));
        }
        return Ok(intent.tag_object_id.clone());
    }
    if object.is_none() {
        require_finalizer_intent(
            github,
            repository,
            finalizer.check_id,
            finalizer.record,
            finalizer.body,
        )?;
        let created: AnnotatedTag = github.mutate(
            "POST",
            &format!("repos/{repository}/git/tags"),
            &json!({
                "tag": package.tag,
                "message": intent.tag_message,
                "object": plan.release_sha,
                "type": "commit",
                "tagger": {
                    "name": APP_LOGIN,
                    "email": APP_EMAIL,
                    "date": plan.tagger_date,
                },
            }),
        )?;
        validate_tag_object(&created, plan, package, intent)?;
    }
    require_finalizer_intent(
        github,
        repository,
        finalizer.check_id,
        finalizer.record,
        finalizer.body,
    )?;
    let created: crate::github::models::GitRef = github.mutate(
        "POST",
        &format!("repos/{repository}/git/refs"),
        &json!({
            "ref": format!("refs/tags/{}", package.tag),
            "sha": intent.tag_object_id,
        }),
    )?;
    if created.name != format!("refs/tags/{}", package.tag)
        || created.object.kind != "tag"
        || created.object.sha != intent.tag_object_id
    {
        return Err("GitHub returned a mismatched annotated-tag ref".to_string());
    }
    Ok(intent.tag_object_id.clone())
}

fn validate_tag_object(
    object: &AnnotatedTag,
    plan: &ReleasePlan,
    package: &PlanPackage,
    intent: &TagIntent,
) -> Result<(), String> {
    if object.sha != intent.tag_object_id
        || object.tag != package.tag
        || object.message != intent.tag_message
        || object.tagger.name != APP_LOGIN
        || object.tagger.email != APP_EMAIL
        || object.tagger.date != plan.tagger_date
        || object.object.kind != "commit"
        || object.object.sha != plan.release_sha
    {
        return Err(format!(
            "annotated tag {} is not the attested object",
            package.tag
        ));
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

fn release_create_payload(package: &PlanPackage, release_sha: &str) -> Value {
    json!({
        "tag_name": package.tag,
        "target_commitish": release_sha,
        "name": package.tag,
        "body": package.release_body,
        "draft": false,
        "prerelease": package.prerelease,
    })
}

fn reconcile_release(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
    package: &PlanPackage,
    tag_intent: &TagIntent,
    finalizer: &FinalizerIntent<'_>,
) -> Result<Release, String> {
    let path = format!(
        "repos/{repository}/releases/tags/{}",
        percent_encode(&package.tag)
    );
    if let Some(release) = github.get_optional::<Release>(&path)? {
        validate_release(&release, package)?;
        require_attested_tag(github, repository, plan, package, tag_intent)?;
        return Ok(release);
    }
    require_finalizer_intent(
        github,
        repository,
        finalizer.check_id,
        finalizer.record,
        finalizer.body,
    )?;
    let release: Release = github.mutate(
        "POST",
        &format!("repos/{repository}/releases"),
        &release_create_payload(package, &plan.release_sha),
    )?;
    validate_release(&release, package)?;
    let readback: Release = github.get(&path)?;
    validate_release(&readback, package)?;
    if readback.id != release.id {
        return Err("GitHub Release identity changed during readback".to_string());
    }
    require_attested_tag(github, repository, plan, package, tag_intent)?;
    Ok(readback)
}

fn require_attested_tag(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
    package: &PlanPackage,
    intent: &TagIntent,
) -> Result<(), String> {
    let ref_path = format!(
        "repos/{repository}/git/ref/tags/{}",
        percent_encode(&package.tag)
    );
    let reference: crate::github::models::GitRef = github.get(&ref_path)?;
    if reference.name != format!("refs/tags/{}", package.tag)
        || reference.object.kind != "tag"
        || reference.object.sha != intent.tag_object_id
    {
        return Err(format!(
            "annotated tag {} changed during Release reconciliation",
            package.tag
        ));
    }
    let object: AnnotatedTag = github.get(&format!(
        "repos/{repository}/git/tags/{}",
        intent.tag_object_id
    ))?;
    validate_tag_object(&object, plan, package, intent)
}

fn validate_release(release: &Release, package: &PlanPackage) -> Result<(), String> {
    // GitHub documents target_commitish as unused when the annotated tag
    // already exists. The exact attested tag ref/object is the source
    // authority; this response field is accepted only as bounded API data.
    if release.id == 0
        || release.tag_name != package.tag
        || release.target_commitish.is_empty()
        || release.target_commitish.len() > 256
        || release.target_commitish.contains(['\0', '\r', '\n'])
        || release.name != package.tag
        || release.body != package.release_body
        || sha256(release.body.as_bytes()) != package.release_body_sha256
        || release.draft
        || release.prerelease != package.prerelease
        || !release.immutable
        || release.author.login != APP_LOGIN
        || release.author.id != APP_ID
        || release.author.kind != "Bot"
        || !release.assets.is_empty()
    {
        return Err(format!(
            "GitHub Release {} is not exact and immutable",
            package.tag
        ));
    }
    Ok(())
}

pub(super) fn notify_command(
    input: NotifyInput<'_>,
    github: &mut impl Transport,
) -> Result<(), String> {
    let plan = decode_plan(input.plan, input.plan_digest)?;
    let intent = decode_intent(input.intent, &plan, input.plan_digest)?;
    let check_id = positive(input.intent_check_id, "intent Check ID")?;
    validate_app_token(
        github,
        input.repository,
        input.expected_app_slug,
        input.expected_installation_id,
    )?;
    let entries: Vec<FinalizedEntry> = serde_json::from_str(input.finalized_entries)
        .map_err(|error| format!("finalized entry schema is invalid: {error}"))?;
    if serde_json::to_string(&entries).ok().as_deref() != Some(input.finalized_entries)
        || entries.len() != plan.packages.len()
    {
        return Err("finalized entry inventory is incomplete or noncanonical".to_string());
    }
    for ((entry, package), tag) in entries.iter().zip(&plan.packages).zip(&intent.tags) {
        if entry.package != package.package
            || entry.version != package.version
            || entry.release_id == 0
            || entry.tag != package.tag
            || entry.tag_object_id != tag.tag_object_id
            || entry.release_body_sha256 != package.release_body_sha256
        {
            return Err("finalized entry differs from the attested release train".to_string());
        }
    }
    let payload = json!({
        "event_type": "official-release-published",
        "client_payload": {
            "schema_version": NOTIFICATION_SCHEMA,
            "repository": input.repository,
            "captured_sha": plan.release_sha,
            "release_plan_digest": input.plan_digest,
            "intent_check_id": check_id,
            "intent_external_id": intent.external_id,
            "releases": entries,
        }
    });
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("encode release notification: {error}"))?;
    if bytes.len() > MAX_NOTIFICATION_BYTES {
        return Err("release notification exceeds its byte bound".to_string());
    }
    github.mutate_empty(
        "POST",
        &format!("repos/{}/dispatches", input.repository),
        &payload,
    )
}

#[derive(Debug, Deserialize)]
struct Installation {
    id: u64,
    app_id: u64,
    app_slug: String,
}

#[derive(Debug, Deserialize)]
struct InstallationRepositories {
    total_count: u64,
    repositories: Vec<InstallationRepository>,
}

#[derive(Debug, Deserialize)]
struct InstallationRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct PublicApp {
    id: u64,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct ViewerResponse {
    data: Option<ViewerData>,
    #[serde(default)]
    errors: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ViewerData {
    viewer: Viewer,
}

#[derive(Debug, Deserialize)]
struct Viewer {
    login: String,
    #[serde(rename = "databaseId")]
    id: u64,
}

pub(super) fn validate_app_token(
    github: &mut impl Transport,
    repository: &str,
    expected_app_slug: &str,
    expected_installation_id: &str,
) -> Result<(), String> {
    if expected_app_slug != APP_SLUG || !is_positive_integer(expected_installation_id) {
        return Err("App Action outputs are missing or unexpected".to_string());
    }
    let expected_installation = expected_installation_id
        .parse::<u64>()
        .map_err(|_| "App installation ID is invalid".to_string())?;
    let public: PublicApp = github.get(&format!("apps/{APP_SLUG}"))?;
    let installation: Installation = github.get("installation")?;
    let repositories: InstallationRepositories = github.get("installation/repositories")?;
    let viewer: ViewerResponse = github.graphql(&json!({
        "query": "query { viewer { login databaseId } }",
    }))?;
    let viewer = viewer
        .data
        .map(|data| data.viewer)
        .filter(|_| viewer.errors.is_none())
        .ok_or_else(|| "App token viewer query returned errors".to_string())?;
    if public.id != APP_PUBLIC_ID
        || public.slug != APP_SLUG
        || installation.id != expected_installation
        || installation.app_id != APP_PUBLIC_ID
        || installation.app_slug != APP_SLUG
        || repositories.total_count != 1
        || repositories.repositories.len() != 1
        || repositories.repositories[0].full_name != repository
        || viewer.login != APP_LOGIN
        || viewer.id != APP_ID
    {
        return Err("App token identity or repository scope is not exact".to_string());
    }
    Ok(())
}

fn positive(value: &str, label: &str) -> Result<u64, String> {
    if !is_positive_integer(value) {
        return Err(format!("{label} must be a positive canonical integer"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{label} exceeds its bound"))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::transport::fake::{Expected, FakeTransport};

    struct MissingRegistry {
        reads: usize,
    }

    impl Registry for MissingRegistry {
        fn exact_version(
            &mut self,
            _package: &str,
            _version: &str,
        ) -> Result<Option<crate::crate_archive::RegistryVersion>, String> {
            self.reads += 1;
            Ok(None)
        }

        fn download(&mut self, _package: &str, _version: &str) -> Result<Vec<u8>, String> {
            panic!("an absent registry package must not be downloaded")
        }
    }

    fn plan() -> ReleasePlan {
        ReleasePlan {
            schema_version: PLAN_SCHEMA,
            repository: "NVIDIA/yaml-sigil-traits".to_string(),
            release_sha: "a".repeat(40),
            authorization: PlanAuthorization {
                pull_request: 50,
                proposal_commit: "b".repeat(40),
                base_commit: "c".repeat(40),
                owner_id: 1,
                merger_id: 2,
            },
            release_plz_version: RELEASE_PLZ_VERSION.to_string(),
            release_config_sha256: "d".repeat(64),
            publish_workflow_sha256: "e".repeat(64),
            proposal_workflow_sha256: "f".repeat(64),
            tagger_epoch: 1_777_777_777,
            tagger_date: "2026-05-02T00:29:37+00:00".to_string(),
            packages: vec![PlanPackage {
                package: "yaml-sigil-traits".to_string(),
                version: "0.4.0".to_string(),
                tag: "v0.4.0".to_string(),
                prerelease: false,
                source_archive_sha256: "1".repeat(64),
                package_inventory_sha256: "2".repeat(64),
                release_body: "notes".to_string(),
                release_body_sha256: sha256(b"notes"),
                registry: RegistryBaseline {
                    state: RegistryState::Absent,
                    checksum: None,
                },
            }],
        }
    }

    fn intent_fixture() -> (ReleasePlan, IntentRecord, String) {
        let plan = plan();
        let (_, plan_digest) = encode_plan(&plan).unwrap();
        let intent = IntentRecord {
            schema_version: INTENT_SCHEMA,
            repository: plan.repository.clone(),
            release_sha: plan.release_sha.clone(),
            plan_digest,
            external_id: "6".repeat(64),
            origin_run_id: 100,
            origin_run_attempt: 1,
            ruleset_evidence_sha256: "7".repeat(64),
            plan: plan.clone(),
            tags: vec![TagIntent {
                package: plan.packages[0].package.clone(),
                tag: plan.packages[0].tag.clone(),
                tag_object_id: "8".repeat(40),
                tag_message: "chore: Release package yaml-sigil-traits version 0.4.0".to_string(),
                release_body_sha256: plan.packages[0].release_body_sha256.clone(),
            }],
        };
        let body = canonical_intent(&intent).unwrap();
        (plan, intent, body)
    }

    fn intent_check(intent: &IntentRecord, body: &str, id: u64, conclusion: &str) -> Value {
        json!({
            "id": id,
            "name": INTENT_NAME,
            "head_sha": intent.release_sha,
            "external_id": intent.external_id,
            "status": "completed",
            "conclusion": conclusion,
            "app": {"id": APP_PUBLIC_ID, "slug": APP_SLUG},
            "output": {
                "title": "Attested source-only release train",
                "summary": body,
            },
        })
    }

    #[test]
    fn release_plan_rejects_unknown_noncanonical_and_wrong_digest_inputs() {
        let plan = plan();
        let (body, digest) = encode_plan(&plan).unwrap();
        assert_eq!(decode_plan(&body, &digest).unwrap(), plan);
        assert!(decode_plan(&format!("{body} "), &digest).is_err());
        assert!(decode_plan(&body, &"0".repeat(64)).is_err());
        let unknown = body.replacen('{', "{\"unknown\":true,", 1);
        assert!(decode_plan(&unknown, &sha256(unknown.as_bytes())).is_err());
    }

    #[test]
    fn registry_progression_accepts_only_monotonic_dependency_prefixes() {
        let expected = plan();
        let mut actual = expected.clone();
        actual.packages[0].registry = RegistryBaseline {
            state: RegistryState::Present,
            checksum: Some("4".repeat(64)),
        };
        assert!(require_registry_transition(&expected, &actual).is_ok());
        assert!(require_registry_transition(&actual, &expected).is_err());
    }

    #[test]
    fn registry_wait_has_one_initial_observation_and_a_bounded_poll_count() {
        let plan = plan();
        let mut registry = MissingRegistry { reads: 0 };
        let mut pauses = 0;
        let error = wait_for_registry(
            &plan,
            &crate::release_policy::TRAITS_POLICY,
            &mut registry,
            2,
            || pauses += 1,
        )
        .unwrap_err();
        assert!(error.contains("within 20 minutes"));
        assert_eq!(registry.reads, 3);
        assert_eq!(pauses, 2);
    }

    #[test]
    fn release_creation_binds_implicit_tag_creation_to_the_release_commit() {
        let package = plan().packages.remove(0);
        let release_sha = "a".repeat(40);
        let payload = release_create_payload(&package, &release_sha);
        assert_eq!(payload["tag_name"], "v0.4.0");
        assert_eq!(payload["target_commitish"], release_sha);
    }

    #[test]
    fn release_reconciliation_rereads_the_exact_attested_tag() {
        let (plan, intent, _) = intent_fixture();
        let package = &plan.packages[0];
        let tag = &intent.tags[0];
        let ref_path = format!(
            "repos/{}/git/ref/tags/{}",
            plan.repository,
            percent_encode(&package.tag)
        );
        let object_path = format!("repos/{}/git/tags/{}", plan.repository, tag.tag_object_id);
        let reference = json!({
            "ref": format!("refs/tags/{}", package.tag),
            "object": {"type": "tag", "sha": tag.tag_object_id},
        });
        let object = json!({
            "sha": tag.tag_object_id,
            "tag": package.tag,
            "message": tag.tag_message,
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": plan.tagger_date,
            },
            "object": {"type": "commit", "sha": plan.release_sha},
        });
        let mut github = FakeTransport::new([
            Expected::json("GET", &ref_path, reference),
            Expected::json("GET", &object_path, object),
        ]);
        require_attested_tag(&mut github, &plan.repository, &plan, package, tag).unwrap();
        github.finish();

        let moved = json!({
            "ref": format!("refs/tags/{}", package.tag),
            "object": {"type": "tag", "sha": "f".repeat(40)},
        });
        let mut github = FakeTransport::new([Expected::json("GET", &ref_path, moved)]);
        assert!(
            require_attested_tag(&mut github, &plan.repository, &plan, package, tag)
                .unwrap_err()
                .contains("changed")
        );
        github.finish();
    }

    #[test]
    fn finalizer_rereads_one_exact_successful_app_intent() {
        let (_, intent, body) = intent_fixture();
        let check = intent_check(&intent, &body, 900, "success");
        let inventory_path = format!(
            "repos/{}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
            intent.repository,
            intent.release_sha,
            percent_encode(INTENT_NAME)
        );
        let check_path = format!("repos/{}/check-runs/900", intent.repository);
        let mut github = FakeTransport::new([
            Expected::json(
                "GET",
                &inventory_path,
                json!({"total_count": 1, "check_runs": [check.clone()]}),
            ),
            Expected::json("GET", &check_path, check),
        ]);
        require_finalizer_intent(&mut github, &intent.repository, 900, &intent, &body).unwrap();
        github.finish();

        let duplicate = intent_check(&intent, &body, 901, "success");
        let mut github = FakeTransport::new([Expected::json(
            "GET",
            &inventory_path,
            json!({
                "total_count": 2,
                "check_runs": [intent_check(&intent, &body, 900, "success"), duplicate],
            }),
        )]);
        assert!(
            require_finalizer_intent(&mut github, &intent.repository, 900, &intent, &body)
                .unwrap_err()
                .contains("duplicated")
        );
        github.finish();
    }

    #[test]
    fn recovery_loads_one_exact_successful_app_intent() {
        let (plan, intent, body) = intent_fixture();
        let check = intent_check(&intent, &body, 900, "success");
        let inventory_path = format!(
            "repos/{}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
            intent.repository,
            intent.release_sha,
            percent_encode(INTENT_NAME)
        );
        let check_path = format!("repos/{}/check-runs/900", intent.repository);
        let mut github = FakeTransport::new([
            Expected::json(
                "GET",
                &inventory_path,
                json!({"total_count": 1, "check_runs": [check.clone()]}),
            ),
            Expected::json("GET", &check_path, check),
        ]);
        let loaded =
            release_object_intent(&mut github, &intent.repository, &intent.release_sha).unwrap();
        let package = loaded.package(&plan.packages[0].package).unwrap();
        assert_eq!(package.tag_object_id, intent.tags[0].tag_object_id);
        assert_eq!(package.tagger_date, plan.tagger_date);
        github.finish();

        let duplicate = intent_check(&intent, &body, 901, "success");
        let mut github = FakeTransport::new([Expected::json(
            "GET",
            &inventory_path,
            json!({
                "total_count": 2,
                "check_runs": [intent_check(&intent, &body, 900, "success"), duplicate],
            }),
        )]);
        let error = release_object_intent(&mut github, &intent.repository, &intent.release_sha)
            .err()
            .expect("duplicate intent must fail");
        assert!(error.contains("one exact"));
        github.finish();
    }

    #[test]
    fn failed_intent_blocks_tag_mutation_after_read_only_reconciliation() {
        let (plan, intent, body) = intent_fixture();
        let package = &plan.packages[0];
        let tag = &intent.tags[0];
        let object_path = format!("repos/{}/git/tags/{}", plan.repository, tag.tag_object_id);
        let ref_path = format!(
            "repos/{}/git/ref/tags/{}",
            plan.repository,
            percent_encode(&package.tag)
        );
        let inventory_path = format!(
            "repos/{}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
            plan.repository,
            plan.release_sha,
            percent_encode(INTENT_NAME)
        );
        let failed = intent_check(&intent, &body, 900, "failure");
        let mut github = FakeTransport::new([
            Expected::missing(&object_path),
            Expected::missing(&ref_path),
            Expected::json(
                "GET",
                &inventory_path,
                json!({"total_count": 1, "check_runs": [failed]}),
            ),
        ]);
        let finalizer = FinalizerIntent {
            check_id: 900,
            record: &intent,
            body: &body,
        };
        assert!(
            reconcile_tag(
                &mut github,
                &plan.repository,
                &plan,
                package,
                tag,
                &finalizer,
            )
            .is_err()
        );
        github.finish();
    }

    #[test]
    fn notification_schema_rejects_unknown_and_legacy_payloads() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClosedPayload {
            schema_version: u64,
            repository: String,
            captured_sha: String,
            release_plan_digest: String,
            intent_check_id: u64,
            intent_external_id: String,
            releases: Vec<FinalizedEntry>,
        }
        let canonical = json!({
            "schema_version": 1,
            "repository": "NVIDIA/yaml-sigil-traits",
            "captured_sha": "a".repeat(40),
            "release_plan_digest": "b".repeat(64),
            "intent_check_id": 1,
            "intent_external_id": "c".repeat(64),
            "releases": [],
        });
        let ClosedPayload {
            schema_version,
            repository,
            captured_sha,
            release_plan_digest,
            intent_check_id,
            intent_external_id,
            releases,
        } = serde_json::from_value(canonical).unwrap();
        assert_eq!(schema_version, 1);
        assert_eq!(repository, "NVIDIA/yaml-sigil-traits");
        assert_eq!(captured_sha, "a".repeat(40));
        assert_eq!(release_plan_digest, "b".repeat(64));
        assert_eq!(intent_check_id, 1);
        assert_eq!(intent_external_id, "c".repeat(64));
        assert!(releases.is_empty());
        let legacy = json!({"version": "0.4.0"});
        assert!(serde_json::from_value::<ClosedPayload>(legacy).is_err());
        let unknown = json!({
            "schema_version": 1,
            "repository": "NVIDIA/yaml-sigil-traits",
            "captured_sha": "a".repeat(40),
            "release_plan_digest": "b".repeat(64),
            "intent_check_id": 1,
            "intent_external_id": "c".repeat(64),
            "releases": [],
            "unknown": true,
        });
        assert!(serde_json::from_value::<ClosedPayload>(unknown).is_err());
    }
}

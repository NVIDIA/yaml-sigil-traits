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
use crate::github::source::{MainRequirement, SourceAuthorization, authorize_source};
use crate::github::transport::{Transport, percent_encode};
use crate::github::{
    append_outputs, git_line, git_output, is_positive_integer, is_sha, repository_policy_for_root,
    require_captured_ancestry,
};
use crate::release_policy::detect;
const PLAN_SCHEMA: u64 = 2;
const INTENT_SCHEMA: u64 = 1;
const NOTIFICATION_SCHEMA: u64 = 1;
const MAX_PLAN_BYTES: usize = 48 * 1024;
const MAX_INTENT_BYTES: usize = 64 * 1024;
const MAX_NOTIFICATION_BYTES: usize = 8 * 1024;
const MAX_EVENT_BYTES: usize = 128 * 1024;
const MAX_POLICY_FILE_BYTES: usize = 256 * 1024;
const MAX_RELEASE_PACKAGES: usize = 8;
const MAX_RELEASE_BODY_BYTES: usize = 16 * 1024;
const MAX_LEGACY_RELEASES: usize = 64;
const REGISTRY_POLL_COUNT: usize = 60;
const REGISTRY_POLL_SECONDS: u64 = 20;
pub(super) const APP_PUBLIC_ID: u64 = 4_653_064;
pub(super) const INTENT_NAME: &str = "Release finalization intent";
const RELEASE_PLZ_VERSION: &str = "0.3.160";
const GITHUB_API_VERSION: &str = "2026-03-10";
const LEGACY_AUTHOR_ID: u64 = 41_898_282;
const LEGACY_AUTHOR_LOGIN: &str = "github-actions[bot]";
const TRAITS_TAG_PATTERNS: &[&str] = &["refs/tags/v*"];
const RS_TAG_PATTERNS: &[&str] = &[
    "refs/tags/yaml-sigil-core-v*",
    "refs/tags/yaml-sigil-transcription-v*",
    "refs/tags/yaml-sigil-signing-v*",
    "refs/tags/yaml-sigil-verification-v*",
];

pub(super) struct PrepareIntentInput<'a> {
    pub(super) plan: &'a str,
    pub(super) plan_digest: &'a str,
    pub(super) origin_run_id: &'a str,
    pub(super) origin_run_attempt: &'a str,
    pub(super) ruleset_evidence_sha256: &'a str,
}

pub(super) struct CaptureInput<'a> {
    pub(super) repository: &'a str,
    pub(super) commit: &'a str,
    pub(super) policy_commit: &'a str,
    pub(super) legacy_inventory_sha256: &'a str,
    pub(super) baseline_version: &'a str,
    pub(super) baseline_commit: &'a str,
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

pub(super) struct ReceiveInput<'a> {
    pub(super) event: &'a Path,
    pub(super) repository: &'a str,
    pub(super) policy_commit: &'a str,
}

struct ReceiveResult {
    replay_key: String,
    replay_state: &'static str,
    captured_release_sha: String,
    release_plan_digest: String,
    intent_check_id: u64,
    policy_sha: String,
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
    policy_commit: String,
    authorization: PlanAuthorization,
    release_plz_version: String,
    release_config_sha256: String,
    legacy_inventory_sha256: String,
    tagger_epoch: u64,
    tagger_date: String,
    packages: Vec<PlanPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PlanAuthorization {
    Proposal {
        pull_request: u64,
        proposal_commit: String,
        base_commit: String,
        owner_id: u64,
        merger_id: u64,
    },
    LegacyInventory,
}

impl From<SourceAuthorization> for PlanAuthorization {
    fn from(value: SourceAuthorization) -> Self {
        Self::Proposal {
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
    release_objects: ReleaseObjectBaseline,
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
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
enum ReleaseObjectBaseline {
    Absent,
    Legacy {
        release_id: u64,
        tag_object_sha: String,
    },
}

#[derive(Debug)]
struct PolicySnapshot {
    commit: String,
    release_config_sha256: String,
    legacy_inventory_sha256: String,
    legacy_inventory: LegacyInventory,
}

struct PlanCaptureInput<'a> {
    root: &'a Path,
    repository: &'a str,
    commit: &'a str,
    policy: &'a PolicySnapshot,
    baseline_version: &'a str,
    baseline_commit: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyInventory {
    schema_version: u64,
    api_version: String,
    repository: String,
    legacy_author: LegacyAuthor,
    prospective_author: LegacyAuthor,
    entries: Vec<LegacyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAuthor {
    id: u64,
    login: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEntry {
    release_id: u64,
    package: String,
    version: String,
    tag: String,
    tag_object_sha: String,
    peeled_commit_sha: String,
    target_commitish: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    asset_count: u64,
    body_sha256: String,
    source_archive_sha256: String,
    path_in_vcs: String,
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
    input: CaptureInput<'_>,
    github: &mut impl Transport,
) -> Result<(), String> {
    let CaptureInput {
        repository,
        commit,
        policy_commit,
        legacy_inventory_sha256,
        baseline_version,
        baseline_commit,
    } = input;
    if !is_sha(commit) {
        return Err("release plan commit must be one lowercase full SHA".to_string());
    }
    let recovered = recover_existing_intent(github, repository, commit)?;
    let current_policy = load_policy_snapshot(
        root,
        repository,
        policy_commit,
        Some(legacy_inventory_sha256),
        github,
    )?;
    let recovered_policy;
    let policy = if let Some((_, _, record)) = &recovered {
        recovered_policy = load_policy_snapshot(
            root,
            repository,
            &record.plan.policy_commit,
            Some(&record.plan.legacy_inventory_sha256),
            github,
        )?;
        &recovered_policy
    } else {
        &current_policy
    };
    let mut registry = CratesIo::new();
    let observed = capture_plan(
        PlanCaptureInput {
            root,
            repository,
            commit,
            policy,
            baseline_version,
            baseline_commit,
        },
        github,
        &mut registry,
    )?;
    if recovered.is_none() {
        require_initial_release_objects(github, repository, &observed)?;
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
        ("policy_commit", &plan.policy_commit),
        ("plan", &body),
        ("plan_digest", &digest),
        ("registry_state", registry_state),
        ("existing_intent", existing_intent),
        ("existing_intent_check_id", &existing_intent_check_id),
        ("existing_intent_digest", &existing_intent_digest),
    ])
}

fn require_initial_release_objects(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
) -> Result<(), String> {
    for package in &plan.packages {
        match &package.release_objects {
            ReleaseObjectBaseline::Absent => {
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
            ReleaseObjectBaseline::Legacy { .. } => {
                require_legacy_release_objects(github, repository, plan, package)?;
            }
        }
    }
    Ok(())
}

fn recover_existing_intent(
    github: &mut impl Transport,
    repository: &str,
    release_sha: &str,
) -> Result<Option<(CheckRun, String, IntentRecord)>, String> {
    let path = format!(
        "repos/{repository}/commits/{}/check-runs?check_name={}&filter=all&per_page=100",
        release_sha,
        percent_encode(INTENT_NAME)
    );
    let checks: CheckRuns = github.get(&path)?;
    if checks.total_count != checks.check_runs.len() as u64 || checks.total_count > 100 {
        return Err("intent Check inventory is incomplete or oversized".to_string());
    }
    let mut recovered = Vec::new();
    for check in checks.check_runs {
        if check.name != INTENT_NAME
            || check.head_sha != release_sha
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
        if record.repository != repository || record.release_sha != release_sha {
            return Err("existing release intent source is wrong".to_string());
        }
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
    let policy = load_policy_snapshot(
        root,
        repository,
        &expected.policy_commit,
        Some(&expected.legacy_inventory_sha256),
        github,
    )?;
    let mut registry = CratesIo::new();
    let actual = capture_plan(
        PlanCaptureInput {
            root,
            repository,
            commit: &expected.release_sha,
            policy: &policy,
            baseline_version,
            baseline_commit,
        },
        github,
        &mut registry,
    )?;
    require_static_plan_match(&expected, &actual)?;
    require_registry_transition(&expected, &actual)?;
    for package in &expected.packages {
        if matches!(
            package.release_objects,
            ReleaseObjectBaseline::Legacy { .. }
        ) {
            require_legacy_release_objects(github, repository, &expected, package)?;
        }
    }
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

pub(super) fn settings_evidence_command(
    root: &Path,
    repository: &str,
    release_sha: &str,
    run_id: &str,
    run_attempt: &str,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    let digest = settings_evidence_sha256(
        repository,
        release_sha,
        positive(run_id, "workflow run ID")?,
        positive(run_attempt, "workflow run attempt")?,
    )?;
    append_outputs(&[("ruleset_evidence_sha256", &digest)])
}

pub(super) fn verify_legacy_command(
    root: &Path,
    repository: &str,
    policy_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    require_current_policy_source(root, repository, policy_commit, github)?;
    let snapshot = load_policy_snapshot(root, repository, policy_commit, None, github)?;
    let mut registry = CratesIo::new();
    verify_live_legacy_inventory(
        github,
        &mut registry,
        repository,
        &snapshot.legacy_inventory,
    )?;
    append_outputs(&[("legacy_inventory_digest", &snapshot.legacy_inventory_sha256)])
}

fn require_current_policy_source(
    root: &Path,
    repository: &str,
    policy_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    if !is_sha(policy_commit) || git_line(root, &["rev-parse", "HEAD"])? != policy_commit {
        return Err("protected release policy is not the exact checked-out commit".to_string());
    }
    let reference: crate::github::models::GitRef =
        github.get(&format!("repos/{repository}/git/ref/heads/main"))?;
    if reference.name != "refs/heads/main"
        || reference.object.kind != "commit"
        || reference.object.sha != policy_commit
    {
        return Err("protected release policy is not exact current main".to_string());
    }
    Ok(())
}

fn verify_live_legacy_inventory(
    github: &mut impl Transport,
    registry: &mut impl Registry,
    repository: &str,
    inventory: &LegacyInventory,
) -> Result<(), String> {
    let releases: Vec<Release> = github.paginate(&format!("repos/{repository}/releases"))?;
    if releases.len() >= 100 {
        return Err("GitHub Release inventory is invalid or truncated".to_string());
    }
    let mut listed = BTreeSet::new();
    for release in &releases {
        if release.id == 0 || !listed.insert(release.id) {
            return Err("GitHub listed an invalid or duplicate Release".to_string());
        }
        if let Some(entry) = inventory
            .entries
            .iter()
            .find(|entry| entry.release_id == release.id)
        {
            if release.tag_name != entry.tag {
                return Err("listed legacy Release tag drifted".to_string());
            }
        } else if release.author.id != inventory.prospective_author.id
            || release.author.login != inventory.prospective_author.login
            || release.author.kind != inventory.prospective_author.kind
            || !release.immutable
            || release.draft
            || release.target_commitish != "main"
            || !release.assets.is_empty()
        {
            return Err("an unpinned mutable, draft, or non-App Release exists".to_string());
        }
    }
    if inventory
        .entries
        .iter()
        .any(|entry| !listed.contains(&entry.release_id))
    {
        return Err("a pinned legacy Release is missing".to_string());
    }

    let policy = release_policy_for_repository(repository)?;
    for entry in &inventory.entries {
        let package_policy = policy
            .packages
            .iter()
            .find(|package| package.package == entry.package)
            .ok_or_else(|| "legacy Release package is outside repository policy".to_string())?;
        let release: Release =
            github.get(&format!("repos/{repository}/releases/{}", entry.release_id))?;
        if release.id != entry.release_id
            || release.tag_name != entry.tag
            || release.target_commitish != entry.target_commitish
            || release.draft != entry.draft
            || release.prerelease != entry.prerelease
            || release.immutable != entry.immutable
            || release.author.id != inventory.legacy_author.id
            || release.author.login != inventory.legacy_author.login
            || release.author.kind != inventory.legacy_author.kind
            || release.assets.len() as u64 != entry.asset_count
            || sha256(release.body.as_bytes()) != entry.body_sha256
        {
            return Err(format!("legacy Release {} drifted", entry.release_id));
        }
        let reference: crate::github::models::GitRef = github.get(&format!(
            "repos/{repository}/git/ref/tags/{}",
            percent_encode(&entry.tag)
        ))?;
        if reference.name != format!("refs/tags/{}", entry.tag)
            || reference.object.kind != "tag"
            || reference.object.sha != entry.tag_object_sha
        {
            return Err("legacy annotated tag ref drifted".to_string());
        }
        let tag: AnnotatedTag = github.get(&format!(
            "repos/{repository}/git/tags/{}",
            entry.tag_object_sha
        ))?;
        if tag.sha != entry.tag_object_sha
            || tag.tag != entry.tag
            || tag.object.kind != "commit"
            || tag.object.sha != entry.peeled_commit_sha
        {
            return Err("legacy annotated tag object drifted".to_string());
        }
        let record = registry
            .exact_version(&entry.package, &entry.version)?
            .ok_or_else(|| "legacy registry record is missing".to_string())?;
        if record.num != entry.version
            || record.yanked
            || record.checksum != entry.source_archive_sha256
        {
            return Err("legacy registry record drifted".to_string());
        }
        let archive = registry.download(&entry.package, &entry.version)?;
        if sha256(&archive) != entry.source_archive_sha256 {
            return Err("legacy source archive checksum drifted".to_string());
        }
        crate::crate_archive::inspect_archive_entries(
            &archive,
            package_policy,
            &entry.version,
            &entry.peeled_commit_sha,
        )?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct DispatchEvent {
    action: String,
    sender: DispatchActor,
    repository: DispatchRepository,
    client_payload: ReleaseNotification,
}

#[derive(Debug, Deserialize)]
struct DispatchActor {
    id: u64,
    login: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize)]
struct DispatchRepository {
    full_name: String,
    default_branch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseNotification {
    schema_version: u64,
    repository: String,
    captured_sha: String,
    release_plan_digest: String,
    intent_check_id: u64,
    intent_external_id: String,
    releases: Vec<FinalizedEntry>,
}

#[derive(Serialize)]
struct RepositoryDispatch<'a> {
    event_type: &'static str,
    client_payload: &'a ReleaseNotification,
}

#[derive(Debug, Deserialize)]
struct WorkflowRun {
    id: u64,
    run_attempt: u64,
    head_sha: String,
    head_branch: String,
    event: String,
    path: String,
    status: String,
    conclusion: Option<String>,
    repository: DispatchRepositoryName,
}

#[derive(Debug, Deserialize)]
struct DispatchRepositoryName {
    full_name: String,
}

#[derive(Serialize)]
struct ReplayDocument<'a> {
    schema_version: u64,
    repository: &'a str,
    release_ids: Vec<u64>,
    tags: Vec<&'a str>,
    captured_sha: &'a str,
    release_plan_digest: &'a str,
    intent_check_id: u64,
}

pub(super) fn receive_command(
    root: &Path,
    input: ReceiveInput<'_>,
    github: &mut impl Transport,
) -> Result<(), String> {
    let mut registry = CratesIo::new();
    let result = receive_with_registry(root, input, github, &mut registry)?;
    let intent_check_id = result.intent_check_id.to_string();
    append_outputs(&[
        ("authorized", "true"),
        ("replay_key", &result.replay_key),
        ("replay_state", result.replay_state),
        ("captured_release_sha", &result.captured_release_sha),
        ("release_plan_digest", &result.release_plan_digest),
        ("intent_check_id", &intent_check_id),
        ("policy_sha", &result.policy_sha),
    ])
}

fn receive_with_registry(
    root: &Path,
    input: ReceiveInput<'_>,
    github: &mut impl Transport,
    registry: &mut impl Registry,
) -> Result<ReceiveResult, String> {
    require_current_policy_source(root, input.repository, input.policy_commit, github)?;
    let event = read_dispatch_event(input.event)?;
    require_notification_size(&event.client_payload)?;
    validate_notification_shape(input.repository, &event.client_payload)?;
    validate_dispatch_identity(&event, input.repository, input.policy_commit, github)?;
    let payload = event.client_payload;

    let check: CheckRun = github.get(&format!(
        "repos/{}/check-runs/{}",
        input.repository, payload.intent_check_id
    ))?;
    let intent_body = check
        .output
        .summary
        .clone()
        .ok_or_else(|| "release intent Check summary is absent".to_string())?;
    let preliminary: IntentRecord = serde_json::from_str(&intent_body)
        .map_err(|error| format!("release intent schema is invalid: {error}"))?;
    let (plan_body, plan_digest) = encode_plan(&preliminary.plan)?;
    if plan_digest != payload.release_plan_digest {
        return Err("release notification plan digest is wrong".to_string());
    }
    let plan = decode_plan(&plan_body, &plan_digest)?;
    let intent = decode_intent(&intent_body, &plan, &plan_digest)?;
    if check.id != payload.intent_check_id
        || check.external_id != payload.intent_external_id
        || intent.external_id != payload.intent_external_id
    {
        return Err("release notification intent identity is wrong".to_string());
    }
    validate_intent_check(&check, &intent, &intent_body)?;
    validate_notification_bindings(input.repository, input.policy_commit, &payload, &intent)?;
    validate_origin_run(input.repository, &intent, github)?;

    let policy = release_policy_for_repository(input.repository)?;
    let mut inspected = vec![false; plan.packages.len()];
    if !observe_registry(&plan, policy, registry, &mut inspected, true)? {
        return Err("crates.io does not contain the complete release train".to_string());
    }
    validate_notification_releases(input.repository, &payload, &intent, github)?;

    let replay = ReplayDocument {
        schema_version: 1,
        repository: input.repository,
        release_ids: payload
            .releases
            .iter()
            .map(|entry| entry.release_id)
            .collect(),
        tags: payload
            .releases
            .iter()
            .map(|entry| entry.tag.as_str())
            .collect(),
        captured_sha: &payload.captured_sha,
        release_plan_digest: &payload.release_plan_digest,
        intent_check_id: payload.intent_check_id,
    };
    let replay_body = serde_json::to_vec(&replay)
        .map_err(|error| format!("encode release replay document: {error}"))?;
    let replay_key = sha256(&replay_body);
    let replay_state = crate::github::release_pr::notification_replay_state(
        github,
        input.repository,
        &replay_key,
    )?;
    Ok(ReceiveResult {
        replay_key,
        replay_state,
        captured_release_sha: payload.captured_sha,
        release_plan_digest: payload.release_plan_digest,
        intent_check_id: payload.intent_check_id,
        policy_sha: input.policy_commit.to_string(),
    })
}

fn read_dispatch_event(path: &Path) -> Result<DispatchEvent, String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| "repository dispatch event path has no file name".to_string())?;
    let body = crate::safe_file::TrustedRoot::open(parent)
        .and_then(|root| root.read_utf8(Path::new(name), MAX_EVENT_BYTES))
        .map_err(|error| format!("read repository dispatch event: {error}"))?;
    if body.is_empty() {
        return Err("repository dispatch event is empty".to_string());
    }
    serde_json::from_str(&body)
        .map_err(|error| format!("repository dispatch event is invalid JSON: {error}"))
}

fn validate_dispatch_identity(
    event: &DispatchEvent,
    repository: &str,
    policy_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    if event.action != "official-release-published"
        || event.sender.id != APP_ID
        || event.sender.login != APP_LOGIN
        || event.sender.kind != "Bot"
        || event.repository.full_name != repository
        || event.repository.default_branch != "main"
    {
        return Err("repository dispatch identity is wrong".to_string());
    }
    let live: DispatchRepository = github.get(&format!("repos/{repository}"))?;
    if live.full_name != repository || live.default_branch != "main" {
        return Err("live repository identity is wrong".to_string());
    }
    let sender: DispatchActor = github.get(&format!("users/{}", percent_encode(APP_LOGIN)))?;
    if sender.id != APP_ID || sender.login != APP_LOGIN || sender.kind != "Bot" {
        return Err("live release sender identity is wrong".to_string());
    }
    let reference: crate::github::models::GitRef =
        github.get(&format!("repos/{repository}/git/ref/heads/main"))?;
    if reference.object.sha != policy_commit {
        return Err("release receiver policy changed during authentication".to_string());
    }
    Ok(())
}

fn canonical_release_version(value: &str) -> bool {
    let Ok(version) = semver::Version::parse(value) else {
        return false;
    };
    if version.to_string() != value || !version.build.is_empty() {
        return false;
    }
    if version.pre.is_empty() {
        return true;
    }
    let Some(number) = version.pre.as_str().strip_prefix("rc.") else {
        return false;
    };
    !number.is_empty()
        && number.as_bytes()[0] != b'0'
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn require_notification_size(payload: &ReleaseNotification) -> Result<(), String> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|error| format!("encode release notification: {error}"))?;
    if bytes.len() > MAX_NOTIFICATION_BYTES {
        return Err("release notification exceeds its byte bound".to_string());
    }
    Ok(())
}

fn validate_notification_shape(
    repository: &str,
    payload: &ReleaseNotification,
) -> Result<(), String> {
    let policy = release_policy_for_repository(repository)?;
    if payload.schema_version != NOTIFICATION_SCHEMA
        || payload.repository != repository
        || !is_sha(&payload.captured_sha)
        || !is_digest(&payload.release_plan_digest)
        || payload.intent_check_id == 0
        || payload.intent_check_id > i64::MAX as u64
        || !is_digest(&payload.intent_external_id)
        || payload.releases.len() != policy.packages.len()
    {
        return Err("release notification binding is invalid".to_string());
    }
    let mut ids = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for (entry, package) in payload.releases.iter().zip(policy.packages) {
        if entry.package != package.package
            || !canonical_release_version(&entry.version)
            || entry.tag != package.tag(&entry.version)
            || entry.release_id == 0
            || entry.release_id > i64::MAX as u64
            || !is_sha(&entry.tag_object_id)
            || !is_digest(&entry.release_body_sha256)
            || !ids.insert(entry.release_id)
            || !tags.insert(entry.tag.as_str())
        {
            return Err("release notification entry is invalid or noncanonical".to_string());
        }
    }
    Ok(())
}

fn validate_notification_bindings(
    repository: &str,
    policy_commit: &str,
    payload: &ReleaseNotification,
    intent: &IntentRecord,
) -> Result<(), String> {
    let plan = &intent.plan;
    let policy = release_policy_for_repository(repository)?;
    if plan.repository != repository
        || plan.release_sha != payload.captured_sha
        || plan.policy_commit != policy_commit
        || plan.packages.len() != policy.packages.len()
        || intent.tags.len() != policy.packages.len()
        || payload.releases.len() != policy.packages.len()
        || plan
            .packages
            .iter()
            .any(|package| !matches!(package.release_objects, ReleaseObjectBaseline::Absent))
    {
        return Err("release notification package family or policy binding is wrong".to_string());
    }
    let mut ids = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for (((entry, package), tag), package_policy) in payload
        .releases
        .iter()
        .zip(&plan.packages)
        .zip(&intent.tags)
        .zip(policy.packages)
    {
        if !canonical_release_version(&entry.version)
            || entry.package != package_policy.package
            || entry.package != package.package
            || entry.package != tag.package
            || entry.version != package.version
            || entry.tag != package_policy.tag(&entry.version)
            || entry.tag != package.tag
            || entry.tag != tag.tag
            || entry.release_id == 0
            || entry.tag_object_id != tag.tag_object_id
            || entry.release_body_sha256 != package.release_body_sha256
            || entry.release_body_sha256 != tag.release_body_sha256
            || package.prerelease != entry.version.contains('-')
            || !ids.insert(entry.release_id)
            || !tags.insert(entry.tag.as_str())
        {
            return Err("release notification entry differs from current policy".to_string());
        }
    }
    Ok(())
}

fn validate_origin_run(
    repository: &str,
    intent: &IntentRecord,
    github: &mut impl Transport,
) -> Result<(), String> {
    let run: WorkflowRun = github.get(&format!(
        "repos/{repository}/actions/runs/{}",
        intent.origin_run_id
    ))?;
    if run.id != intent.origin_run_id
        || run.run_attempt != intent.origin_run_attempt
        || run.head_sha != intent.release_sha
        || run.head_branch != "main"
        || run.event != "workflow_dispatch"
        || run.path != ".github/workflows/publish.yml"
        || !matches!(
            run.status.as_str(),
            "queued" | "in_progress" | "waiting" | "completed"
        )
        || run
            .conclusion
            .as_deref()
            .is_some_and(|conclusion| conclusion != "success")
        || run.repository.full_name != repository
    {
        return Err(
            "originating workflow identity, source, attempt, or state is wrong".to_string(),
        );
    }
    let expected = settings_evidence_sha256(
        repository,
        &intent.release_sha,
        intent.origin_run_id,
        intent.origin_run_attempt,
    )?;
    if intent.ruleset_evidence_sha256 != expected {
        return Err("ruleset evidence does not bind the originating workflow".to_string());
    }
    Ok(())
}

fn validate_notification_releases(
    repository: &str,
    payload: &ReleaseNotification,
    intent: &IntentRecord,
    github: &mut impl Transport,
) -> Result<(), String> {
    for ((entry, package), tag_intent) in payload
        .releases
        .iter()
        .zip(&intent.plan.packages)
        .zip(&intent.tags)
    {
        let release: Release =
            github.get(&format!("repos/{repository}/releases/{}", entry.release_id))?;
        if release.id != entry.release_id {
            return Err("GitHub Release ID differs from the notification".to_string());
        }
        validate_release(&release, package)?;
        let by_tag: Release = github.get(&format!(
            "repos/{repository}/releases/tags/{}",
            percent_encode(&entry.tag)
        ))?;
        if by_tag.id != entry.release_id {
            return Err("GitHub Release tag lookup disagrees".to_string());
        }
        let reference: crate::github::models::GitRef = github.get(&format!(
            "repos/{repository}/git/ref/tags/{}",
            percent_encode(&entry.tag)
        ))?;
        if reference.name != format!("refs/tags/{}", entry.tag)
            || reference.object.kind != "tag"
            || reference.object.sha != entry.tag_object_id
        {
            return Err("annotated tag ref differs from the notification".to_string());
        }
        let tag: AnnotatedTag = github.get(&format!(
            "repos/{repository}/git/tags/{}",
            entry.tag_object_id
        ))?;
        validate_tag_object(&tag, &intent.plan, package, tag_intent)?;
    }
    Ok(())
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

fn load_policy_snapshot(
    root: &Path,
    repository: &str,
    commit: &str,
    expected_legacy_inventory_sha256: Option<&str>,
    github: &mut impl Transport,
) -> Result<PolicySnapshot, String> {
    if !is_sha(commit) || expected_legacy_inventory_sha256.is_some_and(|digest| !is_digest(digest))
    {
        return Err("release policy binding is invalid".to_string());
    }
    repository_policy_for_root(root, repository)?;
    require_captured_ancestry(github, repository, commit)?;
    let config = read_policy_blob(root, commit, ".release-plz.toml")?;
    let inventory_text = read_policy_blob(root, commit, ".github/legacy-release-inventory.json")?;
    let inventory_digest = sha256(inventory_text.as_bytes());
    if expected_legacy_inventory_sha256.is_some_and(|expected| expected != inventory_digest) {
        return Err("legacy Release inventory digest differs from protected policy".to_string());
    }
    let inventory: LegacyInventory = serde_json::from_str(&inventory_text)
        .map_err(|error| format!("parse legacy Release inventory: {error}"))?;
    validate_legacy_inventory(repository, &inventory)?;
    Ok(PolicySnapshot {
        commit: commit.to_string(),
        release_config_sha256: sha256(config.as_bytes()),
        legacy_inventory_sha256: inventory_digest,
        legacy_inventory: inventory,
    })
}

fn read_policy_blob(root: &Path, commit: &str, path: &str) -> Result<String, String> {
    let entry = git_output(root, &["ls-tree", "-z", "--full-tree", commit, "--", path])?;
    let suffix = format!("\t{path}\0");
    let metadata = entry
        .strip_suffix(&suffix)
        .ok_or_else(|| format!("protected policy lacks one exact regular file {path}"))?;
    let mut fields = metadata.split(' ');
    let mode = fields.next();
    let kind = fields.next();
    let object = fields.next();
    if mode != Some("100644")
        || kind != Some("blob")
        || object.is_none_or(|sha| !is_sha(sha))
        || fields.next().is_some()
    {
        return Err(format!(
            "protected policy file {path} is not one regular blob"
        ));
    }
    let object_spec = format!("{commit}:{path}");
    let body = git_output(root, &["show", &object_spec])?;
    if body.is_empty()
        || body.len() > MAX_POLICY_FILE_BYTES
        || body.contains('\0')
        || !body.ends_with('\n')
    {
        return Err(format!(
            "protected policy file {path} is empty or noncanonical"
        ));
    }
    Ok(body)
}

fn validate_legacy_inventory(repository: &str, inventory: &LegacyInventory) -> Result<(), String> {
    let release_policy = release_policy_for_repository(repository)?;
    if inventory.schema_version != 1
        || inventory.api_version != GITHUB_API_VERSION
        || inventory.repository != repository
        || inventory.legacy_author.id != LEGACY_AUTHOR_ID
        || inventory.legacy_author.login != LEGACY_AUTHOR_LOGIN
        || inventory.legacy_author.kind != "Bot"
        || inventory.prospective_author.id != APP_ID
        || inventory.prospective_author.login != APP_LOGIN
        || inventory.prospective_author.kind != "Bot"
        || inventory.entries.is_empty()
        || inventory.entries.len() > MAX_LEGACY_RELEASES
    {
        return Err("legacy Release inventory binding is invalid".to_string());
    }
    let mut ids = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut versions = BTreeSet::new();
    for entry in &inventory.entries {
        let version = semver::Version::parse(&entry.version)
            .map_err(|_| "legacy Release version is invalid".to_string())?;
        let package_policy = release_policy
            .packages
            .iter()
            .find(|policy| policy.package == entry.package)
            .ok_or_else(|| "legacy Release package is outside repository policy".to_string())?;
        if entry.release_id == 0
            || entry.package.is_empty()
            || entry.package.len() > 128
            || entry.version.len() > 128
            || version.to_string() != entry.version
            || entry.tag != package_policy.tag(&entry.version)
            || entry.tag.len() > 256
            || entry.tag.contains(['\0', '\r', '\n'])
            || !is_sha(&entry.tag_object_sha)
            || !is_sha(&entry.peeled_commit_sha)
            || entry.target_commitish != "main"
            || entry.draft
            || entry.prerelease != !version.pre.is_empty()
            || entry.immutable
            || entry.asset_count != 0
            || !is_digest(&entry.body_sha256)
            || !is_digest(&entry.source_archive_sha256)
            || entry.path_in_vcs != package_policy.path_in_vcs
            || entry.path_in_vcs.len() > 256
            || entry.path_in_vcs.contains(['\0', '\r', '\n', '\\'])
            || !ids.insert(entry.release_id)
            || !tags.insert(entry.tag.clone())
            || !versions.insert((entry.package.clone(), entry.version.clone()))
        {
            return Err("legacy Release inventory entry is invalid".to_string());
        }
    }
    Ok(())
}

fn require_source_only_config_for_specs(
    root: &Path,
    policy_commit: &str,
    specs: &[ReleaseSpec<'_>],
    expected_digest: &str,
) -> Result<(), String> {
    let config = read_policy_blob(root, policy_commit, ".release-plz.toml")?;
    if sha256(config.as_bytes()) != expected_digest {
        return Err("release-plz policy changed during plan capture".to_string());
    }
    require_source_only_config(&config, specs)
}

fn legacy_release_entry<'a>(
    inventory: &'a LegacyInventory,
    spec: &ReleaseSpec<'_>,
    commit: &str,
    registry_checksum: &str,
) -> Result<Option<&'a LegacyEntry>, String> {
    let release_body_sha256 = sha256(spec.body.as_bytes());
    let mut matches = inventory.entries.iter().filter(|entry| {
        entry.package == spec.policy.package
            && entry.version == spec.version
            && entry.tag == spec.tag
            && entry.peeled_commit_sha == commit
            && entry.prerelease == spec.prerelease
            && entry.body_sha256 == release_body_sha256
            && entry.source_archive_sha256 == registry_checksum
            && entry.path_in_vcs == spec.policy.path_in_vcs
    });
    let Some(entry) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("legacy Release inventory matches one package more than once".to_string());
    }
    Ok(Some(entry))
}

fn require_uniform_legacy_train(packages: &[PlanPackage]) -> Result<(), String> {
    let legacy = packages
        .iter()
        .filter(|package| {
            matches!(
                package.release_objects,
                ReleaseObjectBaseline::Legacy { .. }
            )
        })
        .count();
    if legacy != 0 && legacy != packages.len() {
        return Err("release train mixes legacy and prospective objects".to_string());
    }
    Ok(())
}

fn capture_plan(
    input: PlanCaptureInput<'_>,
    github: &mut impl Transport,
    registry: &mut impl Registry,
) -> Result<ReleasePlan, String> {
    let PlanCaptureInput {
        root,
        repository,
        commit,
        policy: policy_snapshot,
        baseline_version,
        baseline_commit,
    } = input;
    if !is_sha(commit) {
        return Err("release plan commit must be one lowercase full SHA".to_string());
    }
    let repository_policy = repository_policy_for_root(root, repository)?;
    crate::crate_archive::require_clean_source(root, commit)?;
    let version = manifest_version(root, repository_policy.kind)?;
    let policy = detect(root)?;
    let specs = release_specs(root, policy, &version)?;
    if specs.is_empty() || specs.len() > MAX_RELEASE_PACKAGES {
        return Err("release plan package count is outside its bound".to_string());
    }
    require_source_only_config_for_specs(
        root,
        &policy_snapshot.commit,
        &specs,
        &policy_snapshot.release_config_sha256,
    )?;
    let (tagger_epoch, tagger_date) = commit_timestamp(root, commit)?;
    let mut packages = Vec::with_capacity(specs.len());
    for spec in &specs {
        let record = registry.exact_version(spec.policy.package, &spec.version)?;
        let (source_archive_sha256, package_inventory_sha256, registry, release_objects) =
            match record {
                None => {
                    let archive = package_source(root, spec)?;
                    let source_archive_sha256 = sha256(&archive);
                    let archive_entries = crate::crate_archive::inspect_archive_entries(
                        &archive,
                        spec.policy,
                        &spec.version,
                        commit,
                    )?;
                    (
                        source_archive_sha256,
                        archive_inventory_sha256(&archive_entries),
                        RegistryBaseline {
                            state: RegistryState::Absent,
                            checksum: None,
                        },
                        ReleaseObjectBaseline::Absent,
                    )
                }
                Some(record) => {
                    if record.num != spec.version
                        || record.yanked
                        || !crate::crate_archive::is_checksum(&record.checksum)
                    {
                        return Err(format!(
                            "{} registry state is not one exact non-yanked version",
                            spec.policy.package
                        ));
                    }
                    if let Some(legacy) = legacy_release_entry(
                        &policy_snapshot.legacy_inventory,
                        spec,
                        commit,
                        &record.checksum,
                    )? {
                        // A closed historical inventory is grandfathered state,
                        // not a prospective archive-reproduction exception.
                        let archive = registry.download(spec.policy.package, &spec.version)?;
                        if sha256(&archive) != record.checksum {
                            return Err(format!(
                                "{} legacy registry archive checksum drifted",
                                spec.policy.package
                            ));
                        }
                        let archive_entries = crate::crate_archive::inspect_archive_entries(
                            &archive,
                            spec.policy,
                            &spec.version,
                            commit,
                        )?;
                        (
                            record.checksum.clone(),
                            archive_inventory_sha256(&archive_entries),
                            RegistryBaseline {
                                state: RegistryState::Present,
                                checksum: Some(record.checksum.clone()),
                            },
                            ReleaseObjectBaseline::Legacy {
                                release_id: legacy.release_id,
                                tag_object_sha: legacy.tag_object_sha.clone(),
                            },
                        )
                    } else {
                        let checksum = require_reproduced_archive(root, registry, spec, commit)?;
                        if checksum != record.checksum {
                            return Err(format!(
                                "{} registry checksum changed during plan capture",
                                spec.policy.package
                            ));
                        }
                        let archive = package_source(root, spec)?;
                        let source_archive_sha256 = sha256(&archive);
                        let archive_entries = crate::crate_archive::inspect_archive_entries(
                            &archive,
                            spec.policy,
                            &spec.version,
                            commit,
                        )?;
                        (
                            source_archive_sha256,
                            archive_inventory_sha256(&archive_entries),
                            RegistryBaseline {
                                state: RegistryState::Present,
                                checksum: Some(checksum),
                            },
                            ReleaseObjectBaseline::Absent,
                        )
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
            release_objects,
        });
    }
    require_registry_prefix(&packages)?;
    require_uniform_legacy_train(&packages)?;
    let authorization = if packages.iter().all(|package| {
        matches!(
            package.release_objects,
            ReleaseObjectBaseline::Legacy { .. }
        )
    }) {
        PlanAuthorization::LegacyInventory
    } else {
        let main_requirement = main_requirement(&packages);
        authorize_source(
            github,
            repository,
            commit,
            root,
            baseline_version,
            baseline_commit,
            main_requirement,
        )?
        .into()
    };
    Ok(ReleasePlan {
        schema_version: PLAN_SCHEMA,
        repository: repository.to_string(),
        release_sha: commit.to_string(),
        policy_commit: policy_snapshot.commit.clone(),
        authorization,
        release_plz_version: RELEASE_PLZ_VERSION.to_string(),
        release_config_sha256: policy_snapshot.release_config_sha256.clone(),
        legacy_inventory_sha256: policy_snapshot.legacy_inventory_sha256.clone(),
        tagger_epoch,
        tagger_date,
        packages,
    })
}

fn main_requirement(packages: &[PlanPackage]) -> MainRequirement {
    if packages
        .iter()
        .all(|package| package.registry.state == RegistryState::Absent)
    {
        MainRequirement::Exact
    } else {
        MainRequirement::Ancestry
    }
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
        || !is_sha(&plan.policy_commit)
        || plan.repository.is_empty()
        || plan.release_plz_version != RELEASE_PLZ_VERSION
        || !is_digest(&plan.release_config_sha256)
        || !is_digest(&plan.legacy_inventory_sha256)
        || plan.tagger_epoch == 0
        || plan.tagger_date.is_empty()
        || plan.tagger_date.len() > 64
        || plan.packages.is_empty()
        || plan.packages.len() > MAX_RELEASE_PACKAGES
        || !valid_plan_authorization(&plan.authorization)
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
            || matches!(
                package.release_objects,
                ReleaseObjectBaseline::Legacy { release_id: 0, .. }
            )
            || matches!(
                &package.release_objects,
                ReleaseObjectBaseline::Legacy { tag_object_sha, .. }
                    if !is_sha(tag_object_sha)
            )
            || (matches!(
                package.release_objects,
                ReleaseObjectBaseline::Legacy { .. }
            ) && package.registry.state != RegistryState::Present)
        {
            return Err("release plan package binding is invalid".to_string());
        }
    }
    require_registry_prefix(&plan.packages)?;
    require_uniform_legacy_train(&plan.packages)?;
    let all_legacy = plan.packages.iter().all(|package| {
        matches!(
            package.release_objects,
            ReleaseObjectBaseline::Legacy { .. }
        )
    });
    if matches!(plan.authorization, PlanAuthorization::LegacyInventory) != all_legacy {
        return Err("release plan authorization does not match its object baseline".to_string());
    }
    Ok(())
}

fn valid_plan_authorization(authorization: &PlanAuthorization) -> bool {
    match authorization {
        PlanAuthorization::Proposal {
            pull_request,
            proposal_commit,
            base_commit,
            owner_id,
            merger_id,
        } => {
            *pull_request != 0
                && is_sha(proposal_commit)
                && is_sha(base_commit)
                && *owner_id != 0
                && *merger_id != 0
        }
        PlanAuthorization::LegacyInventory => true,
    }
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
    let expected_ruleset_evidence = settings_evidence_sha256(
        &plan.repository,
        &plan.release_sha,
        origin_run_id,
        origin_run_attempt,
    )?;
    if ruleset_evidence_sha256 != expected_ruleset_evidence {
        return Err("ruleset evidence does not match canonical release settings".to_string());
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
        let (tag_message, object_id) = match &package.release_objects {
            ReleaseObjectBaseline::Absent => {
                let tag_message = format!(
                    "chore: Release package {} version {}",
                    package.package, package.version
                );
                let payload = annotated_tag_payload(plan, &package.tag, &tag_message)?;
                let object_id = hash_git_object(root, "tag", payload.as_bytes())?;
                (tag_message, object_id)
            }
            ReleaseObjectBaseline::Legacy { tag_object_sha, .. } => {
                (String::new(), tag_object_sha.clone())
            }
        };
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
    let expected_ruleset_evidence = settings_evidence_sha256(
        &record.repository,
        &record.release_sha,
        record.origin_run_id,
        record.origin_run_attempt,
    )?;
    if record.ruleset_evidence_sha256 != expected_ruleset_evidence {
        return Err(
            "release intent ruleset evidence does not match canonical release settings".to_string(),
        );
    }
    for ((tag, package), index) in record.tags.iter().zip(&plan.packages).zip(0..) {
        let expected_message = match package.release_objects {
            ReleaseObjectBaseline::Absent => format!(
                "chore: Release package {} version {}",
                package.package, package.version
            ),
            ReleaseObjectBaseline::Legacy { .. } => String::new(),
        };
        if tag.package != package.package
            || tag.tag != package.tag
            || !is_sha(&tag.tag_object_id)
            || tag.release_body_sha256 != package.release_body_sha256
            || tag.tag_message != expected_message
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
        let (tag_object_id, release) = match &package.release_objects {
            ReleaseObjectBaseline::Absent => {
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
                (tag_object_id, release)
            }
            ReleaseObjectBaseline::Legacy { tag_object_sha, .. } => (
                tag_object_sha.clone(),
                require_legacy_release_objects(github, input.repository, &plan, package)?,
            ),
        };
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
        (
            "notification_required",
            if present == plan.packages.len()
                && plan
                    .packages
                    .iter()
                    .all(|package| matches!(package.release_objects, ReleaseObjectBaseline::Absent))
            {
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

fn require_legacy_release_objects(
    github: &mut impl Transport,
    repository: &str,
    plan: &ReleasePlan,
    package: &PlanPackage,
) -> Result<Release, String> {
    let ReleaseObjectBaseline::Legacy {
        release_id,
        tag_object_sha,
    } = &package.release_objects
    else {
        return Err("legacy Release verification requires a legacy plan entry".to_string());
    };
    let ref_path = format!(
        "repos/{repository}/git/ref/tags/{}",
        percent_encode(&package.tag)
    );
    let reference: crate::github::models::GitRef = github.get(&ref_path)?;
    if reference.name != format!("refs/tags/{}", package.tag)
        || reference.object.kind != "tag"
        || reference.object.sha != *tag_object_sha
    {
        return Err(format!("legacy annotated tag {} drifted", package.tag));
    }
    let object: AnnotatedTag =
        github.get(&format!("repos/{repository}/git/tags/{tag_object_sha}"))?;
    if object.sha != *tag_object_sha
        || object.tag != package.tag
        || object.object.kind != "commit"
        || object.object.sha != plan.release_sha
    {
        return Err(format!(
            "legacy annotated tag {} object drifted",
            package.tag
        ));
    }
    let release: Release = github.get(&format!(
        "repos/{repository}/releases/tags/{}",
        percent_encode(&package.tag)
    ))?;
    if release.id != *release_id
        || release.tag_name != package.tag
        || release.target_commitish != "main"
        || release.body != package.release_body
        || sha256(release.body.as_bytes()) != package.release_body_sha256
        || release.draft
        || release.prerelease != package.prerelease
        || release.immutable
        || release.author.login != LEGACY_AUTHOR_LOGIN
        || release.author.id != LEGACY_AUTHOR_ID
        || release.author.kind != "Bot"
        || !release.assets.is_empty()
    {
        return Err(format!("legacy GitHub Release {} drifted", package.tag));
    }
    Ok(release)
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
    let notification = ReleaseNotification {
        schema_version: NOTIFICATION_SCHEMA,
        repository: input.repository.to_string(),
        captured_sha: plan.release_sha,
        release_plan_digest: input.plan_digest.to_string(),
        intent_check_id: check_id,
        intent_external_id: intent.external_id,
        releases: entries,
    };
    require_notification_size(&notification)?;
    validate_notification_shape(input.repository, &notification)?;
    let payload = RepositoryDispatch {
        event_type: "official-release-published",
        client_payload: &notification,
    };
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

pub(super) fn settings_evidence_tag_patterns(
    repository: &str,
) -> Result<&'static [&'static str], String> {
    match repository {
        "NVIDIA/yaml-sigil-traits" => Ok(TRAITS_TAG_PATTERNS),
        "NVIDIA/yaml-sigil-rs" => Ok(RS_TAG_PATTERNS),
        _ => Err("repository is outside the settings-evidence policy".to_string()),
    }
}

fn update_settings_evidence_digest(digest: &mut Sha256, value: &str) {
    digest.update(value.as_bytes());
    digest.update(b"\0");
}

pub(super) fn settings_evidence_sha256(
    repository: &str,
    release_sha: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<String, String> {
    let tag_patterns = settings_evidence_tag_patterns(repository)?;
    if !is_sha(release_sha) {
        return Err("release SHA is invalid".to_string());
    }
    if run_id == 0 {
        return Err("workflow run ID is invalid".to_string());
    }
    if run_attempt == 0 {
        return Err("workflow run attempt is invalid".to_string());
    }

    let mut digest = Sha256::new();
    for value in [
        "yaml-sigil-release-setting-evidence-v1",
        repository,
        &run_id.to_string(),
        &run_attempt.to_string(),
        release_sha,
        "immutable-releases=true",
    ] {
        update_settings_evidence_digest(&mut digest, value);
    }
    for pattern in tag_patterns {
        update_settings_evidence_digest(
            &mut digest,
            &format!("creation={pattern}:Integration:{APP_PUBLIC_ID}:always"),
        );
    }
    for pattern in tag_patterns {
        update_settings_evidence_digest(&mut digest, &format!("update-delete={pattern}:no-bypass"));
    }
    update_settings_evidence_digest(
        &mut digest,
        &format!("forbidden-required-check={INTENT_NAME}"),
    );
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::RELEASE_BRANCH;
    use crate::github::transport::fake::{Expected, FakeTransport};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs;

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

    struct FixtureRegistry {
        record: crate::crate_archive::RegistryVersion,
        archive: Vec<u8>,
        downloads: usize,
    }

    impl Registry for FixtureRegistry {
        fn exact_version(
            &mut self,
            package: &str,
            version: &str,
        ) -> Result<Option<crate::crate_archive::RegistryVersion>, String> {
            if package != "yaml-sigil-traits" || version != "0.4.0" {
                return Err("unexpected fixture registry identity".to_string());
            }
            Ok(Some(self.record.clone()))
        }

        fn download(&mut self, package: &str, version: &str) -> Result<Vec<u8>, String> {
            if package != "yaml-sigil-traits" || version != "0.4.0" {
                return Err("unexpected fixture archive identity".to_string());
            }
            self.downloads += 1;
            Ok(self.archive.clone())
        }
    }

    fn plan() -> ReleasePlan {
        ReleasePlan {
            schema_version: PLAN_SCHEMA,
            repository: "NVIDIA/yaml-sigil-traits".to_string(),
            release_sha: "a".repeat(40),
            policy_commit: "9".repeat(40),
            authorization: PlanAuthorization::Proposal {
                pull_request: 50,
                proposal_commit: "b".repeat(40),
                base_commit: "c".repeat(40),
                owner_id: 1,
                merger_id: 2,
            },
            release_plz_version: RELEASE_PLZ_VERSION.to_string(),
            release_config_sha256: "d".repeat(64),
            legacy_inventory_sha256: "e".repeat(64),
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
                release_objects: ReleaseObjectBaseline::Absent,
            }],
        }
    }

    fn run_git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("run fixture Git command");
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("fixture Git output is UTF-8")
            .trim()
            .to_string()
    }

    fn protected_traits_root() -> (tempfile::TempDir, String) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"yaml-sigil-traits\"\nversion = \"0.4.0\"\nedition = \"2024\"\npublish = [\"crates-io\"]\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub trait Fixture {}\n").unwrap();
        run_git(root, &["init", "--quiet"]);
        run_git(root, &["config", "user.name", "Fixture"]);
        run_git(root, &["config", "user.email", "fixture@example.invalid"]);
        run_git(root, &["add", "Cargo.toml", "src/lib.rs"]);
        run_git(
            root,
            &["commit", "--quiet", "--no-gpg-sign", "-m", "fixture"],
        );
        let commit = run_git(root, &["rev-parse", "HEAD"]);
        (temporary, commit)
    }

    fn fixture_archive(commit: &str) -> Vec<u8> {
        let prefix = "yaml-sigil-traits-0.4.0";
        let vcs = serde_json::to_vec(&json!({
            "git": {"sha1": commit},
            "path_in_vcs": "",
        }))
        .unwrap();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::file());
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(crate::crate_archive::CARGO_ARCHIVE_MTIME);
        header.set_username("").unwrap();
        header.set_groupname("").unwrap();
        header.set_size(vcs.len() as u64);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{prefix}/.cargo_vcs_info.json"),
                vcs.as_slice(),
            )
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn protected_policy_blob_is_read_from_its_commit_not_historical_head() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        run_git(root, &["init", "--quiet"]);
        run_git(root, &["config", "core.autocrlf", "false"]);
        run_git(root, &["config", "user.name", "Fixture"]);
        run_git(root, &["config", "user.email", "fixture@example.invalid"]);
        fs::write(root.join(".release-plz.toml"), "historical = true\n").unwrap();
        run_git(root, &["add", ".release-plz.toml"]);
        run_git(
            root,
            &["commit", "--quiet", "--no-gpg-sign", "-m", "historical"],
        );
        let historical = run_git(root, &["rev-parse", "HEAD"]);
        fs::write(root.join(".release-plz.toml"), "protected = true\n").unwrap();
        run_git(root, &["add", ".release-plz.toml"]);
        run_git(
            root,
            &["commit", "--quiet", "--no-gpg-sign", "-m", "protected"],
        );
        let policy = run_git(root, &["rev-parse", "HEAD"]);
        run_git(root, &["checkout", "--quiet", "--detach", &historical]);
        assert_eq!(
            read_policy_blob(root, &policy, ".release-plz.toml").unwrap(),
            "protected = true\n"
        );
        assert_eq!(
            fs::read_to_string(root.join(".release-plz.toml")).unwrap(),
            "historical = true\n"
        );
    }

    #[test]
    fn exact_legacy_objects_are_grandfathered_read_only() {
        let mut plan = plan();
        plan.packages[0].registry = RegistryBaseline {
            state: RegistryState::Present,
            checksum: Some("1".repeat(64)),
        };
        plan.packages[0].release_objects = ReleaseObjectBaseline::Legacy {
            release_id: 42,
            tag_object_sha: "8".repeat(40),
        };
        plan.authorization = PlanAuthorization::LegacyInventory;
        let package = &plan.packages[0];
        let ref_path = format!(
            "repos/{}/git/ref/tags/{}",
            plan.repository,
            percent_encode(&package.tag)
        );
        let object_path = format!("repos/{}/git/tags/{}", plan.repository, "8".repeat(40));
        let release_path = format!(
            "repos/{}/releases/tags/{}",
            plan.repository,
            percent_encode(&package.tag)
        );
        let expectations = |release_body: &str| {
            [
                Expected::json(
                    "GET",
                    &ref_path,
                    json!({
                        "ref": format!("refs/tags/{}", package.tag),
                        "object": {"type": "tag", "sha": "8".repeat(40)},
                    }),
                ),
                Expected::json(
                    "GET",
                    &object_path,
                    json!({
                        "sha": "8".repeat(40),
                        "tag": package.tag,
                        "message": "historical",
                        "tagger": {"name": "historical", "email": "old@example.invalid", "date": "2025-01-01T00:00:00Z"},
                        "object": {"type": "commit", "sha": plan.release_sha},
                    }),
                ),
                Expected::json(
                    "GET",
                    &release_path,
                    json!({
                        "id": 42,
                        "tag_name": package.tag,
                        "target_commitish": "main",
                        "name": "historical name is outside the closed contract",
                        "body": release_body,
                        "draft": false,
                        "prerelease": package.prerelease,
                        "immutable": false,
                        "author": {"login": LEGACY_AUTHOR_LOGIN, "id": LEGACY_AUTHOR_ID, "type": "Bot"},
                        "assets": [],
                    }),
                ),
            ]
        };
        let mut github = FakeTransport::new(expectations(&package.release_body));
        let release =
            require_legacy_release_objects(&mut github, &plan.repository, &plan, package).unwrap();
        assert_eq!(release.id, 42);
        github.finish();

        let digest = settings_evidence_sha256(&plan.repository, &plan.release_sha, 100, 1).unwrap();
        let (_, plan_digest) = encode_plan(&plan).unwrap();
        let intent = build_intent(Path::new("."), &plan, &plan_digest, 100, 1, &digest).unwrap();
        assert_eq!(intent.tags[0].tag_object_id, "8".repeat(40));
        assert!(intent.tags[0].tag_message.is_empty());

        let mut github = FakeTransport::new(expectations("drifted historical body"));
        assert!(
            require_legacy_release_objects(&mut github, &plan.repository, &plan, package)
                .unwrap_err()
                .contains("drifted")
        );
        github.finish();
    }

    #[test]
    fn only_exact_closed_inventory_uses_the_historical_archive() {
        let policy = &crate::release_policy::TRAITS_POLICY.packages[0];
        let spec = ReleaseSpec {
            policy,
            version: "0.4.0-rc.2".to_string(),
            tag: "v0.4.0-rc.2".to_string(),
            body: "historical notes".to_string(),
            prerelease: true,
        };
        let commit = "a".repeat(40);
        let checksum = "b".repeat(64);
        let inventory = LegacyInventory {
            schema_version: 1,
            api_version: GITHUB_API_VERSION.to_string(),
            repository: "NVIDIA/yaml-sigil-traits".to_string(),
            legacy_author: LegacyAuthor {
                id: LEGACY_AUTHOR_ID,
                login: LEGACY_AUTHOR_LOGIN.to_string(),
                kind: "Bot".to_string(),
            },
            prospective_author: LegacyAuthor {
                id: APP_ID,
                login: APP_LOGIN.to_string(),
                kind: "Bot".to_string(),
            },
            entries: vec![LegacyEntry {
                release_id: 42,
                package: policy.package.to_string(),
                version: spec.version.clone(),
                tag: spec.tag.clone(),
                tag_object_sha: "c".repeat(40),
                peeled_commit_sha: commit.clone(),
                target_commitish: "main".to_string(),
                draft: false,
                prerelease: true,
                immutable: false,
                asset_count: 0,
                body_sha256: sha256(spec.body.as_bytes()),
                source_archive_sha256: checksum.clone(),
                path_in_vcs: policy.path_in_vcs.to_string(),
            }],
        };
        assert_eq!(
            legacy_release_entry(&inventory, &spec, &commit, &checksum)
                .unwrap()
                .unwrap()
                .release_id,
            42
        );
        assert!(
            legacy_release_entry(&inventory, &spec, &commit, &"d".repeat(64))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn source_requires_current_main_until_registry_recovery_exists() {
        let mut plan = plan();
        assert_eq!(main_requirement(&plan.packages), MainRequirement::Exact);
        plan.packages[0].registry.state = RegistryState::Present;
        assert_eq!(main_requirement(&plan.packages), MainRequirement::Ancestry);
    }

    fn intent_fixture() -> (ReleasePlan, IntentRecord, String) {
        let plan = plan();
        let (_, plan_digest) = encode_plan(&plan).unwrap();
        let ruleset_evidence_sha256 =
            settings_evidence_sha256(&plan.repository, &plan.release_sha, 100, 1).unwrap();
        let intent = IntentRecord {
            schema_version: INTENT_SCHEMA,
            repository: plan.repository.clone(),
            release_sha: plan.release_sha.clone(),
            plan_digest,
            external_id: "6".repeat(64),
            origin_run_id: 100,
            origin_run_attempt: 1,
            ruleset_evidence_sha256,
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

    fn notification_fixture() -> ReleaseNotification {
        let (plan, intent, _) = intent_fixture();
        let package = &plan.packages[0];
        ReleaseNotification {
            schema_version: NOTIFICATION_SCHEMA,
            repository: plan.repository.clone(),
            captured_sha: plan.release_sha.clone(),
            release_plan_digest: intent.plan_digest,
            intent_check_id: 900,
            intent_external_id: intent.external_id,
            releases: vec![FinalizedEntry {
                package: package.package.clone(),
                version: package.version.clone(),
                release_id: 1_000,
                tag: package.tag.clone(),
                tag_object_id: intent.tags[0].tag_object_id.clone(),
                release_body_sha256: package.release_body_sha256.clone(),
            }],
        }
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
        let mut legacy = plan;
        legacy.schema_version = PLAN_SCHEMA - 1;
        let (body, digest) = encode_plan(&legacy).unwrap();
        assert!(decode_plan(&body, &digest).is_err());
    }

    #[test]
    fn settings_evidence_encoding_matches_cross_language_vectors() {
        assert_eq!(
            settings_evidence_sha256("NVIDIA/yaml-sigil-traits", &"a".repeat(40), 100, 1).unwrap(),
            "a622fec239319172aefb628be3f81fccbc93d61803c5214c0729e054a2da6c09",
        );
        assert_eq!(
            settings_evidence_sha256("NVIDIA/yaml-sigil-rs", &"a".repeat(40), 100, 1).unwrap(),
            "917d89e6ef528f6db27ef6a93717c7d4907420e11e040ed8adec07508e339568",
        );
    }

    #[test]
    fn release_intent_rejects_a_mismatched_canonical_settings_digest() {
        let (plan, mut intent, _) = intent_fixture();
        let plan_digest = intent.plan_digest.clone();
        intent.ruleset_evidence_sha256 = "0".repeat(64);
        let body = canonical_intent(&intent).unwrap();
        let error = decode_intent(&body, &plan, &plan_digest).unwrap_err();
        assert!(error.contains("does not match canonical release settings"));
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
    fn notification_sender_and_receiver_share_one_closed_schema() {
        let notification = notification_fixture();
        require_notification_size(&notification).unwrap();
        validate_notification_shape(&notification.repository, &notification).unwrap();

        let dispatch = RepositoryDispatch {
            event_type: "official-release-published",
            client_payload: &notification,
        };
        let dispatch = serde_json::to_value(dispatch).unwrap();
        let event: DispatchEvent = serde_json::from_value(json!({
            "action": dispatch["event_type"],
            "sender": {"id": APP_ID, "login": APP_LOGIN, "type": "Bot"},
            "repository": {
                "full_name": notification.repository,
                "default_branch": "main",
            },
            "client_payload": dispatch["client_payload"],
        }))
        .unwrap();
        assert_eq!(event.client_payload, notification);
    }

    #[test]
    fn notification_schema_rejects_legacy_incomplete_unknown_and_duplicate_fields() {
        let notification = notification_fixture();
        let legacy = json!({"version": "0.4.0"});
        assert!(serde_json::from_value::<ReleaseNotification>(legacy).is_err());

        let mut incomplete = serde_json::to_value(&notification).unwrap();
        incomplete.as_object_mut().unwrap().remove("releases");
        assert!(serde_json::from_value::<ReleaseNotification>(incomplete).is_err());

        let mut unknown = serde_json::to_value(&notification).unwrap();
        unknown["unknown"] = Value::Bool(true);
        assert!(serde_json::from_value::<ReleaseNotification>(unknown).is_err());

        let canonical = serde_json::to_string(&notification).unwrap();
        let duplicate = canonical.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(serde_json::from_str::<ReleaseNotification>(&duplicate).is_err());
    }

    #[test]
    fn notification_rejects_wrong_version_oversize_and_noncanonical_values() {
        let notification = notification_fixture();

        let mut wrong_version = notification.clone();
        wrong_version.schema_version = NOTIFICATION_SCHEMA + 1;
        assert!(validate_notification_shape(&wrong_version.repository, &wrong_version).is_err());

        let mut incomplete = notification.clone();
        incomplete.releases.clear();
        assert!(validate_notification_shape(&incomplete.repository, &incomplete).is_err());

        let mut noncanonical = notification.clone();
        noncanonical.releases[0].version = "0.4.0+metadata".to_string();
        noncanonical.releases[0].tag = "v0.4.0+metadata".to_string();
        assert!(validate_notification_shape(&noncanonical.repository, &noncanonical).is_err());

        let mut oversized = notification.clone();
        oversized.releases[0].package = "x".repeat(MAX_NOTIFICATION_BYTES);
        assert!(require_notification_size(&oversized).is_err());

        let mut out_of_range = notification;
        out_of_range.intent_check_id = i64::MAX as u64 + 1;
        assert!(validate_notification_shape(&out_of_range.repository, &out_of_range).is_err());
    }

    #[test]
    fn dispatch_event_read_is_bounded_before_parsing() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("event.json");
        fs::write(&path, vec![b' '; MAX_EVENT_BYTES + 1]).unwrap();
        assert!(
            read_dispatch_event(&path)
                .unwrap_err()
                .contains("exceeds its")
        );
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_event_read_never_follows_a_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target.json");
        let path = temporary.path().join("event.json");
        fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_dispatch_event(&path).is_err());
    }

    #[test]
    fn current_notification_and_plan_schema_pass_the_complete_receiver() {
        let (temporary, policy_commit) = protected_traits_root();
        let root = temporary.path();
        let mut plan = plan();
        plan.policy_commit = policy_commit.clone();

        let archive = fixture_archive(&plan.release_sha);
        let package_policy = &crate::release_policy::TRAITS_POLICY.packages[0];
        let archive_entries = crate::crate_archive::inspect_archive_entries(
            &archive,
            package_policy,
            &plan.packages[0].version,
            &plan.release_sha,
        )
        .unwrap();
        let archive_digest = sha256(&archive);
        plan.packages[0].source_archive_sha256 = archive_digest.clone();
        plan.packages[0].package_inventory_sha256 = archive_inventory_sha256(&archive_entries);

        let (plan_body, plan_digest) = encode_plan(&plan).unwrap();
        let ruleset_evidence =
            settings_evidence_sha256(&plan.repository, &plan.release_sha, 100, 1).unwrap();
        let intent = build_intent(root, &plan, &plan_digest, 100, 1, &ruleset_evidence).unwrap();
        let intent_body = canonical_intent(&intent).unwrap();
        let notification = ReleaseNotification {
            schema_version: NOTIFICATION_SCHEMA,
            repository: plan.repository.clone(),
            captured_sha: plan.release_sha.clone(),
            release_plan_digest: plan_digest.clone(),
            intent_check_id: 900,
            intent_external_id: intent.external_id.clone(),
            releases: vec![FinalizedEntry {
                package: plan.packages[0].package.clone(),
                version: plan.packages[0].version.clone(),
                release_id: 1_000,
                tag: plan.packages[0].tag.clone(),
                tag_object_id: intent.tags[0].tag_object_id.clone(),
                release_body_sha256: plan.packages[0].release_body_sha256.clone(),
            }],
        };
        let event_path = root.join("event.json");
        fs::write(
            &event_path,
            serde_json::to_vec(&json!({
                "action": "official-release-published",
                "sender": {"id": APP_ID, "login": APP_LOGIN, "type": "Bot"},
                "repository": {
                    "full_name": plan.repository,
                    "default_branch": "main",
                },
                "client_payload": notification,
            }))
            .unwrap(),
        )
        .unwrap();

        let repository = plan.repository.clone();
        let main_ref = json!({
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": policy_commit},
        });
        let repository_identity = json!({
            "full_name": repository,
            "default_branch": "main",
        });
        let sender = json!({"id": APP_ID, "login": APP_LOGIN, "type": "Bot"});
        let release = json!({
            "id": 1_000,
            "tag_name": plan.packages[0].tag,
            "target_commitish": "main",
            "name": plan.packages[0].tag,
            "body": plan.packages[0].release_body,
            "draft": false,
            "prerelease": plan.packages[0].prerelease,
            "immutable": true,
            "author": {"id": APP_ID, "login": APP_LOGIN, "type": "Bot"},
            "assets": [],
        });
        let tag = json!({
            "sha": intent.tags[0].tag_object_id,
            "tag": plan.packages[0].tag,
            "message": intent.tags[0].tag_message,
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": plan.tagger_date,
            },
            "object": {"type": "commit", "sha": plan.release_sha},
        });
        let ref_path = format!(
            "repos/{repository}/git/ref/tags/{}",
            percent_encode(&plan.packages[0].tag)
        );
        let tag_path = format!(
            "repos/{repository}/git/tags/{}",
            intent.tags[0].tag_object_id
        );
        let release_by_tag_path = format!(
            "repos/{repository}/releases/tags/{}",
            percent_encode(&plan.packages[0].tag)
        );
        let release_branch = percent_encode(&format!("NVIDIA:{RELEASE_BRANCH}"));
        let mut github = FakeTransport::new([
            Expected::json(
                "GET",
                &format!("repos/{repository}/git/ref/heads/main"),
                main_ref.clone(),
            ),
            Expected::json("GET", &format!("repos/{repository}"), repository_identity),
            Expected::json(
                "GET",
                &format!("users/{}", percent_encode(APP_LOGIN)),
                sender.clone(),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/git/ref/heads/main"),
                main_ref,
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/check-runs/900"),
                intent_check(&intent, &intent_body, 900, "success"),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/actions/runs/100"),
                json!({
                    "id": 100,
                    "run_attempt": 1,
                    "head_sha": plan.release_sha,
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                    "path": ".github/workflows/publish.yml",
                    "status": "completed",
                    "conclusion": "success",
                    "repository": {"full_name": repository},
                }),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/releases/1000"),
                release.clone(),
            ),
            Expected::json("GET", &release_by_tag_path, release),
            Expected::json(
                "GET",
                &ref_path,
                json!({
                    "ref": format!("refs/tags/{}", plan.packages[0].tag),
                    "object": {"type": "tag", "sha": intent.tags[0].tag_object_id},
                }),
            ),
            Expected::json("GET", &tag_path, tag),
            Expected::json(
                "GET",
                &format!("users/{}", percent_encode(APP_LOGIN)),
                sender,
            ),
            Expected::json(
                "GET",
                &format!(
                    "repos/{repository}/git/matching-refs/heads/{}",
                    percent_encode(RELEASE_BRANCH)
                ),
                json!([]),
            ),
            Expected::json(
                "PAGINATE",
                &format!("repos/{repository}/pulls?state=open&head={release_branch}"),
                json!([]),
            ),
        ]);
        let mut registry = FixtureRegistry {
            record: crate::crate_archive::RegistryVersion {
                num: "0.4.0".to_string(),
                yanked: false,
                checksum: archive_digest,
            },
            archive,
            downloads: 0,
        };
        let result = receive_with_registry(
            root,
            ReceiveInput {
                event: &event_path,
                repository: &repository,
                policy_commit: &policy_commit,
            },
            &mut github,
            &mut registry,
        )
        .unwrap();
        assert_eq!(result.replay_state, "new");
        assert_eq!(result.captured_release_sha, plan.release_sha);
        assert_eq!(result.release_plan_digest, plan_digest);
        assert_eq!(result.intent_check_id, 900);
        assert_eq!(result.policy_sha, policy_commit);
        assert!(is_digest(&result.replay_key));
        assert_eq!(registry.downloads, 1);
        github.finish();
        assert_eq!(decode_plan(&plan_body, &plan_digest).unwrap(), plan);
    }

    #[test]
    fn notification_shape_rejects_reordered_and_duplicate_rs_release_sets() {
        let mut notification = ReleaseNotification {
            schema_version: NOTIFICATION_SCHEMA,
            repository: "NVIDIA/yaml-sigil-rs".to_string(),
            captured_sha: "a".repeat(40),
            release_plan_digest: "b".repeat(64),
            intent_check_id: 900,
            intent_external_id: "c".repeat(64),
            releases: crate::release_policy::RUST_POLICY
                .packages
                .iter()
                .enumerate()
                .map(|(index, package)| FinalizedEntry {
                    package: package.package.to_string(),
                    version: "0.4.0".to_string(),
                    release_id: 1_000 + index as u64,
                    tag: package.tag("0.4.0"),
                    tag_object_id: format!("{index:040x}"),
                    release_body_sha256: format!("{index:064x}"),
                })
                .collect(),
        };
        validate_notification_shape(&notification.repository, &notification).unwrap();

        notification.releases.swap(0, 1);
        assert!(validate_notification_shape(&notification.repository, &notification).is_err());
        notification.releases.swap(0, 1);
        notification.releases[1].release_id = notification.releases[0].release_id;
        assert!(validate_notification_shape(&notification.repository, &notification).is_err());
    }

    #[test]
    fn wrong_dispatch_sender_is_rejected_before_live_reads() {
        let notification = notification_fixture();
        let event = DispatchEvent {
            action: "official-release-published".to_string(),
            sender: DispatchActor {
                id: APP_ID + 1,
                login: APP_LOGIN.to_string(),
                kind: "Bot".to_string(),
            },
            repository: DispatchRepository {
                full_name: notification.repository.clone(),
                default_branch: "main".to_string(),
            },
            client_payload: notification,
        };
        let mut github = FakeTransport::new([]);
        assert!(
            validate_dispatch_identity(
                &event,
                &event.repository.full_name,
                &"a".repeat(40),
                &mut github
            )
            .is_err()
        );
        github.finish();
    }

    #[test]
    fn release_and_intent_app_identity_remain_exact() {
        let (plan, intent, body) = intent_fixture();
        let mut check: CheckRun =
            serde_json::from_value(intent_check(&intent, &body, 900, "success")).unwrap();
        validate_intent_check(&check, &intent, &body).unwrap();
        check.app.id += 1;
        assert!(validate_intent_check(&check, &intent, &body).is_err());

        let mut release: Release = serde_json::from_value(json!({
            "id": 1_000,
            "tag_name": plan.packages[0].tag,
            "target_commitish": "main",
            "name": plan.packages[0].tag,
            "body": plan.packages[0].release_body,
            "draft": false,
            "prerelease": plan.packages[0].prerelease,
            "immutable": true,
            "author": {"id": APP_ID, "login": APP_LOGIN, "type": "Bot"},
            "assets": [],
        }))
        .unwrap();
        validate_release(&release, &plan.packages[0]).unwrap();
        release.immutable = false;
        assert!(validate_release(&release, &plan.packages[0]).is_err());
        release.immutable = true;
        release.assets.push(json!({"id": 1}));
        assert!(validate_release(&release, &plan.packages[0]).is_err());
    }

    #[test]
    fn exact_legacy_inventory_uses_the_shared_archive_validator() {
        let plan = plan();
        let archive = fixture_archive(&plan.release_sha);
        let checksum = sha256(&archive);
        let release_id = 42;
        let tag_object_sha = "8".repeat(40);
        let body = "historical notes";
        let inventory = LegacyInventory {
            schema_version: 1,
            api_version: GITHUB_API_VERSION.to_string(),
            repository: plan.repository.clone(),
            legacy_author: LegacyAuthor {
                id: LEGACY_AUTHOR_ID,
                login: LEGACY_AUTHOR_LOGIN.to_string(),
                kind: "Bot".to_string(),
            },
            prospective_author: LegacyAuthor {
                id: APP_ID,
                login: APP_LOGIN.to_string(),
                kind: "Bot".to_string(),
            },
            entries: vec![LegacyEntry {
                release_id,
                package: plan.packages[0].package.clone(),
                version: plan.packages[0].version.clone(),
                tag: plan.packages[0].tag.clone(),
                tag_object_sha: tag_object_sha.clone(),
                peeled_commit_sha: plan.release_sha.clone(),
                target_commitish: "main".to_string(),
                draft: false,
                prerelease: false,
                immutable: false,
                asset_count: 0,
                body_sha256: sha256(body.as_bytes()),
                source_archive_sha256: checksum.clone(),
                path_in_vcs: "".to_string(),
            }],
        };
        validate_legacy_inventory(&plan.repository, &inventory).unwrap();
        let release = json!({
            "id": release_id,
            "tag_name": plan.packages[0].tag,
            "target_commitish": "main",
            "name": plan.packages[0].tag,
            "body": body,
            "draft": false,
            "prerelease": false,
            "immutable": false,
            "author": {"id": LEGACY_AUTHOR_ID, "login": LEGACY_AUTHOR_LOGIN, "type": "Bot"},
            "assets": [],
        });
        let mut github = FakeTransport::new([
            Expected::json(
                "PAGINATE",
                &format!("repos/{}/releases", plan.repository),
                json!([release.clone()]),
            ),
            Expected::json(
                "GET",
                &format!("repos/{}/releases/{release_id}", plan.repository),
                release,
            ),
            Expected::json(
                "GET",
                &format!(
                    "repos/{}/git/ref/tags/{}",
                    plan.repository,
                    percent_encode(&plan.packages[0].tag)
                ),
                json!({"ref": format!("refs/tags/{}", plan.packages[0].tag), "object": {"type": "tag", "sha": tag_object_sha}}),
            ),
            Expected::json(
                "GET",
                &format!("repos/{}/git/tags/{}", plan.repository, tag_object_sha),
                json!({
                    "sha": tag_object_sha,
                    "tag": plan.packages[0].tag,
                    "message": "historical",
                    "tagger": {
                        "name": LEGACY_AUTHOR_LOGIN,
                        "email": "historical@example.invalid",
                        "date": "2025-01-01T00:00:00Z",
                    },
                    "object": {"type": "commit", "sha": plan.release_sha},
                }),
            ),
        ]);
        let mut registry = FixtureRegistry {
            record: crate::crate_archive::RegistryVersion {
                num: "0.4.0".to_string(),
                yanked: false,
                checksum,
            },
            archive,
            downloads: 0,
        };
        verify_live_legacy_inventory(&mut github, &mut registry, &plan.repository, &inventory)
            .unwrap();
        assert_eq!(registry.downloads, 1);
        github.finish();

        let unexpected = json!({
            "id": 99,
            "tag_name": "v9.9.9",
            "target_commitish": "main",
            "name": "v9.9.9",
            "body": "unexpected",
            "draft": false,
            "prerelease": false,
            "immutable": false,
            "author": {"id": APP_ID, "login": APP_LOGIN, "type": "Bot"},
            "assets": [],
        });
        let mut github = FakeTransport::new([Expected::json(
            "PAGINATE",
            &format!("repos/{}/releases", plan.repository),
            json!([unexpected]),
        )]);
        assert!(
            verify_live_legacy_inventory(&mut github, &mut registry, &plan.repository, &inventory,)
                .is_err()
        );
        github.finish();
    }

    #[test]
    fn legacy_authorization_cannot_cover_prospective_objects() {
        let mut plan = plan();
        plan.authorization = PlanAuthorization::LegacyInventory;
        let (body, digest) = encode_plan(&plan).unwrap();
        assert!(decode_plan(&body, &digest).is_err());

        plan.packages[0].registry = RegistryBaseline {
            state: RegistryState::Present,
            checksum: Some("1".repeat(64)),
        };
        plan.packages[0].release_objects = ReleaseObjectBaseline::Legacy {
            release_id: 42,
            tag_object_sha: "8".repeat(40),
        };
        let (body, digest) = encode_plan(&plan).unwrap();
        assert_eq!(decode_plan(&body, &digest).unwrap(), plan);
    }
}

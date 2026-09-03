// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Read-only release-setting validation for one exact active workflow run.

use std::collections::BTreeSet;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::release_train::{
    APP_PUBLIC_ID, INTENT_NAME, SETTINGS_AUTHORIZATION_NAME, settings_evidence_tag_patterns,
};
use super::transport::{GITHUB_API_VERSION, Transport, percent_encode};
use super::{append_outputs, git_line, is_positive_integer, is_sha, repository_policy_for_root};

const MAIN_RULESET: &str = "Protect main and require CI";
const V1ALPHA1_RULESET: &str = "Protect v1alpha1 tag";
const CREATION_RULESET: &str = "Protect release tag creation";
const UPDATE_DELETE_RULESET: &str = "Protect release tag updates and deletion";
const WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const APPROVAL_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_RULESETS: usize = 99;
const REVIEW_POLL_COUNT: usize = 120;
const REVIEW_POLL_DELAY: Duration = Duration::from_secs(10);
const SETTINGS_EVIDENCE_SCHEMA: u64 = 1;
const MAX_SETTINGS_EVIDENCE_BYTES: usize = 64 * 1024;
pub(super) const SETTINGS_EVIDENCE_PREFIX: &str = "yaml-sigil-release-settings-v1:";

#[derive(Debug, Deserialize)]
struct Repository {
    full_name: String,
    default_branch: String,
}

#[derive(Debug, Deserialize)]
struct WorkflowRunRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GitRef {
    #[serde(rename = "ref")]
    name: String,
    object: GitObject,
}

#[derive(Debug, Deserialize)]
struct GitObject {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
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
    repository: WorkflowRunRepository,
    #[serde(default)]
    check_suite_node_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ImmutableReleases {
    enabled: bool,
    enforced_by_owner: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Ruleset {
    id: u64,
    name: String,
    target: String,
    source_type: String,
    source: String,
    enforcement: String,
    bypass_actors: Vec<Value>,
    conditions: Value,
    rules: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RulesetSummary {
    id: u64,
    target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SettingsSnapshot {
    schema_version: u64,
    api_version: String,
    repository: String,
    policy_commit: String,
    run_id: u64,
    run_attempt: u64,
    observed_at: u64,
    approve_before: u64,
    immutable_releases: ImmutableReleases,
    rulesets: Vec<Ruleset>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsEvidence {
    schema_version: u64,
    snapshot: SettingsSnapshot,
    readback_sha256: String,
}

#[derive(Debug)]
struct Evidence {
    body: String,
    readback_sha256: String,
    readback_utc: String,
    approve_before_utc: String,
}

#[derive(Debug)]
pub(super) struct SettingsReview {
    pub(super) evidence: String,
    pub(super) evidence_sha256: String,
    pub(super) review_id: u64,
    pub(super) reviewer_id: u64,
    pub(super) reviewer_login: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    #[serde(default)]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlData {
    node: Option<GraphqlCheckSuite>,
}

#[derive(Debug, Deserialize)]
struct GraphqlCheckSuite {
    #[serde(rename = "workflowRun")]
    workflow_run: Option<GraphqlWorkflowRun>,
}

#[derive(Debug, Deserialize)]
struct GraphqlWorkflowRun {
    #[serde(rename = "databaseId")]
    database_id: Option<u64>,
    #[serde(rename = "runAttempt")]
    run_attempt: u64,
    event: String,
    #[serde(rename = "deploymentReviews")]
    deployment_reviews: GraphqlReviewConnection,
}

#[derive(Debug, Deserialize)]
struct GraphqlReviewConnection {
    #[serde(rename = "totalCount")]
    total_count: u64,
    nodes: Vec<Option<GraphqlReview>>,
}

#[derive(Debug, Deserialize)]
struct GraphqlReview {
    #[serde(rename = "databaseId")]
    database_id: Option<u64>,
    state: String,
    comment: String,
    user: GraphqlUser,
    environments: GraphqlEnvironmentConnection,
}

#[derive(Debug, Deserialize)]
struct GraphqlUser {
    login: String,
    #[serde(rename = "databaseId")]
    database_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GraphqlEnvironmentConnection {
    #[serde(rename = "totalCount")]
    total_count: u64,
    nodes: Vec<Option<GraphqlEnvironment>>,
}

#[derive(Debug, Deserialize)]
struct GraphqlEnvironment {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CollaboratorPermission {
    permission: String,
    user: PermissionUser,
}

#[derive(Debug, Deserialize)]
struct PermissionUser {
    login: String,
    id: u64,
}

const REVIEW_QUERY: &str = r#"
query($checkSuite: ID!) {
  node(id: $checkSuite) {
    ... on CheckSuite {
      workflowRun {
        databaseId
        runAttempt
        event
        deploymentReviews(first: 100) {
          totalCount
          nodes {
            databaseId
            state
            comment
            user { login databaseId }
            environments(first: 10) {
              totalCount
              nodes { name }
            }
          }
        }
      }
    }
  }
}
"#;

fn repository_admin_command(
    repository: &str,
    policy_commit: &str,
    run_id: u64,
    run_attempt: u64,
) -> String {
    format!(
        "GH_TOKEN=\"$(gh auth token --hostname github.com)\" cargo +stable xtask github \
         release-train settings-preflight --repository {repository} --policy-commit \
         {policy_commit} --run-id {run_id} --run-attempt {run_attempt}"
    )
}

pub(super) fn request_command(
    root: &Path,
    repository: &str,
    policy_commit: &str,
    run_id: &str,
    run_attempt: &str,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    if !is_sha(policy_commit) || git_line(root, &["rev-parse", "HEAD"])? != policy_commit {
        return Err("release settings request must come from the exact policy commit".to_string());
    }
    let run_id = positive(run_id, "workflow run ID")?;
    let run_attempt = positive(run_attempt, "workflow run attempt")?;
    println!("repository_admin_checkout={repository}@{policy_commit}");
    println!(
        "repository_admin_command={}",
        repository_admin_command(repository, policy_commit, run_id, run_attempt)
    );
    println!("approval_comment_prefix={SETTINGS_EVIDENCE_PREFIX}");
    println!("evidence_window_seconds={}", APPROVAL_WINDOW.as_secs());
    Ok(())
}

pub(super) fn preflight_command(
    root: &Path,
    repository: &str,
    policy_commit: &str,
    run_id: &str,
    run_attempt: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    if !is_sha(policy_commit) || git_line(root, &["rev-parse", "HEAD"])? != policy_commit {
        return Err("release settings must be checked from the exact policy commit".to_string());
    }
    let run_id = positive(run_id, "workflow run ID")?;
    let run_attempt = positive(run_attempt, "workflow run attempt")?;
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_string())?
        .as_secs();
    let evidence = validate_preflight(
        repository,
        policy_commit,
        run_id,
        run_attempt,
        observed,
        github,
    )?;
    println!("repository_admin_settings=valid");
    println!("readback_sha256={}", evidence.readback_sha256);
    println!("readback_utc={}", evidence.readback_utc);
    println!("approve_before_utc={}", evidence.approve_before_utc);
    println!(
        "approval_comment={SETTINGS_EVIDENCE_PREFIX}{}",
        evidence.body
    );
    Ok(())
}

pub(super) fn await_review_command(
    root: &Path,
    repository: &str,
    policy_commit: &str,
    run_id: &str,
    run_attempt: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    if !is_sha(policy_commit) {
        return Err("settings review policy commit is invalid".to_string());
    }
    let run_id = positive(run_id, "workflow run ID")?;
    let run_attempt = positive(run_attempt, "workflow run attempt")?;
    let run: WorkflowRun = github.get(&format!("repos/{repository}/actions/runs/{run_id}"))?;
    if run.id != run_id
        || run.run_attempt != run_attempt
        || run.head_sha != policy_commit
        || run.head_branch != "main"
        || run.event != "workflow_dispatch"
        || run.path != WORKFLOW_PATH
        || !matches!(
            run.status.as_str(),
            "queued" | "in_progress" | "waiting" | "requested" | "pending"
        )
        || run.conclusion.is_some()
        || run.repository.full_name != repository
    {
        return Err("settings review workflow identity or state drifted".to_string());
    }
    let check_suite_node_id = run
        .check_suite_node_id
        .ok_or_else(|| "workflow run lacks its Check Suite identity".to_string())?;
    if check_suite_node_id.is_empty() || check_suite_node_id.len() > 256 {
        return Err("workflow run Check Suite identity is invalid".to_string());
    }

    for poll in 0..REVIEW_POLL_COUNT {
        if let Some(review) = review_once(
            repository,
            policy_commit,
            run_id,
            run_attempt,
            &check_suite_node_id,
            now_epoch()?,
            github,
        )? {
            let review_id = review.review_id.to_string();
            let reviewer_id = review.reviewer_id.to_string();
            return append_outputs(&[
                ("settings_evidence", &review.evidence),
                ("settings_evidence_sha256", &review.evidence_sha256),
                ("settings_review_id", &review_id),
                ("settings_reviewer_id", &reviewer_id),
                ("settings_reviewer_login", &review.reviewer_login),
            ]);
        }
        if poll + 1 < REVIEW_POLL_COUNT {
            thread::sleep(REVIEW_POLL_DELAY);
        }
    }
    Err("timed out waiting for one exact repository-admin settings review".to_string())
}

fn review_once(
    repository: &str,
    policy_commit: &str,
    run_id: u64,
    run_attempt: u64,
    check_suite_node_id: &str,
    now: u64,
    github: &mut impl Transport,
) -> Result<Option<SettingsReview>, String> {
    let response: GraphqlResponse = github.graphql(&json!({
        "query": REVIEW_QUERY,
        "variables": {"checkSuite": check_suite_node_id},
    }))?;
    if !response.errors.is_empty() {
        let first = response.errors[0]
            .message
            .chars()
            .take(256)
            .collect::<String>();
        return Err(format!("settings review GraphQL query failed: {first}"));
    }
    let workflow = response
        .data
        .and_then(|data| data.node)
        .and_then(|suite| suite.workflow_run)
        .ok_or_else(|| "settings review workflow is absent from its Check Suite".to_string())?;
    if workflow.database_id != Some(run_id)
        || workflow.run_attempt != run_attempt
        || workflow.event != "workflow_dispatch"
    {
        return Err("settings review GraphQL workflow identity drifted".to_string());
    }
    let connection = workflow.deployment_reviews;
    if connection.total_count > 100 || connection.total_count != connection.nodes.len() as u64 {
        return Err("settings review inventory is incomplete or oversized".to_string());
    }
    let mut approved = Vec::new();
    for node in connection.nodes {
        let review = node.ok_or_else(|| "settings review inventory contains null".to_string())?;
        if review.environments.total_count > 10
            || review.environments.total_count != review.environments.nodes.len() as u64
        {
            return Err(
                "settings review environment inventory is incomplete or oversized".to_string(),
            );
        }
        let environments = review
            .environments
            .nodes
            .into_iter()
            .map(|environment| {
                environment
                    .map(|value| value.name)
                    .ok_or_else(|| "settings review environment is null".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !environments.iter().any(|name| name == "crates-io") {
            continue;
        }
        if review.state != "APPROVED"
            || environments != ["crates-io"]
            || !review.comment.starts_with(SETTINGS_EVIDENCE_PREFIX)
        {
            return Err("crates-io approval lacks exact settings evidence".to_string());
        }
        let review_id = review
            .database_id
            .filter(|value| *value > 0)
            .ok_or_else(|| "settings review ID is invalid".to_string())?;
        let reviewer_id = review
            .user
            .database_id
            .filter(|value| *value > 0)
            .ok_or_else(|| "settings reviewer ID is invalid".to_string())?;
        if review.user.login.is_empty() || review.user.login.len() > 256 {
            return Err("settings reviewer login is invalid".to_string());
        }
        let evidence = review
            .comment
            .strip_prefix(SETTINGS_EVIDENCE_PREFIX)
            .ok_or_else(|| "settings evidence prefix is absent".to_string())?;
        validate_evidence(
            evidence,
            repository,
            policy_commit,
            run_id,
            run_attempt,
            now,
            true,
        )?;
        approved.push(SettingsReview {
            evidence: evidence.to_string(),
            evidence_sha256: evidence_sha256(evidence),
            review_id,
            reviewer_id,
            reviewer_login: review.user.login,
        });
    }
    if approved.len() > 1 {
        return Err("multiple crates-io settings reviews claim one workflow attempt".to_string());
    }
    let Some(review) = approved.pop() else {
        return Ok(None);
    };
    let permission: CollaboratorPermission = github.get(&format!(
        "repos/{repository}/collaborators/{}/permission",
        percent_encode(&review.reviewer_login)
    ))?;
    if permission.permission != "admin"
        || permission.user.login != review.reviewer_login
        || permission.user.id != review.reviewer_id
    {
        return Err("settings reviewer lacks current repository-admin authority".to_string());
    }
    Ok(Some(review))
}

fn now_epoch() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_string())
        .map(|duration| duration.as_secs())
}

fn validate_preflight(
    repository: &str,
    policy_commit: &str,
    run_id: u64,
    run_attempt: u64,
    observed: u64,
    github: &mut impl Transport,
) -> Result<Evidence, String> {
    let live: Repository = github.get(&format!("repos/{repository}"))?;
    if live.full_name != repository || live.default_branch != "main" {
        return Err("repository identity or default branch drifted".to_string());
    }
    let reference: GitRef = github.get(&format!("repos/{repository}/git/ref/heads/main"))?;
    if reference.name != "refs/heads/main"
        || reference.object.kind != "commit"
        || reference.object.sha != policy_commit
    {
        return Err("policy commit is no longer exact current main".to_string());
    }
    let run: WorkflowRun = github.get(&format!("repos/{repository}/actions/runs/{run_id}"))?;
    if run.id != run_id
        || run.run_attempt != run_attempt
        || run.head_sha != policy_commit
        || run.head_branch != "main"
        || run.event != "workflow_dispatch"
        || run.path != WORKFLOW_PATH
        || !matches!(
            run.status.as_str(),
            "queued" | "in_progress" | "waiting" | "requested" | "pending"
        )
        || run.conclusion.is_some()
        || run.repository.full_name != repository
    {
        return Err("workflow run identity, source, attempt, or active state drifted".to_string());
    }
    let immutable: ImmutableReleases =
        github.get(&format!("repos/{repository}/immutable-releases"))?;
    if !immutable.enabled {
        return Err("repository immutable Releases are not enabled".to_string());
    }
    let mut rulesets = fetch_rulesets(repository, github)?;
    reject_intent_collision(&rulesets)?;
    validate_main_ruleset(repository, &rulesets)?;
    validate_tag_rulesets(repository, &rulesets)?;
    rulesets.sort_by(|left, right| (&left.target, left.id).cmp(&(&right.target, right.id)));

    let approve_before = observed
        .checked_add(APPROVAL_WINDOW.as_secs())
        .ok_or_else(|| "approval deadline overflowed".to_string())?;
    let snapshot = SettingsSnapshot {
        schema_version: SETTINGS_EVIDENCE_SCHEMA,
        api_version: GITHUB_API_VERSION.to_string(),
        repository: repository.to_string(),
        policy_commit: policy_commit.to_string(),
        run_id,
        run_attempt,
        observed_at: observed,
        approve_before,
        immutable_releases: immutable,
        rulesets,
    };
    let canonical = serde_json::to_vec(&snapshot)
        .map_err(|error| format!("encode canonical settings readback: {error}"))?;
    let readback_sha256 = format!("{:x}", Sha256::digest(canonical));
    let record = SettingsEvidence {
        schema_version: SETTINGS_EVIDENCE_SCHEMA,
        snapshot,
        readback_sha256: readback_sha256.clone(),
    };
    let body = canonical_evidence(&record)?;
    Ok(Evidence {
        body,
        readback_sha256,
        readback_utc: format_utc(observed)?,
        approve_before_utc: format_utc(approve_before)?,
    })
}

fn canonical_evidence(record: &SettingsEvidence) -> Result<String, String> {
    let body = serde_json::to_string(record)
        .map_err(|error| format!("encode canonical settings evidence: {error}"))?;
    if body.is_empty() || body.len() > MAX_SETTINGS_EVIDENCE_BYTES {
        return Err("settings evidence is empty or oversized".to_string());
    }
    Ok(body)
}

pub(super) fn validate_evidence(
    body: &str,
    repository: &str,
    policy_commit: &str,
    run_id: u64,
    run_attempt: u64,
    now: u64,
    require_fresh: bool,
) -> Result<SettingsEvidence, String> {
    if body.is_empty() || body.len() > MAX_SETTINGS_EVIDENCE_BYTES {
        return Err("settings evidence is empty or oversized".to_string());
    }
    let record: SettingsEvidence = serde_json::from_str(body)
        .map_err(|error| format!("settings evidence schema is invalid: {error}"))?;
    if canonical_evidence(&record)? != body
        || record.schema_version != SETTINGS_EVIDENCE_SCHEMA
        || record.snapshot.schema_version != SETTINGS_EVIDENCE_SCHEMA
        || record.snapshot.api_version != GITHUB_API_VERSION
        || record.snapshot.repository != repository
        || record.snapshot.policy_commit != policy_commit
        || record.snapshot.run_id != run_id
        || record.snapshot.run_attempt != run_attempt
        || !record.snapshot.immutable_releases.enabled
        || !is_digest(&record.readback_sha256)
    {
        return Err("settings evidence binding is invalid".to_string());
    }
    let expected_deadline = record
        .snapshot
        .observed_at
        .checked_add(APPROVAL_WINDOW.as_secs())
        .ok_or_else(|| "settings evidence approval deadline overflowed".to_string())?;
    if record.snapshot.approve_before != expected_deadline
        || (require_fresh
            && (record.snapshot.observed_at > now || now > record.snapshot.approve_before))
    {
        return Err("settings evidence is not within its approval window".to_string());
    }
    let mut ids = BTreeSet::new();
    if record.snapshot.rulesets.is_empty()
        || record.snapshot.rulesets.len() > MAX_RULESETS
        || record
            .snapshot
            .rulesets
            .iter()
            .any(|ruleset| ruleset.id == 0 || !ids.insert(ruleset.id))
        || !record
            .snapshot
            .rulesets
            .windows(2)
            .all(|pair| (&pair[0].target, pair[0].id) < (&pair[1].target, pair[1].id))
    {
        return Err("settings evidence ruleset inventory is invalid".to_string());
    }
    reject_intent_collision(&record.snapshot.rulesets)?;
    validate_main_ruleset(repository, &record.snapshot.rulesets)?;
    validate_tag_rulesets(repository, &record.snapshot.rulesets)?;
    let canonical_snapshot = serde_json::to_vec(&record.snapshot)
        .map_err(|error| format!("encode canonical settings readback: {error}"))?;
    let recomputed = format!("{:x}", Sha256::digest(canonical_snapshot));
    if record.readback_sha256 != recomputed {
        return Err("settings evidence digest does not match its canonical readback".to_string());
    }
    Ok(record)
}

pub(super) fn evidence_sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

pub(super) fn evidence_window(record: &SettingsEvidence) -> (u64, u64) {
    (record.snapshot.observed_at, record.snapshot.approve_before)
}

fn fetch_rulesets(repository: &str, github: &mut impl Transport) -> Result<Vec<Ruleset>, String> {
    let listed: Vec<RulesetSummary> = github.paginate(&format!(
        "repos/{repository}/rulesets?includes_parents=true"
    ))?;
    let selected = listed
        .into_iter()
        .filter(|ruleset| matches!(ruleset.target.as_str(), "branch" | "tag"))
        .collect::<Vec<_>>();
    if selected.is_empty() || selected.len() > MAX_RULESETS {
        return Err("repository ruleset list is empty or oversized".to_string());
    }
    let mut ids = BTreeSet::new();
    let mut details = Vec::with_capacity(selected.len());
    for summary in selected {
        if summary.id == 0 || !ids.insert(summary.id) {
            return Err("repository ruleset list contains an invalid or duplicate ID".to_string());
        }
        let detail: Ruleset = github.get(&format!("repos/{repository}/rulesets/{}", summary.id))?;
        if detail.id != summary.id || detail.target != summary.target {
            return Err(format!("ruleset {} identity drifted", summary.id));
        }
        if detail.bypass_actors.len() > 32 || detail.rules.len() > 32 {
            return Err(format!("ruleset {} is oversized", summary.id));
        }
        details.push(detail);
    }
    Ok(details)
}

fn named_ruleset<'a>(rulesets: &'a [Ruleset], name: &str) -> Result<&'a Ruleset, String> {
    let matches = rulesets
        .iter()
        .filter(|ruleset| ruleset.name == name)
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(format!("ruleset {name:?} is missing or duplicated"))
    }
}

fn require_ref_conditions(ruleset: &Ruleset, includes: &[&str]) -> Result<(), String> {
    if ruleset.conditions == json!({"ref_name": {"exclude": [], "include": includes}}) {
        Ok(())
    } else {
        Err(format!("ruleset {:?} ref conditions drifted", ruleset.name))
    }
}

fn require_rule_types(ruleset: &Ruleset, types: &[&str]) -> Result<(), String> {
    let expected = types
        .iter()
        .map(|kind| json!({"type": kind}))
        .collect::<Vec<_>>();
    if ruleset.rules == expected {
        Ok(())
    } else {
        Err(format!("ruleset {:?} rule types drifted", ruleset.name))
    }
}

fn reject_intent_collision(rulesets: &[Ruleset]) -> Result<(), String> {
    for ruleset in rulesets
        .iter()
        .filter(|ruleset| is_main_applicable(ruleset))
    {
        for rule in &ruleset.rules {
            if rule.get("type").and_then(Value::as_str) != Some("required_status_checks") {
                continue;
            }
            let checks = rule
                .pointer("/parameters/required_status_checks")
                .and_then(Value::as_array)
                .ok_or_else(|| "required-status-check parameters are invalid".to_string())?;
            if checks.len() > 64 {
                return Err("required status checks are oversized".to_string());
            }
            if checks.iter().any(|check| {
                matches!(
                    check.get("context").and_then(Value::as_str),
                    Some(INTENT_NAME) | Some(SETTINGS_AUTHORIZATION_NAME)
                )
            }) {
                return Err(
                    "a release-attestation name collides with an applicable required check"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

fn pattern_could_match_main(pattern: &str) -> bool {
    if matches!(pattern, "~ALL" | "~DEFAULT_BRANCH" | "refs/heads/main") {
        return true;
    }
    let first_meta = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    if first_meta == pattern.len() {
        return false;
    }
    let last_meta = pattern.rfind(['*', '?', ']']).unwrap_or(first_meta);
    let prefix = &pattern[..first_meta];
    let suffix = pattern.get(last_meta + 1..).unwrap_or_default();
    "refs/heads/main".starts_with(prefix) && "refs/heads/main".ends_with(suffix)
}

fn is_main_applicable(ruleset: &Ruleset) -> bool {
    if ruleset.target != "branch" || ruleset.enforcement != "active" {
        return false;
    }
    let Some(ref_name) = ruleset.conditions.get("ref_name") else {
        return true;
    };
    let Some(exclude) = ref_name.get("exclude").and_then(Value::as_array) else {
        return true;
    };
    if exclude.iter().any(|pattern| {
        matches!(
            pattern.as_str(),
            Some("~ALL" | "~DEFAULT_BRANCH" | "refs/heads/main")
        )
    }) {
        return false;
    }
    let Some(include) = ref_name.get("include").and_then(Value::as_array) else {
        return true;
    };
    include.is_empty()
        || include
            .iter()
            .any(|pattern| pattern.as_str().is_none_or(pattern_could_match_main))
}

fn validate_main_ruleset(repository: &str, rulesets: &[Ruleset]) -> Result<(), String> {
    let applicable = rulesets
        .iter()
        .filter(|ruleset| is_main_applicable(ruleset))
        .collect::<Vec<_>>();
    if applicable.len() != 1 || applicable[0].name != MAIN_RULESET {
        return Err(
            "active main-applicable ruleset inventory is unexpected or ambiguous".to_string(),
        );
    }
    let main = applicable[0];
    if main.target != "branch"
        || main.source_type != "Repository"
        || main.source != repository
        || main.enforcement != "active"
        || !main.bypass_actors.is_empty()
    {
        return Err("protected-main ruleset target, enforcement, or bypass drifted".to_string());
    }
    require_ref_conditions(main, &["refs/heads/main"])?;
    let expected = [
        json!({"type": "required_linear_history"}),
        json!({"type": "deletion"}),
        json!({"type": "non_fast_forward"}),
        json!({
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": false,
                "required_reviewers": [],
                "require_code_owner_review": false,
                "dismissal_restriction": {"enabled": false, "allowed_actors": []},
                "require_last_push_approval": false,
                "required_review_thread_resolution": true,
                "require_extra_approval_for_unattributed_changes": true,
                "allowed_merge_methods": ["rebase", "squash"],
            },
        }),
        json!({
            "type": "required_status_checks",
            "parameters": {
                "do_not_enforce_on_create": false,
                "strict_required_status_checks_policy": true,
                "required_status_checks": [{
                    "context": "Required CI",
                    "integration_id": APP_PUBLIC_ID,
                }],
            },
        }),
    ];
    if main.rules.len() != expected.len()
        || expected
            .iter()
            .any(|wanted| main.rules.iter().filter(|rule| *rule == wanted).count() != 1)
    {
        return Err("protected-main rule inventory or parameters drifted".to_string());
    }
    Ok(())
}

fn validate_tag_rulesets(repository: &str, rulesets: &[Ruleset]) -> Result<(), String> {
    let legacy = named_ruleset(rulesets, V1ALPHA1_RULESET)?;
    if legacy.target != "tag"
        || legacy.source_type != "Repository"
        || legacy.source != repository
        || legacy.enforcement != "active"
        || !legacy.bypass_actors.is_empty()
    {
        return Err("existing v1alpha1 protection drifted".to_string());
    }
    require_ref_conditions(legacy, &["refs/tags/v1alpha1"])?;
    require_rule_types(legacy, &["update", "deletion"])?;

    let patterns = settings_evidence_tag_patterns(repository)?;
    let creation = named_ruleset(rulesets, CREATION_RULESET)?;
    if creation.target != "tag"
        || creation.source_type != "Repository"
        || creation.source != repository
        || creation.enforcement != "active"
        || creation.bypass_actors
            != [json!({
                "actor_id": APP_PUBLIC_ID,
                "actor_type": "Integration",
                "bypass_mode": "always",
            })]
    {
        return Err("release-tag creation bypass is not the sole approved App".to_string());
    }
    require_ref_conditions(creation, patterns)?;
    require_rule_types(creation, &["creation"])?;

    let updates = named_ruleset(rulesets, UPDATE_DELETE_RULESET)?;
    if updates.target != "tag"
        || updates.source_type != "Repository"
        || updates.source != repository
        || updates.enforcement != "active"
        || !updates.bypass_actors.is_empty()
    {
        return Err("release-tag update/deletion protection drifted".to_string());
    }
    require_ref_conditions(updates, patterns)?;
    require_rule_types(updates, &["update", "deletion"])
}

fn positive(value: &str, label: &str) -> Result<u64, String> {
    if !is_positive_integer(value) {
        return Err(format!("{label} must be a positive canonical integer"));
    }
    value
        .parse()
        .map_err(|_| format!("{label} exceeds its bound"))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn format_utc(seconds: u64) -> Result<String, String> {
    let seconds =
        i64::try_from(seconds).map_err(|_| "UTC timestamp exceeds its bound".to_string())?;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(1970..=9999).contains(&year) {
        return Err("UTC timestamp is outside the supported year range".to_string());
    }
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::transport::fake::{Expected, FakeTransport};
    use super::*;

    fn rulesets(repository: &str) -> Vec<Ruleset> {
        let patterns = settings_evidence_tag_patterns(repository).unwrap();
        vec![
            Ruleset {
                id: 101,
                name: MAIN_RULESET.to_string(),
                target: "branch".to_string(),
                source_type: "Repository".to_string(),
                source: repository.to_string(),
                enforcement: "active".to_string(),
                bypass_actors: vec![],
                conditions: json!({"ref_name":{"exclude":[],"include":["refs/heads/main"]}}),
                rules: vec![
                    json!({"type":"required_linear_history"}),
                    json!({"type":"deletion"}),
                    json!({"type":"non_fast_forward"}),
                    json!({"type":"pull_request","parameters":{
                        "required_approving_review_count":0,
                        "dismiss_stale_reviews_on_push":false,
                        "required_reviewers":[],
                        "require_code_owner_review":false,
                        "dismissal_restriction":{"enabled":false,"allowed_actors":[]},
                        "require_last_push_approval":false,
                        "required_review_thread_resolution":true,
                        "require_extra_approval_for_unattributed_changes":true,
                        "allowed_merge_methods":["rebase","squash"],
                    }}),
                    json!({"type":"required_status_checks","parameters":{
                        "do_not_enforce_on_create":false,
                        "strict_required_status_checks_policy":true,
                        "required_status_checks":[{"context":"Required CI","integration_id":APP_PUBLIC_ID}],
                    }}),
                ],
            },
            Ruleset {
                id: 102,
                name: V1ALPHA1_RULESET.to_string(),
                target: "tag".to_string(),
                source_type: "Repository".to_string(),
                source: repository.to_string(),
                enforcement: "active".to_string(),
                bypass_actors: vec![],
                conditions: json!({"ref_name":{"exclude":[],"include":["refs/tags/v1alpha1"]}}),
                rules: vec![json!({"type":"update"}), json!({"type":"deletion"})],
            },
            Ruleset {
                id: 103,
                name: CREATION_RULESET.to_string(),
                target: "tag".to_string(),
                source_type: "Repository".to_string(),
                source: repository.to_string(),
                enforcement: "active".to_string(),
                bypass_actors: vec![
                    json!({"actor_id":APP_PUBLIC_ID,"actor_type":"Integration","bypass_mode":"always"}),
                ],
                conditions: json!({"ref_name":{"exclude":[],"include":patterns}}),
                rules: vec![json!({"type":"creation"})],
            },
            Ruleset {
                id: 104,
                name: UPDATE_DELETE_RULESET.to_string(),
                target: "tag".to_string(),
                source_type: "Repository".to_string(),
                source: repository.to_string(),
                enforcement: "active".to_string(),
                bypass_actors: vec![],
                conditions: json!({"ref_name":{"exclude":[],"include":patterns}}),
                rules: vec![json!({"type":"update"}), json!({"type":"deletion"})],
            },
        ]
    }

    fn expectations(repository: &str, rulesets: &[Ruleset]) -> Vec<Expected> {
        let sha = "a".repeat(40);
        let mut expected = vec![
            Expected::json(
                "GET",
                &format!("repos/{repository}"),
                json!({"full_name":repository,"default_branch":"main"}),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/git/ref/heads/main"),
                json!({"ref":"refs/heads/main","object":{"type":"commit","sha":sha}}),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/actions/runs/123456"),
                json!({
                    "id":123456,"run_attempt":2,"head_sha":sha,"head_branch":"main",
                    "event":"workflow_dispatch","path":WORKFLOW_PATH,"status":"waiting",
                    "conclusion":null,"repository":{"full_name":repository},
                }),
            ),
            Expected::json(
                "GET",
                &format!("repos/{repository}/immutable-releases"),
                json!({"enabled":true,"enforced_by_owner":false}),
            ),
            Expected::json(
                "PAGINATE",
                &format!("repos/{repository}/rulesets?includes_parents=true"),
                Value::Array(
                    rulesets
                        .iter()
                        .map(|ruleset| json!({"id":ruleset.id,"target":ruleset.target}))
                        .collect(),
                ),
            ),
        ];
        expected.extend(rulesets.iter().map(|ruleset| {
            Expected::json(
                "GET",
                &format!("repos/{repository}/rulesets/{}", ruleset.id),
                serde_json::to_value(ruleset).unwrap(),
            )
        }));
        expected
    }

    pub(crate) fn evidence(
        repository: &str,
        policy_commit: &str,
        run_id: u64,
        run_attempt: u64,
        observed_at: u64,
    ) -> String {
        let mut rulesets = rulesets(repository);
        rulesets.sort_by(|left, right| (&left.target, left.id).cmp(&(&right.target, right.id)));
        let snapshot = SettingsSnapshot {
            schema_version: SETTINGS_EVIDENCE_SCHEMA,
            api_version: GITHUB_API_VERSION.to_string(),
            repository: repository.to_string(),
            policy_commit: policy_commit.to_string(),
            run_id,
            run_attempt,
            observed_at,
            approve_before: observed_at + APPROVAL_WINDOW.as_secs(),
            immutable_releases: ImmutableReleases {
                enabled: true,
                enforced_by_owner: false,
            },
            rulesets,
        };
        let readback_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        );
        canonical_evidence(&SettingsEvidence {
            schema_version: SETTINGS_EVIDENCE_SCHEMA,
            snapshot,
            readback_sha256,
        })
        .unwrap()
    }

    #[test]
    fn exact_traits_and_rs_settings_produce_bound_evidence() {
        for repository in ["NVIDIA/yaml-sigil-traits", "NVIDIA/yaml-sigil-rs"] {
            let rulesets = rulesets(repository);
            let mut github = FakeTransport::new(expectations(repository, &rulesets));
            let evidence = validate_preflight(
                repository,
                &"a".repeat(40),
                123_456,
                2,
                1_787_940_000,
                &mut github,
            )
            .unwrap();
            assert_eq!(evidence.readback_utc, "2026-08-28T18:00:00Z");
            assert_eq!(evidence.approve_before_utc, "2026-08-28T18:05:00Z");
            let decoded = validate_evidence(
                &evidence.body,
                repository,
                &"a".repeat(40),
                123_456,
                2,
                1_787_940_001,
                true,
            )
            .unwrap();
            assert_eq!(decoded.readback_sha256, evidence.readback_sha256);
            github.finish();
        }
    }

    #[test]
    fn settings_evidence_rejects_tamper_cross_context_staleness_and_unknown_fields() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let policy_commit = "a".repeat(40);
        let body = evidence(repository, &policy_commit, 123_456, 2, 1_787_940_000);

        for result in [
            validate_evidence(
                &body,
                "NVIDIA/yaml-sigil-rs",
                &policy_commit,
                123_456,
                2,
                1_787_940_001,
                true,
            ),
            validate_evidence(
                &body,
                repository,
                &"b".repeat(40),
                123_456,
                2,
                1_787_940_001,
                true,
            ),
            validate_evidence(
                &body,
                repository,
                &policy_commit,
                123_457,
                2,
                1_787_940_001,
                true,
            ),
            validate_evidence(
                &body,
                repository,
                &policy_commit,
                123_456,
                3,
                1_787_940_001,
                true,
            ),
            validate_evidence(
                &body,
                repository,
                &policy_commit,
                123_456,
                2,
                1_787_940_301,
                true,
            ),
        ] {
            assert!(result.is_err());
        }

        let mut tampered: SettingsEvidence = serde_json::from_str(&body).unwrap();
        tampered.readback_sha256 = "0".repeat(64);
        let tampered = canonical_evidence(&tampered).unwrap();
        assert!(
            validate_evidence(
                &tampered,
                repository,
                &policy_commit,
                123_456,
                2,
                1_787_940_001,
                true,
            )
            .unwrap_err()
            .contains("digest does not match")
        );

        let mut unknown: Value = serde_json::from_str(&body).unwrap();
        unknown["unknown"] = json!(true);
        let unknown = serde_json::to_string(&unknown).unwrap();
        assert!(
            validate_evidence(
                &unknown,
                repository,
                &policy_commit,
                123_456,
                2,
                1_787_940_001,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn settings_request_uses_the_existing_gh_identity_without_a_workflow_token() {
        let command =
            repository_admin_command("NVIDIA/yaml-sigil-traits", &"a".repeat(40), 123_456, 2);
        assert_eq!(
            command,
            format!(
                "GH_TOKEN=\"$(gh auth token --hostname github.com)\" cargo +stable xtask github \
                 release-train settings-preflight --repository NVIDIA/yaml-sigil-traits \
                 --policy-commit {} --run-id 123456 --run-attempt 2",
                "a".repeat(40)
            )
        );
        assert!(!command.contains("github.token"));
        assert!(!command.contains("GITHUB_TOKEN"));
    }

    fn review_response(evidence: &str) -> Value {
        json!({
            "data": {"node": {"workflowRun": {
                "databaseId": 123456,
                "runAttempt": 2,
                "event": "workflow_dispatch",
                "deploymentReviews": {
                    "totalCount": 1,
                    "nodes": [{
                        "databaseId": 700,
                        "state": "APPROVED",
                        "comment": format!("{SETTINGS_EVIDENCE_PREFIX}{evidence}"),
                        "user": {"login": "release-admin", "databaseId": 800},
                        "environments": {
                            "totalCount": 1,
                            "nodes": [{"name": "crates-io"}],
                        },
                    }],
                },
            }}},
            "errors": [],
        })
    }

    fn review_expectations(evidence: &str, permission: &str) -> Vec<Expected> {
        vec![
            Expected::mutation(
                "GRAPHQL",
                "graphql",
                json!({
                    "query": REVIEW_QUERY,
                    "variables": {"checkSuite": "CS_fixture"},
                }),
                Ok(review_response(evidence)),
            ),
            Expected::json(
                "GET",
                "repos/NVIDIA/yaml-sigil-traits/collaborators/release-admin/permission",
                json!({
                    "permission": permission,
                    "user": {"login": "release-admin", "id": 800},
                }),
            ),
        ]
    }

    #[test]
    fn settings_review_requires_exact_current_repository_admin_authority() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let policy_commit = "a".repeat(40);
        let body = evidence(repository, &policy_commit, 123_456, 2, 1_787_940_000);
        let mut github = FakeTransport::new(review_expectations(&body, "admin"));
        let review = review_once(
            repository,
            &policy_commit,
            123_456,
            2,
            "CS_fixture",
            1_787_940_001,
            &mut github,
        )
        .unwrap()
        .unwrap();
        assert_eq!(review.review_id, 700);
        assert_eq!(review.reviewer_id, 800);
        assert_eq!(review.reviewer_login, "release-admin");
        assert_eq!(review.evidence, body);
        github.finish();

        let mut github = FakeTransport::new(review_expectations(&body, "write"));
        let error = review_once(
            repository,
            &policy_commit,
            123_456,
            2,
            "CS_fixture",
            1_787_940_001,
            &mut github,
        )
        .unwrap_err();
        assert!(error.contains("lacks current repository-admin authority"));
        github.finish();
    }

    #[test]
    fn settings_review_rejects_missing_duplicate_and_malformed_evidence() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let policy_commit = "a".repeat(40);
        let body = evidence(repository, &policy_commit, 123_456, 2, 1_787_940_000);
        let graphql_payload = json!({
            "query": REVIEW_QUERY,
            "variables": {"checkSuite": "CS_fixture"},
        });

        let mut missing = review_response(&body);
        missing["data"]["node"]["workflowRun"]["deploymentReviews"]["totalCount"] = json!(0);
        missing["data"]["node"]["workflowRun"]["deploymentReviews"]["nodes"] = json!([]);
        let mut github = FakeTransport::new([Expected::mutation(
            "GRAPHQL",
            "graphql",
            graphql_payload.clone(),
            Ok(missing),
        )]);
        assert!(
            review_once(
                repository,
                &policy_commit,
                123_456,
                2,
                "CS_fixture",
                1_787_940_001,
                &mut github,
            )
            .unwrap()
            .is_none()
        );
        github.finish();

        let mut duplicate = review_response(&body);
        let second =
            duplicate["data"]["node"]["workflowRun"]["deploymentReviews"]["nodes"][0].clone();
        duplicate["data"]["node"]["workflowRun"]["deploymentReviews"]["totalCount"] = json!(2);
        duplicate["data"]["node"]["workflowRun"]["deploymentReviews"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(second);
        let mut github = FakeTransport::new([Expected::mutation(
            "GRAPHQL",
            "graphql",
            graphql_payload.clone(),
            Ok(duplicate),
        )]);
        assert!(
            review_once(
                repository,
                &policy_commit,
                123_456,
                2,
                "CS_fixture",
                1_787_940_001,
                &mut github,
            )
            .unwrap_err()
            .contains("multiple crates-io settings reviews")
        );
        github.finish();

        let mut malformed = review_response(&body);
        malformed["data"]["node"]["workflowRun"]["deploymentReviews"]["nodes"][0]["comment"] =
            json!(format!("{SETTINGS_EVIDENCE_PREFIX}{{}}"));
        let mut github = FakeTransport::new([Expected::mutation(
            "GRAPHQL",
            "graphql",
            graphql_payload,
            Ok(malformed),
        )]);
        assert!(
            review_once(
                repository,
                &policy_commit,
                123_456,
                2,
                "CS_fixture",
                1_787_940_001,
                &mut github,
            )
            .is_err()
        );
        github.finish();
    }

    #[test]
    fn settings_rules_reject_bypass_collision_and_inactive_protection() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let mut values = rulesets(repository);
        values[2]
            .bypass_actors
            .push(json!({"actor_id":7,"actor_type":"RepositoryRole","bypass_mode":"always"}));
        assert!(validate_tag_rulesets(repository, &values).is_err());

        let mut values = rulesets(repository);
        values[0]
            .rules
            .push(json!({"type":"required_status_checks","parameters":{
                "required_status_checks":[{"context":INTENT_NAME}],
            }}));
        assert!(reject_intent_collision(&values).is_err());

        let mut values = rulesets(repository);
        values[3].enforcement = "evaluate".to_string();
        assert!(validate_tag_rulesets(repository, &values).is_err());
    }

    #[test]
    fn protected_main_requires_the_complete_exact_rule_inventory() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let baseline = rulesets(repository);
        assert!(validate_main_ruleset(repository, &baseline).is_ok());

        let mut reordered = baseline.clone();
        reordered[0].rules.reverse();
        assert!(validate_main_ruleset(repository, &reordered).is_ok());

        for index in 0..baseline[0].rules.len() {
            let mut missing = baseline.clone();
            missing[0].rules.remove(index);
            assert!(validate_main_ruleset(repository, &missing).is_err());
        }

        let mut duplicated = baseline.clone();
        let duplicate = duplicated[0].rules[0].clone();
        duplicated[0].rules.push(duplicate);
        assert!(validate_main_ruleset(repository, &duplicated).is_err());

        let mut extra = baseline.clone();
        extra[0].rules.push(json!({"type":"creation"}));
        assert!(validate_main_ruleset(repository, &extra).is_err());

        for index in 0..baseline[0].rules.len() {
            let mut weakened = baseline.clone();
            weakened[0].rules[index]["unexpected"] = json!(true);
            assert!(validate_main_ruleset(repository, &weakened).is_err());
        }
    }

    #[test]
    fn protected_main_classifies_extra_rulesets_before_rejecting_them() {
        let repository = "NVIDIA/yaml-sigil-traits";
        let baseline = rulesets(repository);

        let mut extra = baseline[0].clone();
        extra.id = 105;
        extra.name = "Unexpected main control".to_string();
        assert!(
            validate_main_ruleset(repository, &[baseline.clone(), vec![extra]].concat()).is_err()
        );

        let mut inherited = baseline[0].clone();
        inherited.id = 106;
        inherited.name = "Inherited main control".to_string();
        inherited.source_type = "Organization".to_string();
        inherited.source = "NVIDIA".to_string();
        assert!(
            validate_main_ruleset(repository, &[baseline.clone(), vec![inherited]].concat())
                .is_err()
        );

        let mut inactive = baseline[0].clone();
        inactive.id = 107;
        inactive.name = "Inactive main experiment".to_string();
        inactive.enforcement = "evaluate".to_string();
        assert!(
            validate_main_ruleset(repository, &[baseline.clone(), vec![inactive]].concat()).is_ok()
        );

        let mut disjoint = baseline[0].clone();
        disjoint.id = 108;
        disjoint.name = "Release branch control".to_string();
        disjoint.conditions = json!({"ref_name":{"exclude":[],"include":["refs/heads/release/*"]}});
        assert!(validate_main_ruleset(repository, &[baseline, vec![disjoint]].concat()).is_ok());
    }

    #[test]
    fn utc_formatting_is_exact_and_bounded() {
        assert_eq!(format_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_787_940_000).unwrap(), "2026-08-28T18:00:00Z");
        assert!(format_utc(u64::MAX).is_err());
    }
}

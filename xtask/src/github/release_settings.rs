// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Read-only release-setting validation for one exact active workflow run.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::release_train::{
    APP_PUBLIC_ID, INTENT_NAME, settings_evidence_sha256, settings_evidence_tag_patterns,
};
use super::transport::{GITHUB_API_VERSION, Transport};
use super::{git_line, is_positive_integer, is_sha, repository_policy_for_root};

const MAIN_RULESET: &str = "Protect main and require CI";
const V1ALPHA1_RULESET: &str = "Protect v1alpha1 tag";
const CREATION_RULESET: &str = "Protect release tag creation";
const UPDATE_DELETE_RULESET: &str = "Protect release tag updates and deletion";
const WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const APPROVAL_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_RULESETS: usize = 99;

#[derive(Debug, Deserialize)]
struct Repository {
    full_name: String,
    default_branch: String,
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
    repository: Repository,
}

#[derive(Debug, Deserialize, Serialize)]
struct ImmutableReleases {
    enabled: bool,
    enforced_by_owner: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Ruleset {
    id: u64,
    name: String,
    target: String,
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

#[derive(Debug)]
struct Evidence {
    workflow_evidence_sha256: String,
    readback_sha256: String,
    readback_utc: String,
    approve_before_utc: String,
}

pub(super) fn preflight_command(
    root: &Path,
    repository: &str,
    release_sha: &str,
    run_id: &str,
    run_attempt: &str,
    expected_evidence_sha256: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    repository_policy_for_root(root, repository)?;
    if !is_sha(release_sha) || git_line(root, &["rev-parse", "HEAD"])? != release_sha {
        return Err("release settings must be checked from the exact release source".to_string());
    }
    let run_id = positive(run_id, "workflow run ID")?;
    let run_attempt = positive(run_attempt, "workflow run attempt")?;
    if !is_digest(expected_evidence_sha256) {
        return Err("expected workflow evidence digest is invalid".to_string());
    }
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_string())?
        .as_secs();
    let evidence = validate_preflight(
        repository,
        release_sha,
        run_id,
        run_attempt,
        observed,
        github,
    )?;
    if evidence.workflow_evidence_sha256 != expected_evidence_sha256 {
        return Err(
            "workflow evidence digest does not bind these exact settings inputs".to_string(),
        );
    }
    println!("repository_admin_settings=valid");
    println!(
        "workflow_evidence_sha256={}",
        evidence.workflow_evidence_sha256
    );
    println!("readback_sha256={}", evidence.readback_sha256);
    println!("readback_utc={}", evidence.readback_utc);
    println!("approve_before_utc={}", evidence.approve_before_utc);
    Ok(())
}

fn validate_preflight(
    repository: &str,
    release_sha: &str,
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
        || reference.object.sha != release_sha
    {
        return Err("release SHA is no longer exact current main".to_string());
    }
    let run: WorkflowRun = github.get(&format!("repos/{repository}/actions/runs/{run_id}"))?;
    if run.id != run_id
        || run.run_attempt != run_attempt
        || run.head_sha != release_sha
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
    validate_main_ruleset(&rulesets)?;
    validate_tag_rulesets(repository, &rulesets)?;
    rulesets.sort_by(|left, right| (&left.target, left.id).cmp(&(&right.target, right.id)));

    let observed_at = format_utc(observed)?;
    let approve_before = observed
        .checked_add(APPROVAL_WINDOW.as_secs())
        .ok_or_else(|| "approval deadline overflowed".to_string())?;
    let snapshot = json!({
        "schema_version": 1,
        "api_version": GITHUB_API_VERSION,
        "repository": repository,
        "release_sha": release_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_status": run.status,
        "observed_at": observed_at,
        "immutable_releases": immutable,
        "rulesets": rulesets,
    });
    let canonical = serde_json::to_vec(&snapshot)
        .map_err(|error| format!("encode canonical settings readback: {error}"))?;
    Ok(Evidence {
        workflow_evidence_sha256: settings_evidence_sha256(
            repository,
            release_sha,
            run_id,
            run_attempt,
        )?,
        readback_sha256: format!("{:x}", Sha256::digest(canonical)),
        readback_utc: snapshot["observed_at"]
            .as_str()
            .ok_or_else(|| "settings timestamp encoding failed".to_string())?
            .to_string(),
        approve_before_utc: format_utc(approve_before)?,
    })
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
    for ruleset in rulesets {
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
            if checks
                .iter()
                .any(|check| check.get("context").and_then(Value::as_str) == Some(INTENT_NAME))
            {
                return Err(format!(
                    "{INTENT_NAME:?} collides with an applicable required check"
                ));
            }
        }
    }
    Ok(())
}

fn validate_main_ruleset(rulesets: &[Ruleset]) -> Result<(), String> {
    let main = named_ruleset(rulesets, MAIN_RULESET)?;
    if main.target != "branch" || main.enforcement != "active" || !main.bypass_actors.is_empty() {
        return Err("protected-main ruleset target, enforcement, or bypass drifted".to_string());
    }
    require_ref_conditions(main, &["refs/heads/main"])?;
    let required = main
        .rules
        .iter()
        .filter(|rule| rule.get("type").and_then(Value::as_str) == Some("required_status_checks"))
        .collect::<Vec<_>>();
    if required.len() != 1
        || required[0].get("parameters")
            != Some(&json!({
                "do_not_enforce_on_create": false,
                "strict_required_status_checks_policy": true,
                "required_status_checks": [{"context": "Required CI", "integration_id": APP_PUBLIC_ID}],
            }))
    {
        return Err("protected-main Required CI binding drifted".to_string());
    }
    Ok(())
}

fn validate_tag_rulesets(repository: &str, rulesets: &[Ruleset]) -> Result<(), String> {
    let legacy = named_ruleset(rulesets, V1ALPHA1_RULESET)?;
    if legacy.target != "tag" || legacy.enforcement != "active" || !legacy.bypass_actors.is_empty()
    {
        return Err("existing v1alpha1 protection drifted".to_string());
    }
    require_ref_conditions(legacy, &["refs/tags/v1alpha1"])?;
    require_rule_types(legacy, &["update", "deletion"])?;

    let patterns = settings_evidence_tag_patterns(repository)?;
    let creation = named_ruleset(rulesets, CREATION_RULESET)?;
    if creation.target != "tag"
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
mod tests {
    use super::super::transport::fake::{Expected, FakeTransport};
    use super::*;

    fn rulesets(repository: &str) -> Vec<Ruleset> {
        let patterns = settings_evidence_tag_patterns(repository).unwrap();
        vec![
            Ruleset {
                id: 101,
                name: MAIN_RULESET.to_string(),
                target: "branch".to_string(),
                enforcement: "active".to_string(),
                bypass_actors: vec![],
                conditions: json!({"ref_name":{"exclude":[],"include":["refs/heads/main"]}}),
                rules: vec![
                    json!({"type":"required_linear_history"}),
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
                enforcement: "active".to_string(),
                bypass_actors: vec![],
                conditions: json!({"ref_name":{"exclude":[],"include":["refs/tags/v1alpha1"]}}),
                rules: vec![json!({"type":"update"}), json!({"type":"deletion"})],
            },
            Ruleset {
                id: 103,
                name: CREATION_RULESET.to_string(),
                target: "tag".to_string(),
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
                    "conclusion":null,"repository":{"full_name":repository,"default_branch":"main"},
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
            assert_eq!(
                evidence.workflow_evidence_sha256,
                settings_evidence_sha256(repository, &"a".repeat(40), 123_456, 2).unwrap()
            );
            github.finish();
        }
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
    fn utc_formatting_is_exact_and_bounded() {
        assert_eq!(format_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_787_940_000).unwrap(), "2026-08-28T18:00:00Z");
        assert!(format_utc(u64::MAX).is_err());
    }
}

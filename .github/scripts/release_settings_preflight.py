#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Read-only repository-admin preflight for one source-only release run."""

from __future__ import annotations

import argparse
import datetime as dt
import os
from dataclasses import dataclass
from typing import Any

from release_notification_preflight import (
    API_VERSION,
    INTENT_NAME,
    Api,
    PreflightError,
    canonical,
    require,
    require_digest,
    require_positive,
    require_sha,
    require_string,
    sha256,
)

APP_ID = 4_653_064
MAIN_RULESET = "Protect main and require CI"
V1ALPHA1_RULESET = "Protect v1alpha1 tag"
CREATION_RULESET = "Protect release tag creation"
UPDATE_DELETE_RULESET = "Protect release tag updates and deletion"
WORKFLOW_PATH = ".github/workflows/publish.yml"
ACTIVE_RUN_STATES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})


@dataclass(frozen=True)
class SettingsPolicy:
    repository: str
    tag_patterns: tuple[str, ...]


POLICIES = {
    "NVIDIA/yaml-sigil-traits": SettingsPolicy(
        "NVIDIA/yaml-sigil-traits",
        ("refs/tags/v*",),
    ),
    "NVIDIA/yaml-sigil-rs": SettingsPolicy(
        "NVIDIA/yaml-sigil-rs",
        (
            "refs/tags/yaml-sigil-core-v*",
            "refs/tags/yaml-sigil-transcription-v*",
            "refs/tags/yaml-sigil-signing-v*",
            "refs/tags/yaml-sigil-verification-v*",
        ),
    ),
}


def require_list(value: Any, label: str, limit: int) -> list[Any]:
    require(type(value) is list and len(value) <= limit, f"{label} is invalid or oversized")
    return value


def binding_values(
    policy: SettingsPolicy,
    release_sha: str,
    run_id: int,
    run_attempt: int,
) -> tuple[str, ...]:
    values = [
        "yaml-sigil-release-setting-evidence-v1",
        policy.repository,
        str(run_id),
        str(run_attempt),
        release_sha,
        "immutable-releases=true",
    ]
    values.extend(
        f"creation={pattern}:Integration:{APP_ID}:always"
        for pattern in policy.tag_patterns
    )
    values.extend(
        f"update-delete={pattern}:no-bypass"
        for pattern in policy.tag_patterns
    )
    values.append(f"forbidden-required-check={INTENT_NAME}")
    return tuple(values)


def binding_digest(
    policy: SettingsPolicy,
    release_sha: str,
    run_id: int,
    run_attempt: int,
) -> str:
    body = b"".join(
        value.encode("utf-8") + b"\0"
        for value in binding_values(policy, release_sha, run_id, run_attempt)
    )
    return sha256(body)


def ruleset_projection(ruleset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": ruleset.get("id"),
        "name": ruleset.get("name"),
        "target": ruleset.get("target"),
        "enforcement": ruleset.get("enforcement"),
        "bypass_actors": ruleset.get("bypass_actors"),
        "conditions": ruleset.get("conditions"),
        "rules": ruleset.get("rules"),
    }


def fetch_rulesets(api: Api, repository: str) -> list[dict[str, Any]]:
    listed = require_list(
        api.github_json(f"repos/{repository}/rulesets?includes_parents=true&per_page=100"),
        "repository ruleset list",
        99,
    )
    ids: set[int] = set()
    details: list[dict[str, Any]] = []
    for index, summary in enumerate(listed):
        require(type(summary) is dict, f"ruleset summary {index} is invalid")
        if summary.get("target") not in {"branch", "tag"}:
            continue
        ruleset_id = require_positive(summary.get("id"), f"ruleset summary {index} ID")
        require(ruleset_id not in ids, "repository ruleset list contains duplicate IDs")
        ids.add(ruleset_id)
        detail = api.github_json(f"repos/{repository}/rulesets/{ruleset_id}")
        require(type(detail) is dict, f"ruleset {ruleset_id} response is invalid")
        require(detail.get("id") == ruleset_id, f"ruleset {ruleset_id} ID drifted")
        require_list(detail.get("bypass_actors"), f"ruleset {ruleset_id} bypass actors", 32)
        require(type(detail.get("conditions")) is dict, f"ruleset {ruleset_id} conditions are invalid")
        require_list(detail.get("rules"), f"ruleset {ruleset_id} rules", 32)
        details.append(detail)
    require(details, "repository has no branch or tag rulesets")
    return details


def named_rule(rulesets: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [ruleset for ruleset in rulesets if ruleset.get("name") == name]
    require(len(matches) == 1, f"ruleset {name!r} is missing or duplicated")
    return matches[0]


def require_ref_conditions(ruleset: dict[str, Any], includes: tuple[str, ...]) -> None:
    require(
        ruleset.get("conditions")
        == {"ref_name": {"exclude": [], "include": list(includes)}},
        f"ruleset {ruleset.get('name')!r} ref conditions drifted",
    )


def require_rule_types(ruleset: dict[str, Any], types: tuple[str, ...]) -> None:
    require(
        ruleset.get("rules") == [{"type": rule_type} for rule_type in types],
        f"ruleset {ruleset.get('name')!r} rule types drifted",
    )


def reject_intent_collision(rulesets: list[dict[str, Any]]) -> None:
    for ruleset in rulesets:
        for rule in ruleset["rules"]:
            if type(rule) is not dict or rule.get("type") != "required_status_checks":
                continue
            parameters = rule.get("parameters")
            require(type(parameters) is dict, "required-status-check parameters are invalid")
            checks = require_list(
                parameters.get("required_status_checks"),
                "required status checks",
                64,
            )
            for check in checks:
                require(type(check) is dict, "required status check is invalid")
                require(
                    check.get("context") != INTENT_NAME,
                    f"{INTENT_NAME!r} collides with an applicable required check",
                )


def validate_main_ruleset(rulesets: list[dict[str, Any]]) -> None:
    main = named_rule(rulesets, MAIN_RULESET)
    require(
        main.get("target") == "branch"
        and main.get("enforcement") == "active"
        and main.get("bypass_actors") == [],
        "protected-main ruleset target, enforcement, or bypass drifted",
    )
    require_ref_conditions(main, ("refs/heads/main",))
    required = [
        rule
        for rule in main["rules"]
        if type(rule) is dict and rule.get("type") == "required_status_checks"
    ]
    require(len(required) == 1, "protected-main required-check rule is missing or duplicated")
    parameters = required[0].get("parameters")
    require(type(parameters) is dict, "protected-main required-check parameters are invalid")
    require(
        parameters.get("strict_required_status_checks_policy") is True
        and parameters.get("do_not_enforce_on_create") is False
        and parameters.get("required_status_checks")
        == [{"context": "Required CI", "integration_id": APP_ID}],
        "protected-main Required CI binding drifted",
    )


def validate_tag_rulesets(policy: SettingsPolicy, rulesets: list[dict[str, Any]]) -> None:
    legacy = named_rule(rulesets, V1ALPHA1_RULESET)
    require(
        legacy.get("target") == "tag"
        and legacy.get("enforcement") == "active"
        and legacy.get("bypass_actors") == [],
        "existing v1alpha1 protection drifted",
    )
    require_ref_conditions(legacy, ("refs/tags/v1alpha1",))
    require_rule_types(legacy, ("update", "deletion"))

    creation = named_rule(rulesets, CREATION_RULESET)
    require(
        creation.get("target") == "tag" and creation.get("enforcement") == "active",
        "release-tag creation ruleset is not active",
    )
    require(
        creation.get("bypass_actors")
        == [{"actor_id": APP_ID, "actor_type": "Integration", "bypass_mode": "always"}],
        "release-tag creation bypass is not the sole approved App",
    )
    require_ref_conditions(creation, policy.tag_patterns)
    require_rule_types(creation, ("creation",))

    updates = named_rule(rulesets, UPDATE_DELETE_RULESET)
    require(
        updates.get("target") == "tag"
        and updates.get("enforcement") == "active"
        and updates.get("bypass_actors") == [],
        "release-tag update/deletion protection drifted",
    )
    require_ref_conditions(updates, policy.tag_patterns)
    require_rule_types(updates, ("update", "deletion"))


def validate_run(
    api: Api,
    policy: SettingsPolicy,
    release_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    repository = api.github_json(f"repos/{policy.repository}")
    require(type(repository) is dict, "repository response is invalid")
    require(
        repository.get("full_name") == policy.repository
        and repository.get("default_branch") == "main",
        "repository identity or default branch drifted",
    )
    reference = api.github_json(f"repos/{policy.repository}/git/ref/heads/main")
    require(type(reference) is dict and type(reference.get("object")) is dict, "main ref is invalid")
    require(
        reference.get("ref") == "refs/heads/main"
        and reference["object"].get("type") == "commit"
        and reference["object"].get("sha") == release_sha,
        "release SHA is no longer exact current main",
    )

    run = api.github_json(f"repos/{policy.repository}/actions/runs/{run_id}")
    require(type(run) is dict, "workflow run response is invalid")
    run_repository = run.get("repository")
    require(type(run_repository) is dict, "workflow run repository is missing")
    require(
        run.get("id") == run_id
        and run.get("run_attempt") == run_attempt
        and run.get("head_sha") == release_sha
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW_PATH
        and run.get("status") in ACTIVE_RUN_STATES
        and run.get("conclusion") is None
        and run_repository.get("full_name") == policy.repository,
        "workflow run identity, source, attempt, or active state drifted",
    )
    return run


def validate_preflight(
    policy: SettingsPolicy,
    api: Api,
    release_sha: str,
    run_id: int,
    run_attempt: int,
    observed_at: dt.datetime,
) -> dict[str, str]:
    run = validate_run(api, policy, release_sha, run_id, run_attempt)
    immutable = api.github_json(f"repos/{policy.repository}/immutable-releases")
    require(type(immutable) is dict, "immutable-Release response is invalid")
    require(
        immutable.get("enabled") is True,
        "repository immutable Releases are not enabled",
    )

    rulesets = fetch_rulesets(api, policy.repository)
    reject_intent_collision(rulesets)
    validate_main_ruleset(rulesets)
    validate_tag_rulesets(policy, rulesets)

    snapshot = {
        "schema_version": 1,
        "api_version": API_VERSION,
        "repository": policy.repository,
        "release_sha": release_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_status": run["status"],
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "immutable_releases": {
            "enabled": immutable.get("enabled"),
            "enforced_by_owner": immutable.get("enforced_by_owner"),
        },
        "rulesets": sorted(
            (ruleset_projection(ruleset) for ruleset in rulesets),
            key=lambda value: (str(value["target"]), int(value["id"])),
        ),
    }
    deadline = observed_at + dt.timedelta(minutes=5)
    return {
        "workflow_evidence_sha256": binding_digest(
            policy,
            release_sha,
            run_id,
            run_attempt,
        ),
        "readback_sha256": sha256(canonical(snapshot).encode("utf-8")),
        "readback_utc": snapshot["observed_at"],
        "approve_before_utc": deadline.isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--expected-evidence-sha256", required=True)
    args = parser.parse_args()

    try:
        repository = require_string(args.repository, "repository", 256)
        require(repository in POLICIES, "repository is outside the release-settings policy")
        policy = POLICIES[repository]
        release_sha = require_sha(args.release_sha, "release SHA")
        run_id = require_positive(args.run_id, "workflow run ID")
        run_attempt = require_positive(args.run_attempt, "workflow run attempt")
        expected = require_digest(
            args.expected_evidence_sha256,
            "expected workflow evidence digest",
        )
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
        api = Api(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        evidence = validate_preflight(
            policy,
            api,
            release_sha,
            run_id,
            run_attempt,
            observed_at,
        )
        require(
            evidence["workflow_evidence_sha256"] == expected,
            "workflow evidence digest does not bind these exact settings inputs",
        )
        print("repository_admin_settings=valid")
        for key, value in evidence.items():
            print(f"{key}={value}")
    except (OSError, PreflightError) as error:
        print(f"release settings rejected: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

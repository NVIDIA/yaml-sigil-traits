#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the repository-admin release-settings preflight."""

from __future__ import annotations

import copy
import datetime as dt
import unittest
from typing import Any

import release_settings_preflight as preflight
from release_notification_preflight import PreflightError


class FakeApi:
    def __init__(self, github: dict[str, Any]) -> None:
        self.github = github

    def github_json(self, path: str, optional: bool = False) -> Any:
        if path not in self.github:
            if optional:
                return None
            raise AssertionError(f"unexpected GitHub read: {path}")
        return copy.deepcopy(self.github[path])


class Fixture:
    def __init__(self, repository: str) -> None:
        self.policy = preflight.POLICIES[repository]
        self.release_sha = "a" * 40
        self.run_id = 123_456
        self.run_attempt = 2
        self.observed = dt.datetime(2026, 8, 28, 18, 0, tzinfo=dt.timezone.utc)
        rulesets = [
            self.main_ruleset(101),
            self.v1alpha1_ruleset(102),
            self.creation_ruleset(103),
            self.update_ruleset(104),
        ]
        summaries = [
            {
                "id": rule["id"],
                "name": rule["name"],
                "target": rule["target"],
                "enforcement": rule["enforcement"],
            }
            for rule in rulesets
        ]
        self.github: dict[str, Any] = {
            f"repos/{repository}": {
                "full_name": repository,
                "default_branch": "main",
            },
            f"repos/{repository}/git/ref/heads/main": {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": self.release_sha},
            },
            f"repos/{repository}/actions/runs/{self.run_id}": {
                "id": self.run_id,
                "run_attempt": self.run_attempt,
                "head_sha": self.release_sha,
                "head_branch": "main",
                "event": "workflow_dispatch",
                "path": preflight.WORKFLOW_PATH,
                "status": "waiting",
                "conclusion": None,
                "repository": {"full_name": repository},
            },
            f"repos/{repository}/immutable-releases": {
                "enabled": True,
                "enforced_by_owner": False,
            },
            f"repos/{repository}/rulesets?includes_parents=true&per_page=100": summaries,
        }
        for rule in rulesets:
            self.github[f"repos/{repository}/rulesets/{rule['id']}"] = rule

    @staticmethod
    def main_ruleset(identifier: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "name": preflight.MAIN_RULESET,
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/heads/main"]}
            },
            "rules": [
                {"type": "required_linear_history"},
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {
                                "context": "Required CI",
                                "integration_id": preflight.APP_ID,
                            }
                        ],
                    },
                },
            ],
        }

    @staticmethod
    def v1alpha1_ruleset(identifier: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "name": preflight.V1ALPHA1_RULESET,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"exclude": [], "include": ["refs/tags/v1alpha1"]}
            },
            "rules": [{"type": "update"}, {"type": "deletion"}],
        }

    def creation_ruleset(self, identifier: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "name": preflight.CREATION_RULESET,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [
                {
                    "actor_id": preflight.APP_ID,
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ],
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": list(self.policy.tag_patterns),
                }
            },
            "rules": [{"type": "creation"}],
        }

    def update_ruleset(self, identifier: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "name": preflight.UPDATE_DELETE_RULESET,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "exclude": [],
                    "include": list(self.policy.tag_patterns),
                }
            },
            "rules": [{"type": "update"}, {"type": "deletion"}],
        }

    def validate(self) -> dict[str, str]:
        return preflight.validate_preflight(
            self.policy,
            FakeApi(self.github),
            self.release_sha,
            self.run_id,
            self.run_attempt,
            self.observed,
        )


class ReleaseSettingsPreflightTests(unittest.TestCase):
    def test_traits_and_rs_exact_settings_pass(self) -> None:
        for repository in preflight.POLICIES:
            with self.subTest(repository=repository):
                fixture = Fixture(repository)
                evidence = fixture.validate()
                self.assertEqual(
                    evidence["workflow_evidence_sha256"],
                    preflight.binding_digest(
                        fixture.policy,
                        fixture.release_sha,
                        fixture.run_id,
                        fixture.run_attempt,
                    ),
                )
                self.assertEqual(evidence["readback_utc"], "2026-08-28T18:00:00Z")
                self.assertEqual(evidence["approve_before_utc"], "2026-08-28T18:05:00Z")

    def test_immutable_releases_must_be_enabled(self) -> None:
        fixture = Fixture("NVIDIA/yaml-sigil-traits")
        fixture.github[
            f"repos/{fixture.policy.repository}/immutable-releases"
        ]["enabled"] = False
        with self.assertRaisesRegex(PreflightError, "not enabled"):
            fixture.validate()

    def test_only_the_release_app_may_bypass_creation(self) -> None:
        fixture = Fixture("NVIDIA/yaml-sigil-rs")
        creation = fixture.github[
            f"repos/{fixture.policy.repository}/rulesets/103"
        ]
        creation["bypass_actors"].append(
            {"actor_id": 7, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        )
        with self.assertRaisesRegex(PreflightError, "sole approved App"):
            fixture.validate()

    def test_intent_check_may_not_collide_with_required_checks(self) -> None:
        fixture = Fixture("NVIDIA/yaml-sigil-traits")
        main = fixture.github[f"repos/{fixture.policy.repository}/rulesets/101"]
        required = next(
            rule for rule in main["rules"] if rule["type"] == "required_status_checks"
        )
        required["parameters"]["required_status_checks"].append(
            {"context": preflight.INTENT_NAME, "integration_id": preflight.APP_ID}
        )
        with self.assertRaisesRegex(PreflightError, "collides"):
            fixture.validate()

    def test_run_and_current_main_are_exactly_bound(self) -> None:
        fixture = Fixture("NVIDIA/yaml-sigil-rs")
        fixture.github[
            f"repos/{fixture.policy.repository}/actions/runs/{fixture.run_id}"
        ]["head_sha"] = "b" * 40
        with self.assertRaisesRegex(PreflightError, "workflow run identity"):
            fixture.validate()

        fixture = Fixture("NVIDIA/yaml-sigil-rs")
        fixture.github[
            f"repos/{fixture.policy.repository}/git/ref/heads/main"
        ]["object"]["sha"] = "b" * 40
        with self.assertRaisesRegex(PreflightError, "exact current main"):
            fixture.validate()

    def test_release_rules_must_be_active_and_exact(self) -> None:
        fixture = Fixture("NVIDIA/yaml-sigil-traits")
        fixture.github[
            f"repos/{fixture.policy.repository}/rulesets/104"
        ]["enforcement"] = "evaluate"
        with self.assertRaisesRegex(PreflightError, "protection drifted"):
            fixture.validate()


if __name__ == "__main__":
    unittest.main()

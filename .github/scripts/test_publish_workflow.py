# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Structural regressions for the release workflow's authority boundaries."""

from __future__ import annotations

import pathlib
import re
import unittest


WORKFLOW_LIMIT = 256 * 1024
WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[1] / "workflows" / "publish.yml"
)


def read_workflow() -> str:
    size = WORKFLOW.stat().st_size
    if size <= 0 or size > WORKFLOW_LIMIT:
        raise AssertionError(f"publish workflow has invalid size {size}")
    return WORKFLOW.read_text(encoding="utf-8")


def indented_block(body: str, marker: str, next_pattern: str) -> str:
    start = body.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow marker: {marker.strip()}")
    following = re.search(next_pattern, body[start + len(marker) :], re.MULTILINE)
    end = len(body) if following is None else start + len(marker) + following.start()
    return body[start:end]


def job(body: str, name: str) -> str:
    return indented_block(body, f"  {name}:\n", r"^  [a-zA-Z0-9_-]+:\n")


def step(job_body: str, name: str) -> str:
    return indented_block(job_body, f"      - name: {name}\n", r"^      - name: .+\n")


class PublishWorkflowAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = read_workflow()

    def test_admin_settings_read_is_an_operator_attestation(self) -> None:
        release_intent = job(self.workflow, "release-intent")
        request = step(
            release_intent, "Display repository-admin settings evidence request"
        )
        review = step(release_intent, "Authenticate the exact crates.io approval")

        self.assertIn("release-train settings-request", request)
        self.assertNotIn("settings-preflight", request)
        self.assertNotIn("GH_TOKEN:", request)
        self.assertNotIn("github.token", request)
        self.assertNotIn("release-train settings-preflight", self.workflow)
        self.assertIn("release-train await-settings-review", review)
        self.assertIn("GH_TOKEN: ${{ github.token }}", review)

    def test_publication_waits_at_the_final_concurrent_authority_gate(self) -> None:
        publication = job(self.workflow, "publication")
        release_intent = job(self.workflow, "release-intent")
        authority_name = "Await exact pre-publication App authority"
        publication_name = "Publish missing source package and await exact registry state"
        authority = step(publication, authority_name)
        publish = step(publication, publication_name)

        self.assertRegex(publication, r"(?m)^    needs: release-readiness$")
        self.assertRegex(release_intent, r"(?m)^    needs: release-readiness$")
        self.assertIn("environment: crates-io", publication)
        self.assertIn("environment: protected-automation", release_intent)
        self.assertIn("checks: read", publication)
        self.assertIn("deployments: read", release_intent)
        self.assertIn("release-train await-release-authority", authority)
        self.assertIn("release-plz release", publish)

        step_names = re.findall(r"(?m)^      - name: (.+)$", publication)
        self.assertEqual(
            step_names.index(publication_name),
            step_names.index(authority_name) + 1,
            "await-release-authority must remain the final step before publication",
        )
        authority_offset = publication.index(f"      - name: {authority_name}\n")
        for command in ("release-plz release", "cargo publish", "cargo yank"):
            for match in re.finditer(re.escape(command), publication):
                self.assertGreater(
                    match.start(),
                    authority_offset,
                    f"{command} appears before await-release-authority",
                )

    def test_validation_exercises_the_same_handshake_without_publication(self) -> None:
        validation = job(self.workflow, "authority-validation")
        publication = job(self.workflow, "publication")
        release_intent = job(self.workflow, "release-intent")
        publish_authority = step(
            publication, "Await exact pre-publication App authority"
        )

        self.assertRegex(validation, r"(?m)^    needs: release-readiness$")
        self.assertRegex(release_intent, r"(?m)^    needs: release-readiness$")
        self.assertIn("inputs.operation == 'validate'", validation)
        self.assertIn("inputs.operation == 'validate'", release_intent)
        self.assertIn("inputs.operation == 'publish'", release_intent)
        self.assertIn("environment: crates-io", validation)
        self.assertIn("checks: read", validation)
        self.assertIn("contents: read", validation)
        for binding in (
            "release-train await-release-authority",
            '--repository "${GITHUB_REPOSITORY}"',
            '--plan "${PLAN}"',
            '--plan-digest "${PLAN_DIGEST}"',
            '--policy-commit "${POLICY_COMMIT}"',
            '--run-id "${GITHUB_RUN_ID}"',
            '--run-attempt "${GITHUB_RUN_ATTEMPT}"',
        ):
            self.assertIn(binding, validation)
            self.assertIn(binding, publish_authority)
        executable = "\n".join(
            line for line in validation.splitlines()
            if not line.lstrip().startswith("#")
        )
        for forbidden in (
            "id-token:",
            "release-plz",
            "cargo publish",
            "cargo yank",
            "create-github-app-token@",
            "upload-artifact",
        ):
            self.assertNotIn(forbidden, executable)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Structural security regressions for the mutually exclusive release paths."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def job_block(workflow: str, name: str) -> str:
    jobs = workflow.split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", jobs))
    for index, match in enumerate(starts):
        if match.group(1) == name:
            end = starts[index + 1].start() if index + 1 < len(starts) else len(jobs)
            return jobs[match.start() : end]
    raise AssertionError(f"job {name} is missing")


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.publish = read("publish.yml")
        self.entrypoint = read("release-pr.yml")
        self.reusable = read("release-proposal.yml")

    def test_entrypoints_and_call_only_boundary_are_exact(self) -> None:
        self.assertIn("  repository_dispatch:\n    types:\n      - official-release-published", self.publish)
        self.assertNotIn("repository_dispatch:", self.entrypoint)
        self.assertIn("  workflow_call:\n", self.reusable)
        self.assertNotIn("  push:\n", self.reusable)
        self.assertNotIn("  workflow_dispatch:\n", self.reusable)
        caller = job_block(self.entrypoint, "proposal")
        self.assertIn("uses: ./.github/workflows/release-proposal.yml", caller)
        self.assertNotIn("steps:", caller)
        receiver = job_block(self.publish, "release-proposal")
        self.assertIn("github.event_name == 'repository_dispatch'", receiver)
        self.assertIn("github.event.action == 'official-release-published'", receiver)
        self.assertIn("source-event: repository_dispatch", receiver)

    def test_dispatch_cannot_enter_publication_or_oidc(self) -> None:
        readiness = job_block(self.publish, "release-readiness")
        publication = job_block(self.publish, "publication")
        authority_validation = job_block(self.publish, "authority-validation")
        self.assertIn("github.event_name == 'workflow_dispatch'", readiness)
        self.assertIn("github.event_name == 'workflow_dispatch'", publication)
        self.assertNotIn("repository_dispatch", readiness)
        self.assertNotIn("repository_dispatch", publication)
        self.assertNotIn("environment:", readiness)
        self.assertNotIn("id-token:", readiness)
        self.assertNotIn("secrets.", readiness)
        self.assertRegex(
            publication,
            r"permissions:\n      checks: read\n      contents: read\n"
            r"      pull-requests: read\n      id-token: write",
        )
        self.assertNotIn("permission-contents: write", publication)
        self.assertIn("inputs.operation == 'validate'", authority_validation)
        self.assertIn("environment: crates-io", authority_validation)
        self.assertIn("release-train await-release-authority", authority_validation)
        executable = "\n".join(
            line for line in authority_validation.splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertNotIn("id-token:", executable)
        self.assertNotIn("release-plz", executable)
        self.assertNotIn("cargo publish", executable)
        self.assertNotIn("cargo yank", executable)

    def test_dispatch_preflight_uses_exact_current_rust_and_is_secretless(self) -> None:
        preflight = job_block(self.reusable, "release-notification-preflight")
        for forbidden in (
            "environment:",
            "secrets.",
            "id-token:",
            "create-github-app-token@",
            "release-plz",
            "actions/cache@",
            "python3",
            "base64",
            "tar -",
            "gh api",
        ):
            self.assertNotIn(forbidden, preflight)
        self.assertIn("checks: read", preflight)
        self.assertIn("actions: read", preflight)
        self.assertIn("contents: read", preflight)
        self.assertIn("pull-requests: read", preflight)
        self.assertIn("actions/checkout@", preflight)
        self.assertIn("persist-credentials: false", preflight)
        self.assertIn("ref: ${{ github.sha }}", preflight)
        self.assertIn("toolchain: stable", preflight)
        self.assertIn("cargo +stable build --locked --release", preflight)
        self.assertIn("github release-train receive", preflight)
        self.assertIn('--event "${GITHUB_EVENT_PATH}"', preflight)
        self.assertIn('--policy-commit "${GITHUB_SHA}"', preflight)

    def test_every_app_token_job_uses_protected_automation(self) -> None:
        protected = [
            (self.reusable, "proposal"),
            (self.publish, "release-intent"),
            (self.publish, "release-finalizer"),
            (self.publish, "release-notification"),
        ]
        for workflow, name in protected:
            with self.subTest(job=name):
                block = job_block(workflow, name)
                self.assertIn("environment: protected-automation", block)
                self.assertIn("create-github-app-token@", block)
        notification = job_block(self.publish, "release-notification")
        self.assertIn("actions/checkout@", notification)
        self.assertIn("persist-credentials: false", notification)
        self.assertIn("ref: ${{ needs.publication.outputs.policy_commit }}", notification)
        self.assertIn("permission-contents: write", notification)

    def test_tokens_are_minted_after_their_read_only_preflights(self) -> None:
        proposal = job_block(self.reusable, "proposal")
        self.assertLess(
            proposal.index("Recheck official tags and current main before token minting"),
            proposal.index("Create repository-scoped proposal token"),
        )
        intent = job_block(self.publish, "release-intent")
        self.assertLess(intent.index("Recompute release plan"), intent.index("Create checks-only repository token"))
        finalizer = job_block(self.publish, "release-finalizer")
        self.assertLess(
            finalizer.index("Recompute plan and verify both App authorities"),
            finalizer.index("Create finalizer repository token"),
        )
        notification = job_block(self.publish, "release-notification")
        self.assertLess(
            notification.index("Compile protected typed notifier"),
            notification.index("Create notification-only repository token"),
        )

    def test_concurrency_and_replay_inputs_are_static(self) -> None:
        concurrency = self.reusable.split("\njobs:\n", 1)[0]
        self.assertIn("group: release-proposal-${{ github.repository }}", concurrency)
        self.assertIn("cancel-in-progress: false", concurrency)
        self.assertNotIn("inputs.", concurrency)
        proposal = job_block(self.reusable, "proposal")
        self.assertIn("RELEASE_REPLAY_KEY:", proposal)
        self.assertIn("steps.release-pr.outputs.release_replay_key", proposal)

    def test_no_release_path_uploads_or_retains_executables(self) -> None:
        combined = self.publish + self.entrypoint + self.reusable
        for forbidden in (
            "upload-artifact",
            "download-artifact",
            "docker://",
            "actions/cache@",
            "cargo install --path",
        ):
            self.assertNotIn(forbidden, combined)

    def test_trusted_rust_uses_stable_with_archive_cargo_scoped_separately(self) -> None:
        for name in (
            "release-readiness",
            "publication",
            "release-intent",
            "release-finalizer",
        ):
            with self.subTest(job=name):
                block = job_block(self.publish, name)
                self.assertIn("toolchain: 1.95.0,stable", block)
                self.assertIn("YAML_SIGIL_ARCHIVE_CARGO", block)
                self.assertNotIn("toolchain: 1.95.0\n", block)
        notification = job_block(self.publish, "release-notification")
        self.assertIn("toolchain: stable", notification)
        self.assertIn("cargo +stable build --locked --release", notification)
        proposal = job_block(self.reusable, "proposal")
        self.assertIn("toolchain: stable", proposal)
        self.assertNotIn("toolchain: 1.95.0", proposal)
        authority_validation = job_block(self.publish, "authority-validation")
        self.assertIn("toolchain: stable", authority_validation)
        self.assertNotIn("toolchain: 1.95.0", authority_validation)

    def test_trusted_release_cargo_is_explicitly_stable(self) -> None:
        for workflow_name in ("publish.yml", "release-proposal.yml"):
            for line in read(workflow_name).splitlines():
                if re.search(r"\bcargo\s", line):
                    with self.subTest(workflow=workflow_name, line=line):
                        self.assertIn("cargo +stable ", line)

    def test_recovered_source_uses_staged_current_release_policy(self) -> None:
        for name in ("release-readiness", "publication"):
            with self.subTest(job=name):
                block = job_block(self.publish, name)
                recovered = block.split(
                    "- name: Check out captured release source", 1
                )[1]
                self.assertNotRegex(
                    recovered,
                    r"\bcargo(?:\s+\+\S+)?\s+xtask(?:\s|$)",
                )
                for command in (
                    "release-version check",
                    "release-version show",
                    "release-version intent",
                    "release-version check-compatibility",
                ):
                    self.assertIn(
                        f'"${{YAML_SIGIL_RELEASE_XTASK}}" {command}',
                        recovered,
                    )
                for command in (
                    "require-current-main",
                    "baseline prepare",
                    "verify-registry",
                    "check-packages",
                    "prepare-publication-config",
                ):
                    self.assertIn(
                        f'"${{YAML_SIGIL_RELEASE_XTASK}}" release {command}',
                        recovered,
                    )

    def test_admin_settings_read_is_operator_attested(self) -> None:
        intent = job_block(self.publish, "release-intent")
        request = intent.split(
            "- name: Display repository-admin settings evidence request", 1
        )[1].split("- name: Authenticate the exact crates.io approval", 1)[0]
        review = intent.split(
            "- name: Authenticate the exact crates.io approval", 1
        )[1].split("- name: Check out captured trusted source", 1)[0]

        self.assertIn("deployments: read", intent)
        self.assertIn("github release-train settings-request", request)
        self.assertIn('--repository "${GITHUB_REPOSITORY}"', request)
        self.assertIn('--policy-commit "${POLICY_COMMIT}"', request)
        self.assertIn('--run-id "${GITHUB_RUN_ID}"', request)
        self.assertIn('--run-attempt "${GITHUB_RUN_ATTEMPT}"', request)
        self.assertNotIn("settings-preflight", request)
        self.assertNotIn("GH_TOKEN", request)
        self.assertNotIn("github.token", request)

        self.assertIn("github release-train await-settings-review", review)
        self.assertIn("GH_TOKEN: ${{ github.token }}", review)
        self.assertIn('--repository "${GITHUB_REPOSITORY}"', review)
        self.assertIn('--policy-commit "${POLICY_COMMIT}"', review)
        self.assertIn('--run-id "${GITHUB_RUN_ID}"', review)
        self.assertIn('--run-attempt "${GITHUB_RUN_ATTEMPT}"', review)
        self.assertNotIn("github release-train settings-preflight", self.publish)

    def test_release_domain_preflights_use_typed_rust(self) -> None:
        combined = self.publish + self.reusable
        self.assertNotIn("legacy_release_preflight.py", combined)
        self.assertNotIn("release_notification_preflight.py", combined)
        self.assertNotIn("release_evidence.py", combined)
        self.assertGreaterEqual(
            combined.count("github release-train verify-legacy"), 3
        )
        for obsolete in (
            ".github/release-notification-policy.json",
            ".github/scripts/legacy_release_preflight.py",
            ".github/scripts/release_evidence.py",
            ".github/scripts/release_notification_preflight.py",
            ".github/scripts/release_settings_preflight.py",
        ):
            self.assertFalse((ROOT / obsolete).exists(), obsolete)
        releasing = (ROOT / "RELEASING.md").read_text(encoding="utf-8")
        self.assertIn(
            "cargo +stable xtask github release-train settings-preflight",
            releasing,
        )
        self.assertIn("--policy-commit <policy-commit>", releasing)
        self.assertIn("approval_comment=", releasing)
        self.assertNotIn("--expected-evidence-sha256", releasing)

    def test_remote_actions_are_full_sha_pinned_with_version_comments(self) -> None:
        for workflow_name in ("publish.yml", "release-pr.yml", "release-proposal.yml"):
            for line in read(workflow_name).splitlines():
                if "uses:" not in line or "uses: ./" in line:
                    continue
                with self.subTest(workflow=workflow_name, line=line):
                    self.assertRegex(line, r"uses: [^@\s]+@[0-9a-f]{40} # \S+")

    def test_release_shell_authority_comments_are_adjacent(self) -> None:
        for workflow_name in ("publish.yml", "release-proposal.yml"):
            lines = read(workflow_name).splitlines()
            for index, line in enumerate(lines):
                stripped = line.strip()
                is_control = (stripped.startswith("if ") or stripped.startswith("case "))
                is_release_plz = stripped.startswith("release-plz ")
                if not (is_control or is_release_plz):
                    continue
                previous = next(
                    (candidate.strip() for candidate in reversed(lines[:index]) if candidate.strip()),
                    "",
                )
                with self.subTest(workflow=workflow_name, line=index + 1):
                    self.assertTrue(previous.startswith("#"), previous)


if __name__ == "__main__":
    unittest.main()

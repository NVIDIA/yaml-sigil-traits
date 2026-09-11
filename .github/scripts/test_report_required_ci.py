#!/usr/bin/env python3
# Python is justified here because these tests exercise the checkout-free
# protected Python reporter without network access, a candidate checkout, or an
# App token. Keeping the fixtures in the reporter's language makes malformed
# API objects and subprocess results deterministic while avoiding a second
# implementation of the policy in Rust or shell.
"""Deterministic trust-boundary tests for the checkout-free Python reporter.

Python is used here because the protected reporter itself is intentionally a
standard-library-only Python program that runs before any candidate checkout
or App token. These fixtures exercise its API, identity, provenance, bounded-
input, and subprocess boundaries without network access or repository state.
They are not a second workflow-policy implementation.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


MODULE_PATH = Path(__file__).with_name("report_required_ci.py")
SPEC = importlib.util.spec_from_file_location("report_required_ci", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reporter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reporter
SPEC.loader.exec_module(reporter)


REPOSITORY = "NVIDIA/yaml-sigil-rs"
RUN_ID = 1234
ATTEMPT = 2
WORKFLOW_ID = 123456
PULL = 65
HEAD = "a" * 40
POLICY_SHA = "b" * 40
COORDINATION_SHA = "d" * 40
COORDINATION_BRANCH = "dev/0.6.0"
OTHER_COORDINATION_BRANCH = "dev/0.7.0"
WORKFLOW_BLOB = "c" * 40
SIGNER_ID = 42
SIGNER_LOGIN = "example-contributor"
SIGNER_NAME = "Example Contributor"
SIGNER_EMAIL = "contributor@example.invalid"
COORDINATOR_ID = 77
COORDINATOR_LOGIN = "release-coordinator"
COORDINATOR_NAME = "Release Coordinator"
COORDINATOR_EMAIL = "coordinator@example.invalid"
SOURCE_PULL = 66
ACTIVATION_SHA = "1" * 40
SOURCE_CURRENT = HEAD
SOURCE_ORIGINAL = "2" * 40
SOURCE_HEAD = "4" * 40
SOURCE_DIFF = b"""diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
-old_value
+new_value
"""
ACTIVATION_DIFF = b"""diff --git a/Cargo.toml b/Cargo.toml
index 3333333..4444444 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1 +1 @@
-version = "0.5.0"
+version = "0.6.0-rc.0"
"""


class FakeApi:
    """Deterministic path-keyed API fixture."""

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        """Copy fixtures so each negative case mutates isolated evidence."""

        self.responses = copy.deepcopy(responses)
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, path: str) -> Any:
        """Return the fixture for one read-only REST request."""

        return self._take("GET", path, None)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        """Return the fixture for one recorded REST mutation."""

        return self._take("POST", path, payload)

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        """Return the fixture for the reporter's fixed GraphQL query."""

        return self._take("GRAPHQL", query, variables)

    def diff(self, path: str) -> bytes:
        """Return exact diff bytes without text normalization."""

        return self._take("DIFF", path, None)

    def _take(self, method: str, path: str, payload: Any) -> Any:
        """Record one call and fail if the test did not authorize its path."""

        self.calls.append((method, path, copy.deepcopy(payload)))
        key = (method, path)
        if key not in self.responses:
            raise AssertionError(f"unexpected API call: {method} {path}")
        value = self.responses[key]
        return copy.deepcopy(value)


def policy() -> Any:
    """Build the exact protected reporter constants used by all fixtures."""

    return reporter.Policy(
        repository=REPOSITORY,
        policy_sha=POLICY_SHA,
        workflow_id=WORKFLOW_ID,
        workflow_path=".github/workflows/ci.yml",
        job_name="Candidate CI (Linux)",
        app_slug="nvidia-yamlsigil-release-pr",
    )


def fixture(
    base_branch: str = "main",
    base_sha: str | None = None,
) -> tuple[dict[str, Any], dict[tuple[str, str], Any]]:
    """Build a complete ordinary copied-ref delivery and API inventory."""

    if base_sha is None:
        base_sha = POLICY_SHA if base_branch == "main" else COORDINATION_SHA
    run = {
        "id": RUN_ID,
        "run_attempt": ATTEMPT,
        "workflow_id": WORKFLOW_ID,
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "repository": {"full_name": REPOSITORY},
        "head_branch": f"pull-request/{PULL}",
        "head_sha": HEAD,
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
    }
    event = {
        "action": "completed",
        "repository": {"full_name": REPOSITORY},
        "workflow_run": copy.deepcopy(run),
    }
    paths = {
        (
            "GET",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}",
        ): run,
        (
            "GET",
            f"repos/{REPOSITORY}/git/ref/heads/main",
        ): {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": POLICY_SHA},
        },
        (
            "GET",
            f"repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={POLICY_SHA}",
        ): {
            "type": "file",
            "path": ".github/workflows/ci.yml",
            "sha": WORKFLOW_BLOB,
            "size": 1000,
        },
        (
            "GET",
            f"repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={HEAD}",
        ): {
            "type": "file",
            "path": ".github/workflows/ci.yml",
            "sha": WORKFLOW_BLOB,
            "size": 1000,
        },
        (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}",
        ): {
            "number": PULL,
            "state": "open",
            "commits": 1,
            "base": {
                "ref": base_branch,
                "sha": base_sha,
                "repo": {"full_name": REPOSITORY},
            },
            "head": {"sha": HEAD, "ref": "feature", "repo": {"full_name": "fork/repo"}},
        },
        (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        ): [
            {
                "sha": HEAD,
                "author": {
                    "id": SIGNER_ID,
                    "login": SIGNER_LOGIN,
                    "type": "User",
                },
                "committer": {
                    "id": SIGNER_ID,
                    "login": SIGNER_LOGIN,
                    "type": "User",
                },
                "commit": {
                    "author": {"name": SIGNER_NAME, "email": SIGNER_EMAIL},
                    "committer": {"name": SIGNER_NAME, "email": SIGNER_EMAIL},
                    "message": (
                        "fix: bind one identity\n\n"
                        f"Signed-off-by: {SIGNER_NAME} <{SIGNER_EMAIL}>"
                    ),
                    "verification": {"verified": True, "reason": "valid"},
                },
            }
        ],
        ("GRAPHQL", reporter.SIGNATURE_QUERY): {
            "data": {
                "repository": {
                    "pullRequest": {
                        "commits": {
                            "totalCount": 1,
                            "nodes": [
                                {
                                    "commit": {
                                        "oid": HEAD,
                                        "signature": {
                                            "__typename": "SshSignature",
                                            "email": SIGNER_EMAIL,
                                            "isValid": True,
                                            "state": "VALID",
                                            "wasSignedByGitHub": False,
                                            "signer": {
                                                "databaseId": SIGNER_ID,
                                                "login": SIGNER_LOGIN,
                                                "__typename": "User",
                                            },
                                        },
                                    }
                                }
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            }
        },
        (
            "GET",
            f"repos/{REPOSITORY}/git/ref/heads/pull-request/{PULL}",
        ): {
            "ref": f"refs/heads/pull-request/{PULL}",
            "object": {"type": "commit", "sha": HEAD},
        },
        (
            "GET",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100",
        ): {
            "total_count": 2,
            "jobs": [
                {
                    "name": reporter.attested_job_name(
                        "Candidate CI (Linux)",
                        POLICY_SHA,
                        f"refs/heads/{base_branch}",
                        base_sha,
                    ),
                    "run_id": RUN_ID,
                    "run_attempt": ATTEMPT,
                    "head_sha": HEAD,
                    "status": "completed",
                    "conclusion": "success",
                },
                {
                    "name": "Candidate portability (macOS)",
                    "run_id": RUN_ID,
                    "run_attempt": ATTEMPT,
                    "head_sha": HEAD,
                    "status": "completed",
                    "conclusion": "failure",
                },
            ],
        },
        (
            "GET",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts?per_page=1",
        ): {"total_count": 0, "artifacts": []},
    }
    if base_branch != "main":
        paths[("GET", f"repos/{REPOSITORY}/git/ref/heads/{base_branch}")] = {
            "ref": f"refs/heads/{base_branch}",
            "object": {"type": "commit", "sha": base_sha},
        }
    return event, paths


def bind(event: dict[str, Any], responses: dict[tuple[str, str], Any]) -> Any:
    """Run ordinary candidate binding against an isolated fake API."""

    return reporter.bind_candidate(FakeApi(responses), event, policy())


def verbatim_patch_id(diff: bytes) -> str:
    """Derive a fixture value with the same reviewed Git primitive as policy."""

    completed = subprocess.run(
        ["git", "patch-id", "--verbatim"],
        input=diff,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout.decode("ascii").split()[0]


def promotion_commit(
    sha: str,
    parent: str,
    *,
    author_id: int,
    author_login: str,
    author_name: str,
    author_email: str,
    committer_id: int,
    committer_login: str,
    committer_name: str,
    committer_email: str,
    path: str,
    patch: str = "@@ -1 +1 @@\n-old\n+new",
) -> dict[str, Any]:
    """Build one complete linear commit response for promotion fixtures."""

    return {
        "sha": sha,
        "author": {"id": author_id, "login": author_login, "type": "User"},
        "committer": {
            "id": committer_id,
            "login": committer_login,
            "type": "User",
        },
        "parents": [{"sha": parent}],
        "files": [{"filename": path, "status": "modified", "patch": patch}],
        "commit": {
            "author": {"name": author_name, "email": author_email},
            "committer": {"name": committer_name, "email": committer_email},
            "message": (
                "change: retained work\n\n"
                f"Signed-off-by: {author_name} <{author_email}>"
            ),
            "verification": {"verified": True, "reason": "valid"},
        },
    }


def promotion_signature(sha: str) -> dict[str, Any]:
    """Build one exact coordinator-owned GraphQL signature node."""

    return {
        "commit": {
            "oid": sha,
            "signature": {
                "__typename": "SshSignature",
                "email": COORDINATOR_EMAIL,
                "isValid": True,
                "state": "VALID",
                "wasSignedByGitHub": False,
                "signer": {
                    "databaseId": COORDINATOR_ID,
                    "login": COORDINATOR_LOGIN,
                    "__typename": "User",
                },
            },
        }
    }


def promotion_fixture() -> tuple[
    str,
    dict[str, Any],
    reporter.PromotionContext,
    dict[tuple[str, str], Any],
]:
    """Build a complete valid Rust promotion and all authoritative evidence."""

    event, responses = fixture()
    source_patch_id = verbatim_patch_id(SOURCE_DIFF)
    activation_patch_id = verbatim_patch_id(ACTIVATION_DIFF)
    manifest_value = {
        "version": 1,
        "repository": REPOSITORY,
        "policy_sha": POLICY_SHA,
        "promotion_pull": PULL,
        "base_ref": "refs/heads/main",
        "base_sha": POLICY_SHA,
        "head_sha": HEAD,
        "coordination_ref": f"refs/heads/{COORDINATION_BRANCH}",
        "candidate_run_id": RUN_ID,
        "candidate_run_attempt": ATTEMPT,
        "coordinator": {"id": COORDINATOR_ID, "login": COORDINATOR_LOGIN},
        "entries": [
            {
                "kind": "activation",
                "sha": ACTIVATION_SHA,
                "patch_id": activation_patch_id,
                "paths": ["Cargo.toml"],
            },
            {
                "kind": "source",
                "sha": SOURCE_CURRENT,
                "patch_id": source_patch_id,
                "source_pull": SOURCE_PULL,
                "original_sha": SOURCE_ORIGINAL,
            },
        ],
    }
    manifest_raw = json.dumps(manifest_value, separators=(",", ":"), sort_keys=True)
    event = {
        "ref": "main",
        "repository": {"full_name": REPOSITORY},
        "sender": {
            "id": COORDINATOR_ID,
            "login": COORDINATOR_LOGIN,
            "type": "User",
        },
        "inputs": {"manifest": manifest_raw},
    }
    context = reporter.PromotionContext(
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        sha=POLICY_SHA,
        workflow_ref=(
            f"{REPOSITORY}/.github/workflows/required-ci.yml@refs/heads/main"
        ),
        actor=COORDINATOR_LOGIN,
        actor_id=COORDINATOR_ID,
        triggering_actor=COORDINATOR_LOGIN,
        run_attempt=1,
    )

    source_current = promotion_commit(
        SOURCE_CURRENT,
        ACTIVATION_SHA,
        author_id=SIGNER_ID,
        author_login=SIGNER_LOGIN,
        author_name=SIGNER_NAME,
        author_email=SIGNER_EMAIL,
        committer_id=COORDINATOR_ID,
        committer_login=COORDINATOR_LOGIN,
        committer_name=COORDINATOR_NAME,
        committer_email=COORDINATOR_EMAIL,
        path="src/lib.rs",
    )
    source_original = promotion_commit(
        SOURCE_ORIGINAL,
        "5" * 40,
        author_id=SIGNER_ID,
        author_login=SIGNER_LOGIN,
        author_name=SIGNER_NAME,
        author_email=SIGNER_EMAIL,
        committer_id=COORDINATOR_ID,
        committer_login=COORDINATOR_LOGIN,
        committer_name=COORDINATOR_NAME,
        committer_email=COORDINATOR_EMAIL,
        path="src/lib.rs",
    )
    activation = promotion_commit(
        ACTIVATION_SHA,
        POLICY_SHA,
        author_id=COORDINATOR_ID,
        author_login=COORDINATOR_LOGIN,
        author_name=COORDINATOR_NAME,
        author_email=COORDINATOR_EMAIL,
        committer_id=COORDINATOR_ID,
        committer_login=COORDINATOR_LOGIN,
        committer_name=COORDINATOR_NAME,
        committer_email=COORDINATOR_EMAIL,
        path="Cargo.toml",
    )

    pull_path = ("GET", f"repos/{REPOSITORY}/pulls/{PULL}")
    responses[pull_path]["commits"] = 2
    responses[pull_path]["head"] = {
        "sha": HEAD,
        "ref": COORDINATION_BRANCH,
        "repo": {"full_name": REPOSITORY},
    }
    responses[
        ("GET", f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1")
    ] = [activation, source_current]
    responses[("GRAPHQL", reporter.SIGNATURE_QUERY)]["data"]["repository"][
        "pullRequest"
    ]["commits"] = {
        "totalCount": 2,
        "nodes": [promotion_signature(ACTIVATION_SHA), promotion_signature(SOURCE_CURRENT)],
        "pageInfo": {"hasNextPage": False},
    }
    responses[
        ("GET", f"repos/{REPOSITORY}/git/ref/heads/{COORDINATION_BRANCH}")
    ] = {
        "ref": f"refs/heads/{COORDINATION_BRANCH}",
        "object": {"type": "commit", "sha": HEAD},
    }
    responses[
        (
            "GET",
            f"repos/{REPOSITORY}/collaborators/{COORDINATOR_LOGIN}/permission",
        )
    ] = {
        "permission": "write",
        "user": {
            "id": COORDINATOR_ID,
            "login": COORDINATOR_LOGIN,
            "type": "User",
        },
    }
    responses[("GET", f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}")] = {
        "number": SOURCE_PULL,
        "state": "closed",
        "merged": True,
        "merged_at": "2026-09-01T00:00:00Z",
        "commits": 1,
        "merge_commit_sha": SOURCE_ORIGINAL,
        "base": {
            "ref": COORDINATION_BRANCH,
            "repo": {"full_name": REPOSITORY},
        },
    }
    responses[
        (
            "GET",
            f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}/commits?per_page=100&page=1",
        )
    ] = [{"sha": SOURCE_HEAD}]
    responses[
        (
            "GET",
            f"repos/{REPOSITORY}/commits/{SOURCE_ORIGINAL}/pulls?per_page=100&page=1",
        )
    ] = [
        {
            "number": SOURCE_PULL,
            "base": {"repo": {"full_name": REPOSITORY}},
        }
    ]
    for sha, commit in (
        (SOURCE_CURRENT, source_current),
        (SOURCE_ORIGINAL, source_original),
        (ACTIVATION_SHA, activation),
    ):
        responses[
            ("GET", f"repos/{REPOSITORY}/commits/{sha}?per_page=100&page=1")
        ] = commit
    for sha in (SOURCE_CURRENT, SOURCE_ORIGINAL):
        responses[("DIFF", f"repos/{REPOSITORY}/commits/{sha}")] = SOURCE_DIFF
    responses[("DIFF", f"repos/{REPOSITORY}/commits/{ACTIVATION_SHA}")] = (
        ACTIVATION_DIFF
    )
    return manifest_raw, event, context, responses


class BindingTests(unittest.TestCase):
    def test_happy_path_ignores_advisory_failure(self) -> None:
        event, responses = fixture()
        result = bind(event, responses)
        self.assertEqual(result.head_sha, HEAD)
        self.assertEqual(result.base_ref, "refs/heads/main")
        self.assertEqual(result.base_sha, POLICY_SHA)
        self.assertEqual(result.check_name, "Required CI")
        self.assertEqual(result.conclusion, "success")
        self.assertEqual(result.check_conclusion, "success")

    def test_coordination_base_uses_a_nonreusable_check_context(self) -> None:
        event, responses = fixture(COORDINATION_BRANCH)
        coordination = bind(event, responses)
        self.assertEqual(
            coordination.check_name,
            f"Required CI [refs/heads/{COORDINATION_BRANCH}]",
        )
        self.assertEqual(coordination.base_sha, COORDINATION_SHA)

        event, responses = fixture()
        main = bind(event, responses)
        event, responses = fixture(OTHER_COORDINATION_BRANCH)
        other = bind(event, responses)
        self.assertEqual({main.head_sha, coordination.head_sha, other.head_sha}, {HEAD})
        self.assertEqual(len({main.check_name, coordination.check_name, other.check_name}), 3)

        with self.assertRaisesRegex(reporter.ReporterError, "no protected"):
            reporter.base_policy("NVIDIA/another-repository", "main")

    def test_policy_and_contribution_objects_cannot_be_swapped(self) -> None:
        event, responses = fixture(COORDINATION_BRANCH)
        responses[("GET", f"repos/{REPOSITORY}/git/ref/heads/main")]["object"][
            "sha"
        ] = COORDINATION_SHA
        with self.assertRaisesRegex(reporter.ReporterError, "current protected main"):
            bind(event, responses)

        event, responses = fixture(COORDINATION_BRANCH)
        responses[
            ("GET", f"repos/{REPOSITORY}/git/ref/heads/{COORDINATION_BRANCH}")
        ]["object"]["sha"] = POLICY_SHA
        with self.assertRaisesRegex(reporter.ReporterError, "contribution base"):
            bind(event, responses)

    def test_run_attestation_rejects_temporal_policy_or_base_substitution(self) -> None:
        jobs_path = (
            "GET",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100",
        )

        event, responses = fixture()
        responses[jobs_path]["jobs"][0]["name"] = reporter.attested_job_name(
            "Candidate CI (Linux)",
            "e" * 40,
            "refs/heads/main",
            POLICY_SHA,
        )
        with self.assertRaisesRegex(reporter.ReporterError, "attested authoritative"):
            bind(event, responses)

        event, responses = fixture(COORDINATION_BRANCH)
        responses[jobs_path]["jobs"][0]["name"] = reporter.attested_job_name(
            "Candidate CI (Linux)",
            POLICY_SHA,
            "refs/heads/main",
            POLICY_SHA,
        )
        with self.assertRaisesRegex(reporter.ReporterError, "attested authoritative"):
            bind(event, responses)

        event, responses = fixture(COORDINATION_BRANCH)
        responses[jobs_path]["jobs"][0]["name"] = reporter.attested_job_name(
            "Candidate CI (Linux)",
            POLICY_SHA,
            f"refs/heads/{COORDINATION_BRANCH}",
            "e" * 40,
        )
        with self.assertRaisesRegex(reporter.ReporterError, "attested authoritative"):
            bind(event, responses)

    def test_every_security_binding_rejects_drift(self) -> None:
        def wrong_delivered_run_id(event: dict[str, Any], responses: dict[Any, Any]) -> None:
            event["workflow_run"]["id"] = RUN_ID + 1
            responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID + 1}")] = responses[
                ("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")
            ]

        mutations = {
            "delivery action": lambda event, _: event.__setitem__("action", "requested"),
            "delivery repository": lambda event, _: event["repository"].__setitem__("full_name", "NVIDIA/other"),
            "delivery run id": wrong_delivered_run_id,
            "delivery workflow id": lambda event, _: event["workflow_run"].__setitem__("workflow_id", WORKFLOW_ID + 1),
            "stale attempt": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("run_attempt", ATTEMPT + 1),
            "run repository": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")]["repository"].__setitem__("full_name", "NVIDIA/other"),
            "workflow path": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("path", ".github/workflows/other.yml"),
            "workflow event": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("event", "workflow_dispatch"),
            "run id": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("id", RUN_ID + 1),
            "stale protected main": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/git/ref/heads/main")]["object"].__setitem__("sha", "d" * 40),
            "candidate workflow blob": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={HEAD}")].__setitem__("sha", "d" * 40),
            "copied ref syntax": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("head_branch", "pull-request/not-a-number"),
            "closed pull": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")].__setitem__("state", "closed"),
            "wrong base branch": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")]["base"].__setitem__("ref", "develop"),
            "stale pull base": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")]["base"].__setitem__("sha", "d" * 40),
            "moved pull head": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")]["head"].__setitem__("sha", "b" * 40),
            "incomplete commits": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")].__setitem__("commits", 2),
            "unverified commit": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1")][0]["commit"]["verification"].__setitem__("verified", False),
            "moved copied ref": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/git/ref/heads/pull-request/{PULL}")]["object"].__setitem__("sha", "b" * 40),
            "wrong job run": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]["jobs"][0].__setitem__("run_id", RUN_ID + 1),
            "wrong job attempt": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]["jobs"][0].__setitem__("run_attempt", ATTEMPT + 1),
            "wrong job head": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]["jobs"][0].__setitem__("head_sha", "b" * 40),
            "wrong conclusion": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]["jobs"][0].__setitem__("conclusion", None),
            "nonzero artifacts": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts?per_page=1")].update({"total_count": 1, "artifacts": [{"id": 1}]}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                event, responses = fixture()
                mutate(event, responses)
                with self.assertRaises(reporter.ReporterError):
                    bind(event, responses)

    def test_duplicate_authoritative_job_is_rejected(self) -> None:
        event, responses = fixture()
        jobs = responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0]))
        jobs["total_count"] += 1
        with self.assertRaisesRegex(reporter.ReporterError, "missing or duplicated"):
            bind(event, responses)

    def test_verified_signer_and_rest_identities_must_match(self) -> None:
        commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        signature_path = ("GRAPHQL", reporter.SIGNATURE_QUERY)

        def signature(responses: dict[Any, Any]) -> dict[str, Any]:
            return responses[signature_path]["data"]["repository"]["pullRequest"][
                "commits"
            ]["nodes"][0]["commit"]["signature"]

        mutations = {
            "author ID": lambda responses: responses[commits_path][0][
                "author"
            ].__setitem__("id", SIGNER_ID + 1),
            "committer login": lambda responses: responses[commits_path][0][
                "committer"
            ].__setitem__("login", "lookalike"),
            "signer ID": lambda responses: signature(responses)["signer"].__setitem__(
                "databaseId", SIGNER_ID + 1
            ),
            "raw author email": lambda responses: responses[commits_path][0][
                "commit"
            ]["author"].__setitem__("email", "lookalike@example.invalid"),
            "raw committer email": lambda responses: responses[commits_path][0][
                "commit"
            ]["committer"].__setitem__("email", "lookalike@example.invalid"),
            "signature email": lambda responses: signature(responses).__setitem__(
                "email", "lookalike@example.invalid"
            ),
            "GitHub signature": lambda responses: signature(responses).__setitem__(
                "wasSignedByGitHub", True
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                event, responses = fixture()
                mutate(responses)
                with self.assertRaises(reporter.ReporterError):
                    bind(event, responses)

    def test_null_signer_and_forged_dco_fail_closed(self) -> None:
        event, responses = fixture()
        signature = responses[("GRAPHQL", reporter.SIGNATURE_QUERY)]["data"][
            "repository"
        ]["pullRequest"]["commits"]["nodes"][0]["commit"]["signature"]
        signature["signer"] = None
        with self.assertRaisesRegex(reporter.ReporterError, "signer is not an object"):
            bind(event, responses)

        event, responses = fixture()
        commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        responses[commits_path][0]["commit"]["message"] = (
            "fix: forged trailer\n\n"
            f"Signed-off-by: Lookalike <{SIGNER_EMAIL}>"
        )
        with self.assertRaisesRegex(reporter.ReporterError, "raw-author DCO"):
            bind(event, responses)

    def test_signature_inventory_must_be_complete_and_ordered(self) -> None:
        signature_path = ("GRAPHQL", reporter.SIGNATURE_QUERY)

        def commits(responses: dict[Any, Any]) -> dict[str, Any]:
            return responses[signature_path]["data"]["repository"]["pullRequest"][
                "commits"
            ]

        mutations = {
            "count": lambda responses: commits(responses).__setitem__("totalCount", 2),
            "next page": lambda responses: commits(responses)[
                "pageInfo"
            ].__setitem__("hasNextPage", True),
            "OID": lambda responses: commits(responses)["nodes"][0]["commit"].__setitem__(
                "oid", "b" * 40
            ),
            "ambiguous node": lambda responses: commits(responses)["nodes"][0].__setitem__(
                "unexpected", True
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                event, responses = fixture()
                mutate(responses)
                with self.assertRaises(reporter.ReporterError):
                    bind(event, responses)

    def test_bounded_terminal_conclusions_map_to_required_verdict(self) -> None:
        for conclusion in sorted(reporter.TERMINAL_JOB_CONCLUSIONS):
            with self.subTest(conclusion=conclusion):
                event, responses = fixture()
                jobs = responses[
                    (
                        "GET",
                        f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/"
                        f"{ATTEMPT}/jobs?per_page=100",
                    )
                ]
                jobs["jobs"][0]["conclusion"] = conclusion
                result = bind(event, responses)
                expected = "success" if conclusion == "success" else "failure"
                self.assertEqual(result.check_conclusion, expected)


class PromotionBindingTests(unittest.TestCase):
    def promote(
        self,
        manifest_raw: str,
        event: dict[str, Any],
        context: reporter.PromotionContext,
        responses: dict[tuple[str, str], Any],
    ) -> Any:
        """Run promotion binding against one isolated fake API."""

        return reporter.bind_promotion(
            FakeApi(responses), event, policy(), manifest_raw, context
        )

    def replace_manifest(
        self,
        manifest_raw: str,
        event: dict[str, Any],
        mutate: Any,
    ) -> str:
        """Mutate, recanonicalize, and reattach one manifest fixture."""

        value = json.loads(manifest_raw)
        mutate(value)
        updated = json.dumps(value, separators=(",", ":"), sort_keys=True)
        event["inputs"]["manifest"] = updated
        return updated

    def test_happy_path_binds_distinct_promotion_check(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        result = self.promote(manifest_raw, event, context, responses)
        self.assertEqual(result.mode, "promotion")
        self.assertEqual(result.head_sha, HEAD)
        self.assertEqual(result.base_sha, POLICY_SHA)
        self.assertEqual(result.check_name, "Required CI")
        self.assertEqual(result.conclusion, "success")
        self.assertRegex(
            result.external_id,
            rf"^yaml-sigil-promotion-ci:[0-9a-f]{{64}}:{RUN_ID}:{ATTEMPT}:{POLICY_SHA}$",
        )

    def test_automatic_path_ignores_a_promotion_shaped_input(self) -> None:
        event, responses = fixture()
        event["inputs"] = {"manifest": '{"version":1}'}
        api = FakeApi(responses)
        result = reporter.bind_candidate(api, event, policy())
        self.assertEqual(result.mode, "candidate")
        self.assertTrue(result.external_id.startswith("yaml-sigil-required-ci:"))
        self.assertFalse(any(method == "DIFF" for method, _, _ in api.calls))
        self.assertFalse(any("collaborators" in path for _, path, _ in api.calls))

    def test_server_owned_dispatch_context_is_exact(self) -> None:
        mutations = {
            "event": {"event_name": "workflow_run"},
            "ref": {"ref": "refs/heads/dev/0.6.0"},
            "policy": {"sha": "e" * 40},
            "workflow": {
                "workflow_ref": (
                    f"{REPOSITORY}/.github/workflows/required-ci.yml@refs/heads/dev/0.6.0"
                )
            },
            "actor": {"actor": "another-writer"},
            "actor ID": {"actor_id": COORDINATOR_ID + 1},
            "rerun actor": {"triggering_actor": "another-writer"},
            "rerun": {"run_attempt": 2},
        }
        for name, changes in mutations.items():
            with self.subTest(name=name):
                manifest_raw, event, context, responses = promotion_fixture()
                changed = reporter.PromotionContext(
                    **{**context.__dict__, **changes}
                )
                with self.assertRaises(reporter.ReporterError):
                    self.promote(manifest_raw, event, changed, responses)

    def test_current_writer_and_event_sender_are_rebound(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        permission_path = (
            "GET",
            f"repos/{REPOSITORY}/collaborators/{COORDINATOR_LOGIN}/permission",
        )
        responses[permission_path]["permission"] = "read"
        with self.assertRaisesRegex(reporter.ReporterError, "trusted writer"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        event["sender"]["id"] += 1
        with self.assertRaisesRegex(reporter.ReporterError, "sender"):
            self.promote(manifest_raw, event, context, responses)

    def test_candidate_run_and_live_coordination_ref_are_exact(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        manifest_raw = self.replace_manifest(
            manifest_raw,
            event,
            lambda value: value.__setitem__("candidate_run_attempt", ATTEMPT + 1),
        )
        with self.assertRaisesRegex(reporter.ReporterError, "attempt"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        responses[
            ("GET", f"repos/{REPOSITORY}/git/ref/heads/{COORDINATION_BRANCH}")
        ]["object"]["sha"] = "e" * 40
        with self.assertRaisesRegex(reporter.ReporterError, "coordination ref moved"):
            self.promote(manifest_raw, event, context, responses)

    def test_manifest_inventory_rejects_missing_extra_duplicate_and_reorder(self) -> None:
        mutations = {
            "missing": lambda value: value["entries"].pop(),
            "extra": lambda value: value["entries"].append(
                {
                    **value["entries"][1],
                    "sha": "7" * 40,
                }
            ),
            "duplicate": lambda value: value["entries"].append(
                copy.deepcopy(value["entries"][1])
            ),
            "reordered": lambda value: value["entries"].reverse(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                manifest_raw, event, context, responses = promotion_fixture()
                manifest_raw = self.replace_manifest(
                    manifest_raw, event, mutate
                )
                with self.assertRaises(reporter.ReporterError):
                    self.promote(manifest_raw, event, context, responses)

    def test_signer_source_patch_and_coordinator_paths_are_exact(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        signature = responses[("GRAPHQL", reporter.SIGNATURE_QUERY)]["data"][
            "repository"
        ]["pullRequest"]["commits"]["nodes"][0]["commit"]["signature"]
        signature["signer"]["databaseId"] += 1
        with self.assertRaisesRegex(reporter.ReporterError, "coordinator"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        responses[("DIFF", f"repos/{REPOSITORY}/commits/{SOURCE_CURRENT}")] = (
            SOURCE_DIFF.replace(b"new_value", b"different_value")
        )
        with self.assertRaisesRegex(reporter.ReporterError, "logical patch"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        manifest_raw = self.replace_manifest(
            manifest_raw,
            event,
            lambda value: value["entries"][0].__setitem__(
                "paths", ["Cargo.toml", "src/lib.rs"]
            ),
        )
        with self.assertRaisesRegex(reporter.ReporterError, "workspace manifest"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        activation_path = (
            "GET",
            f"repos/{REPOSITORY}/commits/{ACTIVATION_SHA}?per_page=100&page=1",
        )
        responses[activation_path]["files"][0]["filename"] = "src/lib.rs"
        with self.assertRaisesRegex(reporter.ReporterError, "ordinary Cargo.toml"):
            self.promote(manifest_raw, event, context, responses)

    def test_rust_activation_cannot_rename_into_cargo_manifest(self) -> None:
        """Treat both rename endpoints as paths and reject activation renames."""

        manifest_raw, event, context, responses = promotion_fixture()
        activation_path = (
            "GET",
            f"repos/{REPOSITORY}/commits/{ACTIVATION_SHA}?per_page=100&page=1",
        )
        activation = responses[activation_path]
        activation["files"][0].update(
            {
                "status": "renamed",
                "previous_filename": "src/old-version-manifest.toml",
            }
        )
        self.assertEqual(
            reporter._changed_paths(activation, "activation fixture"),
            ("Cargo.toml", "src/old-version-manifest.toml"),
        )
        with self.assertRaisesRegex(reporter.ReporterError, "ordinary Cargo.toml"):
            self.promote(manifest_raw, event, context, responses)

    def test_source_message_and_textual_patch_are_exact(self) -> None:
        for name, sha in {
            "current": SOURCE_CURRENT,
            "original": SOURCE_ORIGINAL,
        }.items():
            with self.subTest(message=name):
                manifest_raw, event, context, responses = promotion_fixture()
                commit_path = (
                    "GET",
                    f"repos/{REPOSITORY}/commits/{sha}?per_page=100&page=1",
                )
                responses[commit_path]["commit"]["message"] += "\nChanged-trailer: yes"
                with self.assertRaisesRegex(
                    reporter.ReporterError, "complete commit message"
                ):
                    self.promote(manifest_raw, event, context, responses)

        for name, sha in {
            "activation": ACTIVATION_SHA,
            "current": SOURCE_CURRENT,
            "original": SOURCE_ORIGINAL,
        }.items():
            with self.subTest(missing_patch=name):
                manifest_raw, event, context, responses = promotion_fixture()
                commit_path = (
                    "GET",
                    f"repos/{REPOSITORY}/commits/{sha}?per_page=100&page=1",
                )
                responses[commit_path]["files"][0].pop("patch")
                with self.assertRaisesRegex(
                    reporter.ReporterError, "complete textual patch"
                ):
                    self.promote(manifest_raw, event, context, responses)

    def test_source_pull_inventory_is_exhaustive(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        another_original = "9" * 40
        source_pull_path = ("GET", f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}")
        responses[source_pull_path]["commits"] = 2
        source_commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}/commits?per_page=100&page=1",
        )
        responses[source_commits_path] = [
            {"sha": another_original},
            {"sha": SOURCE_ORIGINAL},
        ]
        with self.assertRaisesRegex(reporter.ReporterError, "exceed the promotion series"):
            self.promote(manifest_raw, event, context, responses)

    def test_same_source_pull_commits_cannot_be_replayed_in_reverse(self) -> None:
        """Reject a valid two-commit source PR retained in the wrong order.

        This exercises the complete promotion binding rather than comparing
        two lists in isolation. Every commit, association, signature, message,
        patch, and parent is otherwise valid; only the relationship between
        the source PR's order and the final promotion series is reversed.
        """

        manifest_raw, event, context, responses = promotion_fixture()
        original_first = "6" * 40
        current_last = "7" * 40
        source_patch_id = verbatim_patch_id(SOURCE_DIFF)

        manifest = json.loads(manifest_raw)
        manifest["head_sha"] = current_last
        manifest["entries"].append(
            {
                "kind": "source",
                "sha": current_last,
                "patch_id": source_patch_id,
                "source_pull": SOURCE_PULL,
                "original_sha": original_first,
            }
        )
        manifest_raw = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
        event["inputs"]["manifest"] = manifest_raw

        current_last_commit = promotion_commit(
            current_last,
            SOURCE_CURRENT,
            author_id=SIGNER_ID,
            author_login=SIGNER_LOGIN,
            author_name=SIGNER_NAME,
            author_email=SIGNER_EMAIL,
            committer_id=COORDINATOR_ID,
            committer_login=COORDINATOR_LOGIN,
            committer_name=COORDINATOR_NAME,
            committer_email=COORDINATOR_EMAIL,
            path="src/lib.rs",
        )
        original_first_commit = promotion_commit(
            original_first,
            "5" * 40,
            author_id=SIGNER_ID,
            author_login=SIGNER_LOGIN,
            author_name=SIGNER_NAME,
            author_email=SIGNER_EMAIL,
            committer_id=COORDINATOR_ID,
            committer_login=COORDINATOR_LOGIN,
            committer_name=COORDINATOR_NAME,
            committer_email=COORDINATOR_EMAIL,
            path="src/lib.rs",
        )

        run_path = ("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")
        responses[run_path]["head_sha"] = current_last
        pull_path = ("GET", f"repos/{REPOSITORY}/pulls/{PULL}")
        responses[pull_path]["commits"] = 3
        responses[pull_path]["head"]["sha"] = current_last
        promotion_commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        responses[promotion_commits_path].append(current_last_commit)
        graph_commits = responses[("GRAPHQL", reporter.SIGNATURE_QUERY)]["data"][
            "repository"
        ]["pullRequest"]["commits"]
        graph_commits["totalCount"] = 3
        graph_commits["nodes"].append(promotion_signature(current_last))

        responses[
            ("GET", f"repos/{REPOSITORY}/git/ref/heads/pull-request/{PULL}")
        ]["object"]["sha"] = current_last
        jobs_path = (
            "GET",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100",
        )
        for job in responses[jobs_path]["jobs"]:
            job["head_sha"] = current_last
        responses[
            ("GET", f"repos/{REPOSITORY}/git/ref/heads/{COORDINATION_BRANCH}")
        ]["object"]["sha"] = current_last

        candidate_workflow = responses.pop(
            (
                "GET",
                f"repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={HEAD}",
            )
        )
        responses[
            (
                "GET",
                f"repos/{REPOSITORY}/contents/.github/workflows/ci.yml?ref={current_last}",
            )
        ] = candidate_workflow
        responses[
            (
                "GET",
                f"repos/{REPOSITORY}/commits/{current_last}?per_page=100&page=1",
            )
        ] = current_last_commit
        responses[
            (
                "GET",
                f"repos/{REPOSITORY}/commits/{original_first}?per_page=100&page=1",
            )
        ] = original_first_commit
        responses[("DIFF", f"repos/{REPOSITORY}/commits/{current_last}")] = SOURCE_DIFF
        responses[("DIFF", f"repos/{REPOSITORY}/commits/{original_first}")] = SOURCE_DIFF

        source_pull_path = ("GET", f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}")
        responses[source_pull_path]["commits"] = 2
        source_commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}/commits?per_page=100&page=1",
        )
        responses[source_commits_path] = [
            {"sha": original_first},
            {"sha": SOURCE_ORIGINAL},
        ]
        responses[
            (
                "GET",
                f"repos/{REPOSITORY}/commits/{original_first}/pulls?per_page=100&page=1",
            )
        ] = [
            {
                "number": SOURCE_PULL,
                "base": {"repo": {"full_name": REPOSITORY}},
            }
        ]

        with self.assertRaisesRegex(reporter.ReporterError, "reordered"):
            self.promote(manifest_raw, event, context, responses)

    def test_source_pr_and_api_shapes_fail_closed(self) -> None:
        manifest_raw, event, context, responses = promotion_fixture()
        responses[("GET", f"repos/{REPOSITORY}/pulls/{SOURCE_PULL}")][
            "merged"
        ] = False
        with self.assertRaisesRegex(reporter.ReporterError, "terminally merged"):
            self.promote(manifest_raw, event, context, responses)

        manifest_raw, event, context, responses = promotion_fixture()
        responses[
            (
                "GET",
                f"repos/{REPOSITORY}/commits/{SOURCE_ORIGINAL}/pulls?per_page=100&page=1",
            )
        ] = {"unexpected": True}
        with self.assertRaisesRegex(reporter.ReporterError, "not an array"):
            self.promote(manifest_raw, event, context, responses)

    def test_manifest_parser_rejects_malformed_duplicate_and_oversized_input(self) -> None:
        with self.assertRaisesRegex(reporter.ReporterError, "valid JSON"):
            reporter.read_promotion_manifest("{")
        with self.assertRaisesRegex(reporter.ReporterError, "duplicate field"):
            reporter.read_promotion_manifest('{"version":1,"version":1}')
        with self.assertRaisesRegex(reporter.ReporterError, "oversized"):
            reporter.read_promotion_manifest(
                "x" * (reporter.MAX_PROMOTION_MANIFEST_BYTES + 1)
            )

    def test_manifest_parser_enforces_repository_activation_policy(self) -> None:
        manifest_raw, _, _, _ = promotion_fixture()
        value = json.loads(manifest_raw)
        value["entries"].pop(0)
        with self.assertRaisesRegex(reporter.ReporterError, "must begin"):
            reporter.read_promotion_manifest(json.dumps(value))

        value = json.loads(manifest_raw)
        value["entries"][1]["prior_sha"] = "5" * 40
        with self.assertRaisesRegex(reporter.ReporterError, "incomplete or ambiguous"):
            reporter.read_promotion_manifest(json.dumps(value))

        value = json.loads(manifest_raw)
        value["repository"] = "NVIDIA/yaml-sigil-spec"
        value["coordination_ref"] = "refs/heads/v1alpha2"
        with self.assertRaisesRegex(reporter.ReporterError, "cannot contain activation"):
            reporter.read_promotion_manifest(json.dumps(value))
        value["entries"].pop(0)
        parsed = reporter.read_promotion_manifest(json.dumps(value))
        self.assertEqual(parsed.repository, "NVIDIA/yaml-sigil-spec")


class PatchInventoryTests(unittest.TestCase):
    def patch_id(self, raw: bytes, sha: str = "8" * 40) -> str:
        """Compute one policy patch ID from exact fixture bytes."""

        path = f"repos/{REPOSITORY}/commits/{sha}"
        return reporter.PatchInventory(
            FakeApi({("DIFF", path): raw}), REPOSITORY
        ).patch_id(sha, "fixture commit")

    def test_verbatim_ids_distinguish_yaml_and_python_indentation(self) -> None:
        yaml_two = b"""diff --git a/a.yml b/a.yml
--- a/a.yml
+++ b/a.yml
@@ -1 +1 @@
-  run: true
+    run: true
"""
        yaml_three = yaml_two.replace(b"+    run", b"+      run")
        python_four = b"""diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-    return True
+        return True
"""
        python_eight = python_four.replace(b"+        return", b"+            return")
        self.assertNotEqual(self.patch_id(yaml_two), self.patch_id(yaml_three, "9" * 40))
        self.assertNotEqual(
            self.patch_id(python_four, "a" * 40),
            self.patch_id(python_eight, "b" * 40),
        )

    def test_patch_id_process_output_and_failure_are_bounded(self) -> None:
        cases = {
            "empty": subprocess.CompletedProcess([], 0, b"", b""),
            "multiple": subprocess.CompletedProcess(
                [], 0, (b"a" * 40 + b" 0\n" + b"b" * 40 + b" 0\n"), b""
            ),
            "malformed": subprocess.CompletedProcess([], 0, b"not-a-hash 0\n", b""),
            "malformed source": subprocess.CompletedProcess(
                [], 0, b"a" * 40 + b" not-a-sha\n", b""
            ),
            "stderr": subprocess.CompletedProcess([], 0, b"a" * 40 + b" 0\n", b"warning"),
            "failure": subprocess.CompletedProcess([], 1, b"", b"failed"),
        }
        for name, completed in cases.items():
            with self.subTest(name=name), mock.patch.object(
                reporter.subprocess, "run", return_value=completed
            ):
                with self.assertRaises(reporter.ReporterError):
                    self.patch_id(SOURCE_DIFF)

        with mock.patch.object(
            reporter.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["git", "patch-id"], 10),
        ):
            with self.assertRaises(reporter.ReporterError):
                self.patch_id(SOURCE_DIFF)

    def test_patch_input_has_per_commit_and_aggregate_bounds(self) -> None:
        oversized = b"x" * (reporter.MAX_PROMOTION_PATCH_BYTES + 1)
        with self.assertRaisesRegex(reporter.ReporterError, "oversized"):
            self.patch_id(oversized)

        first = "8" * 40
        second = "9" * 40
        inventory = reporter.PatchInventory(
            FakeApi(
                {
                    ("DIFF", f"repos/{REPOSITORY}/commits/{first}"): SOURCE_DIFF,
                    ("DIFF", f"repos/{REPOSITORY}/commits/{second}"): SOURCE_DIFF,
                }
            ),
            REPOSITORY,
        )
        inventory.total_bytes = reporter.MAX_PROMOTION_PATCH_TOTAL_BYTES - len(SOURCE_DIFF)
        inventory.patch_id(first, "first")
        with self.assertRaisesRegex(reporter.ReporterError, "inventory is oversized"):
            inventory.patch_id(second, "second")


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        """Start each reporting case from fresh ordinary-candidate evidence."""

        event, responses = fixture()
        self.binding = bind(event, responses)

    def test_app_scope_must_be_exact(self) -> None:
        api = FakeApi(
            {
                ("GET", "installation/repositories?per_page=100"): {
                    "total_count": 2,
                    "repositories": [
                        {"full_name": REPOSITORY},
                        {"full_name": "NVIDIA/other"},
                    ],
                },
            }
        )
        with self.assertRaisesRegex(reporter.ReporterError, "exactly this repository"):
            reporter.verify_app_scope(api, policy(), "nvidia-yamlsigil-release-pr")

        exact_api = FakeApi(
            {
                ("GET", "installation/repositories?per_page=100"): {
                    "total_count": 1,
                    "repositories": [{"full_name": REPOSITORY}],
                }
            }
        )
        with self.assertRaisesRegex(reporter.ReporterError, "unexpected App"):
            reporter.verify_app_scope(exact_api, policy(), "another-app")
        self.assertEqual(exact_api.calls, [])
        reporter.verify_app_scope(
            exact_api, policy(), "nvidia-yamlsigil-release-pr"
        )
        self.assertEqual(
            exact_api.calls,
            [("GET", "installation/repositories?per_page=100", None)],
        )

    def test_successful_check_is_created_and_read_back(self) -> None:
        query = "check_name=Required+CI&filter=all&per_page=100"
        check = {
            "id": 88,
            "name": "Required CI",
            "head_sha": HEAD,
            "external_id": self.binding.external_id,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "nvidia-yamlsigil-release-pr"},
        }
        api = FakeApi(
            {
                ("GET", f"repos/{REPOSITORY}/commits/{HEAD}/check-runs?{query}"): {
                    "total_count": 0,
                    "check_runs": [],
                },
                ("POST", f"repos/{REPOSITORY}/check-runs"): check,
                ("GET", f"repos/{REPOSITORY}/check-runs/88"): check,
            }
        )
        self.assertEqual(reporter.report_check(api, policy(), self.binding), 88)
        payload = api.calls[1][2]
        self.assertEqual(payload["conclusion"], "success")
        self.assertEqual(payload["head_sha"], HEAD)

    def test_exact_existing_check_is_idempotent(self) -> None:
        query = "check_name=Required+CI&filter=all&per_page=100"
        check = {
            "id": 88,
            "name": "Required CI",
            "head_sha": HEAD,
            "external_id": self.binding.external_id,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "nvidia-yamlsigil-release-pr"},
        }
        api = FakeApi(
            {
                ("GET", f"repos/{REPOSITORY}/commits/{HEAD}/check-runs?{query}"): {
                    "total_count": 1,
                    "check_runs": [check],
                }
            }
        )
        self.assertEqual(reporter.report_check(api, policy(), self.binding), 88)
        self.assertEqual(len(api.calls), 1)

    def test_ordinary_check_cannot_substitute_for_promotion_evidence(self) -> None:
        """Create a promotion check even when ordinary CI already succeeded."""

        manifest_raw, event, context, responses = promotion_fixture()
        promotion = reporter.bind_promotion(
            FakeApi(responses), event, policy(), manifest_raw, context
        )
        self.assertNotEqual(promotion.external_id, self.binding.external_id)
        query = "check_name=Required+CI&filter=all&per_page=100"
        ordinary_check = {
            "id": 88,
            "name": "Required CI",
            "head_sha": HEAD,
            "external_id": self.binding.external_id,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "nvidia-yamlsigil-release-pr"},
        }
        promotion_check = {
            **ordinary_check,
            "id": 89,
            "external_id": promotion.external_id,
        }
        api = FakeApi(
            {
                ("GET", f"repos/{REPOSITORY}/commits/{HEAD}/check-runs?{query}"): {
                    "total_count": 1,
                    "check_runs": [ordinary_check],
                },
                ("POST", f"repos/{REPOSITORY}/check-runs"): promotion_check,
                ("GET", f"repos/{REPOSITORY}/check-runs/89"): promotion_check,
            }
        )
        self.assertEqual(reporter.report_check(api, policy(), promotion), 89)
        self.assertEqual(api.calls[1][2]["external_id"], promotion.external_id)
        self.assertEqual(
            api.calls[1][2]["output"]["title"],
            "Authorized cumulative promotion result",
        )

    def test_coordination_check_uses_only_its_base_context(self) -> None:
        event, responses = fixture(COORDINATION_BRANCH)
        binding = bind(event, responses)
        query = (
            "check_name=Required+CI+%5Brefs%2Fheads%2Fdev%2F0.6.0%5D"
            "&filter=all&per_page=100"
        )
        check = {
            "id": 89,
            "name": binding.check_name,
            "head_sha": HEAD,
            "external_id": binding.external_id,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "nvidia-yamlsigil-release-pr"},
        }
        api = FakeApi(
            {
                ("GET", f"repos/{REPOSITORY}/commits/{HEAD}/check-runs?{query}"): {
                    "total_count": 0,
                    "check_runs": [],
                },
                ("POST", f"repos/{REPOSITORY}/check-runs"): check,
                ("GET", f"repos/{REPOSITORY}/check-runs/89"): check,
            }
        )
        self.assertEqual(reporter.report_check(api, policy(), binding), 89)
        self.assertEqual(api.calls[1][2]["name"], binding.check_name)


if __name__ == "__main__":
    unittest.main()

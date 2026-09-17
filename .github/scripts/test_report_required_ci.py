#!/usr/bin/env python3
# Python is justified here because these tests directly import the checkout-free
# protected Python reporter and exercise its bounded API contract without
# network access, a candidate checkout, or an App token. Keeping fixtures in
# the reporter's language avoids reimplementing its policy in Rust or shell.
"""Deterministic trust-boundary tests for the checkout-free Python reporter.

The fixtures model bounded GitHub REST responses and verify the automatic
candidate binding, DCO policy, base-specific check identity, App scope,
idempotency, and fail-closed behavior. They perform no network access or
repository mutation and are not a second workflow-policy implementation.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from dataclasses import replace
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
                    "verification": {"verified": False, "reason": "unsigned"},
                },
            }
        ],
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


STAGING_JOB = "Trusted CI / Linux result"
STAGING_REF = f"ci-testing/pr-{PULL}-{HEAD}"
STAGING_ACTOR = {"id": 74, "login": "reviewing-writer", "type": "User"}
PREFIX = f"repos/{REPOSITORY}"
RUN_PATH = ("GET", f"{PREFIX}/actions/runs/{RUN_ID}")
PULL_PATH = ("GET", f"{PREFIX}/pulls/{PULL}")
COMMITS_PATH = ("GET", f"{PREFIX}/pulls/{PULL}/commits?per_page=100&page=1")
JOBS_PATH = (
    "GET", f"{PREFIX}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100"
)
PERMISSION_PATH = ("GET", f"{PREFIX}/collaborators/reviewing-writer/permission")
STAGED_REF_PATH = ("GET", f"{PREFIX}/git/ref/heads/{STAGING_REF}")


def staged_fixture() -> tuple[dict[str, Any], dict[tuple[str, str], Any]]:
    """Model a reviewed writer push of changed workflow bytes without a checkout."""

    event, responses = fixture()
    run = responses[RUN_PATH]
    run["head_branch"] = STAGING_REF
    run["actor"] = copy.deepcopy(STAGING_ACTOR)
    # A rerunner is not the original actor whose exact-head admission matters.
    run["triggering_actor"] = {"id": 99, "login": "rerunner", "type": "User"}
    event["workflow_run"] = copy.deepcopy(run)
    responses[PERMISSION_PATH] = {
        "permission": "write", "user": copy.deepcopy(STAGING_ACTOR)
    }
    responses[COMMITS_PATH][0]["parents"] = [{"sha": POLICY_SHA}]
    ref = responses.pop(("GET", f"{PREFIX}/git/ref/heads/pull-request/{PULL}"))
    ref["ref"] = f"refs/heads/{STAGING_REF}"
    responses[STAGED_REF_PATH] = ref
    responses[JOBS_PATH]["jobs"][0]["name"] = STAGING_JOB
    # Staging is explicitly allowed to test reviewed workflow changes. Any
    # attempt to read/interpret those workflow bytes is an unexpected API call.
    for sha in (POLICY_SHA, HEAD):
        del responses[("GET", f"{PREFIX}/contents/.github/workflows/ci.yml?ref={sha}")]
    return event, responses


def bind_staged(event: dict[str, Any], responses: dict[tuple[str, str], Any]) -> Any:
    """Run the separate staging route under protected enabled policy."""

    return reporter.bind_candidate(
        FakeApi(responses), event, replace(policy(), staging_job_name=STAGING_JOB)
    )


class StagingTests(unittest.TestCase):
    def test_reviewed_workflow_changes_receive_main_verdict(self) -> None:
        event, responses = staged_fixture()
        binding = bind_staged(event, responses)
        self.assertEqual(binding.head_sha, HEAD)
        self.assertEqual(binding.base_sha, POLICY_SHA)
        self.assertEqual(binding.check_name, "Required CI")
        self.assertEqual(binding.staging_actor, "reviewing-writer")
        self.assertEqual(binding.check_conclusion, "success")

    def test_each_current_writer_role_is_eligible(self) -> None:
        for role in ("write", "maintain", "admin"):
            with self.subTest(role=role):
                event, responses = staged_fixture()
                responses[PERMISSION_PATH]["permission"] = role
                self.assertEqual(bind_staged(event, responses).check_conclusion, "success")

    def test_staging_is_explicitly_enabled_and_main_only(self) -> None:
        event, responses = staged_fixture()
        with self.assertRaisesRegex(reporter.ReporterError, "not enabled"):
            reporter.bind_candidate(FakeApi(responses), event, policy())
        for base in ("dev/0.6.0", "support/0.5"):
            with self.subTest(base=base):
                event, responses = staged_fixture()
                responses[PULL_PATH]["base"]["ref"] = base
                with self.assertRaisesRegex(reporter.ReporterError, "requires a main"):
                    bind_staged(event, responses)

    def test_complete_linear_series_proves_current_main_ancestry(self) -> None:
        event, responses = staged_fixture()
        first = copy.deepcopy(responses[COMMITS_PATH][0])
        first["sha"] = "d" * 40
        responses[COMMITS_PATH][0]["parents"] = [{"sha": first["sha"]}]
        responses[COMMITS_PATH].insert(0, first)
        responses[PULL_PATH]["commits"] = 2
        self.assertEqual(bind_staged(event, responses).head_sha, HEAD)
        responses[COMMITS_PATH][0]["parents"][0]["sha"] = "e" * 40
        with self.assertRaisesRegex(reporter.ReporterError, "successors of current main"):
            bind_staged(event, responses)

    def test_all_non_successful_terminal_results_fail_the_required_check(self) -> None:
        for conclusion in reporter.TERMINAL_JOB_CONCLUSIONS:
            with self.subTest(conclusion=conclusion):
                event, responses = staged_fixture()
                responses[JOBS_PATH]["jobs"][0]["conclusion"] = conclusion
                expected = "success" if conclusion == "success" else "failure"
                self.assertEqual(bind_staged(event, responses).check_conclusion, expected)

    def test_staging_rejects_every_inconsistent_authority_binding(self) -> None:
        cases = {
            "read-only actor": lambda e, r: r[PERMISSION_PATH].update(permission="read"),
            "triage actor": lambda e, r: r[PERMISSION_PATH].update(permission="triage"),
            "missing permission": lambda e, r: r[PERMISSION_PATH].pop("permission"),
            "different permission user": lambda e, r: r[PERMISSION_PATH]["user"].update(id=75),
            "renamed permission user": lambda e, r: r[PERMISSION_PATH]["user"].update(login="other"),
            "bot pusher": lambda e, r: r[RUN_PATH]["actor"].update(type="Bot"),
            "missing original actor": lambda e, r: r[RUN_PATH].pop("actor"),
            "forged delivered actor": lambda e, r: e["workflow_run"]["actor"].update(id=75),
            "wrong encoded head": lambda e, r: r[RUN_PATH].update(head_branch=f"ci-testing/pr-{PULL}-{'d' * 40}"),
            "ad hoc staging ref": lambda e, r: r[RUN_PATH].update(head_branch="ci-testing/example-20260917"),
            "noncanonical PR": lambda e, r: r[RUN_PATH].update(head_branch=f"ci-testing/pr-0{PULL}-{HEAD}"),
            "moved PR head": lambda e, r: r[PULL_PATH]["head"].update(sha="d" * 40),
            "closed PR": lambda e, r: r[PULL_PATH].update(state="closed"),
            "moved staging ref": lambda e, r: r[STAGED_REF_PATH]["object"].update(sha="d" * 40),
            "wrong main ancestry": lambda e, r: r[COMMITS_PATH][0].update(parents=[{"sha": "d" * 40}]),
            "merge commit": lambda e, r: r[COMMITS_PATH][0]["parents"].append({"sha": "d" * 40}),
            "root commit": lambda e, r: r[COMMITS_PATH][0].update(parents=[]),
            "missing DCO": lambda e, r: r[COMMITS_PATH][0]["commit"].update(message="unsigned"),
            "incomplete commits": lambda e, r: r[PULL_PATH].update(commits=2),
            "stale attempt": lambda e, r: r[RUN_PATH].update(run_attempt=ATTEMPT + 1),
            "different workflow": lambda e, r: r[RUN_PATH].update(workflow_id=WORKFLOW_ID + 1),
            "different workflow path": lambda e, r: r[RUN_PATH].update(path=".github/workflows/other.yml"),
            "different event": lambda e, r: r[RUN_PATH].update(event="workflow_dispatch"),
            "missing aggregate": lambda e, r: r[JOBS_PATH]["jobs"][0].update(name="unrelated"),
            "stale aggregate": lambda e, r: r[JOBS_PATH]["jobs"][0].update(run_attempt=ATTEMPT + 1),
            "incomplete jobs": lambda e, r: r[JOBS_PATH].update(total_count=3),
            "artifact": lambda e, r: r[("GET", f"{PREFIX}/actions/runs/{RUN_ID}/artifacts?per_page=1")].update(total_count=1),
            "moved main": lambda e, r: r[("GET", f"{PREFIX}/git/ref/heads/main")]["object"].update(sha="e" * 40),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                event, responses = staged_fixture()
                mutate(event, responses)
                with self.assertRaises(reporter.ReporterError):
                    bind_staged(event, responses)

    def test_duplicate_staging_aggregate_is_rejected(self) -> None:
        event, responses = staged_fixture()
        jobs = responses[JOBS_PATH]
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0]))
        jobs["total_count"] += 1
        with self.assertRaisesRegex(reporter.ReporterError, "duplicated"):
            bind_staged(event, responses)

    def test_revoked_writer_before_reporting_cannot_create_a_check(self) -> None:
        event, responses = staged_fixture()
        read_api = FakeApi(responses)
        app_api = FakeApi({("GET", "installation/repositories?per_page=100"): {
            "total_count": 1, "repositories": [{"full_name": REPOSITORY}]
        }})
        original_get = read_api.get
        reads = 0

        def revoke(path: str) -> Any:
            nonlocal reads
            value = original_get(path)
            if path == PERMISSION_PATH[1]:
                reads += 1
                if reads == 2:
                    value["permission"] = "read"
            return value

        read_api.get = revoke
        args = reporter.parser().parse_args([
            "report", "--event", "unused.json", "--repository", REPOSITORY,
            "--policy-sha", POLICY_SHA, "--workflow-id", str(WORKFLOW_ID),
            "--workflow-path", ".github/workflows/ci.yml", "--job-name", "Candidate CI (Linux)",
            "--staging-job-name", STAGING_JOB, "--app-slug", "nvidia-yamlsigil-release-pr",
        ])
        with mock.patch.object(reporter, "read_event", return_value=event), \
             mock.patch.object(reporter, "GitHubApi", side_effect=[read_api, app_api]), \
             mock.patch.dict(reporter.os.environ, {"APP_SLUG": "nvidia-yamlsigil-release-pr"}):
            with self.assertRaisesRegex(reporter.ReporterError, "current repository writer"):
                reporter.run(args)
        self.assertEqual(reads, 2)
        self.assertFalse(any(call[0] == "POST" for call in app_api.calls))


class WorkflowBlobTests(unittest.TestCase):
    def test_reusable_caller_preserves_binding_and_all_callee_blobs(self) -> None:
        event, responses = fixture()
        name = "Candidate CI / Candidate CI (Linux)"
        paths = (".github/workflows/ci-trusted.yml", ".github/workflows/ci-candidate.yml")
        protected = replace(policy(), job_name=name, workflow_policy_paths=paths)
        responses[JOBS_PATH]["jobs"][0]["name"] = reporter.attested_job_name(
            name, POLICY_SHA, "refs/heads/main", POLICY_SHA
        )
        for path in paths:
            for sha in (POLICY_SHA, HEAD):
                responses[("GET", f"{PREFIX}/contents/{path}?ref={sha}")] = {
                    "type": "file", "path": path, "sha": WORKFLOW_BLOB, "size": 1000
                }
        self.assertEqual(reporter.bind_candidate(FakeApi(responses), event, protected).head_sha, HEAD)
        for path in paths:
            with self.subTest(path=path):
                changed = copy.deepcopy(responses)
                changed[("GET", f"{PREFIX}/contents/{path}?ref={HEAD}")]["sha"] = "d" * 40
                with self.assertRaisesRegex(reporter.ReporterError, "differs from protected"):
                    reporter.bind_candidate(FakeApi(changed), event, protected)

    def test_local_callee_must_match_protected_main(self) -> None:
        event, responses = fixture()
        path = ".github/workflows/ci-candidate.yml"
        for sha in (POLICY_SHA, HEAD):
            responses[("GET", f"{PREFIX}/contents/{path}?ref={sha}")] = {
                "type": "file", "path": path, "sha": WORKFLOW_BLOB, "size": 1000
            }
        protected = replace(policy(), workflow_policy_paths=(path,))
        self.assertEqual(reporter.bind_candidate(FakeApi(responses), event, protected).head_sha, HEAD)
        responses[("GET", f"{PREFIX}/contents/{path}?ref={HEAD}")]["sha"] = "d" * 40
        with self.assertRaisesRegex(reporter.ReporterError, "differs from protected"):
            reporter.bind_candidate(FakeApi(responses), event, protected)

    def test_policy_paths_are_regular_explicit_workflow_paths(self) -> None:
        for path in ("../ci.yml", ".github/workflows/ci.yml", ".github/workflows/../ci.yml"):
            with self.subTest(path=path):
                with self.assertRaises(reporter.ReporterError):
                    replace(policy(), workflow_policy_paths=(path,)).validate()


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

    def test_support_checks_are_exact_and_spec_rejects_support(self) -> None:
        event, responses = fixture("support/0.5")
        support = bind(event, responses)
        self.assertEqual(support.check_name, "Required CI [refs/heads/support/0.5]")
        self.assertEqual(support.base_sha, COORDINATION_SHA)
        other_event, other_responses = fixture("support/0.6")
        other = bind(other_event, other_responses)
        self.assertNotEqual(support.check_name, other.check_name)
        for repo in ("NVIDIA/yaml-sigil-rs", "NVIDIA/yaml-sigil-traits"):
            for branch in ("support/0.5", "support/999999999.999999999"):
                self.assertLessEqual(len(reporter.base_policy(repo, branch)[1]), 128)
            for branch in ("support/0", "support/0.5.1", "support/00.5", "support/0.05", "support/1000000000.5"):
                with self.assertRaises(reporter.ReporterError):
                    reporter.base_policy(repo, branch)
        with self.assertRaises(reporter.ReporterError):
            reporter.base_policy("NVIDIA/yaml-sigil-spec", "support/0.5")

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

    def test_unsigned_candidate_is_accepted_without_signature_query(self) -> None:
        event, responses = fixture()
        api = FakeApi(responses)
        result = reporter.bind_candidate(api, event, policy())
        self.assertEqual(result.head_sha, HEAD)
        self.assertFalse(any(method == "GRAPHQL" for method, _, _ in api.calls))

    def test_multi_commit_main_candidate_uses_ordinary_required_check(self) -> None:
        """Bind and report one ordinary multi-commit main candidate."""

        event, responses = fixture()
        pull_path = ("GET", f"repos/{REPOSITORY}/pulls/{PULL}")
        commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        first = copy.deepcopy(responses[commits_path][0])
        first["sha"] = "e" * 40
        first["commit"]["message"] = (
            "fix: first signed-off change\n\n"
            f"Signed-off-by: {SIGNER_NAME} <{SIGNER_EMAIL}>"
        )
        responses[pull_path]["commits"] = 2
        responses[commits_path].insert(0, first)

        read_api = FakeApi(responses)
        binding = reporter.bind_candidate(read_api, event, policy())
        self.assertEqual(binding.head_sha, HEAD)
        self.assertEqual(binding.base_ref, "refs/heads/main")
        self.assertEqual(binding.check_name, "Required CI")
        self.assertEqual(
            binding.external_id,
            f"yaml-sigil-required-ci:{RUN_ID}:{ATTEMPT}:{POLICY_SHA}",
        )

        query = "check_name=Required+CI&filter=all&per_page=100"
        check = {
            "id": 88,
            "name": "Required CI",
            "head_sha": HEAD,
            "external_id": binding.external_id,
            "status": "completed",
            "conclusion": "success",
            "app": {"slug": "nvidia-yamlsigil-release-pr"},
        }
        app_api = FakeApi(
            {
                ("GET", f"repos/{REPOSITORY}/commits/{HEAD}/check-runs?{query}"): {
                    "total_count": 0,
                    "check_runs": [],
                },
                ("POST", f"repos/{REPOSITORY}/check-runs"): check,
                ("GET", f"repos/{REPOSITORY}/check-runs/88"): check,
            }
        )
        self.assertEqual(reporter.report_check(app_api, policy(), binding), 88)
        self.assertEqual(
            app_api.calls[1][2]["output"]["title"],
            "Authorized candidate CI result",
        )

    def test_removed_promotion_operations_are_rejected(self) -> None:
        """Keep the deleted manual command surface unreachable."""

        for operation in ("inspect-promotion", "report-promotion"):
            with self.subTest(operation=operation):
                with mock.patch("sys.stderr"):
                    with self.assertRaises(SystemExit):
                        reporter.parser().parse_args([operation])

    def test_missing_or_mismatched_raw_author_dco_fails_closed(self) -> None:
        commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        for name, message in {
            "missing": "fix: missing trailer",
            "mismatched": (
                "fix: mismatched trailer\n\n"
                f"Signed-off-by: Lookalike <{SIGNER_EMAIL}>"
            ),
        }.items():
            with self.subTest(name=name):
                event, responses = fixture()
                responses[commits_path][0]["commit"]["message"] = message
                with self.assertRaisesRegex(reporter.ReporterError, "raw-author DCO"):
                    bind(event, responses)

    def test_ordinary_candidate_does_not_require_rest_account_identity(self) -> None:
        event, responses = fixture()
        commits_path = (
            "GET",
            f"repos/{REPOSITORY}/pulls/{PULL}/commits?per_page=100&page=1",
        )
        responses[commits_path][0]["author"] = None
        responses[commits_path][0]["committer"] = None
        result = bind(event, responses)
        self.assertEqual(result.head_sha, HEAD)

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


class ReportingTests(unittest.TestCase):
    def test_staged_verdict_records_admission_and_is_idempotent(self) -> None:
        event, responses = staged_fixture()
        binding = bind_staged(event, responses)
        check = {
            "id": 88, "name": "Required CI", "head_sha": HEAD,
            "external_id": binding.external_id, "status": "completed",
            "conclusion": "success", "app": {"slug": policy().app_slug},
        }
        inventory_path = (
            "GET", f"{PREFIX}/commits/{HEAD}/check-runs?"
            "check_name=Required+CI&filter=all&per_page=100"
        )
        app_api = FakeApi({
            inventory_path: {"total_count": 0, "check_runs": []},
            ("POST", f"{PREFIX}/check-runs"): check,
            ("GET", f"{PREFIX}/check-runs/88"): check,
        })
        self.assertEqual(reporter.report_check(app_api, policy(), binding), 88)
        payload = next(call[2] for call in app_api.calls if call[0] == "POST")
        self.assertIn("staged by `reviewing-writer`", payload["output"]["summary"])
        app_api.responses[inventory_path] = {"total_count": 1, "check_runs": [check]}
        self.assertEqual(reporter.report_check(app_api, policy(), binding), 88)
        self.assertEqual(sum(call[0] == "POST" for call in app_api.calls), 1)

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

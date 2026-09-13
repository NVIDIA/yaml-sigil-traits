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

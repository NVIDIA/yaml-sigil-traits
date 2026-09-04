#!/usr/bin/env python3
"""Tests for the checkout-free required-CI reporter."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).with_name("report_required_ci.py")
SPEC = importlib.util.spec_from_file_location("report_required_ci", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reporter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reporter
SPEC.loader.exec_module(reporter)


REPOSITORY = "NVIDIA/yaml-sigil-test"
RUN_ID = 1234
ATTEMPT = 2
WORKFLOW_ID = 123456
PULL = 65
HEAD = "a" * 40
SIGNER_ID = 42
SIGNER_LOGIN = "example-contributor"
SIGNER_NAME = "Example Contributor"
SIGNER_EMAIL = "contributor@example.invalid"


class FakeApi:
    """Deterministic path-keyed API fixture."""

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        self.responses = copy.deepcopy(responses)
        self.calls: list[tuple[str, str, Any]] = []

    def get(self, path: str) -> Any:
        return self._take("GET", path, None)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self._take("POST", path, payload)

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        return self._take("GRAPHQL", query, variables)

    def _take(self, method: str, path: str, payload: Any) -> Any:
        self.calls.append((method, path, copy.deepcopy(payload)))
        key = (method, path)
        if key not in self.responses:
            raise AssertionError(f"unexpected API call: {method} {path}")
        value = self.responses[key]
        return copy.deepcopy(value)


def policy() -> Any:
    return reporter.Policy(
        repository=REPOSITORY,
        workflow_id=WORKFLOW_ID,
        workflow_path=".github/workflows/ci.yml",
        job_name="Candidate CI (Linux)",
        check_name="Required CI",
        app_slug="nvidia-yamlsigil-release-pr",
    )


def fixture() -> tuple[dict[str, Any], dict[tuple[str, str], Any]]:
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
            f"repos/{REPOSITORY}/pulls/{PULL}",
        ): {
            "number": PULL,
            "state": "open",
            "commits": 1,
            "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
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
                    "name": "Candidate CI (Linux)",
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
    return event, paths


def bind(event: dict[str, Any], responses: dict[tuple[str, str], Any]) -> Any:
    return reporter.bind_candidate(FakeApi(responses), event, policy())


class BindingTests(unittest.TestCase):
    def test_happy_path_ignores_advisory_failure(self) -> None:
        event, responses = fixture()
        result = bind(event, responses)
        self.assertEqual(result.head_sha, HEAD)
        self.assertEqual(result.conclusion, "success")
        self.assertEqual(result.check_conclusion, "success")

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
            "copied ref syntax": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}")].__setitem__("head_branch", "pull-request/not-a-number"),
            "closed pull": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")].__setitem__("state", "closed"),
            "wrong base branch": lambda _, responses: responses[("GET", f"repos/{REPOSITORY}/pulls/{PULL}")]["base"].__setitem__("ref", "develop"),
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

    def test_bounded_terminal_failure_maps_to_failure(self) -> None:
        event, responses = fixture()
        jobs = responses[("GET", f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}/jobs?per_page=100")]
        jobs["jobs"][0]["conclusion"] = "timed_out"
        result = bind(event, responses)
        self.assertEqual(result.check_conclusion, "failure")


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
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


if __name__ == "__main__":
    unittest.main()

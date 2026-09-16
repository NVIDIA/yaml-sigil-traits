#!/usr/bin/env python3
# Python is justified here because these deterministic fixtures exercise the
# pre-checkout Python binder without network access, credentials, or candidate
# subprocesses. Keeping tests in the binder's language avoids a second policy
# implementation and makes malformed GitHub JSON exact and reproducible.
"""Deterministic trust-boundary tests for copied-ref pull-request binding.

The fixtures model only the binder's bounded anonymous GitHub reads and its
validated runner-output append. They prove accepted unsigned main and
coordination-base bindings as well as fail-closed behavior for stale refs,
malformed objects, unsupported bases, and noncanonical release branches.
HTTP fixtures exercise bounded diagnostics, shared deadlines, and fresh binding
after retry waits without depending on live GitHub failures.
They initiate no network requests, GitHub mutations, checkouts, or
subprocesses. A test-managed temporary file exercises the binder's sole
production filesystem mutation: appending validated runner-output scalars.
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
from contextlib import ExitStack
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("bind-candidate-pr.py")
SPEC = importlib.util.spec_from_file_location("bind_candidate_pr", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
binder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = binder
SPEC.loader.exec_module(binder)


REPOSITORY = "NVIDIA/yaml-sigil-rs"
PULL = 17
HEAD = "a" * 40
POLICY_SHA = "b" * 40
COORDINATION_SHA = "c" * 40
COORDINATION_BRANCH = "dev/0.6.0"
COORDINATION_REF = f"refs/heads/{COORDINATION_BRANCH}"
COPIED_REF = f"pull-request/{PULL}"


class FakeApi:
    """Path-keyed read-only API fixture."""

    def __init__(self, responses: dict[str, Any]) -> None:
        """Deep-copy one case's responses so mutations stay isolated."""

        self.responses = copy.deepcopy(responses)
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        """Return one expected response and reject unmodeled API reads."""

        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected API call: {path}")
        return copy.deepcopy(self.responses[path])


def fixture(
    branch: str = "release-plz-manual-1.2.3-rc.4",
    base_branch: str = "main",
) -> dict[str, Any]:
    """Build one internally consistent anonymous GitHub response inventory."""

    prefix = f"repos/{REPOSITORY}"
    base_sha = POLICY_SHA if base_branch == "main" else COORDINATION_SHA
    responses = {
        f"{prefix}/pulls/{PULL}": {
            "number": PULL,
            "state": "open",
            "commits": 1,
            "base": {
                "ref": base_branch,
                "sha": base_sha,
                "repo": {"full_name": REPOSITORY},
            },
            "head": {
                "ref": branch,
                "sha": HEAD,
                "repo": {"full_name": REPOSITORY},
            },
        },
        f"{prefix}/pulls/{PULL}/commits?per_page=100": [
            {
                "sha": HEAD,
                "commit": {
                    "verification": {"verified": False, "reason": "unsigned"}
                },
            }
        ],
        f"{prefix}/git/ref/heads/{COPIED_REF}": {
            "ref": f"refs/heads/{COPIED_REF}",
            "object": {"type": "commit", "sha": HEAD},
        },
        f"{prefix}/git/ref/heads/main": {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": POLICY_SHA},
        },
    }
    if base_branch != "main":
        responses[f"{prefix}/git/ref/heads/{base_branch}"] = {
            "ref": f"refs/heads/{base_branch}",
            "object": {"type": "commit", "sha": base_sha},
        }
    return responses


def bind(responses: dict[str, Any]) -> Any:
    """Run the production binder against one isolated fixture inventory."""

    return binder.bind_candidate_pr(
        FakeApi(responses), REPOSITORY, COPIED_REF, HEAD, POLICY_SHA
    )


class CandidatePrBindingTests(unittest.TestCase):
    """Exercise accepted bindings and every mutable fail-closed boundary."""

    def test_canonical_release_branch_is_emitted(self) -> None:
        result = bind(fixture())
        self.assertEqual(result.release_branch, "release-plz-manual-1.2.3-rc.4")
        self.assertEqual(result.base_ref, "refs/heads/main")
        self.assertEqual(result.base_sha, POLICY_SHA)
        self.assertEqual(result.check_name, "Required CI")

    def test_ordinary_unsigned_branch_emits_no_release_value(self) -> None:
        result = bind(fixture("docs/clarify-example"))
        self.assertIsNone(result.release_branch)

    def test_coordination_base_has_a_distinct_required_check(self) -> None:
        result = bind(fixture("feat/new-api", COORDINATION_BRANCH))
        self.assertEqual(result.base_ref, COORDINATION_REF)
        self.assertEqual(result.base_sha, COORDINATION_SHA)
        self.assertEqual(result.check_name, f"Required CI [{COORDINATION_REF}]")
        self.assertIsNone(result.release_branch)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "output")
            binder.append_output(output, result)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                (
                    f"base_ref={COORDINATION_REF}\n"
                    f"base_sha={COORDINATION_SHA}\n"
                    f"check_name=Required CI [{COORDINATION_REF}]\n"
                    "release_branch=\n"
                ),
            )

    def test_policy_and_contribution_objects_cannot_be_swapped(self) -> None:
        responses = fixture("feat/new-api", COORDINATION_BRANCH)
        with self.assertRaisesRegex(binder.BindingError, "protected policy"):
            binder.bind_candidate_pr(
                FakeApi(responses),
                REPOSITORY,
                COPIED_REF,
                HEAD,
                COORDINATION_SHA,
            )

        responses = fixture("feat/new-api", COORDINATION_BRANCH)
        responses[f"repos/{REPOSITORY}/git/ref/heads/{COORDINATION_BRANCH}"][
            "object"
        ]["sha"] = POLICY_SHA
        with self.assertRaisesRegex(binder.BindingError, "contribution base"):
            bind(responses)

    def test_every_mutable_binding_rejects_drift(self) -> None:
        prefix = f"repos/{REPOSITORY}"
        pull_path = f"{prefix}/pulls/{PULL}"
        commits_path = f"{prefix}/pulls/{PULL}/commits?per_page=100"
        copied_path = f"{prefix}/git/ref/heads/{COPIED_REF}"
        main_path = f"{prefix}/git/ref/heads/main"
        mutations = {
            "pull number": lambda value: value[pull_path].__setitem__(
                "number", PULL + 1
            ),
            "pull state": lambda value: value[pull_path].__setitem__("state", "closed"),
            "base ref": lambda value: value[pull_path]["base"].__setitem__(
                "ref", "develop"
            ),
            "base repo": lambda value: value[pull_path]["base"]["repo"].__setitem__(
                "full_name", "NVIDIA/other"
            ),
            "base SHA": lambda value: value[pull_path]["base"].__setitem__(
                "sha", "c" * 40
            ),
            "head SHA": lambda value: value[pull_path]["head"].__setitem__(
                "sha", "c" * 40
            ),
            "incomplete commits": lambda value: value[pull_path].__setitem__(
                "commits", 2
            ),
            "last commit": lambda value: value[commits_path][0].__setitem__(
                "sha", "c" * 40
            ),
            "copied name": lambda value: value[copied_path].__setitem__(
                "ref", "refs/heads/pull-request/18"
            ),
            "copied type": lambda value: value[copied_path]["object"].__setitem__(
                "type", "tag"
            ),
            "copied SHA": lambda value: value[copied_path]["object"].__setitem__(
                "sha", "c" * 40
            ),
            "main name": lambda value: value[main_path].__setitem__(
                "ref", "refs/heads/other"
            ),
            "main type": lambda value: value[main_path]["object"].__setitem__(
                "type", "tag"
            ),
            "main SHA": lambda value: value[main_path]["object"].__setitem__(
                "sha", "c" * 40
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                responses = fixture()
                mutate(responses)
                with self.assertRaises(binder.BindingError):
                    bind(responses)

        oversized = fixture()
        oversized[pull_path]["commits"] = 101
        with self.assertRaisesRegex(binder.BindingError, "exceeds"):
            bind(oversized)

    def test_release_branch_must_be_canonical_and_repository_owned(self) -> None:
        with self.assertRaisesRegex(binder.BindingError, "canonical"):
            bind(fixture("release-plz-manual-01.2.3"))

        responses = fixture()
        responses[f"repos/{REPOSITORY}/pulls/{PULL}"]["head"]["repo"][
            "full_name"
        ] = "fork/repo"
        with self.assertRaisesRegex(binder.BindingError, "canonical"):
            bind(responses)

        with self.assertRaisesRegex(binder.BindingError, "canonical"):
            bind(fixture("release-plz-manual-1.2.3", COORDINATION_BRANCH))

    def test_support_base_and_release_branch_bind_the_same_line(self) -> None:
        for branch in ("fix/backport", "release-plz-manual-0.5.2-rc.1"):
            result = bind(fixture(branch, "support/0.5"))
            self.assertEqual(result.base_ref, "refs/heads/support/0.5")
            self.assertEqual(result.check_name, "Required CI [refs/heads/support/0.5]")
            self.assertEqual(result.base_sha, COORDINATION_SHA)
        for version in ("0.6.0", "1.5.2", "00.5.2", "0.5.2+local"):
            with self.assertRaisesRegex(binder.BindingError, "canonical"):
                bind(fixture(f"release-plz-manual-{version}", "support/0.5"))
        for repo in ("NVIDIA/yaml-sigil-rs", "NVIDIA/yaml-sigil-traits"):
            self.assertEqual(binder.base_policy(repo, "support/999999999.999999999")[0],
                             "refs/heads/support/999999999.999999999")
            for branch in ("support/0", "support/0.5.1", "support/00.5", "support/0.05", "support/1000000000.5"):
                with self.assertRaises(binder.BindingError):
                    binder.base_policy(repo, branch)
        with self.assertRaises(binder.BindingError):
            binder.base_policy("NVIDIA/yaml-sigil-spec", "support/0.5")

    def test_coordination_base_must_match_repository_policy(self) -> None:
        with self.assertRaisesRegex(binder.BindingError, "allowed contribution"):
            bind(fixture("feat/new-api", "dev/not-semver"))

        with self.assertRaisesRegex(binder.BindingError, "no protected"):
            binder.base_policy("NVIDIA/another-repository", "main")

        for branch in ("v2", "v2alpha1", "v2beta3"):
            self.assertEqual(
                binder.base_policy("NVIDIA/yaml-sigil-spec", branch),
                (
                    f"refs/heads/{branch}",
                    f"Required CI [refs/heads/{branch}]",
                ),
            )
        for branch in ("v0", "v1alpha0", "dev/2.0.0"):
            with self.assertRaisesRegex(binder.BindingError, "allowed contribution"):
                binder.base_policy("NVIDIA/yaml-sigil-spec", branch)


class RecordingBody(io.BytesIO):
    """Record read bounds while retaining ordinary response close behavior."""

    def read(self, size: int = -1) -> bytes:
        self.requested_size = size
        return super().read(size)


class HttpBindingTests(unittest.TestCase):
    """Exercise the real HTTP client without network or actual retry sleeps."""

    def setUp(self) -> None:
        self.now = 1000.0
        self.latency = 0.0
        self.sleeps: list[float] = []
        self.calls: list[str] = []
        self.timeouts: list[float] = []
        self.errors: dict[str, list[tuple[int, dict[str, str], bytes]]] = {}
        self.bodies: list[RecordingBody] = []
        self.responses = fixture("fix/example")
        self.pull_path = f"repos/{REPOSITORY}/pulls/{PULL}"
        self.after_wait = lambda: None
        self.log = io.StringIO()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(binder.urllib.request, "urlopen", self.urlopen))
        stack.enter_context(patch.object(binder.time, "monotonic", lambda: self.now))
        stack.enter_context(patch.object(binder.time, "time", lambda: self.now))
        stack.enter_context(patch.object(binder.time, "sleep", self.sleep))
        stack.enter_context(patch.object(binder.sys, "stderr", self.log))

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay
        self.after_wait()

    def fail(
        self, status: int, headers: dict[str, str] | None = None,
        body: bytes = b'{}', *, path: str | None = None, times: int = 1,
    ) -> None:
        self.errors[path or self.pull_path] = [(status, headers or {}, body)] * times

    def urlopen(self, request: Any, timeout: float) -> RecordingBody:
        path = request.full_url.removeprefix(binder.API_ROOT + "/")
        self.assertEqual(request.get_method(), "GET")
        self.assertFalse(request.has_header("Authorization"))
        self.calls.append(path)
        self.timeouts.append(timeout)
        self.now += self.latency
        if self.errors.get(path):
            status, values, raw = self.errors[path].pop(0)
            headers = Message()
            for name, value in values.items():
                headers[name] = value
            body = RecordingBody(raw)
            self.bodies.append(body)
            raise urllib.error.HTTPError(request.full_url, status, "fixture", headers, body)
        response = self.responses[path]
        body = RecordingBody(response if isinstance(response, bytes) else json.dumps(response).encode())
        self.bodies.append(body)
        return body

    def bind(self) -> Any:
        return binder.bind_with_retries(REPOSITORY, COPIED_REF, HEAD, POLICY_SHA)

    def test_recoverable_http_errors_honor_delays(self) -> None:
        cases = [
            (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1002"}, b'{}', 3),
            (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1002",
                   "retry-after": "5"}, b'{}', 5),
            (403, {"retry-after": "2"}, b'{}', 2),
            (403, {}, b'{"message":"You have exceeded a secondary rate limit."}', 60),
            (429, {}, b'{}', 60),
            (429, {"retry-after": "0"}, b'{}', 1),
            (503, {"retry-after": "4"}, b'{}', 4),
            *((status, {}, b'{}', 1) for status in (500, 502, 503, 504)),
        ]
        for status, headers, body, delay in cases:
            with self.subTest(status=status, headers=headers):
                self.now = 1000
                self.sleeps.clear()
                self.calls.clear()
                self.fail(status, headers, body)
                self.assertEqual(self.bind().base_sha, POLICY_SHA)
                self.assertEqual(self.sleeps, [delay])
                self.assertEqual(self.calls[:2], [self.pull_path] * 2)
                self.assertTrue(all(body.closed for body in self.bodies))

    def test_fatal_errors_do_not_retry(self) -> None:
        cases = [
            (403, {}, b'{"message":"Resource not accessible"}'),
            (401, {"retry-after": "1"}, b'{}'),
            (404, {}, b'{}'),
            (501, {}, b'{}'),
            (403, {"x-ratelimit-remaining": "0"}, b'{}'),
            *((403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": value}, b'{}')
              for value in ("-1", "nan", "1" * 13, "1002\nignored")),
        ]
        for status, headers, body in cases:
            with self.subTest(status=status, headers=headers):
                self.calls.clear()
                self.fail(status, headers, body)
                with self.assertRaisesRegex(binder.BindingError, f"HTTP {status}"):
                    self.bind()
                self.assertEqual(self.calls, [self.pull_path])
                self.assertEqual(self.sleeps, [])

    def test_diagnostics_are_bounded_and_allowlisted(self) -> None:
        self.fail(403, {
            "x-github-request-id": "A1:B2-C3",
            "x-ratelimit-limit": "60", "x-ratelimit-remaining": "0",
            "x-ratelimit-used": "60", "x-ratelimit-reset": "9999",
            "x-ratelimit-resource": "core", "retry-after": "20",
            "authorization": "private-header",
        }, b'{"message":"private-body"}')
        with self.assertRaises(binder.BindingError) as raised:
            self.bind()
        diagnostic = str(raised.exception)
        for expected in (self.pull_path, "HTTP 403", "primary rate limit",
                         "A1:B2-C3", "x-ratelimit-reset=9999", "retry-after=20",
                         "attempt 1/3", "exceeds remaining"):
            self.assertIn(expected, diagnostic)
        self.assertNotIn("private", diagnostic)
        self.assertEqual(self.bodies[0].requested_size, binder.MAX_ERROR_BYTES + 1)
        self.assertTrue(self.bodies[0].closed)
        self.assertEqual(self.sleeps, [])

        for raw in (b'not JSON', b'{"message":17}', b'\xff', b'[' * 2000,
                    b'x' * (binder.MAX_ERROR_BYTES + 100)):
            with self.subTest(raw_length=len(raw)):
                self.fail(403, {"x-github-request-id": "unsafe\n::error::",
                                "retry-after": "-1", "x-ratelimit-resource": "\x1b[31m"}, raw)
                with self.assertRaises(binder.BindingError) as raised:
                    self.bind()
                self.assertNotIn("unsafe", str(raised.exception))
                self.assertNotIn("\x1b", str(raised.exception))
                self.assertEqual(self.sleeps, [])

    def test_attempts_and_secondary_backoff_are_bounded(self) -> None:
        self.fail(503, times=3)
        with self.assertRaisesRegex(binder.BindingError, "attempts exhausted"):
            self.bind()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.sleeps, [1, 2])

        self.calls.clear()
        self.sleeps.clear()
        self.fail(429, times=3)
        with self.assertRaisesRegex(binder.BindingError, "required wait 120.0s"):
            self.bind()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.sleeps, [60])

    def test_request_time_counts_against_the_shared_budget(self) -> None:
        self.latency = 20
        self.fail(429, {"retry-after": "60"}, path=f"repos/{REPOSITORY}/git/ref/heads/main")
        with self.assertRaisesRegex(binder.BindingError, "remaining 40.0s"):
            self.bind()
        self.assertEqual(self.sleeps, [])

        self.calls.clear()
        self.timeouts.clear()
        self.responses = fixture("fix/example", COORDINATION_BRANCH)
        self.latency = 25
        with self.assertRaisesRegex(binder.BindingError, "budget"):
            self.bind()
        self.assertEqual(self.timeouts, [30, 30, 30, 30, 20])

    def test_stalled_io_and_transport_errors_fail_without_retry(self) -> None:
        finished = threading.Event()
        started = threading.Event()

        def stalled(*args: Any, **kwargs: Any) -> io.BytesIO:
            started.set()
            finished.wait()
            return io.BytesIO(b'{}')

        try:
            with patch.object(binder, "MAX_REQUEST_SECONDS", 0.02), \
                 patch.object(binder.urllib.request, "urlopen", stalled):
                with self.assertRaisesRegex(binder.BindingError, "timed out"):
                    self.bind()
                self.assertTrue(started.is_set())
        finally:
            finished.set()
        for error in (urllib.error.URLError("fixture"), TimeoutError("fixture")):
            with patch.object(binder.urllib.request, "urlopen", side_effect=error) as request:
                with self.assertRaisesRegex(binder.BindingError, "read failed"):
                    self.bind()
                self.assertEqual(request.call_count, 1)
        self.assertEqual(self.sleeps, [])

    def test_malformed_success_responses_remain_fatal(self) -> None:
        for raw in (b'not JSON', b'x' * (binder.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(raw_length=len(raw)):
                self.calls.clear()
                self.responses[self.pull_path] = raw
                with self.assertRaises(binder.BindingError):
                    self.bind()
                self.assertEqual(self.calls, [self.pull_path])
                self.assertEqual(self.sleeps, [])

    def test_retry_rebinds_every_mutable_object(self) -> None:
        prefix = f"repos/{REPOSITORY}/git/ref/heads/"
        changes = [
            lambda: self.responses[self.pull_path].__setitem__("state", "closed"),
            lambda: self.responses[self.pull_path]["head"].__setitem__("sha", "d" * 40),
            *(lambda name=name: self.responses[prefix + name]["object"].__setitem__("sha", "d" * 40)
              for name in ("main", COPIED_REF, COORDINATION_BRANCH)),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.responses = fixture("fix/example", COORDINATION_BRANCH)
                self.calls.clear()
                self.sleeps.clear()
                self.after_wait = change
                self.fail(503, path=prefix + "main")
                with self.assertRaises(binder.BindingError):
                    self.bind()
                self.assertEqual(self.calls[4], self.pull_path)
                self.assertEqual(self.sleeps, [1])

    def test_cli_writes_only_one_complete_successful_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "output")
            arguments = [str(MODULE_PATH), "--repository", REPOSITORY,
                         "--copied-ref", COPIED_REF, "--head-sha", HEAD,
                         "--policy-sha", POLICY_SHA, "--output", str(output)]
            with patch.object(binder.sys, "argv", arguments):
                self.fail(503, path=f"repos/{REPOSITORY}/git/ref/heads/main")
                self.assertEqual(binder.main(), 0)
                expected = (f"base_ref=refs/heads/main\nbase_sha={POLICY_SHA}\n"
                            "check_name=Required CI\nrelease_branch=\n")
                self.assertEqual(output.read_text(), expected)
                self.fail(503, path=f"repos/{REPOSITORY}/git/ref/heads/main")
                self.after_wait = lambda: self.responses[self.pull_path].__setitem__(
                    "state", "closed"
                )
                self.assertEqual(binder.main(), 1)
                self.assertEqual(output.read_text(), expected)


if __name__ == "__main__":
    unittest.main()

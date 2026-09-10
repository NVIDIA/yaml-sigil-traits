#!/usr/bin/env python3
"""Tests for anonymous copied-ref pull-request binding."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


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
        self.responses = copy.deepcopy(responses)
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        self.calls.append(path)
        if path not in self.responses:
            raise AssertionError(f"unexpected API call: {path}")
        return copy.deepcopy(self.responses[path])


def fixture(
    branch: str = "release-plz-manual-1.2.3-rc.4",
    base_branch: str = "main",
) -> dict[str, Any]:
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
                    "verification": {"verified": True, "reason": "valid"}
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
    return binder.bind_candidate_pr(
        FakeApi(responses), REPOSITORY, COPIED_REF, HEAD, POLICY_SHA
    )


class CandidatePrBindingTests(unittest.TestCase):
    def test_canonical_release_branch_is_emitted(self) -> None:
        result = bind(fixture())
        self.assertEqual(result.release_branch, "release-plz-manual-1.2.3-rc.4")
        self.assertEqual(result.base_ref, "refs/heads/main")
        self.assertEqual(result.base_sha, POLICY_SHA)
        self.assertEqual(result.check_name, "Required CI")

    def test_ordinary_branch_emits_no_release_value(self) -> None:
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
            "unverified commit": lambda value: value[commits_path][0]["commit"][
                "verification"
            ].__setitem__("verified", False),
            "verification reason": lambda value: value[commits_path][0]["commit"][
                "verification"
            ].__setitem__("reason", "unsigned"),
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

    def test_coordination_base_must_match_repository_policy(self) -> None:
        with self.assertRaisesRegex(binder.BindingError, "allowed coordination"):
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
            with self.assertRaisesRegex(binder.BindingError, "allowed coordination"):
                binder.base_policy("NVIDIA/yaml-sigil-spec", branch)


if __name__ == "__main__":
    unittest.main()

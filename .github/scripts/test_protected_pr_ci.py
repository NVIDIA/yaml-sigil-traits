#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for protected-main pull-request policy."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("protected_pr_ci.py")
VERIFIER_PATH = MODULE_PATH.with_name("protected_checkout.py")
TERMINAL_DRIVER_PATH = MODULE_PATH.with_name("terminal_candidate.py")
TERMINAL_SHELL_PATH = MODULE_PATH.with_name("run-terminal-candidate.sh")
TERMINAL_WINDOWS_PATH = MODULE_PATH.with_name("run-terminal-candidate-windows.ps1")
COMMIT_POLICY_PATH = MODULE_PATH.with_name("check-pull-request-commits.sh")
POLICY_PATH = MODULE_PATH.parent.parent / "protected-pr-ci.json"
COMMAND_WORKFLOW_PATH = MODULE_PATH.parent.parent / "workflows" / "pr-ci-command.yml"
REUSABLE_WORKFLOW_PATH = MODULE_PATH.parent.parent / "workflows" / "pr-ci.yml"
RECONCILE_WORKFLOW_PATH = (
    MODULE_PATH.parent.parent / "workflows" / "pr-ci-reconcile.yml"
)
CHECKOUT_ACTION_PATH = (
    MODULE_PATH.parent.parent
    / "actions"
    / "protected-candidate-checkout"
    / "action.yml"
)
SPEC = importlib.util.spec_from_file_location("protected_pr_ci", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)
VERIFIER_SPEC = importlib.util.spec_from_file_location("protected_checkout", VERIFIER_PATH)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
verifier = importlib.util.module_from_spec(VERIFIER_SPEC)
sys.modules[VERIFIER_SPEC.name] = verifier
VERIFIER_SPEC.loader.exec_module(verifier)
TERMINAL_SPEC = importlib.util.spec_from_file_location(
    "terminal_candidate", TERMINAL_DRIVER_PATH
)
assert TERMINAL_SPEC is not None and TERMINAL_SPEC.loader is not None
terminal_candidate = importlib.util.module_from_spec(TERMINAL_SPEC)
sys.modules[TERMINAL_SPEC.name] = terminal_candidate
TERMINAL_SPEC.loader.exec_module(terminal_candidate)


REPOSITORY = "NVIDIA/yaml-sigil-example"
MAIN_SHA = "a" * 40
HEAD_SHA = "b" * 40
OLD_SHA = "c" * 40
BASE_TREE_SHA = "d" * 40
HEAD_TREE_SHA = "e" * 40
BASE_BLOB_SHA = "1" * 40
HEAD_BLOB_SHA = "2" * 40
DIRECTORY_TREE_SHA = "f" * 40
SPEC_MAIN_SHA = "6" * 40
RUN_ID = 101
RUN_ATTEMPT = 1
WORKFLOW_ID = 701
PULL_NUMBER = 7
COMMENT_ID = 19
BOT = "nvidia-yamlsigil-release-pr[bot]"
BOT_ID = 318780254
BOT_EMAIL = "318780254+nvidia-yamlsigil-release-pr[bot]@users.noreply.github.com"
APP_SLUG = "nvidia-yamlsigil-release-pr"
WEB_FLOW = "web-flow"
WEB_FLOW_ID = 19864447
GITHUB_COMMITTER_NAME = "GitHub"
GITHUB_COMMITTER_EMAIL = "noreply@github.com"
MAINTAINER = "maintainer"


def policy() -> dict:
    return {
        "version": 4,
        "repository": REPOSITORY,
        "repository_kind": "traits",
        "default_branch": "main",
        "workflow_file": ".github/workflows/pr-ci-command.yml",
        "required_check": "Required CI",
        "release_app": {
            "enabled": True,
            "login": BOT,
            "bot_user_id": BOT_ID,
            "slug": APP_SLUG,
            "head_ref": "release-plz-next",
            "commit_author_name": BOT,
            "commit_author_email": BOT_EMAIL,
            "commit_committer_login": WEB_FLOW,
            "commit_committer_user_id": WEB_FLOW_ID,
            "commit_committer_name": GITHUB_COMMITTER_NAME,
            "commit_committer_email": GITHUB_COMMITTER_EMAIL,
            "allowed_paths": ["Cargo.toml", "CHANGELOG.md"],
        },
        "expected_jobs": ["commit_policy", "workflow_lint", "candidate_ci"],
        "supplemental_candidate_ci": True,
        "trusted_gitlinks": [
            {
                "path": "source-spec",
                "repository": "NVIDIA/yaml-sigil-spec",
                "branch": "main",
            }
        ],
    }


def policy_bash() -> str:
    """Return Git Bash on Windows instead of the WSL launcher."""
    if os.name != "nt":
        return "bash"

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("cannot locate Git while resolving Git Bash")
    git_path = pathlib.Path(git)
    candidates = (
        git_path.parent / "bash.exe",
        git_path.parent.parent / "bin" / "bash.exe",
        git_path.parent.parent / "usr" / "bin" / "bash.exe",
        git_path.parent.parent.parent / "bin" / "bash.exe",
        git_path.parent.parent.parent / "usr" / "bin" / "bash.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return os.fspath(candidate)
    raise RuntimeError(f"cannot locate Git Bash beside {git_path}")


def event(body: str | None = None) -> dict:
    return {
        "action": "created",
        "repository": {"full_name": REPOSITORY},
        "issue": {"number": 7, "pull_request": {"url": "https://example.invalid/pr/7"}},
        "comment": {
            "id": 19,
            "body": body if body is not None else f"/ok to test {HEAD_SHA}",
            "created_at": "2026-08-28T12:00:00Z",
            "updated_at": "2026-08-28T12:00:00Z",
            "user": {"id": 1, "login": MAINTAINER, "type": "User"},
        },
        "sender": {"id": 1, "login": MAINTAINER, "type": "User"},
    }


def adoption_event() -> dict:
    return event(f"/ok to test-and-adopt {HEAD_SHA}")


def environment() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_ACTOR": MAINTAINER,
        "GITHUB_EVENT_NAME": "issue_comment",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_TRIGGERING_ACTOR": MAINTAINER,
        "GITHUB_RUN_ATTEMPT": "1",
        "POLICY_SHA": MAIN_SHA,
    }


def call_binding(
    *,
    head_sha: str = HEAD_SHA,
    pull_number: int = PULL_NUMBER,
    comment_id: int = COMMENT_ID,
) -> object:
    return controller.CallBinding(
        pull_number=pull_number,
        head_sha=head_sha,
        comment_id=comment_id,
    )


def workflow_job(
    *,
    binding=None,
    run_id: int = RUN_ID,
    attempt: int = RUN_ATTEMPT,
    policy_sha: str = MAIN_SHA,
    name: str | None = None,
) -> dict:
    selected = binding or call_binding()
    return {
        "id": 901,
        "run_id": run_id,
        "run_attempt": attempt,
        "head_sha": policy_sha,
        "name": name or selected.encode_job_name(),
        "status": "in_progress",
        "conclusion": None,
    }


def workflow_run(
    *,
    run_id: int = RUN_ID,
    attempt: int = RUN_ATTEMPT,
    policy_sha: str = MAIN_SHA,
    status: str = "in_progress",
    conclusion: str | None = None,
) -> dict:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": WORKFLOW_ID,
        "name": f"PR #{PULL_NUMBER} comment {COMMENT_ID}",
        "path": ".github/workflows/pr-ci-command.yml",
        "event": "issue_comment",
        "head_branch": "main",
        "head_sha": policy_sha,
        "status": status,
        "conclusion": conclusion,
        "actor": {"login": MAINTAINER},
        "triggering_actor": {"login": MAINTAINER},
    }


def workflow_run_event(*, attempt: int = RUN_ATTEMPT, conclusion: str = "failure") -> dict:
    return {
        "action": "completed",
        "repository": {"full_name": REPOSITORY},
        "workflow_run": workflow_run(
            attempt=attempt,
            status="completed",
            conclusion=conclusion,
        ),
    }


def git_commit(
    *,
    sha: str = HEAD_SHA,
    parent: str = MAIN_SHA,
    author_login: str = MAINTAINER,
    committer_login: str = MAINTAINER,
    author_id: int = 1,
    committer_id: int = 1,
    author_type: str = "User",
    committer_type: str = "User",
    author_name: str = "Maintainer",
    author_email: str = "maintainer@example.invalid",
    committer_name: str = "Maintainer",
    committer_email: str = "maintainer@example.invalid",
    message: str | None = None,
    verified: bool = True,
) -> dict:
    default_message = (
        "ci: update policy\n\n"
        f"Signed-off-by: {author_name} <{author_email}>\n"
        + (
            f"Signed-off-by: {committer_name} <{committer_email}>\n"
            if (author_name, author_email) != (committer_name, committer_email)
            else ""
        )
    )
    return {
        "sha": sha,
        "parents": [{"sha": parent}],
        "author": {"login": author_login, "id": author_id, "type": author_type},
        "committer": {
            "login": committer_login,
            "id": committer_id,
            "type": committer_type,
        },
        "commit": {
            "author": {"name": author_name, "email": author_email},
            "committer": {"name": committer_name, "email": committer_email},
            "message": message or default_message,
            "verification": {
                "verified": verified,
                "reason": "valid" if verified else "unsigned",
            },
        },
    }


def git_signature(
    *,
    sha: str = HEAD_SHA,
    signer_login: str = MAINTAINER,
    signer_id: int = 1,
    email: str = "maintainer@example.invalid",
    valid: bool = True,
    github_signed: bool = False,
    kind: str = "GpgSignature",
) -> dict:
    return {
        "oid": sha,
        "signature": {
            "__typename": kind,
            "email": email,
            "isValid": valid,
            "state": "VALID" if valid else "INVALID",
            "wasSignedByGitHub": github_signed,
            "signer": {
                "databaseId": signer_id,
                "login": signer_login,
                "__typename": "User",
            },
        },
    }


def recursive_tree(tree_sha: str, leaves: dict[str, tuple[str, str, str]]) -> dict:
    directories = {
        "/".join(path.split("/")[:length])
        for path in leaves
        for length in range(1, len(path.split("/")))
    }
    entries = [
        {
            "path": path,
            "mode": "040000",
            "type": "tree",
            "sha": DIRECTORY_TREE_SHA,
        }
        for path in sorted(directories)
    ]
    entries.extend(
        {
            "path": path,
            "type": leaf[0],
            "mode": leaf[1],
            "sha": leaf[2],
        }
        for path, leaf in sorted(leaves.items())
    )
    return {"sha": tree_sha, "truncated": False, "tree": entries}


class FakeAuthorizationApi:
    def __init__(self) -> None:
        self.api_url = "https://api.github.com"
        self.main_sha = MAIN_SHA
        self.final_main_sha = None
        self.main_sha_sequence = None
        self.main_error_on_read = None
        self.permissions = {MAINTAINER: "write"}
        self.commits = [{"sha": HEAD_SHA, "parents": [{"sha": MAIN_SHA}]}]
        self.details = {HEAD_SHA: git_commit()}
        self.signatures = {HEAD_SHA: git_signature()}
        self.git_commits = {
            MAIN_SHA: {"sha": MAIN_SHA, "tree": {"sha": BASE_TREE_SHA}},
            HEAD_SHA: {"sha": HEAD_SHA, "tree": {"sha": HEAD_TREE_SHA}},
        }
        self.trees = {}
        self.set_tree_files(
            {"README.md": ("blob", "100644", BASE_BLOB_SHA)},
            {"README.md": ("blob", "100644", HEAD_BLOB_SHA)},
        )
        self.comment = copy.deepcopy(event()["comment"])
        self.comment_issue_number = 7
        self.posts = []
        self.get_paths = []
        self.run = workflow_run()
        self.jobs = [workflow_job()]
        self.runs = [self.run]
        self.main_reads = 0
        self.pull_reads = 0
        self.final_pull = None
        self.spec_main_sha = SPEC_MAIN_SHA
        self.comparisons = {}
        self.pull = {
            "number": 7,
            "state": "open",
            "user": {"login": "contributor", "id": 42, "type": "User"},
            "base": {
                "ref": "main",
                "sha": MAIN_SHA,
                "repo": {"full_name": REPOSITORY},
            },
            "head": {
                "ref": "feature",
                "sha": HEAD_SHA,
                "repo": {"full_name": "contributor/yaml-sigil-example"},
            },
            "changed_files": 1,
            "commits": 1,
            "maintainer_can_modify": True,
        }

    def allow_ancestry(self, ancestor: str, descendant: str) -> None:
        self.comparisons[(ancestor, descendant)] = {
            "status": "ahead",
            "merge_base_commit": {"sha": ancestor},
            "base_commit": {"sha": ancestor},
            "head_commit": {"sha": descendant},
        }

    def set_tree_files(
        self,
        base: dict[str, tuple[str, str, str]],
        head: dict[str, tuple[str, str, str]],
    ) -> None:
        self.trees[BASE_TREE_SHA] = recursive_tree(BASE_TREE_SHA, base)
        self.trees[HEAD_TREE_SHA] = recursive_tree(HEAD_TREE_SHA, head)

    def set_change(
        self, path: str, status: str = "modified", previous_filename: str | None = None
    ) -> None:
        base: dict[str, tuple[str, str, str]] = {}
        head: dict[str, tuple[str, str, str]] = {}
        if status == "modified":
            base[path] = ("blob", "100644", BASE_BLOB_SHA)
            head[path] = ("blob", "100644", HEAD_BLOB_SHA)
        elif status == "added":
            head[path] = ("blob", "100644", HEAD_BLOB_SHA)
        elif status == "removed":
            base[path] = ("blob", "100644", BASE_BLOB_SHA)
        elif status == "renamed":
            if previous_filename is None:
                raise AssertionError("a renamed fixture needs previous_filename")
            base[previous_filename] = ("blob", "100644", BASE_BLOB_SHA)
            head[path] = ("blob", "100644", BASE_BLOB_SHA)
        else:
            raise AssertionError(f"unsupported fixture status {status}")
        self.set_tree_files(base, head)

    def get(self, path: str):
        self.get_paths.append(path)
        if "/collaborators/" in path and path.endswith("/permission"):
            login = path.split("/collaborators/", 1)[1].rsplit("/permission", 1)[0]
            return {"permission": self.permissions.get(login, "none")}
        if path == "/repos/NVIDIA/yaml-sigil-spec/git/ref/heads/main":
            return {"object": {"type": "commit", "sha": self.spec_main_sha}}
        if path.startswith("/repos/NVIDIA/yaml-sigil-spec/compare/"):
            pair = path.rsplit("/", 1)[1]
            ancestor, descendant = pair.split("...", 1)
            return copy.deepcopy(self.comparisons[(ancestor, descendant)])
        if path.endswith("/git/ref/heads/main"):
            self.main_reads += 1
            if self.main_reads == self.main_error_on_read:
                raise controller.PolicyError("main ref reread failed")
            if self.main_sha_sequence is not None:
                index = min(self.main_reads - 1, len(self.main_sha_sequence) - 1)
                return {
                    "object": {
                        "type": "commit",
                        "sha": self.main_sha_sequence[index],
                    }
                }
            sha = (
                self.final_main_sha
                if self.main_reads > 1 and self.final_main_sha is not None
                else self.main_sha
            )
            return {"object": {"type": "commit", "sha": sha}}
        if path.endswith("/pulls/7"):
            self.pull_reads += 1
            value = self.final_pull if self.pull_reads > 1 and self.final_pull else self.pull
            return copy.deepcopy(value)
        if path.endswith("/issues/comments/19"):
            value = copy.deepcopy(self.comment)
            value["issue_url"] = (
                f"{self.api_url}/repos/{REPOSITORY}/issues/"
                f"{self.comment_issue_number}"
            )
            return value
        if path.endswith(f"/actions/runs/{RUN_ID}"):
            return copy.deepcopy(self.run)
        if "/actions/workflows/" in path:
            return {
                "id": WORKFLOW_ID,
                "name": controller.CALLER_WORKFLOW_NAME,
                "path": ".github/workflows/pr-ci-command.yml",
                "state": "active",
            }
        if "/git/commits/" in path:
            sha = path.split("/git/commits/", 1)[1].split("?", 1)[0]
            return copy.deepcopy(self.git_commits[sha])
        if "/git/trees/" in path:
            sha = path.split("/git/trees/", 1)[1].split("?", 1)[0]
            return copy.deepcopy(self.trees[sha])
        if "/commits/" in path:
            sha = path.rsplit("/", 1)[1]
            return copy.deepcopy(self.details[sha])
        raise AssertionError(f"unexpected GET {path}")

    def paginate(self, path: str, *, max_items: int, label: str):
        del path, max_items
        if label == "pull request commits":
            return copy.deepcopy(self.commits)
        raise AssertionError(f"unexpected pagination label {label}")

    def paginate_key(self, path, key, *, max_items, label):
        del path, key, max_items
        if label == "workflow run jobs":
            return copy.deepcopy(self.jobs)
        if label == "protected workflow runs":
            return copy.deepcopy(self.runs)
        raise AssertionError(f"unexpected keyed pagination label {label}")

    def commit_signatures(self, repository, pull_number, oids):
        self.signature_repository = repository
        self.signature_pull_number = pull_number
        return {oid: copy.deepcopy(self.signatures[oid]) for oid in oids}

    def post(self, path: str, payload: dict):
        self.posts.append((path, payload))
        return None


def authorize_fixture(
    api: FakeAuthorizationApi,
    approval: dict | None = None,
) -> controller.Authorization:
    selected = approval or event()
    api.comment = copy.deepcopy(selected["comment"])
    return controller.authorize(selected, policy(), api, environment())


class AuthorizationTests(unittest.TestCase):
    def test_repository_policy_configuration_is_valid(self) -> None:
        controller.load_config(str(POLICY_PATH))

    def test_shared_classifier_covers_candidate_validation_surfaces(self) -> None:
        repository_policy = controller.load_config(str(POLICY_PATH))
        kind = repository_policy["repository_kind"]
        for path in (
            ".github/workflows/ci.yml",
            ".github/workflows/pr-ci-command.yml",
            ".github/workflows/pr-ci-reconcile.yml",
            ".github/workflows/pr-ci.yml",
            ".github/scripts/protected_pr_ci.py",
            ".github/scripts/protected_checkout.py",
            ".github/scripts/check-pull-request-commits.sh",
            ".github/protected-pr-ci.json",
            ".cargo/config.toml",
            "nested/.cargo/config.toml",
            "Cargo.toml",
            "nested/Cargo.lock",
            "build.rs",
            "deny.toml",
            "xtask/src/main.rs",
            ".release-plz.toml",
            "RELEASING.md",
        ):
            with self.subTest(path=path):
                self.assertTrue(controller.is_sensitive_path(path, kind))

    def test_spec_and_rs_classifier_extensions_are_explicit(self) -> None:
        for path in (
            "proto/buf.yaml",
            "proto/buf.lock",
            "proto/buf.gen.yaml",
            "ＰＲＯＴＯ/ＢＵＦ.YAML",
        ):
            with self.subTest(spec_buf_policy=path):
                self.assertTrue(controller.is_sensitive_path(path, "spec"))
        for path in (
            "buf.yaml",
            "nested/proto/buf.yaml",
            "proto/buf.yaml.example",
            "proto/readme.md",
        ):
            with self.subTest(spec_buf_near_miss=path):
                self.assertFalse(controller.is_sensitive_path(path, "spec"))
        self.assertTrue(
            controller.is_sensitive_path(
                "conformance/rebuild-rs/vendor/acvp/vectors.json", "spec"
            )
        )
        self.assertTrue(
            controller.is_sensitive_path(
                "conformance/rebuild-rs/pinned-dir/src/lib.rs", "spec"
            )
        )
        self.assertTrue(
            controller.is_sensitive_path(
                "conformance/rebuild-rs/xtask/src/main.rs", "spec"
            )
        )
        self.assertTrue(
            controller.is_sensitive_path("crates/core/buf.yaml", "rs")
        )
        self.assertFalse(controller.is_sensitive_path("README.md", "traits"))

    def test_writer_permissions_are_accepted(self) -> None:
        for permission in ("write", "push", "maintain", "admin"):
            with self.subTest(permission=permission):
                api = FakeAuthorizationApi()
                api.permissions[MAINTAINER] = permission
                result = controller.authorize(event(), policy(), api, environment())
                self.assertEqual(result.head_sha, HEAD_SHA)

    def test_non_writer_commenter_is_rejected(self) -> None:
        api = FakeAuthorizationApi()
        api.permissions[MAINTAINER] = "read"
        with self.assertRaisesRegex(controller.PolicyError, "write authority"):
            controller.authorize(event(), policy(), api, environment())

    def test_non_writer_rerun_actor_is_rejected(self) -> None:
        api = FakeAuthorizationApi()
        api.permissions["rerunner"] = "read"
        env = environment()
        env["GITHUB_TRIGGERING_ACTOR"] = "rerunner"
        with self.assertRaisesRegex(controller.PolicyError, "triggering actor"):
            controller.authorize(event(), policy(), api, env)

    def test_command_is_exact_and_sha_bound(self) -> None:
        for body in (
            f" /ok to test {HEAD_SHA}",
            f"/ok to test {HEAD_SHA}\n",
            f"/ok to test {HEAD_SHA.upper()}",
            "/ok to test main",
        ):
            candidate_event = event(body)
            api = FakeAuthorizationApi()
            api.comment = copy.deepcopy(candidate_event["comment"])
            with self.subTest(body=body), self.assertRaises(controller.PolicyError):
                controller.authorize(candidate_event, policy(), api, environment())

        candidate_event = event(f"/ok to test {OLD_SHA}")
        api = FakeAuthorizationApi()
        api.comment = copy.deepcopy(candidate_event["comment"])
        with self.assertRaisesRegex(controller.PolicyError, "exact current pull request head"):
            controller.authorize(candidate_event, policy(), api, environment())

    def test_stale_policy_and_base_are_rejected(self) -> None:
        api = FakeAuthorizationApi()
        api.main_sha = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "policy commit"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.pull["base"]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "base is not current main"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.commits[0]["parents"] = [{"sha": OLD_SHA}]
        with self.assertRaisesRegex(controller.PolicyError, "linear descendant"):
            controller.authorize(event(), policy(), api, environment())

    def test_live_main_and_pull_state_are_rechecked_before_authorization(self) -> None:
        api = FakeAuthorizationApi()
        api.final_main_sha = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "main changed during"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.final_pull = copy.deepcopy(api.pull)
        api.final_pull["head"]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "head changed during"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.final_pull = copy.deepcopy(api.pull)
        api.final_pull["base"]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "base changed during"):
            controller.authorize(event(), policy(), api, environment())

    def test_commit_pagination_count_mismatch_is_rejected(self) -> None:
        api = FakeAuthorizationApi()
        api.pull["commits"] = 2
        with self.assertRaisesRegex(controller.PolicyError, "pagination"):
            controller.authorize(event(), policy(), api, environment())

    def test_renamed_candidate_ci_source_requires_candidate_validation(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change(
            "docs/retired-workflow.md",
            "renamed",
            previous_filename=".github/workflows/ci.yml",
        )
        approval = adoption_event()
        api.comment = copy.deepcopy(approval["comment"])
        result = controller.authorize(approval, policy(), api, environment())
        self.assertTrue(result.candidate_ci_required)

    def test_mutable_pull_file_view_is_never_authoritative(self) -> None:
        api = FakeAuthorizationApi()
        api.pull["changed_files"] = 999_999
        result = controller.authorize(event(), policy(), api, environment())
        self.assertEqual(result.head_sha, HEAD_SHA)
        self.assertFalse(any("/pulls/7/files" in path for path in api.get_paths))

    def test_workflow_change_from_fork_is_authorized(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change(".github/workflows/ci.yml")
        approval = adoption_event()
        api.comment = copy.deepcopy(approval["comment"])
        result = controller.authorize(approval, policy(), api, environment())
        self.assertEqual(
            result.head_repository, "contributor/yaml-sigil-example"
        )
        self.assertTrue(result.candidate_ci_required)

    def test_normalized_workflow_names_do_not_change_commit_policy(self) -> None:
        for path in (
            ".GitHub/Workflows/ci.yml",
            ".ＧitHub/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                api = FakeAuthorizationApi()
                api.set_change(path)
                approval = adoption_event()
                api.comment = copy.deepcopy(approval["comment"])
                result = controller.authorize(
                    approval, policy(), api, environment()
                )
                self.assertTrue(result.candidate_ci_required)

    def test_classifier_directory_roots_descendants_and_near_misses(self) -> None:
        for path in (
            ".cargo",
            ".CARGO/config.toml",
            ".ＣＡＲＧＯ",
            "nested/.cargo",
            "nested/.ＣＡＲＧＯ/config.toml",
        ):
            with self.subTest(path=path):
                self.assertTrue(controller.is_sensitive_path(path, "traits"))

        for path in (
            ".carg",
            ".cargo-cache/config.toml",
            ".cargo.toml",
            "nested/.cargo-cache/config.toml",
            "nested/source-spec/README.md",
            "source-specification/README.md",
        ):
            with self.subTest(near_miss=path):
                self.assertFalse(controller.is_sensitive_path(path, "traits"))

    def test_unusual_directory_entries_use_the_same_commit_policy(self) -> None:
        for path, leaf in (
            (".cargo", ("blob", "120000", HEAD_BLOB_SHA)),
            (".ＣＡＲＧＯ", ("blob", "120000", HEAD_BLOB_SHA)),
            ("nested/.cargo", ("blob", "120000", HEAD_BLOB_SHA)),
            ("benches", ("blob", "120000", HEAD_BLOB_SHA)),
            ("nested/ＢＥＮＣＨＥＳ", ("blob", "120000", HEAD_BLOB_SHA)),
            ("examples", ("blob", "120000", HEAD_BLOB_SHA)),
            ("nested/ＥＸＡＭＰＬＥＳ", ("blob", "120000", HEAD_BLOB_SHA)),
            ("source-spec/README.md", ("blob", "100644", HEAD_BLOB_SHA)),
        ):
            with self.subTest(path=path, entry_type=leaf[0]):
                api = FakeAuthorizationApi()
                api.set_tree_files({}, {path: leaf})
                approval = (
                    adoption_event()
                    if controller.is_sensitive_path(path, "traits")
                    else event()
                )
                api.comment = copy.deepcopy(approval["comment"])
                result = controller.authorize(approval, policy(), api, environment())
                self.assertEqual(result.head_sha, HEAD_SHA)

    def test_changed_gitlink_requires_adoption_and_approved_forward_lineage(self) -> None:
        api = FakeAuthorizationApi()
        api.set_tree_files(
            {"source-spec": ("commit", "160000", BASE_BLOB_SHA)},
            {"source-spec": ("commit", "160000", HEAD_BLOB_SHA)},
        )
        api.allow_ancestry(BASE_BLOB_SHA, HEAD_BLOB_SHA)
        api.allow_ancestry(HEAD_BLOB_SHA, SPEC_MAIN_SHA)

        with self.assertRaisesRegex(controller.PolicyError, "sensitive changes require"):
            controller.authorize(event(), policy(), api, environment())

        result = authorize_fixture(api, adoption_event())
        self.assertTrue(result.sensitive)
        self.assertIn(
            "/repos/NVIDIA/yaml-sigil-spec/compare/"
            f"{HEAD_BLOB_SHA}...{SPEC_MAIN_SHA}",
            api.get_paths,
        )

    def test_unchanged_gitlink_uses_the_protected_base_pin(self) -> None:
        api = FakeAuthorizationApi()
        source_spec = ("commit", "160000", BASE_BLOB_SHA)
        api.set_tree_files(
            {
                "source-spec": source_spec,
                "README.md": ("blob", "100644", BASE_BLOB_SHA),
            },
            {
                "source-spec": source_spec,
                "README.md": ("blob", "100644", HEAD_BLOB_SHA),
            },
        )

        result = controller.authorize(event(), policy(), api, environment())
        self.assertFalse(result.sensitive)
        self.assertFalse(any("/compare/" in path for path in api.get_paths))

    def test_gitlink_lineage_rejects_downgrades_and_fork_only_commits(self) -> None:
        for failure in ("downgrade", "fork-only"):
            with self.subTest(failure=failure):
                api = FakeAuthorizationApi()
                api.set_tree_files(
                    {"source-spec": ("commit", "160000", BASE_BLOB_SHA)},
                    {"source-spec": ("commit", "160000", HEAD_BLOB_SHA)},
                )
                api.allow_ancestry(BASE_BLOB_SHA, HEAD_BLOB_SHA)
                api.allow_ancestry(HEAD_BLOB_SHA, SPEC_MAIN_SHA)
                if failure == "downgrade":
                    api.comparisons[(BASE_BLOB_SHA, HEAD_BLOB_SHA)][
                        "merge_base_commit"
                    ]["sha"] = HEAD_BLOB_SHA
                else:
                    api.comparisons[(HEAD_BLOB_SHA, SPEC_MAIN_SHA)][
                        "merge_base_commit"
                    ]["sha"] = OLD_SHA
                with self.assertRaisesRegex(
                    controller.PolicyError, "approved forward ancestry"
                ):
                    authorize_fixture(api, adoption_event())

    def test_gitlink_lineage_rejects_untrusted_or_malformed_entries(self) -> None:
        api = FakeAuthorizationApi()
        api.set_tree_files(
            {"other-spec": ("commit", "160000", BASE_BLOB_SHA)},
            {"other-spec": ("commit", "160000", HEAD_BLOB_SHA)},
        )
        with self.assertRaisesRegex(controller.PolicyError, "trusted lineage policy"):
            authorize_fixture(api, adoption_event())

        api = FakeAuthorizationApi()
        api.set_tree_files(
            {"source-spec": ("commit", "160000", BASE_BLOB_SHA)},
            {"source-spec": ("blob", "100644", HEAD_BLOB_SHA)},
        )
        with self.assertRaisesRegex(controller.PolicyError, "exact commit gitlink"):
            authorize_fixture(api, adoption_event())

    def test_candidate_ci_directory_entries_match_any_leaf_type(self) -> None:
        for path, leaf in (
            (".cargo", ("blob", "120000", HEAD_BLOB_SHA)),
            (".ＣＡＲＧＯ", ("blob", "120000", HEAD_BLOB_SHA)),
            ("nested/.cargo", ("blob", "120000", HEAD_BLOB_SHA)),
            (".github/workflows/ci.yml", ("blob", "100644", HEAD_BLOB_SHA)),
        ):
            with self.subTest(path=path, entry_type=leaf[0]):
                api = FakeAuthorizationApi()
                api.set_tree_files({}, {path: leaf})
                approval = adoption_event()
                api.comment = copy.deepcopy(approval["comment"])
                result = controller.authorize(
                    approval, policy(), api, environment()
                )
                self.assertTrue(result.candidate_ci_required)

    def test_executable_targets_use_the_same_commit_policy(self) -> None:
        for path in (
            "benches/throughput.rs",
            "nested/benches/throughput.rs",
            "examples/verify.rs",
            "nested/examples/verify.rs",
        ):
            with self.subTest(path=path):
                api = FakeAuthorizationApi()
                api.set_change(path)
                result = controller.authorize(event(), policy(), api, environment())
                self.assertEqual(result.head_sha, HEAD_SHA)
                self.assertFalse(result.candidate_ci_required)

    def test_build_scripts_use_the_same_commit_policy(self) -> None:
        for path in ("build.rs", "nested/BUILD.RS"):
            with self.subTest(path=path):
                api = FakeAuthorizationApi()
                api.set_change(path)
                approval = adoption_event()
                api.comment = copy.deepcopy(approval["comment"])
                result = controller.authorize(approval, policy(), api, environment())
                self.assertEqual(result.head_sha, HEAD_SHA)
                self.assertTrue(result.candidate_ci_required)

    def test_sensitive_adoption_preserves_author_and_adopter_dco(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.details[HEAD_SHA] = git_commit(
            author_login="contributor",
            author_id=42,
            author_name="Contributor",
            author_email="contributor@example.invalid",
            committer_name="Maintainer",
            committer_email="maintainer@example.invalid",
        )
        approval = adoption_event()
        api.comment = copy.deepcopy(approval["comment"])
        result = controller.authorize(approval, policy(), api, environment())
        self.assertEqual(
            result.head_repository, "contributor/yaml-sigil-example"
        )

        api.details[HEAD_SHA]["commit"]["message"] = (
            "ci: update policy\n\n"
            "Signed-off-by: Maintainer <maintainer@example.invalid>\n"
        )
        with self.assertRaisesRegex(controller.PolicyError, "original author's DCO"):
            controller.authorize(approval, policy(), api, environment())

        api.details[HEAD_SHA]["commit"]["message"] = (
            "ci: update policy\n\n"
            "Signed-off-by: Contributor <contributor@example.invalid>\n"
        )
        with self.assertRaisesRegex(controller.PolicyError, "adopting committer's DCO"):
            controller.authorize(approval, policy(), api, environment())

    def test_every_human_commit_requires_valid_github_verification(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("AGENTS.md")
        api.signatures[HEAD_SHA] = git_signature(valid=False)
        with self.assertRaisesRegex(controller.PolicyError, "not GitHub Verified"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.set_change("AGENTS.md")
        api.details[HEAD_SHA] = git_commit(committer_login="outsider")
        with self.assertRaisesRegex(controller.PolicyError, "verified signer"):
            controller.authorize(event(), policy(), api, environment())

    def test_full_commit_response_must_match_requested_sha(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.details[HEAD_SHA]["sha"] = OLD_SHA
        approval = adoption_event()
        api.comment = copy.deepcopy(approval["comment"])
        with self.assertRaisesRegex(controller.PolicyError, "requested SHA"):
            controller.authorize(approval, policy(), api, environment())

    def test_exact_release_app_author_and_committer_are_accepted(self) -> None:
        api = self.release_app_api()
        result = controller.authorize(event(), policy(), api, environment())
        self.assertEqual(result.head_sha, HEAD_SHA)

        api.set_change("Cargo.toml", "removed")
        with self.assertRaisesRegex(controller.PolicyError, "only modify existing"):
            controller.authorize(event(), policy(), api, environment())

    def release_app_api(self) -> FakeAuthorizationApi:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.pull["user"] = {"login": BOT, "id": BOT_ID, "type": "Bot"}
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.pull["head"]["ref"] = "release-plz-next"
        api.details[HEAD_SHA] = git_commit(
            author_login=BOT,
            author_id=BOT_ID,
            author_type="Bot",
            committer_login=WEB_FLOW,
            committer_id=WEB_FLOW_ID,
            author_name=BOT,
            author_email=BOT_EMAIL,
            committer_name=GITHUB_COMMITTER_NAME,
            committer_email=GITHUB_COMMITTER_EMAIL,
            message=(
                "chore(release): prepare candidate\n\n"
                "Signed-off-by: nvidia-yamlsigil-release-pr[bot] "
                f"<{BOT_EMAIL}>\n"
            ),
        )
        api.signatures[HEAD_SHA] = git_signature(
            signer_login=WEB_FLOW,
            signer_id=WEB_FLOW_ID,
            email=GITHUB_COMMITTER_EMAIL,
            github_signed=True,
        )
        return api

    def test_release_app_rejects_wrong_bot_id_and_raw_author(self) -> None:
        api = self.release_app_api()
        api.pull["user"]["id"] += 1
        with self.assertRaisesRegex(controller.PolicyError, "exact release App identity"):
            controller.authorize(event(), policy(), api, environment())

        api = self.release_app_api()
        api.pull["user"]["login"] = "release-app-lookalike"
        with self.assertRaisesRegex(controller.PolicyError, "exact release App identity"):
            controller.authorize(event(), policy(), api, environment())

        api = self.release_app_api()
        api.details[HEAD_SHA]["author"]["id"] += 1
        with self.assertRaisesRegex(controller.PolicyError, "author is unexpected"):
            controller.authorize(event(), policy(), api, environment())

        for field in ("name", "email"):
            with self.subTest(field=field):
                api = self.release_app_api()
                api.details[HEAD_SHA]["commit"]["author"][field] = "lookalike"
                with self.assertRaisesRegex(controller.PolicyError, f"author {field}"):
                    controller.authorize(event(), policy(), api, environment())

    def test_release_app_identity_cannot_fall_back_when_disabled(self) -> None:
        api = self.release_app_api()
        disabled = policy()
        disabled["release_app"]["enabled"] = False

        with self.assertRaisesRegex(controller.PolicyError, "exception is disabled"):
            controller.authorize(event(), disabled, api, environment())

    def test_release_app_rejects_bot_raw_committer(self) -> None:
        api = self.release_app_api()
        api.details[HEAD_SHA]["commit"]["committer"] = {
            "name": BOT,
            "email": BOT_EMAIL,
        }
        with self.assertRaisesRegex(controller.PolicyError, "raw commit committer name"):
            controller.authorize(event(), policy(), api, environment())

    def test_release_app_rejects_human_rest_committer(self) -> None:
        api = self.release_app_api()
        api.details[HEAD_SHA]["committer"]["login"] = MAINTAINER
        with self.assertRaisesRegex(controller.PolicyError, "committer is unexpected"):
            controller.authorize(event(), policy(), api, environment())

    def test_release_app_rejects_wrong_web_flow_user_id(self) -> None:
        api = self.release_app_api()
        api.details[HEAD_SHA]["committer"]["id"] += 1
        with self.assertRaisesRegex(controller.PolicyError, "committer is unexpected"):
            controller.authorize(event(), policy(), api, environment())

    def test_release_app_rejects_wrong_web_flow_and_raw_github_identity(self) -> None:
        api = self.release_app_api()
        api.details[HEAD_SHA]["committer"]["login"] = "web-flow-lookalike"
        with self.assertRaisesRegex(controller.PolicyError, "committer is unexpected"):
            controller.authorize(event(), policy(), api, environment())

        for field in ("name", "email"):
            with self.subTest(field=field):
                api = self.release_app_api()
                api.details[HEAD_SHA]["commit"]["committer"][field] = "lookalike"
                with self.assertRaisesRegex(controller.PolicyError, f"committer {field}"):
                    controller.authorize(event(), policy(), api, environment())

    def test_release_app_rejects_invalid_signature(self) -> None:
        api = self.release_app_api()
        api.signatures[HEAD_SHA] = git_signature(
            signer_login=WEB_FLOW,
            signer_id=WEB_FLOW_ID,
            email=GITHUB_COMMITTER_EMAIL,
            valid=False,
            github_signed=True,
        )
        with self.assertRaisesRegex(controller.PolicyError, "not GitHub Verified"):
            controller.authorize(event(), policy(), api, environment())

    def test_release_app_requires_one_parent_and_author_dco(self) -> None:
        api = self.release_app_api()
        api.details[HEAD_SHA]["parents"].append({"sha": OLD_SHA})
        with self.assertRaisesRegex(controller.PolicyError, "exactly one parent"):
            controller.authorize(event(), policy(), api, environment())

        api = self.release_app_api()
        api.details[HEAD_SHA]["commit"]["message"] = (
            "chore(release): prepare candidate\n"
        )
        with self.assertRaisesRegex(controller.PolicyError, "author's DCO sign-off"):
            controller.authorize(event(), policy(), api, environment())

    def test_release_app_identity_parent_and_allowlist_are_exact(self) -> None:
        base_api = FakeAuthorizationApi()
        base_api.set_change("Cargo.toml")
        base_api.pull["user"] = {"login": BOT, "id": BOT_ID, "type": "Bot"}
        base_api.pull["head"]["repo"]["full_name"] = REPOSITORY
        base_api.pull["head"]["ref"] = "release-plz-next"
        base_api.details[HEAD_SHA] = git_commit(
            parent=OLD_SHA,
            author_login=BOT,
            author_id=BOT_ID,
            author_type="Bot",
            committer_login=WEB_FLOW,
            committer_id=WEB_FLOW_ID,
            author_name=BOT,
            author_email=BOT_EMAIL,
            committer_name=GITHUB_COMMITTER_NAME,
            committer_email=GITHUB_COMMITTER_EMAIL,
            message=(
                "chore(release): prepare candidate\n\n"
                "Signed-off-by: nvidia-yamlsigil-release-pr[bot] "
                f"<{BOT_EMAIL}>\n"
            ),
        )
        base_api.signatures[HEAD_SHA] = git_signature(
            signer_login=WEB_FLOW,
            signer_id=WEB_FLOW_ID,
            email=GITHUB_COMMITTER_EMAIL,
            github_signed=True,
        )
        with self.assertRaisesRegex(controller.PolicyError, "current main"):
            controller.authorize(event(), policy(), base_api, environment())

        api = copy.deepcopy(base_api)
        api.details[HEAD_SHA]["parents"] = [{"sha": MAIN_SHA}]
        api.set_change(".github/workflows/ci.yml")
        with self.assertRaisesRegex(controller.PolicyError, "allowlist"):
            controller.authorize(event(), policy(), api, environment())

    def test_comment_receiver_ignores_near_misses_and_returns_sanitized_values(self) -> None:
        api = FakeAuthorizationApi()
        self.assertIsNone(
            controller.authorize_comment(
                event("looks useful"), policy(), api, environment()
            )
        )
        self.assertEqual(api.posts, [])

        authorization = controller.authorize_comment(
            event(), policy(), api, environment()
        )
        self.assertIsNotNone(authorization)
        assert authorization is not None
        self.assertEqual(
            authorization.github_outputs(),
            {
                "repository": REPOSITORY,
                "pull_number": str(PULL_NUMBER),
                "head_sha": HEAD_SHA,
                "base_sha": MAIN_SHA,
                "head_repository": "contributor/yaml-sigil-example",
                "policy_sha": MAIN_SHA,
                "comment_id": str(COMMENT_ID),
                "binding_digest": authorization.binding_digest,
                "command_mode": "test",
                "sensitive": "false",
                "candidate_ci_required": "false",
            },
        )
        self.assertEqual(api.posts, [])

    def test_comment_receiver_rejects_cache_writable_event_classes(self) -> None:
        for event_name in ("workflow_dispatch", "repository_dispatch"):
            env = environment()
            env["GITHUB_EVENT_NAME"] = event_name
            with self.subTest(event_name=event_name), self.assertRaisesRegex(
                controller.PolicyError, "retain the issue_comment event"
            ):
                controller.authorize_comment(
                    event(), policy(), FakeAuthorizationApi(), env
                )

    def test_reusable_call_reloads_the_exact_comment_and_job_binding(self) -> None:
        api = FakeAuthorizationApi()
        api.jobs[0]["name"] = (
            f"{controller.CALLER_JOB_NAME} / {call_binding().encode_job_name()}"
        )
        result = controller.authorize_call(
            event(),
            policy(),
            api,
            environment(),
            repository=REPOSITORY,
            pull_number=PULL_NUMBER,
            head_sha=HEAD_SHA,
            base_sha=MAIN_SHA,
            policy_sha=MAIN_SHA,
            comment_id=COMMENT_ID,
            run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT,
        )
        self.assertEqual(result.head_sha, HEAD_SHA)

        with self.assertRaisesRegex(controller.PolicyError, "authorized head SHA"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=OLD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

    def test_reusable_call_rejects_changed_comment_issue_or_ref(self) -> None:
        api = FakeAuthorizationApi()
        api.comment["body"] = f"/ok to test {OLD_SHA}"
        with self.assertRaisesRegex(controller.PolicyError, "comment or identity changed"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

        api = FakeAuthorizationApi()
        api.comment_issue_number = 8
        with self.assertRaisesRegex(controller.PolicyError, "comment moved"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

        api = FakeAuthorizationApi()
        env = environment()
        env["GITHUB_REF"] = "refs/heads/release-plz-next"
        with self.assertRaisesRegex(controller.PolicyError, "exact main"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                env,
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

    def test_reusable_call_requires_a_current_rerun_writer(self) -> None:
        api = FakeAuthorizationApi()
        api.permissions["outsider"] = "read"
        env = environment()
        env["GITHUB_TRIGGERING_ACTOR"] = "outsider"
        with self.assertRaisesRegex(controller.PolicyError, "triggering actor"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                env,
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

    def test_reusable_call_binding_is_unique_complete_and_attempt_aware(self) -> None:
        api = FakeAuthorizationApi()
        api.jobs = []
        with self.assertRaisesRegex(controller.PolicyError, "binding job is missing"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

        api = FakeAuthorizationApi()
        api.jobs.append(workflow_job())
        with self.assertRaisesRegex(controller.PolicyError, "multiple reusable-call"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

        api = FakeAuthorizationApi()
        api.jobs[0]["name"] = f"{controller.JOB_BINDING_MARKER}truncated"
        with self.assertRaisesRegex(controller.PolicyError, "malformed or truncated"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )

        api = FakeAuthorizationApi()
        api.jobs[0]["run_attempt"] = 2
        with self.assertRaisesRegex(controller.PolicyError, "binding job is missing"):
            controller.authorize_call(
                event(),
                policy(),
                api,
                environment(),
                repository=REPOSITORY,
                pull_number=PULL_NUMBER,
                head_sha=HEAD_SHA,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
                comment_id=COMMENT_ID,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
            )


    def test_sensitive_change_rejects_the_ordinary_command(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        with self.assertRaisesRegex(controller.PolicyError, "test-and-adopt"):
            controller.authorize(event(), policy(), api, environment())

    def test_sensitive_fork_requires_maintainer_edits(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change(".github/workflows/ci.yml")
        api.pull["maintainer_can_modify"] = False
        with self.assertRaisesRegex(controller.PolicyError, "maintainer edits"):
            authorize_fixture(api, adoption_event())

    def test_edit_away_and_restore_invalidates_the_comment_timestamp(self) -> None:
        api = FakeAuthorizationApi()
        api.comment["updated_at"] = "2026-08-28T12:00:01Z"
        with self.assertRaisesRegex(controller.PolicyError, "comment or identity changed"):
            controller.authorize(event(), policy(), api, environment())

    def test_direct_external_contributor_identity_is_valid_without_membership(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("src/lib.rs")
        api.details[HEAD_SHA] = git_commit(
            author_login="external-contributor",
            committer_login="external-contributor",
            author_id=42,
            committer_id=42,
            author_name="External Contributor",
            committer_name="External Contributor",
            author_email="external@example.invalid",
            committer_email="external@example.invalid",
        )
        api.signatures[HEAD_SHA] = git_signature(
            signer_login="external-contributor",
            signer_id=42,
            email="external@example.invalid",
            kind="SshSignature",
        )
        result = authorize_fixture(api)
        self.assertEqual(result.head_sha, HEAD_SHA)
        self.assertNotIn("external-contributor", api.permissions)

    def test_direct_identity_id_login_and_type_disagreements_fail_closed(self) -> None:
        mutations = (
            ("id", 2),
            ("login", "lookalike"),
            ("type", "Bot"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                api = FakeAuthorizationApi()
                api.set_change("src/lib.rs")
                api.details[HEAD_SHA]["author"][field] = value
                with self.assertRaisesRegex(controller.PolicyError, "verified signer"):
                    authorize_fixture(api)

    def test_null_signature_signer_and_forged_dco_fail_closed(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("src/lib.rs")
        api.signatures[HEAD_SHA]["signature"]["signer"] = None
        with self.assertRaisesRegex(controller.PolicyError, "signer must be an object"):
            authorize_fixture(api)

        api = FakeAuthorizationApi()
        api.set_change("src/lib.rs")
        api.details[HEAD_SHA]["commit"]["message"] = (
            "ci: forged trailer\n\n"
            "Signed-off-by: Lookalike <maintainer@example.invalid>\n"
        )
        with self.assertRaisesRegex(controller.PolicyError, "author's DCO"):
            authorize_fixture(api)

    def test_web_flow_does_not_authorize_an_arbitrary_human_commit(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("src/lib.rs")
        api.details[HEAD_SHA] = git_commit(
            author_login=WEB_FLOW,
            committer_login=WEB_FLOW,
            author_id=WEB_FLOW_ID,
            committer_id=WEB_FLOW_ID,
            author_name=GITHUB_COMMITTER_NAME,
            committer_name=GITHUB_COMMITTER_NAME,
            author_email=GITHUB_COMMITTER_EMAIL,
            committer_email=GITHUB_COMMITTER_EMAIL,
        )
        api.signatures[HEAD_SHA] = git_signature(
            signer_login=WEB_FLOW,
            signer_id=WEB_FLOW_ID,
            email=GITHUB_COMMITTER_EMAIL,
            github_signed=True,
        )
        with self.assertRaisesRegex(controller.PolicyError, "unsupported GitHub web-flow"):
            authorize_fixture(api)

    def test_release_app_requires_the_exact_gpg_web_flow_shape(self) -> None:
        api = self.release_app_api()
        api.signatures[HEAD_SHA]["signature"]["__typename"] = "SshSignature"
        with self.assertRaisesRegex(controller.PolicyError, "exact GitHub web-flow"):
            controller.authorize(event(), policy(), api, environment())

    def test_adopting_signer_must_remain_a_writer(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.details[HEAD_SHA] = git_commit(
            author_login="external-contributor",
            author_id=42,
            author_name="External Contributor",
            author_email="external@example.invalid",
            committer_login="adopter",
            committer_id=2,
            committer_name="Adopter",
            committer_email="adopter@example.invalid",
        )
        api.signatures[HEAD_SHA] = git_signature(
            signer_login="adopter",
            signer_id=2,
            email="adopter@example.invalid",
        )
        api.permissions["adopter"] = "read"
        with self.assertRaisesRegex(controller.PolicyError, "adopting signer"):
            authorize_fixture(api, adoption_event())


class ImmutableTreeTests(unittest.TestCase):
    @staticmethod
    def snapshot(leaves: dict[str, tuple[str, str, str]]) -> controller.GitTree:
        return controller.GitTree(paths=frozenset(leaves), leaves=leaves)

    def test_additions_removals_modifications_and_renames_are_derived(self) -> None:
        unchanged = ("blob", "100644", "3" * 40)
        renamed = ("blob", "100644", "4" * 40)
        base = self.snapshot(
            {
                "modified.txt": ("blob", "100644", "5" * 40),
                "old-name.txt": renamed,
                "removed.txt": ("blob", "100644", "6" * 40),
                "unchanged.txt": unchanged,
            }
        )
        head = self.snapshot(
            {
                "added.txt": ("blob", "100644", "7" * 40),
                "modified.txt": ("blob", "100755", "5" * 40),
                "new-name.txt": renamed,
                "unchanged.txt": unchanged,
            }
        )

        paths, statuses = controller.changed_tree_paths(base, head)

        self.assertEqual(
            list(zip(paths, statuses, strict=True)),
            [
                ("added.txt", "added"),
                ("modified.txt", "mode-or-type-changed"),
                ("new-name.txt", "added"),
                ("old-name.txt", "removed"),
                ("removed.txt", "removed"),
            ],
        )

    def test_gitlink_replacement_retains_root_identity(self) -> None:
        base = self.snapshot(
            {"source-spec": ("commit", "160000", BASE_BLOB_SHA)}
        )
        head = self.snapshot(
            {"source-spec/README.md": ("blob", "100644", HEAD_BLOB_SHA)}
        )

        paths, statuses = controller.changed_tree_paths(base, head)

        self.assertEqual(
            list(zip(paths, statuses, strict=True)),
            [
                ("source-spec", "removed"),
                ("source-spec/README.md", "added"),
            ],
        )

    def test_commit_and_tree_responses_are_bound_to_exact_requested_objects(self) -> None:
        for sha, label in ((MAIN_SHA, "base"), (HEAD_SHA, "head")):
            with self.subTest(object=label):
                api = FakeAuthorizationApi()
                api.git_commits[sha]["sha"] = OLD_SHA
                with self.assertRaisesRegex(controller.PolicyError, "requested SHA"):
                    controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "does not match its commit"):
            controller.authorize(event(), policy(), api, environment())

    def test_external_head_git_objects_use_the_installed_base_repository(self) -> None:
        api = FakeAuthorizationApi()
        result = controller.authorize(event(), policy(), api, environment())
        self.assertNotEqual(result.head_repository, REPOSITORY)
        git_object_paths = [path for path in api.get_paths if "/git/" in path]
        self.assertIn(
            controller.repo_api_path(REPOSITORY, f"/git/commits/{HEAD_SHA}"),
            git_object_paths,
        )
        self.assertTrue(
            all(path.startswith(f"/repos/{REPOSITORY}/git/") for path in git_object_paths)
        )

    def test_truncated_and_over_limit_trees_fail_closed(self) -> None:
        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA]["truncated"] = True
        with self.assertRaisesRegex(controller.PolicyError, "truncated"):
            controller.authorize(event(), policy(), api, environment())

        with mock.patch.object(controller, "MAX_TREE_ENTRIES", 0):
            with self.assertRaisesRegex(controller.PolicyError, "tree exceeds"):
                controller.authorize(
                    event(), policy(), FakeAuthorizationApi(), environment()
                )

        with mock.patch.object(controller, "MAX_CHANGED_PATHS", 0):
            with self.assertRaisesRegex(controller.PolicyError, "tree diff exceeds"):
                controller.authorize(
                    event(), policy(), FakeAuthorizationApi(), environment()
                )

    def test_malformed_recursive_trees_fail_closed(self) -> None:
        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA]["tree"] = {}
        with self.assertRaisesRegex(controller.PolicyError, "must be an array"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA]["tree"].append(
            copy.deepcopy(api.trees[HEAD_TREE_SHA]["tree"][0])
        )
        with self.assertRaisesRegex(controller.PolicyError, "duplicate paths"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA]["tree"][0]["mode"] = "100600"
        with self.assertRaisesRegex(controller.PolicyError, "invalid mode"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.trees[HEAD_TREE_SHA] = {
            "sha": HEAD_TREE_SHA,
            "truncated": False,
            "tree": [
                {
                    "path": "missing-parent/file.txt",
                    "mode": "100644",
                    "type": "blob",
                    "sha": HEAD_BLOB_SHA,
                }
            ],
        }
        with self.assertRaisesRegex(controller.PolicyError, "omits a parent"):
            controller.authorize(event(), policy(), api, environment())

    def test_candidate_collision_with_unchanged_base_path_is_rejected(self) -> None:
        api = FakeAuthorizationApi()
        unchanged = ("blob", "100644", BASE_BLOB_SHA)
        api.set_tree_files(
            {"Cargo.toml": unchanged},
            {
                "Cargo.toml": unchanged,
                "cargo.TOML": ("blob", "100644", HEAD_BLOB_SHA),
            },
        )
        with self.assertRaisesRegex(controller.PolicyError, "casefold path collisions"):
            controller.authorize(event(), policy(), api, environment())

    def test_candidate_unicode_and_directory_collisions_are_rejected(self) -> None:
        for head in (
            {
                "docs/caf\N{LATIN SMALL LETTER E WITH ACUTE}.md": (
                    "blob",
                    "100644",
                    BASE_BLOB_SHA,
                ),
                "docs/cafe\N{COMBINING ACUTE ACCENT}.md": (
                    "blob",
                    "100644",
                    HEAD_BLOB_SHA,
                ),
            },
            {
                "Src/a.txt": ("blob", "100644", BASE_BLOB_SHA),
                "src/b.txt": ("blob", "100644", HEAD_BLOB_SHA),
            },
        ):
            with self.subTest(paths=sorted(head)):
                api = FakeAuthorizationApi()
                api.set_tree_files({}, head)
                with self.assertRaisesRegex(
                    controller.PolicyError, "casefold path collisions"
                ):
                    controller.authorize(event(), policy(), api, environment())


class ProtectedCheckoutTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.temporary_directory = pathlib.Path(temporary_directory.name)
        self.repository = self.temporary_directory / "repository"
        self.repository.mkdir()
        discovered_git = shutil.which("git")
        assert discovered_git is not None
        self.git = os.path.realpath(discovered_git)
        self.run_git("init", "--quiet", "--initial-branch=main")
        self.run_git("config", "user.name", "Verifier Test")
        self.run_git("config", "user.email", "verifier@example.invalid")
        workflow = self.repository / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: candidate\n", encoding="utf-8")
        self.run_git("add", ".github/workflows/ci.yml")
        self.run_git("commit", "--quiet", "-m", "test: candidate")
        self.head_sha = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.blob_sha = self.run_git(
            "hash-object", "--no-filters", "--", ".github/workflows/ci.yml"
        ).stdout.strip()
        self.base_tree = controller.GitTree(paths=frozenset(), leaves={})
        self.head_tree = controller.GitTree(
            paths=frozenset(
                {
                    ".github",
                    ".github/workflows",
                    ".github/workflows/ci.yml",
                }
            ),
            leaves={
                ".github/workflows/ci.yml": (
                    "blob",
                    "100644",
                    self.blob_sha,
                )
            },
        )
        self.config = self.temporary_directory / "protected-pr-ci.json"
        self.config.write_text(
            json.dumps(policy(), sort_keys=True), encoding="utf-8"
        )

    def run_git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.git, *arguments],
            cwd=self.repository,
            text=True,
            capture_output=True,
            check=True,
        )

    def verify(self) -> None:
        with mock.patch.object(
            verifier.policy,
            "git_tree_for_commit",
            side_effect=[self.base_tree, self.head_tree],
        ):
            verifier.verify(
                self.repository,
                self.git,
                REPOSITORY,
                MAIN_SHA,
                self.head_sha,
                os.fspath(self.config),
                mock.Mock(),
            )

    def test_exact_sensitive_blob_and_head_are_accepted(self) -> None:
        self.verify()

    def test_exact_sensitive_gitlink_is_verified_from_the_index(self) -> None:
        source_sha = "6" * 40
        self.run_git(
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            source_sha,
            "source-spec",
        )
        self.run_git("commit", "--quiet", "-m", "test: add exact gitlink")
        self.head_sha = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.head_tree = controller.GitTree(
            paths=self.head_tree.paths | {"source-spec"},
            leaves={
                **self.head_tree.leaves,
                "source-spec": ("commit", "160000", source_sha),
            },
        )
        self.verify()

        self.head_tree = controller.GitTree(
            paths=self.head_tree.paths,
            leaves={
                **self.head_tree.leaves,
                "source-spec": ("commit", "160000", "7" * 40),
            },
        )
        with self.assertRaisesRegex(
            controller.PolicyError, "differs from its authorized Git entry"
        ):
            self.verify()

    def test_policy_staging_records_exact_files_digests_and_tools(self) -> None:
        destination = self.temporary_directory / "staged-policy"
        github_output = self.temporary_directory / "github-output"
        verifier.stage_policy(
            MODULE_PATH.parents[2], destination, os.fspath(github_output)
        )
        outputs = dict(
            line.split("=", 1)
            for line in github_output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(
            set(outputs),
            {
                "verifier",
                "verifier_sha256",
                "controller",
                "controller_sha256",
                "config",
                "config_sha256",
                "python",
                "git",
                "path",
            },
        )
        for label in ("verifier", "controller", "config"):
            value = pathlib.Path(outputs[label]).read_bytes()
            self.assertEqual(outputs[f"{label}_sha256"], verifier.sha256_bytes(value))
        self.assertTrue(os.path.isabs(outputs["python"]))
        self.assertTrue(os.path.isabs(outputs["git"]))

    def test_modified_or_untracked_sensitive_file_fails_closed(self) -> None:
        workflow = self.repository / ".github" / "workflows" / "ci.yml"
        workflow.write_text("name: tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(controller.PolicyError, "authorized Git blob"):
            self.verify()

        self.run_git("checkout", "--quiet", "--", ".github/workflows/ci.yml")
        (self.repository / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        with self.assertRaisesRegex(controller.PolicyError, "untracked sensitive"):
            self.verify()

    def test_sensitive_symlink_and_reparse_point_fail_closed(self) -> None:
        workflow = self.repository / ".github" / "workflows" / "ci.yml"
        if os.name != "nt":
            workflow.unlink()
            workflow.symlink_to(self.repository / ".git" / "HEAD")
            with self.assertRaisesRegex(
                controller.PolicyError, "link, reparse point"
            ):
                self.verify()

            workflow.unlink()
            workflow.write_text("name: candidate\n", encoding="utf-8")
        with (
            mock.patch.object(
                verifier,
                "has_reparse_point",
                side_effect=lambda metadata: stat.S_ISREG(metadata.st_mode),
            ),
            self.assertRaisesRegex(controller.PolicyError, "link, reparse point"),
        ):
            self.verify()

    @unittest.skipUnless(os.name == "nt", "Windows reparse-point regression")
    def test_windows_intermediate_junction_fails_closed(self) -> None:
        workflows = self.repository / ".github" / "workflows"
        target = self.repository / "workflows-target"
        workflows.replace(target)
        completed = subprocess.run(
            [
                os.environ.get("COMSPEC", "cmd.exe"),
                "/d",
                "/c",
                "mklink",
                "/J",
                os.fspath(workflows),
                os.fspath(target),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"cannot create test junction: {completed.stdout}{completed.stderr}",
        )
        self.addCleanup(os.rmdir, workflows)

        with self.assertRaisesRegex(
            controller.PolicyError, "missing or untracked sensitive paths"
        ):
            self.verify()

    def test_aliases_and_short_name_shapes_fail_closed(self) -> None:
        if os.name != "nt":
            alias_root = self.repository / ".GITHUB"
            if not alias_root.exists():
                alias = alias_root / "workflows"
                alias.mkdir(parents=True)
                (alias / "extra.yml").write_text(
                    "name: alias\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    controller.PolicyError, "casefold aliases"
                ):
                    self.verify()

                shutil.rmtree(alias_root)
            else:
                self.assertTrue(
                    os.path.samefile(alias_root, self.repository / ".github")
                )
        (self.repository / "CARGO~1.TOM").write_text("alias\n", encoding="utf-8")
        with self.assertRaisesRegex(controller.PolicyError, "short-name-shaped"):
            self.verify()

    def test_enumeration_entry_metadata_and_time_limits_fail_closed(self) -> None:
        with (
            mock.patch.object(controller, "MAX_TREE_ENTRIES", 0),
            self.assertRaisesRegex(controller.PolicyError, "exceeds 0 entries"),
        ):
            self.verify()

        with (
            mock.patch.object(controller, "MAX_PATH_METADATA_BYTES", 1),
            self.assertRaisesRegex(controller.PolicyError, "metadata exceeds"),
        ):
            self.verify()

        with (
            mock.patch.object(verifier.time, "monotonic", side_effect=[0.0, 31.0]),
            self.assertRaisesRegex(controller.PolicyError, "exceeded 30 seconds"),
        ):
            self.verify()

    def test_trusted_git_uses_only_the_resolved_tool_directory(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(
            verifier.subprocess, "run", return_value=completed
        ) as run:
            verifier.trusted_git(self.git, self.repository, ["status"])
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["PATH"], os.path.dirname(self.git))
        self.assertNotIn("HOME", environment)
        self.assertEqual(run.call_args.args[0][0], self.git)


class WorkflowStructureTests(unittest.TestCase):
    @staticmethod
    def job_block(workflow: str, name: str) -> str:
        lines = workflow.splitlines(keepends=True)
        start = lines.index(f"  {name}:\n")
        end = next(
            (
                index
                for index in range(start + 1, len(lines))
                if lines[index].startswith("  ")
                and not lines[index].startswith("    ")
                and lines[index].rstrip().endswith(":")
            ),
            len(lines),
        )
        return "".join(lines[start:end])

    def test_composite_verifier_is_the_first_post_checkout_step(self) -> None:
        action = CHECKOUT_ACTION_PATH.read_text(encoding="utf-8")
        stage = action.index("- name: Stage protected verifier and trusted tools")
        checkout = action.index("- name: Check out exact candidate")
        verify_step = action.index("- name: Verify exact candidate checkout")
        self.assertLess(stage, checkout)
        self.assertLess(checkout, verify_step)
        between = action[checkout:verify_step]
        self.assertNotIn("\n    - name:", between)
        self.assertIn("persist-credentials: false", between)
        self.assertIn("submodules: false", between)
        self.assertIn("--expected-verifier-sha256", action[verify_step:])
        self.assertIn('PATH: ${{ steps.protected.outputs.path }}', action[verify_step:])

    def test_every_primary_candidate_checkout_uses_the_protected_action(self) -> None:
        workflow = REUSABLE_WORKFLOW_PATH.read_text(encoding="utf-8")
        protected_uses = (
            "uses: ./policy/.github/actions/protected-candidate-checkout"
        )
        self.assertGreaterEqual(workflow.count(protected_uses), 1)
        self.assertNotIn("- name: Check out exact candidate\n", workflow)
        self.assertIn("binding_digest:", workflow)
        self.assertIn("--binding-digest", workflow)
        self.assertIn("results_json:", workflow)

    def test_candidate_executing_jobs_are_terminal_and_action_free(self) -> None:
        workflow = REUSABLE_WORKFLOW_PATH.read_text(encoding="utf-8")
        config = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        jobs = ["platform_verifier"]
        jobs.extend(
            ["rebuild_rs"]
            if config["repository_kind"] == "spec"
            else ["rust", "candidate_ci"]
        )
        for name in jobs:
            block = self.job_block(workflow, name)
            self.assertNotIn("uses:", block, name)
            self.assertEqual(
                sum(
                    line.startswith("      - name:")
                    for line in block.splitlines()
                ),
                1,
                name,
            )
            self.assertIn("exec bash --noprofile --norc", block, name)
            self.assertIn("run-terminal-candidate.sh", block, name)
            self.assertIn('${GITHUB_ENV}', block, name)

    def test_terminal_boundary_scrubs_and_separates_candidate_identity(self) -> None:
        shell = TERMINAL_SHELL_PATH.read_text(encoding="utf-8")
        windows = TERMINAL_WINDOWS_PATH.read_text(encoding="utf-8")
        driver = TERMINAL_DRIVER_PATH.read_text(encoding="utf-8")
        self.assertIn("sudo -n -u", shell)
        self.assertIn('chmod 0700 "${command_directory}"', shell)
        self.assertIn('pkill -KILL -u "${candidate_uid}"', shell)
        for name in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            self.assertIn(name, shell)
        self.assertIn("runner command files do not share one protected directory", shell)
        self.assertIn("disposable candidate identity could not be removed", shell)
        self.assertIn("New-LocalUser", windows)
        self.assertIn("$startInfo.Environment.Clear()", windows)
        self.assertIn("'/deny'", windows)
        self.assertIn("'/inheritance:r'", windows)
        self.assertIn("(WD,AD,WEA,WA,DE,DC,WDAC,WO)", windows)
        self.assertIn("Stop-CandidateProcesses", windows)
        self.assertIn("Remove-LocalUser", windows)
        self.assertIn("identity remains after removal", windows)
        self.assertIn("require_command_files_inaccessible", driver)
        self.assertIn("require_parent_process_isolated", driver)
        self.assertIn("require_tree_read_only", driver)
        self.assertIn("spawn_detached_canary", driver)

    def test_terminal_setup_uses_elevated_and_native_paths(self) -> None:
        shell = TERMINAL_SHELL_PATH.read_text(encoding="utf-8")
        windows = TERMINAL_WINDOWS_PATH.read_text(encoding="utf-8")
        self.assertIn("cygpath -w \"${trusted_git}\"", shell)
        self.assertIn('--git "${verifier_git}"', shell)
        self.assertIn('sudo -n chown -R "${candidate_uid}"', shell)
        self.assertNotIn('\nchown -R "${candidate_uid}"', shell)
        self.assertIn("mktemp -d /tmp/yaml-sigil-terminal.XXXXXX", shell)
        self.assertIn("mktemp -d /c/yaml-sigil-terminal.XXXXXX", shell)
        self.assertIn('policy_root="${sandbox}/protected-policy"', shell)
        self.assertIn('install -m 0555 "${trusted_cargo}"', shell)
        self.assertIn('protected_validator="${trusted_cargo}"', shell)
        self.assertIn(
            'cp -R "${trusted_python_source}/." "${trusted_python_root}/"', shell
        )
        self.assertIn(
            'trusted_python="${trusted_python_root}/${trusted_python_name}"', shell
        )
        self.assertIn(
            'trusted_python_name="$(basename "${trusted_python_command}")"', shell
        )
        self.assertIn(
            'trusted_python="$(realpath "${trusted_python_command}")"', shell
        )
        self.assertIn("-Description 'Disposable YamlSigil candidate'", windows)
        self.assertNotIn("candidate validation identity", windows)
        self.assertLess(
            windows.index('"${candidateSid}:RX"'),
            windows.index("Invoke-Icacls -Arguments @($Sandbox, '/inheritance:r'"),
        )
        self.assertNotIn("'/C'", windows)

    def test_terminal_driver_rejects_runner_and_preload_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"YAML_SIGIL_TERMINAL_CANDIDATE": "1"},
            clear=True,
        ):
            terminal_candidate.require_minimal_environment()
        for name in ("GITHUB_ENV", "ACTIONS_RUNTIME_TOKEN", "LD_PRELOAD"):
            with self.subTest(name=name), mock.patch.dict(
                os.environ,
                {"YAML_SIGIL_TERMINAL_CANDIDATE": "1", name: "poison"},
                clear=True,
            ):
                with self.assertRaises(terminal_candidate.IsolationError):
                    terminal_candidate.require_minimal_environment()

    def test_detached_helper_publishes_complete_pid_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            marker = root / "detached.pid"
            with mock.patch.object(terminal_candidate.time, "sleep"):
                self.assertEqual(terminal_candidate.detached_helper(marker), 0)
            self.assertEqual(marker.read_text(encoding="ascii"), str(os.getpid()))
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_terminal_driver_rejects_reachable_command_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            command_file = pathlib.Path(directory) / "github_env"
            command_file.write_text("", encoding="utf-8")
            with self.assertRaises(terminal_candidate.IsolationError):
                terminal_candidate.require_command_files_inaccessible(command_file)

    def test_terminal_driver_rejects_writable_trusted_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            trusted_file = root / "trusted-tool"
            trusted_file.write_bytes(b"tool")
            with self.assertRaises(terminal_candidate.IsolationError):
                terminal_candidate.require_tree_read_only(root, "trusted tree")
            with self.assertRaises(terminal_candidate.IsolationError):
                terminal_candidate.require_file_read_only(trusted_file, "trusted tool")

    def test_controller_token_jobs_compile_before_checks_only_tokens(self) -> None:
        command = COMMAND_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertEqual(command.count("Create checks-only GitHub App token"), 2)
        self.assertEqual(command.count("permission-checks: write"), 2)
        self.assertNotIn("permission-contents:", command)
        start = command.index("  start_check:")
        protected = command.index("  protected_ci:")
        finish = command.index("  finish_check:")
        start_job = command[start:protected]
        finish_job = command[finish:]
        for job in (start_job, finish_job):
            self.assertLess(
                job.index("Load immutable check policy"),
                job.index("Create checks-only GitHub App token"),
            )
            self.assertLess(
                job.index("Verify exact App token repository scope"),
                job.index("App-owned in-progress check")
                if "App-owned in-progress check" in job
                else job.index("Revalidate state and finalize App check"),
            )
            self.assertNotIn("actions/checkout@", job)

    def test_reconciliation_token_jobs_remain_checkout_free(self) -> None:
        workflow = RECONCILE_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertNotIn("actions/checkout@", workflow)


class CommitPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.repository = pathlib.Path(temporary_directory.name)
        self.run_git("init", "--quiet", "--initial-branch=main")
        self.empty_tree = self.run_git(
            "hash-object", "-t", "tree", "--stdin", input_text=""
        ).stdout.strip()

    def run_git(
        self,
        *args: str,
        input_text: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process_environment = os.environ.copy()
        process_environment.update(environment or {})
        return subprocess.run(
            ["git", *args],
            cwd=self.repository,
            env=process_environment,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )

    def commit(
        self,
        message: str,
        *,
        parent: str | None = None,
        author_name: str = "Base Author",
        author_email: str = "base-author@example.invalid",
        committer_name: str = "Base Committer",
        committer_email: str = "base-committer@example.invalid",
    ) -> str:
        args = ["commit-tree", self.empty_tree]
        if parent is not None:
            args.extend(["-p", parent])
        args.extend(["-m", message])
        result = self.run_git(
            *args,
            environment={
                "GIT_AUTHOR_NAME": author_name,
                "GIT_AUTHOR_EMAIL": author_email,
                "GIT_COMMITTER_NAME": committer_name,
                "GIT_COMMITTER_EMAIL": committer_email,
            },
        )
        return result.stdout.strip()

    def run_policy(
        self, base_sha: str, head_sha: str
    ) -> subprocess.CompletedProcess[str]:
        process_environment = os.environ.copy()
        process_environment.update({"BASE_SHA": base_sha, "HEAD_SHA": head_sha})
        return subprocess.run(
            [policy_bash(), str(COMMIT_POLICY_PATH)],
            cwd=self.repository,
            env=process_environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_generic_platform_committer_signoff_does_not_satisfy_author_dco(
        self,
    ) -> None:
        base = self.commit("test: base")
        head = self.commit(
            "test: candidate\n\nSigned-off-by: GitHub <noreply@github.com>",
            parent=base,
            author_name="Contributor",
            author_email="contributor@example.invalid",
            committer_name="GitHub",
            committer_email="noreply@github.com",
        )

        result = self.run_policy(base, head)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("matching its author.", result.stdout)

    def test_exact_author_signoff_is_accepted_when_committer_differs(self) -> None:
        base = self.commit("test: base")
        head = self.commit(
            "test: candidate\n\n"
            "Signed-off-by: Contributor <contributor@example.invalid>",
            parent=base,
            author_name="Contributor",
            author_email="contributor@example.invalid",
            committer_name="GitHub",
            committer_email="noreply@github.com",
        )

        result = self.run_policy(base, head)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Validated 1 linear, signed-off pull request commit(s).", result.stdout
        )


class PaginationApi(controller.GitHubApi):
    def __init__(self, responses):
        self.responses = list(responses)
        self.token = "test"
        self.api_url = "https://example.invalid"

    def get(self, path: str):
        del path
        if not self.responses:
            raise controller.PolicyError("unexpected page request")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class PaginationTests(unittest.TestCase):
    def test_api_response_size_is_bounded(self) -> None:
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                self.assert_limit = limit
                return b"12345"

        response = Response()
        api = controller.GitHubApi("token", "https://example.invalid")
        with (
            mock.patch.object(controller, "MAX_API_RESPONSE_BYTES", 4),
            mock.patch.object(
                controller.urllib.request,
                "urlopen",
                return_value=response,
            ),
            self.assertRaisesRegex(controller.PolicyError, "size limit"),
        ):
            api.get("/example")
        self.assertEqual(response.assert_limit, 5)

    def test_api_error_response_size_is_bounded(self) -> None:
        class ErrorBody:
            def read(self, limit):
                self.assert_limit = limit
                return b"12345"

            def close(self):
                pass

        body = ErrorBody()
        error = controller.urllib.error.HTTPError(
            "https://example.invalid/example",
            500,
            "server error",
            {},
            body,
        )
        api = controller.GitHubApi("token", "https://example.invalid")
        with (
            mock.patch.object(controller, "MAX_API_ERROR_DETAIL_BYTES", 4),
            mock.patch.object(
                controller.urllib.request,
                "urlopen",
                side_effect=error,
            ),
            self.assertRaisesRegex(
                controller.PolicyError,
                r"HTTP 500: 1234\.\.\.$",
            ),
        ):
            api.get("/example")
        self.assertEqual(body.assert_limit, 5)

    def test_list_pagination_fails_on_intermediate_error(self) -> None:
        api = PaginationApi([[{} for _ in range(100)], controller.PolicyError("page failed")])
        with self.assertRaisesRegex(controller.PolicyError, "page failed"):
            api.paginate("/items", max_items=200, label="items")

    def test_keyed_pagination_requires_stable_complete_total(self) -> None:
        api = PaginationApi(
            [
                {"total_count": 101, "items": [{} for _ in range(100)]},
                {"total_count": 102, "items": [{}]},
            ]
        )
        with self.assertRaisesRegex(controller.PolicyError, "total changed"):
            api.paginate_key("/items", "items", max_items=200, label="items")

    def test_pagination_limits_and_completion_fail_closed(self) -> None:
        api = PaginationApi([[{} for _ in range(100)]])
        with self.assertRaisesRegex(controller.PolicyError, "supported limit"):
            api.paginate("/items", max_items=99, label="items")

        api = PaginationApi([{"total_count": 2, "items": [{}]}])
        with self.assertRaisesRegex(controller.PolicyError, "incomplete"):
            api.paginate_key("/items", "items", max_items=2, label="items")

        api = PaginationApi([[{} for _ in range(100)] for _ in range(2)])
        with mock.patch.object(controller, "MAX_PAGES", 2):
            with self.assertRaisesRegex(controller.PolicyError, "did not terminate"):
                api.paginate("/items", max_items=200, label="items")


class GraphQlResponse:
    status = 200

    def __init__(self, value: dict) -> None:
        self.raw = json.dumps(value, separators=(",", ":")).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.raw[:limit]


def requested_graphql_page(request) -> tuple[int, str | None, int, str]:
    body = json.loads(request.data)
    variables = body["variables"]
    return variables["first"], variables["after"], variables["number"], body["query"]


def graphql_signature_value(
    signatures: list[dict],
    *,
    total_count: int,
    has_next: bool,
    end_cursor: str | None,
) -> dict:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "commits": {
                        "totalCount": total_count,
                        "nodes": [{"commit": signature} for signature in signatures],
                        "pageInfo": {
                            "hasNextPage": has_next,
                            "endCursor": end_cursor,
                        },
                    }
                }
            }
        }
    }


def graphql_signature_response(
    oids: list[str],
    *,
    total_count: int | None = None,
    has_next: bool = False,
    end_cursor: str | None = None,
) -> GraphQlResponse:
    return GraphQlResponse(
        graphql_signature_value(
            [git_signature(sha=oid) for oid in oids],
            total_count=len(oids) if total_count is None else total_count,
            has_next=has_next,
            end_cursor=end_cursor,
        )
    )


def graphql_signature_pages(oids: list[str]):
    offset = 0
    expected_cursor = None

    def respond(request, *_args, **_kwargs) -> GraphQlResponse:
        nonlocal offset, expected_cursor
        first, after, number, query = requested_graphql_page(request)
        if number != PULL_NUMBER or after != expected_cursor:
            raise AssertionError("unexpected pull request signature page")
        if "pullRequest(number:$number)" not in query or "object(oid:" in query:
            raise AssertionError("signature query escaped the pull request connection")
        batch = oids[offset : offset + first]
        offset += len(batch)
        has_next = offset < len(oids)
        end_cursor = f"cursor-{offset}"
        expected_cursor = end_cursor if has_next else None
        return graphql_signature_response(
            batch,
            total_count=len(oids),
            has_next=has_next,
            end_cursor=end_cursor,
        )

    return respond


class GraphQlSignatureTests(unittest.TestCase):
    def test_signature_query_text_matches_the_intended_selection_tree(self) -> None:
        api = controller.GitHubApi("token", "https://example.invalid")
        with mock.patch.object(
            controller.urllib.request,
            "urlopen",
            return_value=graphql_signature_response([HEAD_SHA]),
        ) as urlopen:
            api.commit_signatures(REPOSITORY, PULL_NUMBER, [HEAD_SHA])

        _, _, _, query = requested_graphql_page(urlopen.call_args.args[0])
        expected = "".join(
            """
            query($owner:String!,$name:String!,$number:Int!,$first:Int!,$after:String){
              repository(owner:$owner,name:$name){
                pullRequest(number:$number){
                  commits(first:$first,after:$after){
                    totalCount
                    nodes{
                      commit{
                        oid
                        signature{
                          __typename
                          email
                          isValid
                          state
                          wasSignedByGitHub
                          signer{databaseId login __typename}
                        }
                      }
                    }
                    pageInfo{hasNextPage endCursor}
                  }
                }
              }
            }
            """.split()
        )
        self.assertEqual("".join(query.split()), expected)

    def test_signature_inventory_is_batched_five_by_fifty(self) -> None:
        oids = [f"{index:040x}" for index in range(1, 251)]
        api = controller.GitHubApi("token", "https://example.invalid")
        with mock.patch.object(
            controller.urllib.request,
            "urlopen",
            side_effect=graphql_signature_pages(oids),
        ) as urlopen:
            observed = api.commit_signatures(REPOSITORY, PULL_NUMBER, oids)
        self.assertEqual(list(observed), oids)
        self.assertEqual(urlopen.call_count, 5)
        self.assertTrue(
            all(
                requested_graphql_page(call.args[0])[0] == 50
                for call in urlopen.call_args_list
            )
        )
        self.assertTrue(
            all(
                requested_graphql_page(call.args[0])[2] == PULL_NUMBER
                and "pullRequest(number:$number)"
                in requested_graphql_page(call.args[0])[3]
                and "object(oid:" not in requested_graphql_page(call.args[0])[3]
                for call in urlopen.call_args_list
            )
        )

    def test_251_commits_and_excess_requests_fail_before_ambiguity(self) -> None:
        api = controller.GitHubApi("token", "https://example.invalid")
        oids = [f"{index:040x}" for index in range(1, 252)]
        with self.assertRaisesRegex(controller.PolicyError, "commit limit"):
            api.commit_signatures(REPOSITORY, PULL_NUMBER, oids)

        with (
            mock.patch.object(controller, "MAX_SIGNATURE_BATCH", 1),
            mock.patch.object(controller, "MAX_SIGNATURE_REQUESTS", 1),
            mock.patch.object(
                controller.urllib.request,
                "urlopen",
                side_effect=graphql_signature_pages([HEAD_SHA, OLD_SHA]),
            ) as urlopen,
            self.assertRaisesRegex(controller.PolicyError, "too many GraphQL requests"),
        ):
            api.commit_signatures(REPOSITORY, PULL_NUMBER, [HEAD_SHA, OLD_SHA])
        self.assertEqual(urlopen.call_count, 1)

    def test_aggregate_success_body_budget_has_a_sentinel(self) -> None:
        first = graphql_signature_response(
            [HEAD_SHA],
            total_count=2,
            has_next=True,
            end_cursor="cursor-1",
        )
        second = graphql_signature_response(
            [OLD_SHA],
            total_count=2,
            end_cursor="cursor-2",
        )
        budget = len(first.raw) + len(second.raw) - 1
        api = controller.GitHubApi("token", "https://example.invalid")
        with (
            mock.patch.object(controller, "MAX_SIGNATURE_BATCH", 1),
            mock.patch.object(controller, "MAX_API_RESPONSE_BYTES", budget),
            mock.patch.object(
                controller.urllib.request,
                "urlopen",
                side_effect=[first, second],
            ),
            self.assertRaisesRegex(controller.PolicyError, "aggregate commit signature"),
        ):
            api.commit_signatures(REPOSITORY, PULL_NUMBER, [HEAD_SHA, OLD_SHA])

    def test_partial_graphql_errors_are_rejected_even_with_data(self) -> None:
        response = graphql_signature_response([HEAD_SHA], end_cursor="cursor-1")
        value = json.loads(response.raw)
        value["errors"] = [{"message": "partial"}]
        api = controller.GitHubApi("token", "https://example.invalid")
        with (
            mock.patch.object(
                controller.urllib.request,
                "urlopen",
                return_value=GraphQlResponse(value),
            ),
            self.assertRaisesRegex(controller.PolicyError, "contains errors"),
        ):
            api.commit_signatures(REPOSITORY, PULL_NUMBER, [HEAD_SHA])

    def test_missing_extra_duplicate_and_reordered_results_fail_closed(self) -> None:
        cases = {
            "missing": [git_signature(sha=HEAD_SHA)],
            "extra": [
                git_signature(sha=HEAD_SHA),
                git_signature(sha=OLD_SHA),
                git_signature(sha=MAIN_SHA),
            ],
            "duplicate": [
                git_signature(sha=HEAD_SHA),
                git_signature(sha=HEAD_SHA),
            ],
            "reordered": [
                git_signature(sha=OLD_SHA),
                git_signature(sha=HEAD_SHA),
            ],
        }
        for label, signatures in cases.items():
            with self.subTest(case=label):
                api = controller.GitHubApi("token", "https://example.invalid")
                with (
                    mock.patch.object(
                        controller.urllib.request,
                        "urlopen",
                        return_value=GraphQlResponse(
                            graphql_signature_value(
                                signatures,
                                total_count=2,
                                has_next=False,
                                end_cursor="cursor-2",
                            )
                        ),
                    ),
                    self.assertRaises(controller.PolicyError),
                ):
                    api.commit_signatures(
                        REPOSITORY, PULL_NUMBER, [HEAD_SHA, OLD_SHA]
                    )

    def test_duplicate_requested_oids_fail_before_network_access(self) -> None:
        api = controller.GitHubApi("token", "https://example.invalid")
        with (
            mock.patch.object(controller.urllib.request, "urlopen") as urlopen,
            self.assertRaisesRegex(controller.PolicyError, "duplicate commit OIDs"),
        ):
            api.commit_signatures(REPOSITORY, PULL_NUMBER, [HEAD_SHA, HEAD_SHA])
        urlopen.assert_not_called()


class AppTokenScopeTests(unittest.TestCase):
    def test_exact_single_repository_inventory_is_required(self) -> None:
        api = mock.Mock()
        api.paginate_key.return_value = [{"id": 11, "full_name": REPOSITORY}]
        controller.require_app_token_repository_scope(api, REPOSITORY)
        api.paginate_key.assert_called_once_with(
            "/installation/repositories",
            "repositories",
            max_items=2,
            label="App token repository inventory",
        )

        for inventory in (
            [],
            [
                {"id": 11, "full_name": REPOSITORY},
                {"id": 12, "full_name": "NVIDIA/another"},
            ],
            [{"id": 11, "full_name": "NVIDIA/another"}],
            [{"id": 0, "full_name": REPOSITORY}],
        ):
            with self.subTest(inventory=inventory):
                api = mock.Mock()
                api.paginate_key.return_value = inventory
                with self.assertRaises(controller.PolicyError):
                    controller.require_app_token_repository_scope(api, REPOSITORY)


class FakeCheckApi:
    def __init__(self, checks=None) -> None:
        self.checks = list(checks or [])
        self.patches = []
        self.posts = []
        self.patch_response_overrides = {}

    def get(self, path: str):
        if "/check-runs/" in path:
            check_id = int(path.rsplit("/", 1)[1])
            return next(check for check in self.checks if check["id"] == check_id)
        raise AssertionError(f"unexpected GET {path}")

    def paginate_key(self, path, key, *, max_items, label):
        del path, key, max_items, label
        return self.checks

    def patch(self, path, payload):
        self.patches.append((path, payload))
        check_id = int(path.rsplit("/", 1)[1])
        check = next(check for check in self.checks if check["id"] == check_id)
        check.update(payload)
        response = copy.deepcopy(check)
        response.update(self.patch_response_overrides.get(payload["conclusion"], {}))
        return response

    def post(self, path, payload):
        self.posts.append((path, payload))
        check = {
            "id": 99,
            "name": payload["name"],
            "head_sha": payload["head_sha"],
            "external_id": payload["external_id"],
            "status": payload["status"],
            "app": {"slug": APP_SLUG},
        }
        self.checks.append(check)
        return check


def authorization_digest(
    api: FakeAuthorizationApi | None = None,
    approval: dict | None = None,
) -> str:
    selected_api = api or FakeAuthorizationApi()
    selected_event = approval or event()
    selected_api.comment = copy.deepcopy(selected_event["comment"])
    return controller.authorize(
        selected_event, policy(), selected_api, environment()
    ).binding_digest


def external(
    run_id: int = 101,
    attempt: int = 1,
    binding_digest: str | None = None,
) -> object:
    return controller.ExternalId(
        repository=REPOSITORY,
        pull_number=7,
        head_sha=HEAD_SHA,
        base_sha=MAIN_SHA,
        policy_sha=MAIN_SHA,
        binding_digest=binding_digest or authorization_digest(),
        run_id=run_id,
        run_attempt=attempt,
    )


def job_results(
    *, workflow_lint: str = "success", candidate_ci: str = "skipped"
) -> str:
    return json.dumps(
        {
            "commit_policy": "success",
            "workflow_lint": workflow_lint,
            "candidate_ci": candidate_ci,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def pending_check(check_id: int, binding, slug: str = APP_SLUG) -> dict:
    return {
        "id": check_id,
        "name": "Required CI",
        "head_sha": HEAD_SHA,
        "external_id": binding.encode(),
        "status": "in_progress",
        "app": {"slug": slug},
    }


class CheckRunTests(unittest.TestCase):
    def test_external_id_round_trip_binds_all_fields(self) -> None:
        binding = external()
        self.assertEqual(
            controller.ExternalId.decode(
                binding.encode(),
                repository=REPOSITORY,
                base_sha=MAIN_SHA,
                policy_sha=MAIN_SHA,
            ),
            binding,
        )
        self.assertLessEqual(len(binding.encode()), 255)

    def test_retry_closes_prior_app_check_but_not_actions_check(self) -> None:
        old = external(run_id=100)
        api = FakeCheckApi(
            [
                pending_check(1, old),
                pending_check(2, old, slug="github-actions"),
            ]
        )
        check_id, encoded = controller.start_check(api, policy(), external(), APP_SLUG)
        self.assertEqual(check_id, 99)
        self.assertEqual(encoded, external().encode())
        self.assertEqual(len(api.patches), 1)
        self.assertTrue(api.patches[0][0].endswith("/check-runs/1"))
        self.assertEqual(api.patches[0][1]["conclusion"], "cancelled")

    def test_ambiguous_app_check_binding_fails_closed(self) -> None:
        check = pending_check(1, external(run_id=100))
        check["external_id"] = "not-a-binding"
        api = FakeCheckApi([check])
        with self.assertRaisesRegex(controller.PolicyError, "external ID"):
            controller.start_check(api, policy(), external(), APP_SLUG)

    def test_app_slug_must_match_before_any_check_write(self) -> None:
        api = FakeCheckApi()
        with self.assertRaisesRegex(controller.PolicyError, "configured release App"):
            controller.start_check(api, policy(), external(), "another-app")
        self.assertEqual(api.posts, [])

    def test_expected_jobs_are_exact_and_skips_remain_explicit(self) -> None:
        expected = ["commit_policy", "workflow_lint", "candidate_ci"]
        self.assertEqual(
            controller.parse_results(
                [
                    "commit_policy=success",
                    "workflow_lint=success",
                    "candidate_ci=skipped",
                ],
                expected,
            ),
            {
                "commit_policy": "success",
                "workflow_lint": "success",
                "candidate_ci": "skipped",
            },
        )
        with self.assertRaisesRegex(controller.PolicyError, "exactly match"):
            controller.parse_results(["commit_policy=success"], expected)
        results = controller.parse_results(
            [
                "commit_policy=success",
                "workflow_lint=skipped",
                "candidate_ci=skipped",
            ],
            expected,
        )
        self.assertNotEqual(results["workflow_lint"], "success")

    def test_final_report_reauthorizes_and_requires_every_job(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        controller.finish_check(
            app_api,
            FakeAuthorizationApi(),
            policy(),
            event(),
            environment(),
            binding,
            COMMENT_ID,
            1,
            job_results(),
            APP_SLUG,
        )
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "success")

        app_api = FakeCheckApi([pending_check(1, binding)])
        with self.assertRaisesRegex(controller.PolicyError, "did not all succeed"):
            controller.finish_check(
                app_api,
                FakeAuthorizationApi(),
                policy(),
                event(),
                environment(),
                binding,
                COMMENT_ID,
                1,
                job_results(workflow_lint="skipped"),
                APP_SLUG,
            )
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")

    def test_required_candidate_ci_may_not_be_skipped(self) -> None:
        approval = adoption_event()
        binding_api = FakeAuthorizationApi()
        binding_api.set_change(".github/workflows/ci.yml")
        binding = external(
            binding_digest=authorization_digest(binding_api, approval)
        )
        app_api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.set_change(".github/workflows/ci.yml")
        auth_api.comment = copy.deepcopy(approval["comment"])

        with self.assertRaisesRegex(controller.PolicyError, "did not all succeed"):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                approval,
                environment(),
                binding,
                COMMENT_ID,
                1,
                job_results(),
                APP_SLUG,
            )

        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")

    def test_success_is_overwritten_if_main_advances_during_reconciliation(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.main_sha_sequence = [
            MAIN_SHA,
            MAIN_SHA,
            MAIN_SHA,
            MAIN_SHA,
            MAIN_SHA,
            MAIN_SHA,
            OLD_SHA,
        ]

        with self.assertRaisesRegex(
            controller.PolicyError, "main changed during final check reconciliation"
        ):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                event(),
                environment(),
                binding,
                COMMENT_ID,
                1,
                job_results(),
                APP_SLUG,
            )

        self.assertEqual(
            [payload["conclusion"] for _path, payload in app_api.patches],
            ["success", "failure"],
        )
        self.assertEqual(app_api.patches[0][0], app_api.patches[1][0])
        self.assertEqual(app_api.checks[0]["conclusion"], "failure")

    def test_success_is_overwritten_if_reconciliation_read_fails(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.main_error_on_read = 7

        with self.assertRaisesRegex(controller.PolicyError, "main ref reread failed"):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                event(),
                environment(),
                binding,
                COMMENT_ID,
                1,
                job_results(),
                APP_SLUG,
            )

        self.assertEqual(
            [payload["conclusion"] for _path, payload in app_api.patches],
            ["success", "failure"],
        )
        self.assertEqual(app_api.patches[0][0], app_api.patches[1][0])
        self.assertEqual(app_api.checks[0]["conclusion"], "failure")

    def test_reconciliation_validates_failure_patch_response_binding(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        app_api.patch_response_overrides["failure"] = {
            "external_id": external(run_id=999).encode()
        }
        auth_api = FakeAuthorizationApi()
        auth_api.main_error_on_read = 7

        with self.assertRaisesRegex(controller.PolicyError, "binding is unexpected"):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                event(),
                environment(),
                binding,
                COMMENT_ID,
                1,
                job_results(),
                APP_SLUG,
            )

        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")
        self.assertEqual(app_api.checks[0]["conclusion"], "failure")

    def test_cancelled_workflow_reconciles_only_its_app_check(self) -> None:
        binding = external()
        api = FakeCheckApi(
            [
                pending_check(1, binding),
                pending_check(2, binding, slug="github-actions"),
            ]
        )
        auth_api = FakeAuthorizationApi()
        auth_api.run = workflow_run(status="completed", conclusion="cancelled")
        count = controller.reconcile_run(
            api,
            auth_api,
            policy(),
            workflow_run_event(conclusion="cancelled"),
            REPOSITORY,
            APP_SLUG,
        )
        self.assertEqual(count, 1)
        self.assertEqual(len(api.patches), 1)
        self.assertEqual(api.patches[0][1]["conclusion"], "cancelled")

    def test_late_retry_event_cannot_close_a_newer_attempt(self) -> None:
        binding = external(attempt=2)
        api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.run = workflow_run(status="completed", conclusion="cancelled")
        count = controller.reconcile_run(
            api,
            auth_api,
            policy(),
            workflow_run_event(conclusion="cancelled"),
            REPOSITORY,
            APP_SLUG,
        )
        self.assertEqual(count, 0)
        self.assertEqual(api.patches, [])

    def test_sweep_closes_only_a_completed_bound_run(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        actions_api = FakeAuthorizationApi()
        actions_api.run = workflow_run(status="completed", conclusion="failure")
        actions_api.runs = [actions_api.run]
        count = controller.sweep_runs(
            app_api,
            actions_api,
            policy(),
            REPOSITORY,
            APP_SLUG,
        )
        self.assertEqual(count, 1)
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")

    def test_ordinary_comment_run_has_no_protected_binding(self) -> None:
        auth_api = FakeAuthorizationApi()
        auth_api.run = workflow_run(status="completed", conclusion="success")
        auth_api.jobs = [
            {
                "id": 902,
                "run_id": RUN_ID,
                "run_attempt": RUN_ATTEMPT,
                "head_sha": MAIN_SHA,
                "name": "Inspect test command",
                "status": "completed",
                "conclusion": "success",
            }
        ]
        protected = controller.completed_run_from_event(
            auth_api,
            policy(),
            workflow_run_event(conclusion="success"),
            REPOSITORY,
        )
        self.assertIsNone(protected)

    def test_reconciliation_revalidates_comment_permission_before_closing(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.run = workflow_run(status="completed", conclusion="failure")
        auth_api.permissions[MAINTAINER] = "read"

        count = controller.reconcile_run(
            app_api,
            auth_api,
            policy(),
            workflow_run_event(conclusion="failure"),
            REPOSITORY,
            APP_SLUG,
        )

        self.assertEqual(count, 1)
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")
        self.assertIn(
            "Final state validation failed",
            app_api.patches[-1][1]["output"]["summary"],
        )


if __name__ == "__main__":
    unittest.main()

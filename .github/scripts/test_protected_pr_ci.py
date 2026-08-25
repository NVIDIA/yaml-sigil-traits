#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the protected-main pull-request controller."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("protected_pr_ci.py")
POLICY_PATH = MODULE_PATH.parent.parent / "protected-pr-ci.json"
SPEC = importlib.util.spec_from_file_location("protected_pr_ci", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
SPEC.loader.exec_module(controller)


REPOSITORY = "NVIDIA/yaml-sigil-example"
MAIN_SHA = "a" * 40
HEAD_SHA = "b" * 40
OLD_SHA = "c" * 40
BASE_TREE_SHA = "d" * 40
HEAD_TREE_SHA = "e" * 40
BASE_BLOB_SHA = "1" * 40
HEAD_BLOB_SHA = "2" * 40
DIRECTORY_TREE_SHA = "f" * 40
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
        "version": 1,
        "default_branch": "main",
        "workflow_file": ".github/workflows/pr-ci.yml",
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
        "expected_jobs": ["commit_policy", "workflow_lint"],
        "sensitive_paths": [
            "CODEOWNERS",
            ".github/**",
            ".cargo/**",
            "Cargo.toml",
            "**/Cargo.toml",
            "build.rs",
            "**/build.rs",
            "AGENTS.md",
            ".agents/**",
            "source-spec/**",
        ],
    }


def event(body: str | None = None) -> dict:
    return {
        "action": "created",
        "repository": {"full_name": REPOSITORY},
        "issue": {"number": 7, "pull_request": {"url": "https://example.invalid/pr/7"}},
        "comment": {
            "id": 19,
            "body": body if body is not None else f"/ok to test {HEAD_SHA}",
            "user": {"login": MAINTAINER},
        },
    }


def environment() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_ACTOR": MAINTAINER,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_TRIGGERING_ACTOR": MAINTAINER,
        "GITHUB_RUN_ATTEMPT": "1",
        "POLICY_SHA": MAIN_SHA,
    }


def workflow_dispatch_event() -> dict:
    return {
        "repository": {"full_name": REPOSITORY},
        "inputs": {
            "pull_number": "7",
            "head_sha": HEAD_SHA,
            "base_sha": MAIN_SHA,
            "policy_sha": MAIN_SHA,
            "comment_id": "19",
        },
    }


def git_commit(
    *,
    sha: str = HEAD_SHA,
    parent: str = MAIN_SHA,
    author_login: str = MAINTAINER,
    committer_login: str = MAINTAINER,
    author_id: int = 1,
    committer_id: int = 1,
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
        "author": {"login": author_login, "id": author_id},
        "committer": {"login": committer_login, "id": committer_id},
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
        self.main_reads = 0
        self.pull_reads = 0
        self.final_pull = None
        self.pull = {
            "number": 7,
            "state": "open",
            "user": {"login": "contributor"},
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

    def post(self, path: str, payload: dict):
        self.posts.append((path, payload))
        return None


class AuthorizationTests(unittest.TestCase):
    def test_repository_policy_configuration_is_valid(self) -> None:
        controller.load_config(str(POLICY_PATH))

    def test_repository_directory_patterns_match_roots_and_descendants(self) -> None:
        repository_policy = controller.load_config(str(POLICY_PATH))
        declarations = [
            pattern
            for pattern in repository_policy["sensitive_paths"]
            if pattern.endswith("/**")
        ]
        self.assertTrue(declarations)

        for declaration in declarations:
            root = declaration[:-3]
            if root.startswith("**/"):
                root = f"nested/{root[3:]}"
            with self.subTest(declaration=declaration, root=root):
                self.assertTrue(controller.is_sensitive(root, [declaration]))
                self.assertTrue(
                    controller.is_sensitive(f"{root}/representative-file", [declaration])
                )

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
        api = FakeAuthorizationApi()
        for body in (
            f" /ok to test {HEAD_SHA}",
            f"/ok to test {HEAD_SHA}\n",
            f"/ok to test {HEAD_SHA.upper()}",
            "/ok to test main",
        ):
            with self.subTest(body=body), self.assertRaises(controller.PolicyError):
                controller.authorize(event(body), policy(), api, environment())

        with self.assertRaisesRegex(controller.PolicyError, "exact current pull request head"):
            controller.authorize(event(f"/ok to test {OLD_SHA}"), policy(), api, environment())

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

    def test_renamed_sensitive_source_is_remove_plus_add(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change(
            "docs/retired-workflow.md",
            "renamed",
            previous_filename=".github/workflows/ci.yml",
        )
        with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
            controller.authorize(event(), policy(), api, environment())

    def test_mutable_pull_file_view_is_never_authoritative(self) -> None:
        api = FakeAuthorizationApi()
        api.pull["changed_files"] = 999_999
        result = controller.authorize(event(), policy(), api, environment())
        self.assertEqual(result.head_sha, HEAD_SHA)
        self.assertFalse(any("/pulls/7/files" in path for path in api.get_paths))

    def test_sensitive_fork_change_runs_no_candidate_policy(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change(".github/workflows/ci.yml")
        with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
            controller.authorize(event(), policy(), api, environment())

    def test_sensitive_matching_uses_unicode_normalized_casefold_paths(self) -> None:
        for path in (
            ".GitHub/Workflows/ci.yml",
            ".ＧitHub/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                api = FakeAuthorizationApi()
                api.set_change(path)
                with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
                    controller.authorize(event(), policy(), api, environment())

    def test_directory_patterns_cover_roots_descendants_and_normalized_forms(self) -> None:
        patterns = [".cargo/**", "source-spec/**"]
        for path in (
            ".cargo",
            ".CARGO/config.toml",
            ".ＣＡＲＧＯ",
            "source-spec",
            "SOURCE-SPEC/proto/schema.proto",
            "ＳＯＵＲＣＥ－ＳＰＥＣ/README.md",
        ):
            with self.subTest(path=path):
                self.assertTrue(controller.is_sensitive(path, patterns))

        for path in (
            ".carg",
            ".cargo-cache/config.toml",
            ".cargo.toml",
            "nested/.cargo/config.toml",
            "nested/source-spec/README.md",
            "source-specification/README.md",
        ):
            with self.subTest(near_miss=path):
                self.assertFalse(controller.is_sensitive(path, patterns))

        self.assertTrue(controller.is_sensitive("SOURCE-SPEC", ["source-spec"]))
        self.assertFalse(
            controller.is_sensitive("source-spec/README.md", ["source-spec"])
        )

    def test_sensitive_directory_entries_require_writer_adoption(self) -> None:
        for path, leaf in (
            (".cargo", ("blob", "120000", HEAD_BLOB_SHA)),
            (".ＣＡＲＧＯ", ("blob", "120000", HEAD_BLOB_SHA)),
            ("source-spec", ("commit", "160000", HEAD_BLOB_SHA)),
            ("source-spec/README.md", ("blob", "100644", HEAD_BLOB_SHA)),
        ):
            with self.subTest(path=path, entry_type=leaf[0]):
                api = FakeAuthorizationApi()
                api.set_tree_files({}, {path: leaf})
                with self.assertRaisesRegex(
                    controller.PolicyError, "same-repository branch"
                ):
                    controller.authorize(event(), policy(), api, environment())

    def test_root_and_nested_build_scripts_are_sensitive(self) -> None:
        for path in ("build.rs", "nested/BUILD.RS"):
            with self.subTest(path=path):
                api = FakeAuthorizationApi()
                api.set_change(path)
                with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
                    controller.authorize(event(), policy(), api, environment())

    def test_verified_writer_adoption_requires_both_dco_identities(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.permissions[MAINTAINER] = "maintain"
        api.details[HEAD_SHA] = git_commit(
            author_login="contributor",
            author_name="Contributor",
            author_email="contributor@example.invalid",
            committer_name="Maintainer",
            committer_email="maintainer@example.invalid",
        )
        result = controller.authorize(event(), policy(), api, environment())
        self.assertEqual(result.head_repository, REPOSITORY)

        api.details[HEAD_SHA]["commit"]["message"] = (
            "ci: update policy\n\n"
            "Signed-off-by: Contributor <contributor@example.invalid>\n"
        )
        with self.assertRaisesRegex(controller.PolicyError, "adopting committer"):
            controller.authorize(event(), policy(), api, environment())

    def test_sensitive_adoption_requires_verified_writer_commit(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("AGENTS.md")
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.details[HEAD_SHA] = git_commit(verified=False)
        with self.assertRaisesRegex(controller.PolicyError, "not GitHub Verified"):
            controller.authorize(event(), policy(), api, environment())

        api.details[HEAD_SHA] = git_commit(committer_login="outsider")
        api.permissions["outsider"] = "read"
        with self.assertRaisesRegex(controller.PolicyError, "committer"):
            controller.authorize(event(), policy(), api, environment())

    def test_full_commit_response_must_match_requested_sha(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.details[HEAD_SHA]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "requested SHA"):
            controller.authorize(event(), policy(), api, environment())

    def test_exact_release_app_author_and_committer_are_accepted(self) -> None:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.pull["user"] = {"login": BOT, "id": BOT_ID}
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.pull["head"]["ref"] = "release-plz-next"
        api.details[HEAD_SHA] = git_commit(
            author_login=BOT,
            author_id=BOT_ID,
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
        result = controller.authorize(event(), policy(), api, environment())
        self.assertEqual(result.head_sha, HEAD_SHA)

        api.set_change("Cargo.toml", "removed")
        with self.assertRaisesRegex(controller.PolicyError, "only modify existing"):
            controller.authorize(event(), policy(), api, environment())

    def release_app_api(self) -> FakeAuthorizationApi:
        api = FakeAuthorizationApi()
        api.set_change("Cargo.toml")
        api.pull["user"] = {"login": BOT, "id": BOT_ID}
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.pull["head"]["ref"] = "release-plz-next"
        api.details[HEAD_SHA] = git_commit(
            author_login=BOT,
            author_id=BOT_ID,
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
        return api

    def test_release_app_rejects_wrong_bot_id_and_raw_author(self) -> None:
        api = self.release_app_api()
        api.pull["user"]["id"] += 1
        with self.assertRaisesRegex(controller.PolicyError, "pull request author ID"):
            controller.authorize(event(), policy(), api, environment())

        api = self.release_app_api()
        api.details[HEAD_SHA]["author"]["id"] += 1
        with self.assertRaisesRegex(controller.PolicyError, "author ID"):
            controller.authorize(event(), policy(), api, environment())

        for field in ("name", "email"):
            with self.subTest(field=field):
                api = self.release_app_api()
                api.details[HEAD_SHA]["commit"]["author"][field] = "lookalike"
                with self.assertRaisesRegex(controller.PolicyError, f"author {field}"):
                    controller.authorize(event(), policy(), api, environment())

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
        with self.assertRaisesRegex(controller.PolicyError, "committer ID"):
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
        api.details[HEAD_SHA]["commit"]["verification"] = {
            "verified": False,
            "reason": "invalid",
        }
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
        base_api.pull["user"] = {"login": BOT, "id": BOT_ID}
        base_api.pull["head"]["repo"]["full_name"] = REPOSITORY
        base_api.pull["head"]["ref"] = "release-plz-next"
        base_api.details[HEAD_SHA] = git_commit(
            parent=OLD_SHA,
            author_login=BOT,
            author_id=BOT_ID,
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
        with self.assertRaisesRegex(controller.PolicyError, "current main"):
            controller.authorize(event(), policy(), base_api, environment())

        api = copy.deepcopy(base_api)
        api.details[HEAD_SHA]["parents"] = [{"sha": MAIN_SHA}]
        api.set_change(".github/workflows/ci.yml")
        with self.assertRaisesRegex(controller.PolicyError, "allowlist"):
            controller.authorize(event(), policy(), api, environment())

    def test_comment_dispatch_ignores_near_misses_and_sanitizes_inputs(self) -> None:
        api = FakeAuthorizationApi()
        self.assertFalse(controller.dispatch_comment(event("looks useful"), policy(), api, environment()))
        self.assertEqual(api.posts, [])

        self.assertTrue(controller.dispatch_comment(event(), policy(), api, environment()))
        self.assertEqual(len(api.posts), 1)
        path, payload = api.posts[0]
        self.assertTrue(path.endswith("/actions/workflows/.github%2Fworkflows%2Fpr-ci.yml/dispatches"))
        self.assertEqual(payload["ref"], "main")
        self.assertEqual(payload["inputs"], workflow_dispatch_event()["inputs"])

    def test_dispatched_request_reloads_the_exact_comment(self) -> None:
        api = FakeAuthorizationApi()
        result = controller.authorize_dispatch(
            workflow_dispatch_event(), policy(), api, environment()
        )
        self.assertEqual(result.head_sha, HEAD_SHA)

        changed = workflow_dispatch_event()
        changed["inputs"]["head_sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "dispatch head SHA"):
            controller.authorize_dispatch(changed, policy(), api, environment())

    def test_dispatched_request_rejects_changed_comment_issue_or_ref(self) -> None:
        api = FakeAuthorizationApi()
        api.comment["body"] = f"/ok to test {OLD_SHA}"
        with self.assertRaisesRegex(controller.PolicyError, "exact current pull request head"):
            controller.authorize_dispatch(
                workflow_dispatch_event(), policy(), api, environment()
            )

        api = FakeAuthorizationApi()
        api.comment_issue_number = 8
        with self.assertRaisesRegex(controller.PolicyError, "another issue"):
            controller.authorize_dispatch(
                workflow_dispatch_event(), policy(), api, environment()
            )

        api = FakeAuthorizationApi()
        env = environment()
        env["GITHUB_REF"] = "refs/heads/release-plz-next"
        with self.assertRaisesRegex(controller.PolicyError, "exact main"):
            controller.authorize_dispatch(workflow_dispatch_event(), policy(), api, env)

    def test_direct_dispatch_requires_a_current_writer(self) -> None:
        api = FakeAuthorizationApi()
        api.permissions["outsider"] = "read"
        env = environment()
        env["GITHUB_ACTOR"] = "outsider"
        env["GITHUB_TRIGGERING_ACTOR"] = "outsider"
        with self.assertRaisesRegex(controller.PolicyError, "workflow dispatch actor"):
            controller.authorize_dispatch(workflow_dispatch_event(), policy(), api, env)

    def test_dispatched_rerun_requires_a_current_writer(self) -> None:
        api = FakeAuthorizationApi()
        env = environment()
        env["GITHUB_ACTOR"] = controller.GITHUB_ACTIONS_LOGIN
        env["GITHUB_TRIGGERING_ACTOR"] = controller.GITHUB_ACTIONS_LOGIN
        controller.authorize_dispatch(workflow_dispatch_event(), policy(), api, env)

        env["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaisesRegex(controller.PolicyError, "may not rerun"):
            controller.authorize_dispatch(workflow_dispatch_event(), policy(), api, env)


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
                ("modified.txt", "modified"),
                ("new-name.txt", "added"),
                ("old-name.txt", "removed"),
                ("removed.txt", "removed"),
            ],
        )

    def test_gitlink_replacement_retains_sensitive_root_identity(self) -> None:
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
        self.assertTrue(
            all(controller.is_sensitive(path, ["source-spec/**"]) for path in paths)
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


class FakeActionsApi:
    def __init__(self, runs) -> None:
        self.runs = runs

    def paginate_key(self, path, key, *, max_items, label):
        del path, key, max_items, label
        return self.runs


def external(run_id: int = 101, attempt: int = 1) -> object:
    return controller.ExternalId(
        repository=REPOSITORY,
        pull_number=7,
        head_sha=HEAD_SHA,
        base_sha=MAIN_SHA,
        policy_sha=MAIN_SHA,
        run_id=run_id,
        run_attempt=attempt,
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
        self.assertEqual(controller.ExternalId.decode(binding.encode()), binding)
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

    def test_expected_jobs_are_exact_and_skips_fail(self) -> None:
        expected = ["commit_policy", "workflow_lint"]
        self.assertEqual(
            controller.parse_results(
                ["commit_policy=success", "workflow_lint=success"], expected
            ),
            {"commit_policy": "success", "workflow_lint": "success"},
        )
        with self.assertRaisesRegex(controller.PolicyError, "exactly match"):
            controller.parse_results(["commit_policy=success"], expected)
        results = controller.parse_results(
            ["commit_policy=success", "workflow_lint=skipped"], expected
        )
        self.assertNotEqual(results["workflow_lint"], "success")

    def test_final_report_reauthorizes_and_requires_every_job(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        controller.finish_check(
            app_api,
            FakeAuthorizationApi(),
            policy(),
            workflow_dispatch_event(),
            environment(),
            binding,
            1,
            ["commit_policy=success", "workflow_lint=success"],
            APP_SLUG,
        )
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "success")

        app_api = FakeCheckApi([pending_check(1, binding)])
        with self.assertRaisesRegex(controller.PolicyError, "did not all succeed"):
            controller.finish_check(
                app_api,
                FakeAuthorizationApi(),
                policy(),
                workflow_dispatch_event(),
                environment(),
                binding,
                1,
                ["commit_policy=success", "workflow_lint=skipped"],
                APP_SLUG,
            )
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")

    def test_success_is_overwritten_if_main_advances_during_reconciliation(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        auth_api = FakeAuthorizationApi()
        auth_api.main_sha_sequence = [MAIN_SHA, MAIN_SHA, MAIN_SHA, OLD_SHA]

        with self.assertRaisesRegex(
            controller.PolicyError, "main changed during final check reconciliation"
        ):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                workflow_dispatch_event(),
                environment(),
                binding,
                1,
                ["commit_policy=success", "workflow_lint=success"],
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
        auth_api.main_error_on_read = 4

        with self.assertRaisesRegex(controller.PolicyError, "main ref reread failed"):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                workflow_dispatch_event(),
                environment(),
                binding,
                1,
                ["commit_policy=success", "workflow_lint=success"],
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
        auth_api.main_error_on_read = 4

        with self.assertRaisesRegex(controller.PolicyError, "binding is unexpected"):
            controller.finish_check(
                app_api,
                auth_api,
                policy(),
                workflow_dispatch_event(),
                environment(),
                binding,
                1,
                ["commit_policy=success", "workflow_lint=success"],
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
        run_event = {
            "action": "completed",
            "repository": {"full_name": REPOSITORY},
            "workflow_run": {
                "id": binding.run_id,
                "run_attempt": binding.run_attempt,
                "name": "Protected pull request CI",
                "path": ".github/workflows/pr-ci.yml",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": binding.policy_sha,
                "display_title": f"PR #7 /ok to test {HEAD_SHA}",
                "conclusion": "cancelled",
            },
        }
        count = controller.reconcile_run(api, policy(), run_event, REPOSITORY, APP_SLUG)
        self.assertEqual(count, 1)
        self.assertEqual(len(api.patches), 1)
        self.assertEqual(api.patches[0][1]["conclusion"], "cancelled")

    def test_late_retry_event_cannot_close_a_newer_attempt(self) -> None:
        binding = external(attempt=2)
        api = FakeCheckApi([pending_check(1, binding)])
        run_event = {
            "action": "completed",
            "repository": {"full_name": REPOSITORY},
            "workflow_run": {
                "id": binding.run_id,
                "run_attempt": 1,
                "name": "Protected pull request CI",
                "path": ".github/workflows/pr-ci.yml",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": binding.policy_sha,
                "display_title": f"PR #7 /ok to test {HEAD_SHA}",
                "conclusion": "cancelled",
            },
        }
        count = controller.reconcile_run(
            api, policy(), run_event, REPOSITORY, APP_SLUG
        )
        self.assertEqual(count, 0)
        self.assertEqual(api.patches, [])

    def test_sweep_closes_only_a_completed_bound_run(self) -> None:
        binding = external()
        app_api = FakeCheckApi([pending_check(1, binding)])
        run = {
            "id": binding.run_id,
            "run_attempt": binding.run_attempt,
            "name": "Protected pull request CI",
            "path": ".github/workflows/pr-ci.yml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": binding.policy_sha,
            "display_title": f"PR #7 /ok to test {HEAD_SHA}",
            "status": "completed",
            "conclusion": "failure",
        }
        count = controller.sweep_runs(
            app_api,
            FakeActionsApi([run]),
            policy(),
            REPOSITORY,
            APP_SLUG,
        )
        self.assertEqual(count, 1)
        self.assertEqual(app_api.patches[-1][1]["conclusion"], "failure")


if __name__ == "__main__":
    unittest.main()

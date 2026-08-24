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
            "AGENTS.md",
            ".agents/**",
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


class FakeAuthorizationApi:
    def __init__(self) -> None:
        self.api_url = "https://api.github.com"
        self.main_sha = MAIN_SHA
        self.permissions = {MAINTAINER: "write"}
        self.files = [{"filename": "README.md", "status": "modified"}]
        self.commits = [{"sha": HEAD_SHA, "parents": [{"sha": MAIN_SHA}]}]
        self.details = {HEAD_SHA: git_commit()}
        self.comment = copy.deepcopy(event()["comment"])
        self.comment_issue_number = 7
        self.posts = []
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

    def get(self, path: str):
        if "/collaborators/" in path and path.endswith("/permission"):
            login = path.split("/collaborators/", 1)[1].rsplit("/permission", 1)[0]
            return {"permission": self.permissions.get(login, "none")}
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"type": "commit", "sha": self.main_sha}}
        if path.endswith("/pulls/7"):
            return self.pull
        if path.endswith("/issues/comments/19"):
            value = copy.deepcopy(self.comment)
            value["issue_url"] = (
                f"{self.api_url}/repos/{REPOSITORY}/issues/"
                f"{self.comment_issue_number}"
            )
            return value
        if "/commits/" in path:
            sha = path.rsplit("/", 1)[1]
            return self.details[sha]
        raise AssertionError(f"unexpected GET {path}")

    def paginate(self, path: str, *, max_items: int, label: str):
        del path, max_items
        if label == "pull request files":
            return self.files
        if label == "pull request commits":
            return self.commits
        raise AssertionError(f"unexpected pagination label {label}")

    def post(self, path: str, payload: dict):
        self.posts.append((path, payload))
        return None


class AuthorizationTests(unittest.TestCase):
    def test_repository_policy_configuration_is_valid(self) -> None:
        controller.load_config(str(POLICY_PATH))

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

    def test_pagination_count_mismatch_is_rejected(self) -> None:
        api = FakeAuthorizationApi()
        api.pull["changed_files"] = 2
        with self.assertRaisesRegex(controller.PolicyError, "pagination"):
            controller.authorize(event(), policy(), api, environment())

    def test_renamed_sensitive_source_and_unknown_status_fail_closed(self) -> None:
        api = FakeAuthorizationApi()
        api.files = [
            {
                "filename": "docs/retired-workflow.md",
                "previous_filename": ".github/workflows/ci.yml",
                "status": "renamed",
            }
        ]
        with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
            controller.authorize(event(), policy(), api, environment())

        api = FakeAuthorizationApi()
        api.files[0]["status"] = "mystery"
        with self.assertRaisesRegex(controller.PolicyError, "unknown status"):
            controller.authorize(event(), policy(), api, environment())

    def test_sensitive_fork_change_runs_no_candidate_policy(self) -> None:
        api = FakeAuthorizationApi()
        api.files = [{"filename": ".github/workflows/ci.yml", "status": "modified"}]
        with self.assertRaisesRegex(controller.PolicyError, "same-repository branch"):
            controller.authorize(event(), policy(), api, environment())

    def test_verified_writer_adoption_requires_both_dco_identities(self) -> None:
        api = FakeAuthorizationApi()
        api.files = [{"filename": "Cargo.toml", "status": "modified"}]
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
        api.files = [{"filename": "AGENTS.md", "status": "modified"}]
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
        api.files = [{"filename": "Cargo.toml", "status": "modified"}]
        api.pull["head"]["repo"]["full_name"] = REPOSITORY
        api.details[HEAD_SHA]["sha"] = OLD_SHA
        with self.assertRaisesRegex(controller.PolicyError, "requested SHA"):
            controller.authorize(event(), policy(), api, environment())

    def test_exact_release_app_author_and_committer_are_accepted(self) -> None:
        api = FakeAuthorizationApi()
        api.files = [{"filename": "Cargo.toml", "status": "modified"}]
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

        api.files[0]["status"] = "removed"
        with self.assertRaisesRegex(controller.PolicyError, "only modify existing"):
            controller.authorize(event(), policy(), api, environment())

    def release_app_api(self) -> FakeAuthorizationApi:
        api = FakeAuthorizationApi()
        api.files = [{"filename": "Cargo.toml", "status": "modified"}]
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
        base_api.files = [{"filename": "Cargo.toml", "status": "modified"}]
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
        api.files = [{"filename": ".github/workflows/ci.yml", "status": "modified"}]
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


class FakeCheckApi:
    def __init__(self, checks=None) -> None:
        self.checks = list(checks or [])
        self.patches = []
        self.posts = []

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
        return check

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

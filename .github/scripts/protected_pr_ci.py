#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Authorize and report protected-main pull-request validation.

The workflow that invokes this module is loaded from the protected default
branch.  Candidate commits are treated only as data until ``authorize`` has
checked the exact command, current repository state, live permissions, and
sensitive-path policy.  Check runs are created and updated only with the
repository's narrowly scoped GitHub App token.

This module intentionally uses only the Python standard library so privileged
check jobs can download it at an immutable policy commit without checking out
a candidate or installing packages.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


API_VERSION = "2022-11-28"
COMMAND_RE = re.compile(r"/ok to test ([0-9a-f]{40})")
RUN_TITLE_RE = re.compile(r"PR #([1-9][0-9]*) /ok to test ([0-9a-f]{40})")
SHA_RE = re.compile(r"[0-9a-f]{40}")
WRITER_PERMISSIONS = frozenset({"write", "push", "maintain", "admin"})
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
TERMINAL_CHECK_STATUSES = frozenset({"completed"})
CHECK_NAME = "Required CI"
MAX_CHANGED_PATHS = 3_000
MAX_PULL_COMMITS = 250
MAX_TREE_ENTRIES = 100_000
MAX_PAGES = 100


class PolicyError(RuntimeError):
    """A closed-policy decision or ambiguous API response."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_sequence(value: Any, label: str) -> Sequence[Any]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and value != "", f"{label} must be a nonempty string")
    return value


def require_integer(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    return value


def validate_sha(value: Any, label: str) -> str:
    sha = require_string(value, label)
    require(SHA_RE.fullmatch(sha) is not None, f"{label} must be a lowercase 40-character SHA")
    return sha


def validate_login(value: Any, label: str) -> str:
    login = require_string(value, label)
    require(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[bot\])?", login)
        is not None,
        f"{label} is not a valid GitHub login",
    )
    return login


def validate_repository(value: Any, label: str = "repository") -> str:
    repository = require_string(value, label)
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        f"{label} must be owner/name",
    )
    return repository


def validate_path(value: Any, label: str) -> str:
    path = require_string(value, label)
    pure = PurePosixPath(path)
    require(not pure.is_absolute(), f"{label} must be repository-relative")
    require("\\" not in path and "\x00" not in path, f"{label} is not normalized")
    require(
        all(part not in {"", ".", ".."} for part in path.split("/")),
        f"{label} is not normalized",
    )
    require(not any(ord(char) < 32 for char in path), f"{label} contains a control character")
    return path


def load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot read {path}: {error}") from error


def load_config(path: str) -> Mapping[str, Any]:
    config = require_mapping(load_json(path), "policy configuration")
    required = {
        "version",
        "default_branch",
        "workflow_file",
        "required_check",
        "release_app",
        "expected_jobs",
        "sensitive_paths",
    }
    require(set(config) == required, "policy configuration keys are incomplete or ambiguous")
    require(config["version"] == 1, "unsupported policy configuration version")
    require(config["default_branch"] == "main", "the protected branch must be exact main")
    validate_path(config["workflow_file"], "workflow_file")
    require(config["required_check"] == CHECK_NAME, f"required_check must be {CHECK_NAME!r}")

    release_app = require_mapping(config["release_app"], "release_app")
    app_keys = {
        "enabled",
        "login",
        "bot_user_id",
        "slug",
        "head_ref",
        "commit_author_name",
        "commit_author_email",
        "commit_committer_login",
        "commit_committer_user_id",
        "commit_committer_name",
        "commit_committer_email",
        "allowed_paths",
    }
    require(set(release_app) == app_keys, "release_app keys are incomplete or ambiguous")
    require(isinstance(release_app["enabled"], bool), "release_app.enabled must be boolean")
    validate_login(release_app["login"], "release_app.login")
    require(
        require_integer(release_app["bot_user_id"], "release_app.bot_user_id") > 0,
        "release_app.bot_user_id must be positive",
    )
    validate_login(release_app["slug"], "release_app.slug")
    require_string(release_app["head_ref"], "release_app.head_ref")
    require_string(release_app["commit_author_name"], "release_app.commit_author_name")
    require_string(release_app["commit_author_email"], "release_app.commit_author_email")
    validate_login(
        release_app["commit_committer_login"],
        "release_app.commit_committer_login",
    )
    require(
        require_integer(
            release_app["commit_committer_user_id"],
            "release_app.commit_committer_user_id",
        )
        > 0,
        "release_app.commit_committer_user_id must be positive",
    )
    require_string(
        release_app["commit_committer_name"],
        "release_app.commit_committer_name",
    )
    require_string(
        release_app["commit_committer_email"],
        "release_app.commit_committer_email",
    )
    allowed_paths = require_sequence(release_app["allowed_paths"], "release_app.allowed_paths")
    require(
        len(set(allowed_paths)) == len(allowed_paths),
        "release_app.allowed_paths must not contain duplicates",
    )
    for index, item in enumerate(allowed_paths):
        validate_path(item, f"release_app.allowed_paths[{index}]")

    jobs = require_sequence(config["expected_jobs"], "expected_jobs")
    require(jobs and len(set(jobs)) == len(jobs), "expected_jobs must be nonempty and unique")
    for index, job in enumerate(jobs):
        require(
            isinstance(job, str) and re.fullmatch(r"[a-z][a-z0-9_]*", job) is not None,
            f"expected_jobs[{index}] is not a job identifier",
        )

    patterns = require_sequence(config["sensitive_paths"], "sensitive_paths")
    require(patterns and len(set(patterns)) == len(patterns), "sensitive_paths must be nonempty and unique")
    for index, pattern in enumerate(patterns):
        require_string(pattern, f"sensitive_paths[{index}]")
        require("\\" not in pattern and not pattern.startswith("/"), f"sensitive_paths[{index}] is invalid")
    return config


class GitHubApi:
    """Small fail-closed GitHub REST client."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        require(token != "", "GitHub API token is empty")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        require(path.startswith("/"), "GitHub API path must be absolute")
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "yaml-sigil-protected-pr-ci/1",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.api_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                require(200 <= response.status < 300, f"GitHub API returned HTTP {response.status}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise PolicyError(f"GitHub API {method} {path} failed with HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise PolicyError(f"GitHub API {method} {path} failed: {error}") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise PolicyError(f"GitHub API {method} {path} returned invalid JSON") from error

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", path, payload)

    def patch(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("PATCH", path, payload)

    def paginate(self, path: str, *, max_items: int, label: str) -> list[Any]:
        items: list[Any] = []
        for page in range(1, MAX_PAGES + 1):
            separator = "&" if "?" in path else "?"
            value = self.get(f"{path}{separator}per_page=100&page={page}")
            page_items = require_sequence(value, f"{label} page {page}")
            items.extend(page_items)
            require(len(items) <= max_items, f"{label} exceeds the supported limit of {max_items}")
            if len(page_items) < 100:
                return items
        raise PolicyError(f"{label} pagination did not terminate")

    def paginate_key(
        self, path: str, key: str, *, max_items: int, label: str
    ) -> list[Any]:
        items: list[Any] = []
        declared_total: int | None = None
        for page in range(1, MAX_PAGES + 1):
            separator = "&" if "?" in path else "?"
            value = require_mapping(
                self.get(f"{path}{separator}per_page=100&page={page}"),
                f"{label} page {page}",
            )
            page_items = require_sequence(value.get(key), f"{label}.{key} page {page}")
            total = require_integer(value.get("total_count"), f"{label}.total_count")
            if declared_total is None:
                declared_total = total
                require(total <= max_items, f"{label} exceeds the supported limit of {max_items}")
            else:
                require(total == declared_total, f"{label} total changed during pagination")
            items.extend(page_items)
            require(len(items) <= max_items, f"{label} exceeds the supported limit of {max_items}")
            if len(page_items) < 100:
                require(len(items) == declared_total, f"{label} pagination was incomplete")
                return items
        raise PolicyError(f"{label} pagination did not terminate")


def repo_api_path(repository: str, suffix: str) -> str:
    owner, name = validate_repository(repository).split("/", 1)
    return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}{suffix}"


def permission_for(api: GitHubApi, repository: str, login: str) -> str:
    login = validate_login(login, "permission login")
    result = require_mapping(
        api.get(repo_api_path(repository, f"/collaborators/{urllib.parse.quote(login, safe='')}/permission")),
        f"permission for {login}",
    )
    permission = require_string(result.get("permission"), f"permission for {login}")
    require(permission in {"none", "read", "triage", *WRITER_PERMISSIONS}, f"unknown permission {permission!r}")
    return permission


def require_writer(api: GitHubApi, repository: str, login: str, label: str) -> None:
    permission = permission_for(api, repository, login)
    require(permission in WRITER_PERMISSIONS, f"{label} does not currently have write authority")


def command_sha(body: Any) -> str | None:
    if not isinstance(body, str):
        return None
    match = COMMAND_RE.fullmatch(body)
    return match.group(1) if match is not None else None


def exact_command(body: Any) -> str:
    requested_sha = command_sha(body)
    require(
        requested_sha is not None,
        "comment must be exactly /ok to test followed by a lowercase full head SHA",
    )
    assert requested_sha is not None
    return requested_sha


def normalized_casefold(value: str) -> str:
    """Return the compatibility-normalized, case-insensitive identity."""

    normalized = unicodedata.normalize("NFKC", value)
    return unicodedata.normalize("NFKC", normalized.casefold())


def is_sensitive(path: str, patterns: Sequence[str]) -> bool:
    """Match declarations, treating a trailing ``/**`` as including its root."""
    identity = normalized_casefold(path)
    for pattern in patterns:
        declaration = normalized_casefold(pattern)
        if fnmatch.fnmatchcase(identity, declaration):
            return True
        if declaration.endswith("/**") and fnmatch.fnmatchcase(
            identity, declaration[:-3]
        ):
            return True
    return False


def commit_identities(commit: Mapping[str, Any]) -> tuple[str, str]:
    details = require_mapping(commit.get("commit"), "commit details")
    author = require_mapping(details.get("author"), "commit author")
    committer = require_mapping(details.get("committer"), "commit committer")
    author_identity = f"{require_string(author.get('name'), 'commit author name')} <{require_string(author.get('email'), 'commit author email')}>"
    committer_identity = f"{require_string(committer.get('name'), 'commit committer name')} <{require_string(committer.get('email'), 'commit committer email')}>"
    return author_identity, committer_identity


def signoffs(message: Any) -> set[str]:
    text = require_string(message, "commit message")
    found = set()
    for line in text.splitlines():
        match = re.fullmatch(r"Signed-off-by:\s*(.+)", line, flags=re.IGNORECASE)
        if match:
            found.add(match.group(1))
    return found


def require_verified(commit: Mapping[str, Any], label: str) -> None:
    details = require_mapping(commit.get("commit"), f"{label} details")
    verification = require_mapping(details.get("verification"), f"{label} verification")
    require(verification.get("verified") is True, f"{label} is not GitHub Verified")
    require(verification.get("reason") == "valid", f"{label} verification is not valid")


def require_dco(commit: Mapping[str, Any], *, require_committer: bool, label: str) -> None:
    details = require_mapping(commit.get("commit"), f"{label} details")
    found = signoffs(details.get("message"))
    author, committer = commit_identities(commit)
    require(author in found, f"{label} lacks the author's DCO sign-off")
    if require_committer:
        require(committer in found, f"{label} lacks the adopting committer's DCO sign-off")


def current_main(api: GitHubApi, repository: str, branch: str) -> str:
    ref = require_mapping(api.get(repo_api_path(repository, f"/git/ref/heads/{branch}")), "main ref")
    obj = require_mapping(ref.get("object"), "main ref object")
    require(obj.get("type") == "commit", "main ref does not identify a commit")
    return validate_sha(obj.get("sha"), "current main SHA")


TreeLeaf = tuple[str, str, str]


@dataclass(frozen=True)
class GitTree:
    paths: frozenset[str]
    leaves: Mapping[str, TreeLeaf]


def git_tree_for_commit(
    api: GitHubApi, repository: str, commit_sha: str, label: str
) -> GitTree:
    """Load one complete recursive tree bound to an exact Git commit object."""

    commit = require_mapping(
        api.get(repo_api_path(repository, f"/git/commits/{commit_sha}")),
        f"{label} Git commit",
    )
    require(
        validate_sha(commit.get("sha"), f"{label} Git commit response SHA")
        == commit_sha,
        f"{label} Git commit response does not match the requested SHA",
    )
    tree = require_mapping(commit.get("tree"), f"{label} Git commit tree")
    tree_sha = validate_sha(tree.get("sha"), f"{label} Git commit tree SHA")
    response = require_mapping(
        api.get(repo_api_path(repository, f"/git/trees/{tree_sha}?recursive=1")),
        f"{label} recursive Git tree",
    )
    require(
        validate_sha(response.get("sha"), f"{label} recursive Git tree SHA")
        == tree_sha,
        f"{label} recursive Git tree does not match its commit",
    )
    require(
        response.get("truncated") is False,
        f"{label} recursive Git tree is truncated or ambiguous",
    )
    entries = require_sequence(response.get("tree"), f"{label} recursive Git tree entries")
    require(
        len(entries) <= MAX_TREE_ENTRIES,
        f"{label} recursive Git tree exceeds the supported limit of {MAX_TREE_ENTRIES}",
    )

    paths: set[str] = set()
    entry_types: dict[str, str] = {}
    leaves: dict[str, TreeLeaf] = {}
    valid_modes = {
        "blob": frozenset({"100644", "100755", "120000"}),
        "tree": frozenset({"040000"}),
        "commit": frozenset({"160000"}),
    }
    for index, value in enumerate(entries):
        entry = require_mapping(value, f"{label} Git tree entry {index}")
        path = validate_path(entry.get("path"), f"{label} Git tree entry {index} path")
        require(path not in paths, f"{label} recursive Git tree contains duplicate paths")
        entry_type = require_string(
            entry.get("type"), f"{label} Git tree entry {index} type"
        )
        require(
            entry_type in valid_modes,
            f"{label} Git tree entry {index} has an unsupported type",
        )
        mode = require_string(entry.get("mode"), f"{label} Git tree entry {index} mode")
        require(
            mode in valid_modes[entry_type],
            f"{label} Git tree entry {index} has an invalid mode",
        )
        sha = validate_sha(entry.get("sha"), f"{label} Git tree entry {index} SHA")
        paths.add(path)
        entry_types[path] = entry_type
        if entry_type != "tree":
            leaves[path] = (entry_type, mode, sha)

    for path in paths:
        parts = path.split("/")
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            require(
                entry_types.get(parent) == "tree",
                f"{label} recursive Git tree omits a parent tree entry",
            )
    return GitTree(paths=frozenset(paths), leaves=leaves)


def require_no_path_collisions(paths: Iterable[str]) -> None:
    """Reject checkout-ambiguous candidate paths before candidate execution."""

    identities: dict[str, str] = {}
    for path in sorted(paths):
        identity = normalized_casefold(path)
        previous = identities.setdefault(identity, path)
        require(
            previous == path,
            "candidate tree contains Unicode-normalized casefold path collisions",
        )


def changed_tree_paths(base: GitTree, head: GitTree) -> tuple[list[str], list[str]]:
    """Derive leaf changes from immutable trees; a rename is remove plus add."""

    paths = sorted(set(base.leaves) | set(head.leaves))
    paths = [path for path in paths if base.leaves.get(path) != head.leaves.get(path)]
    require(
        len(paths) <= MAX_CHANGED_PATHS,
        f"tree diff exceeds the supported limit of {MAX_CHANGED_PATHS}",
    )
    statuses = []
    for path in paths:
        if path not in base.leaves:
            statuses.append("added")
        elif path not in head.leaves:
            statuses.append("removed")
        else:
            statuses.append("modified")
    return paths, statuses


def pull_commits(api: GitHubApi, repository: str, number: int, expected: int) -> list[Mapping[str, Any]]:
    require(1 <= expected <= MAX_PULL_COMMITS, "pull request commit count is outside the supported range")
    values = api.paginate(
        repo_api_path(repository, f"/pulls/{number}/commits"),
        max_items=MAX_PULL_COMMITS,
        label="pull request commits",
    )
    require(len(values) == expected, "pull request commit pagination did not match commits")
    commits = [require_mapping(value, f"pull request commit {index}") for index, value in enumerate(values)]
    shas = [validate_sha(commit.get("sha"), f"pull request commit {index} SHA") for index, commit in enumerate(commits)]
    require(len(set(shas)) == len(shas), "pull request commits contain duplicate SHAs")
    return commits


def require_live_authorization_state(
    api: GitHubApi,
    repository: str,
    branch: str,
    pull_number: int,
    main_sha: str,
    head_sha: str,
    head_repository: str,
    head_ref: str,
    *,
    phase: str = "pull request authorization",
) -> None:
    """Re-read mutable PR and main refs at a reporting security boundary."""

    require(
        current_main(api, repository, branch) == main_sha,
        f"main changed during {phase}",
    )
    pull = require_mapping(
        api.get(repo_api_path(repository, f"/pulls/{pull_number}")),
        "rechecked pull request",
    )
    require(pull.get("state") == "open", f"pull request closed during {phase}")
    require(pull.get("number") == pull_number, f"pull request number changed during {phase}")
    base = require_mapping(pull.get("base"), "rechecked pull request base")
    base_repo = require_mapping(base.get("repo"), "rechecked pull request base repository")
    require(
        base_repo.get("full_name") == repository
        and base.get("ref") == branch
        and validate_sha(base.get("sha"), "rechecked pull request base SHA") == main_sha,
        f"pull request base changed during {phase}",
    )
    head = require_mapping(pull.get("head"), "rechecked pull request head")
    head_repo = require_mapping(head.get("repo"), "rechecked pull request head repository")
    require(
        validate_sha(head.get("sha"), "rechecked pull request head SHA") == head_sha
        and validate_repository(
            head_repo.get("full_name"), "rechecked pull request head repository"
        )
        == head_repository
        and require_string(head.get("ref"), "rechecked pull request head ref")
        == head_ref,
        f"pull request head changed during {phase}",
    )
    require(
        current_main(api, repository, branch) == main_sha,
        f"main changed during {phase}",
    )


def require_commit_chain(
    commits: Sequence[Mapping[str, Any]], base_sha: str, head_sha: str
) -> None:
    expected_parent = base_sha
    for index, commit in enumerate(commits):
        sha = validate_sha(commit.get("sha"), f"pull request commit {index} SHA")
        parents = require_sequence(commit.get("parents"), f"pull request commit {index} parents")
        require(len(parents) == 1, f"pull request commit {index} must be linear")
        parent = require_mapping(parents[0], f"pull request commit {index} parent")
        require(
            validate_sha(parent.get("sha"), f"pull request commit {index} parent SHA")
            == expected_parent,
            "pull request head is not a linear descendant of current main",
        )
        expected_parent = sha
    require(expected_parent == head_sha, "pull request commit chain does not end at the head")


def full_commit(api: GitHubApi, repository: str, sha: str) -> Mapping[str, Any]:
    commit = require_mapping(
        api.get(repo_api_path(repository, f"/commits/{sha}")), f"commit {sha}"
    )
    require(
        validate_sha(commit.get("sha"), f"commit {sha} response SHA") == sha,
        "commit response does not match the requested SHA",
    )
    return commit


def require_release_app_change(
    api: GitHubApi,
    repository: str,
    pull: Mapping[str, Any],
    commits: Sequence[Mapping[str, Any]],
    paths: Sequence[str],
    statuses: Sequence[str],
    main_sha: str,
    release_app: Mapping[str, Any],
) -> None:
    require(release_app.get("enabled") is True, "release App exception is disabled")
    user = require_mapping(pull.get("user"), "pull request author")
    require(user.get("login") == release_app.get("login"), "pull request is not owned by the release App")
    require(
        user.get("id") == release_app.get("bot_user_id"),
        "pull request author ID does not match the release App",
    )
    head = require_mapping(pull.get("head"), "pull request head")
    head_repo = require_mapping(head.get("repo"), "pull request head repository")
    require(head_repo.get("full_name") == repository, "release App head must be in this repository")
    require(head.get("ref") == release_app.get("head_ref"), "release App head branch is unexpected")
    require(len(commits) == 1, "release App proposal must contain exactly one commit")
    allowed = set(require_sequence(release_app.get("allowed_paths"), "release App allowed paths"))
    require(paths and set(paths) <= allowed, "release App proposal changed a path outside its generated-file allowlist")
    require(
        statuses and all(status == "modified" for status in statuses),
        "release App proposal may only modify existing generated files",
    )

    sha = validate_sha(commits[0].get("sha"), "release App commit SHA")
    commit = full_commit(api, repository, sha)
    parents = require_sequence(commit.get("parents"), "release App commit parents")
    require(len(parents) == 1, "release App commit must have exactly one parent")
    parent = require_mapping(parents[0], "release App commit parent")
    require(parent.get("sha") == main_sha, "release App commit parent is not current main")
    author = require_mapping(commit.get("author"), "release App commit author")
    require(author.get("login") == release_app.get("login"), "release App commit author is unexpected")
    require(
        author.get("id") == release_app.get("bot_user_id"),
        "release App commit author ID is unexpected",
    )
    committer = require_mapping(commit.get("committer"), "release App commit committer")
    require(
        committer.get("login") == release_app.get("commit_committer_login"),
        "release App commit committer is unexpected",
    )
    require(
        committer.get("id") == release_app.get("commit_committer_user_id"),
        "release App commit committer ID is unexpected",
    )
    details = require_mapping(commit.get("commit"), "release App commit details")
    raw_author = require_mapping(details.get("author"), "release App raw commit author")
    require(
        raw_author.get("name") == release_app.get("commit_author_name"),
        "release App raw commit author name is unexpected",
    )
    require(
        raw_author.get("email") == release_app.get("commit_author_email"),
        "release App raw commit author email is unexpected",
    )
    raw_committer = require_mapping(
        details.get("committer"), "release App raw commit committer"
    )
    require(
        raw_committer.get("name") == release_app.get("commit_committer_name"),
        "release App raw commit committer name is unexpected",
    )
    require(
        raw_committer.get("email") == release_app.get("commit_committer_email"),
        "release App raw commit committer email is unexpected",
    )
    require_verified(commit, "release App commit")
    require_dco(commit, require_committer=False, label="release App commit")


def require_adopted_change(
    api: GitHubApi,
    repository: str,
    pull: Mapping[str, Any],
    commits: Sequence[Mapping[str, Any]],
) -> None:
    head = require_mapping(pull.get("head"), "pull request head")
    head_repo = require_mapping(head.get("repo"), "pull request head repository")
    require(head_repo.get("full_name") == repository, "sensitive changes require a same-repository branch")

    for index, summary in enumerate(commits):
        sha = validate_sha(summary.get("sha"), f"adopted commit {index} SHA")
        commit = full_commit(api, repository, sha)
        parents = require_sequence(commit.get("parents"), f"adopted commit {index} parents")
        require(len(parents) == 1, f"adopted commit {index} must be linear")
        require_verified(commit, f"adopted commit {index}")
        committer = require_mapping(commit.get("committer"), f"adopted commit {index} GitHub committer")
        login = validate_login(committer.get("login"), f"adopted commit {index} GitHub committer login")
        require_writer(api, repository, login, f"adopted commit {index} committer")
        require_dco(commit, require_committer=True, label=f"adopted commit {index}")


@dataclass(frozen=True)
class Authorization:
    repository: str
    pull_number: int
    head_sha: str
    base_sha: str
    head_repository: str
    head_ref: str
    policy_sha: str
    comment_id: int

    def github_outputs(self) -> Mapping[str, str]:
        return {
            "repository": self.repository,
            "pull_number": str(self.pull_number),
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "head_repository": self.head_repository,
            "policy_sha": self.policy_sha,
            "comment_id": str(self.comment_id),
        }


def authorize(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
) -> Authorization:
    require(event.get("action") == "created", "only newly created comments are accepted")
    repository = validate_repository(environment.get("GITHUB_REPOSITORY"), "GITHUB_REPOSITORY")
    event_repo = require_mapping(event.get("repository"), "event repository")
    require(event_repo.get("full_name") == repository, "event repository does not match the workflow repository")

    issue = require_mapping(event.get("issue"), "event issue")
    require(isinstance(issue.get("pull_request"), dict), "the comment is not on a pull request")
    pull_number = require_integer(issue.get("number"), "pull request number")
    require(pull_number > 0, "pull request number must be positive")
    comment = require_mapping(event.get("comment"), "event comment")
    requested_sha = exact_command(comment.get("body"))
    comment_id = require_integer(comment.get("id"), "comment id")
    require(comment_id > 0, "comment id must be positive")
    commenter = validate_login(require_mapping(comment.get("user"), "comment user").get("login"), "commenter")
    actor = validate_login(environment.get("GITHUB_ACTOR"), "GITHUB_ACTOR")
    triggering_actor = validate_login(environment.get("GITHUB_TRIGGERING_ACTOR"), "GITHUB_TRIGGERING_ACTOR")
    require(commenter == actor, "workflow actor does not match the comment author")
    require_writer(api, repository, commenter, "comment author")
    require_writer(api, repository, triggering_actor, "triggering actor")

    policy_sha = validate_sha(environment.get("POLICY_SHA"), "POLICY_SHA")
    branch = require_string(config.get("default_branch"), "default_branch")
    main_sha = current_main(api, repository, branch)
    require(main_sha == policy_sha, "the workflow policy commit is no longer current main")

    pull = require_mapping(api.get(repo_api_path(repository, f"/pulls/{pull_number}")), "pull request")
    require(pull.get("state") == "open", "pull request is not open")
    require(pull.get("number") == pull_number, "pull request number is ambiguous")
    base = require_mapping(pull.get("base"), "pull request base")
    base_repo = require_mapping(base.get("repo"), "pull request base repository")
    require(base_repo.get("full_name") == repository, "pull request targets another repository")
    require(base.get("ref") == branch, "pull request does not target exact main")
    base_sha = validate_sha(base.get("sha"), "pull request base SHA")
    require(base_sha == main_sha, "pull request base is not current main")
    head = require_mapping(pull.get("head"), "pull request head")
    head_sha = validate_sha(head.get("sha"), "pull request head SHA")
    require(head_sha == requested_sha, "comment SHA is not the exact current pull request head")
    head_repo = require_mapping(head.get("repo"), "pull request head repository")
    head_repository = validate_repository(head_repo.get("full_name"), "pull request head repository")
    head_ref = require_string(head.get("ref"), "pull request head ref")

    base_tree = git_tree_for_commit(api, repository, base_sha, "base")
    # GitHub retains the exact PR head object in the base repository. Keep both
    # immutable-tree reads inside the installation token's repository scope.
    head_tree = git_tree_for_commit(api, repository, head_sha, "head")
    require_no_path_collisions(head_tree.paths)
    paths, statuses = changed_tree_paths(base_tree, head_tree)
    commit_count = require_integer(pull.get("commits"), "pull request commits")
    commits = pull_commits(api, repository, pull_number, commit_count)
    require(validate_sha(commits[-1].get("sha"), "last pull request commit SHA") == head_sha, "commit list does not end at pull request head")
    require_commit_chain(commits, base_sha, head_sha)

    patterns = [require_string(value, "sensitive path pattern") for value in require_sequence(config.get("sensitive_paths"), "sensitive_paths")]
    sensitive = [path for path in paths if is_sensitive(path, patterns)]
    if sensitive:
        release_app = require_mapping(config.get("release_app"), "release_app")
        user = require_mapping(pull.get("user"), "pull request author")
        if user.get("login") == release_app.get("login"):
            require_release_app_change(
                api, repository, pull, commits, paths, statuses, main_sha, release_app
            )
        else:
            require_adopted_change(api, repository, pull, commits)

    require_live_authorization_state(
        api,
        repository,
        branch,
        pull_number,
        main_sha,
        head_sha,
        head_repository,
        head_ref,
    )

    return Authorization(
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        policy_sha=policy_sha,
        comment_id=comment_id,
    )


def positive_decimal(value: Any, label: str) -> int:
    text = require_string(value, label)
    require(re.fullmatch(r"[1-9][0-9]*", text) is not None, f"{label} must be a positive decimal integer")
    return int(text)


def dispatch_inputs(event: Mapping[str, Any]) -> Mapping[str, Any]:
    inputs = require_mapping(event.get("inputs"), "workflow dispatch inputs")
    required = {"pull_number", "head_sha", "base_sha", "policy_sha", "comment_id"}
    require(set(inputs) == required, "workflow dispatch input keys are incomplete or ambiguous")
    return inputs


def original_comment_event(
    api: GitHubApi,
    repository: str,
    pull_number: int,
    comment_id: int,
) -> Mapping[str, Any]:
    comment = require_mapping(
        api.get(repo_api_path(repository, f"/issues/comments/{comment_id}")),
        "original comment",
    )
    require(comment.get("id") == comment_id, "original comment ID is ambiguous")
    expected_issue_url = f"{api.api_url}{repo_api_path(repository, f'/issues/{pull_number}')}"
    require(comment.get("issue_url") == expected_issue_url, "original comment belongs to another issue")
    return {
        "action": "created",
        "repository": {"full_name": repository},
        "issue": {"number": pull_number, "pull_request": {}},
        "comment": comment,
    }


def require_dispatch_actor(
    api: GitHubApi,
    repository: str,
    environment: Mapping[str, str],
) -> None:
    actor = validate_login(environment.get("GITHUB_ACTOR"), "GITHUB_ACTOR")
    triggering_actor = validate_login(
        environment.get("GITHUB_TRIGGERING_ACTOR"), "GITHUB_TRIGGERING_ACTOR"
    )
    run_attempt = positive_decimal(environment.get("GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT")
    if actor != GITHUB_ACTIONS_LOGIN:
        require_writer(api, repository, actor, "workflow dispatch actor")
    if triggering_actor == GITHUB_ACTIONS_LOGIN:
        require(run_attempt == 1, "an automated identity may not rerun protected validation")
    else:
        require_writer(api, repository, triggering_actor, "workflow dispatch triggering actor")


def authorize_dispatch(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
) -> Authorization:
    repository = validate_repository(environment.get("GITHUB_REPOSITORY"), "GITHUB_REPOSITORY")
    branch = require_string(config.get("default_branch"), "default_branch")
    require(
        environment.get("GITHUB_REF") == f"refs/heads/{branch}",
        "protected validation must be dispatched on exact main",
    )
    event_repo = require_mapping(event.get("repository"), "event repository")
    require(event_repo.get("full_name") == repository, "event repository does not match the workflow repository")
    inputs = dispatch_inputs(event)
    pull_number = positive_decimal(inputs.get("pull_number"), "pull_number input")
    comment_id = positive_decimal(inputs.get("comment_id"), "comment_id input")
    requested_head = validate_sha(inputs.get("head_sha"), "head_sha input")
    requested_base = validate_sha(inputs.get("base_sha"), "base_sha input")
    requested_policy = validate_sha(inputs.get("policy_sha"), "policy_sha input")
    policy_sha = validate_sha(environment.get("POLICY_SHA"), "POLICY_SHA")
    require(requested_policy == policy_sha, "dispatch policy SHA is not the workflow policy SHA")

    comment_event = original_comment_event(api, repository, pull_number, comment_id)
    original_comment = require_mapping(comment_event.get("comment"), "original comment")
    original_user = require_mapping(original_comment.get("user"), "original comment user")
    commenter = validate_login(original_user.get("login"), "original commenter")
    synthetic_environment = dict(environment)
    synthetic_environment["GITHUB_ACTOR"] = commenter
    synthetic_environment["GITHUB_TRIGGERING_ACTOR"] = commenter
    result = authorize(comment_event, config, api, synthetic_environment)
    require(result.head_sha == requested_head, "dispatch head SHA differs from the authorized request")
    require(result.base_sha == requested_base, "dispatch base SHA differs from the authorized request")
    require(result.policy_sha == requested_policy, "dispatch policy SHA differs from the authorized request")
    require(result.comment_id == comment_id, "dispatch comment ID differs from the authorized request")
    require_dispatch_actor(api, repository, environment)
    return result


def dispatch_comment(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
) -> bool:
    comment = event.get("comment")
    if not isinstance(comment, dict) or command_sha(comment.get("body")) is None:
        return False
    authorization = authorize(event, config, api, environment)
    workflow_file = validate_path(config.get("workflow_file"), "workflow_file")
    encoded_workflow = urllib.parse.quote(workflow_file, safe="")
    api.post(
        repo_api_path(authorization.repository, f"/actions/workflows/{encoded_workflow}/dispatches"),
        {
            "ref": require_string(config.get("default_branch"), "default_branch"),
            "inputs": {
                "pull_number": str(authorization.pull_number),
                "head_sha": authorization.head_sha,
                "base_sha": authorization.base_sha,
                "policy_sha": authorization.policy_sha,
                "comment_id": str(authorization.comment_id),
            },
        },
    )
    return True


def write_github_outputs(path: str, values: Mapping[str, str]) -> None:
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            for key, value in values.items():
                require(re.fullmatch(r"[a-z][a-z0-9_]*", key) is not None, f"invalid output name {key!r}")
                require("\n" not in value and "\r" not in value, f"output {key} contains a newline")
                handle.write(f"{key}={value}\n")
    except OSError as error:
        raise PolicyError(f"cannot write GitHub outputs: {error}") from error


@dataclass(frozen=True)
class ExternalId:
    repository: str
    pull_number: int
    head_sha: str
    base_sha: str
    policy_sha: str
    run_id: int
    run_attempt: int

    def encode(self) -> str:
        fields = (
            "v1",
            self.repository,
            str(self.pull_number),
            self.head_sha,
            self.base_sha,
            self.policy_sha,
            str(self.run_id),
            str(self.run_attempt),
        )
        require(not any("|" in value for value in fields), "external ID field contains a delimiter")
        encoded = "|".join(fields)
        require(len(encoded) <= 255, "external ID exceeds GitHub's limit")
        return encoded

    @staticmethod
    def decode(value: Any) -> "ExternalId":
        encoded = require_string(value, "check external ID")
        fields = encoded.split("|")
        require(len(fields) == 8 and fields[0] == "v1", "check external ID is invalid")
        try:
            pull_number = int(fields[2])
            run_id = int(fields[6])
            run_attempt = int(fields[7])
        except ValueError as error:
            raise PolicyError("check external ID contains a non-integer field") from error
        require(pull_number > 0 and run_id > 0 and run_attempt > 0, "check external ID integers must be positive")
        return ExternalId(
            repository=validate_repository(fields[1], "external ID repository"),
            pull_number=pull_number,
            head_sha=validate_sha(fields[3], "external ID head SHA"),
            base_sha=validate_sha(fields[4], "external ID base SHA"),
            policy_sha=validate_sha(fields[5], "external ID policy SHA"),
            run_id=run_id,
            run_attempt=run_attempt,
        )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_app_slug(observed_slug: Any, expected_slug: str) -> None:
    observed = validate_login(observed_slug, "token App slug")
    require(observed == expected_slug, "token does not belong to the configured release App")


def list_check_runs(api: GitHubApi, repository: str, head_sha: str, check_name: str) -> list[Mapping[str, Any]]:
    query = urllib.parse.urlencode({"check_name": check_name, "filter": "all"})
    values = api.paginate_key(
        repo_api_path(repository, f"/commits/{head_sha}/check-runs?{query}"),
        "check_runs",
        max_items=1_000,
        label="check runs",
    )
    return [require_mapping(value, f"check run {index}") for index, value in enumerate(values)]


def check_is_from_app(check: Mapping[str, Any], app_slug: str) -> bool:
    app = check.get("app")
    return isinstance(app, dict) and app.get("slug") == app_slug


def complete_check(
    api: GitHubApi,
    repository: str,
    check_id: int,
    conclusion: str,
    title: str,
    summary: str,
) -> Mapping[str, Any]:
    require(conclusion in {"success", "failure", "cancelled"}, "unsupported check conclusion")
    updated = require_mapping(
        api.patch(
            repo_api_path(repository, f"/check-runs/{check_id}"),
            {
                "status": "completed",
                "conclusion": conclusion,
                "completed_at": utc_now(),
                "output": {"title": title[:255], "summary": summary[:65_535]},
            },
        ),
        "updated check run",
    )
    require(updated.get("id") == check_id, "updated check run ID is ambiguous")
    require(updated.get("status") == "completed", "updated check run is not completed")
    require(updated.get("conclusion") == conclusion, "updated check run conclusion is unexpected")
    return updated


def start_check(
    api: GitHubApi,
    config: Mapping[str, Any],
    external: ExternalId,
    observed_app_slug: str,
) -> tuple[int, str]:
    release_app = require_mapping(config.get("release_app"), "release_app")
    app_slug = validate_login(release_app.get("slug"), "release App slug")
    require_app_slug(observed_app_slug, app_slug)
    check_name = require_string(config.get("required_check"), "required_check")
    encoded = external.encode()
    checks = list_check_runs(api, external.repository, external.head_sha, check_name)
    for check in checks:
        if not check_is_from_app(check, app_slug) or check.get("status") in TERMINAL_CHECK_STATUSES:
            continue
        prior = ExternalId.decode(check.get("external_id"))
        if prior.repository == external.repository and prior.pull_number == external.pull_number and prior.head_sha == external.head_sha:
            check_id = require_integer(check.get("id"), "prior check id")
            complete_check(
                api,
                external.repository,
                check_id,
                "cancelled",
                "Superseded by a newer authorized run",
                f"Run {external.run_id} attempt {external.run_attempt} replaced this pending check.",
            )

    created = require_mapping(
        api.post(
            repo_api_path(external.repository, "/check-runs"),
            {
                "name": check_name,
                "head_sha": external.head_sha,
                "status": "in_progress",
                "started_at": utc_now(),
                "external_id": encoded,
                "output": {
                    "title": "Protected-main validation is running",
                    "summary": f"Authorized run {external.run_id} attempt {external.run_attempt} is validating the exact pull-request head.",
                },
            },
        ),
        "created check run",
    )
    check_id = require_integer(created.get("id"), "created check id")
    require(created.get("name") == check_name, "created check name is unexpected")
    require(created.get("head_sha") == external.head_sha, "created check head is unexpected")
    require(created.get("external_id") == encoded, "created check external ID is unexpected")
    require(check_is_from_app(created, app_slug), "created check is not owned by the configured App")
    return check_id, encoded


def parse_results(values: Iterable[str], expected_jobs: Sequence[str]) -> Mapping[str, str]:
    results: dict[str, str] = {}
    for value in values:
        require("=" in value, f"job result {value!r} is invalid")
        job, result = value.split("=", 1)
        require(job not in results, f"job result {job!r} is duplicated")
        require(result in {"success", "failure", "cancelled", "skipped"}, f"job {job!r} has unknown result {result!r}")
        results[job] = result
    require(set(results) == set(expected_jobs), "reported jobs do not exactly match the protected inventory")
    return results


def validate_check_value(
    check: Mapping[str, Any],
    config: Mapping[str, Any],
    external: ExternalId,
    check_id: int,
    observed_app_slug: str,
) -> Mapping[str, Any]:
    release_app = require_mapping(config.get("release_app"), "release_app")
    app_slug = validate_login(release_app.get("slug"), "release App slug")
    require_app_slug(observed_app_slug, app_slug)
    require(check.get("id") == check_id, "check run ID is ambiguous")
    require(check.get("name") == config.get("required_check"), "check run name is unexpected")
    require(check.get("head_sha") == external.head_sha, "check run head is unexpected")
    require(check.get("external_id") == external.encode(), "check run binding is unexpected")
    require(check_is_from_app(check, app_slug), "check run is not owned by the configured App")
    return check


def validate_check(
    api: GitHubApi,
    config: Mapping[str, Any],
    external: ExternalId,
    check_id: int,
    observed_app_slug: str,
) -> Mapping[str, Any]:
    check = require_mapping(
        api.get(repo_api_path(external.repository, f"/check-runs/{check_id}")),
        "check run",
    )
    return validate_check_value(
        check, config, external, check_id, observed_app_slug
    )


def finish_check(
    app_api: GitHubApi,
    auth_api: GitHubApi,
    config: Mapping[str, Any],
    event: Mapping[str, Any],
    environment: Mapping[str, str],
    external: ExternalId,
    check_id: int,
    result_values: Iterable[str],
    observed_app_slug: str,
) -> None:
    check = validate_check(app_api, config, external, check_id, observed_app_slug)
    require(check.get("status") not in TERMINAL_CHECK_STATUSES, "check run is already completed")
    error: PolicyError | None = None
    try:
        current = authorize_dispatch(event, config, auth_api, environment)
        require(current.repository == external.repository, "repository changed before reporting")
        require(current.pull_number == external.pull_number, "pull request changed before reporting")
        require(current.head_sha == external.head_sha, "pull request head changed before reporting")
        require(current.base_sha == external.base_sha, "pull request base changed before reporting")
        require(current.policy_sha == external.policy_sha, "policy commit changed before reporting")
        expected = [require_string(value, "expected job") for value in require_sequence(config.get("expected_jobs"), "expected_jobs")]
        results = parse_results(result_values, expected)
        failed = [(job, result) for job, result in results.items() if result != "success"]
        if failed:
            details = ", ".join(f"{job}={result}" for job, result in failed)
            raise PolicyError(f"required candidate jobs did not all succeed: {details}")
    except PolicyError as caught:
        error = caught

    if error is None:
        try:
            updated = complete_check(
                app_api,
                external.repository,
                check_id,
                "success",
                "Protected-main validation succeeded",
                f"All protected jobs succeeded for pull request #{external.pull_number} at {external.head_sha}.",
            )
            validate_check_value(
                updated, config, external, check_id, observed_app_slug
            )

            # GitHub cannot atomically update a check and compare the mutable
            # branch and pull-request refs. Narrow that unavoidable window by
            # checking the exact state again after success is visible. Strict
            # up-to-date branch protection remains the merge-time backstop.
            branch = require_string(config.get("default_branch"), "default_branch")
            require_live_authorization_state(
                auth_api,
                external.repository,
                branch,
                external.pull_number,
                external.base_sha,
                external.head_sha,
                current.head_repository,
                current.head_ref,
                phase="final check reconciliation",
            )
        except PolicyError as reconciliation_error:
            failed = complete_check(
                app_api,
                external.repository,
                check_id,
                "failure",
                "Protected-main validation became stale",
                str(reconciliation_error),
            )
            validate_check_value(
                failed, config, external, check_id, observed_app_slug
            )
            raise reconciliation_error
    else:
        failed = complete_check(
            app_api,
            external.repository,
            check_id,
            "failure",
            "Protected-main validation failed",
            str(error),
        )
        validate_check_value(
            failed, config, external, check_id, observed_app_slug
        )
        raise error


def parse_run_title(value: Any) -> tuple[int, str]:
    title = require_string(value, "workflow run title")
    match = RUN_TITLE_RE.fullmatch(title)
    require(match is not None, "workflow run title is not a protected pull-request run")
    return int(match.group(1)), match.group(2)


def protected_run_identity(
    run: Mapping[str, Any], config: Mapping[str, Any]
) -> tuple[int, str, int, int, str]:
    require(run.get("name") == "Protected pull request CI", "unexpected workflow name")
    require(run.get("event") == "workflow_dispatch", "unexpected workflow event")
    require(
        run.get("path") == config.get("workflow_file"),
        "unexpected workflow path",
    )
    require(
        run.get("head_branch") == config.get("default_branch"),
        "unexpected workflow branch",
    )
    pull_number, head_sha = parse_run_title(run.get("display_title"))
    run_id = require_integer(run.get("id"), "workflow run id")
    run_attempt = require_integer(run.get("run_attempt"), "workflow run attempt")
    require(run_id > 0 and run_attempt > 0, "workflow run identity must be positive")
    policy_sha = validate_sha(run.get("head_sha"), "workflow policy SHA")
    return pull_number, head_sha, run_id, run_attempt, policy_sha


def pending_checks_for_run(
    api: GitHubApi,
    config: Mapping[str, Any],
    repository: str,
    pull_number: int,
    head_sha: str,
    run_id: int,
    run_attempt: int,
    policy_sha: str,
) -> list[tuple[Mapping[str, Any], ExternalId]]:
    release_app = require_mapping(config.get("release_app"), "release_app")
    app_slug = validate_login(release_app.get("slug"), "release App slug")
    checks = list_check_runs(api, repository, head_sha, require_string(config.get("required_check"), "required_check"))
    matches = []
    for check in checks:
        if not check_is_from_app(check, app_slug) or check.get("status") in TERMINAL_CHECK_STATUSES:
            continue
        external = ExternalId.decode(check.get("external_id"))
        if (
            external.repository == repository
            and external.pull_number == pull_number
            and external.head_sha == head_sha
            and external.run_id == run_id
            and external.run_attempt == run_attempt
            and external.policy_sha == policy_sha
        ):
            matches.append((check, external))
    return matches


def reconcile_run(
    app_api: GitHubApi,
    config: Mapping[str, Any],
    event: Mapping[str, Any],
    repository: str,
    observed_app_slug: str,
) -> int:
    release_app = require_mapping(config.get("release_app"), "release_app")
    require_app_slug(observed_app_slug, validate_login(release_app.get("slug"), "release App slug"))
    require(event.get("action") == "completed", "only completed workflow runs are reconciled")
    event_repository = require_mapping(event.get("repository"), "event repository")
    require(
        event_repository.get("full_name") == repository,
        "event repository does not match the workflow repository",
    )
    run = require_mapping(event.get("workflow_run"), "workflow_run")
    pull_number, head_sha, run_id, run_attempt, policy_sha = protected_run_identity(
        run, config
    )
    matches = pending_checks_for_run(
        app_api,
        config,
        repository,
        pull_number,
        head_sha,
        run_id,
        run_attempt,
        policy_sha,
    )
    require(len(matches) <= 1, "multiple pending checks match one workflow run")
    if not matches:
        return 0
    check, _external = matches[0]
    check_id = require_integer(check.get("id"), "check run id")
    conclusion = run.get("conclusion")
    if conclusion == "cancelled":
        check_conclusion = "cancelled"
        title = "Validation run was cancelled"
    else:
        check_conclusion = "failure"
        title = "Validation run ended without a final report"
    complete_check(
        app_api,
        repository,
        check_id,
        check_conclusion,
        title,
        f"Workflow run {run_id} completed with conclusion {conclusion!r} before its protected finalizer completed the check.",
    )
    return 1


def sweep_runs(
    app_api: GitHubApi,
    actions_api: GitHubApi,
    config: Mapping[str, Any],
    repository: str,
    observed_app_slug: str,
) -> int:
    release_app = require_mapping(config.get("release_app"), "release_app")
    require_app_slug(observed_app_slug, validate_login(release_app.get("slug"), "release App slug"))
    workflow_file = validate_path(config.get("workflow_file"), "workflow_file")
    encoded_workflow = urllib.parse.quote(workflow_file, safe="")
    runs = actions_api.paginate_key(
        repo_api_path(repository, f"/actions/workflows/{encoded_workflow}/runs"),
        "workflow_runs",
        max_items=1_000,
        label="protected workflow runs",
    )
    completed = 0
    for value in runs:
        run = require_mapping(value, "protected workflow run")
        try:
            pull_number, head_sha, run_id, run_attempt, policy_sha = (
                protected_run_identity(run, config)
            )
        except PolicyError:
            continue
        matches = pending_checks_for_run(
            app_api,
            config,
            repository,
            pull_number,
            head_sha,
            run_id,
            run_attempt,
            policy_sha,
        )
        require(len(matches) <= 1, "multiple pending checks match one workflow run")
        if not matches:
            continue
        status = require_string(run.get("status"), "protected workflow run status")
        if status != "completed":
            continue
        check, _external = matches[0]
        conclusion = run.get("conclusion")
        complete_check(
            app_api,
            repository,
            require_integer(check.get("id"), "check run id"),
            "cancelled" if conclusion == "cancelled" else "failure",
            "Orphaned validation check closed",
            f"Workflow run {run_id} is complete and no protected finalizer completed this check.",
        )
        completed += 1
    return completed


def environment() -> Mapping[str, str]:
    return os.environ


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    require(value != "", f"{name} is required")
    return value


def external_from_args(args: argparse.Namespace) -> ExternalId:
    return ExternalId(
        repository=validate_repository(args.repository),
        pull_number=args.pull_number,
        head_sha=validate_sha(args.head_sha, "head SHA"),
        base_sha=validate_sha(args.base_sha, "base SHA"),
        policy_sha=validate_sha(args.policy_sha, "policy SHA"),
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )


def add_external_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-number", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--policy-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    authorize_parser = subparsers.add_parser("authorize")
    authorize_parser.add_argument("--event", required=True)
    authorize_parser.add_argument("--config", required=True)
    authorize_parser.add_argument("--github-output", required=True)

    dispatch_comment_parser = subparsers.add_parser("dispatch-comment")
    dispatch_comment_parser.add_argument("--event", required=True)
    dispatch_comment_parser.add_argument("--config", required=True)

    authorize_dispatch_parser = subparsers.add_parser("authorize-dispatch")
    authorize_dispatch_parser.add_argument("--event", required=True)
    authorize_dispatch_parser.add_argument("--config", required=True)
    authorize_dispatch_parser.add_argument("--github-output", required=True)

    start_parser = subparsers.add_parser("start-check")
    start_parser.add_argument("--config", required=True)
    start_parser.add_argument("--github-output", required=True)
    add_external_arguments(start_parser)

    finish_parser = subparsers.add_parser("finish-check")
    finish_parser.add_argument("--event", required=True)
    finish_parser.add_argument("--config", required=True)
    finish_parser.add_argument("--check-id", required=True, type=int)
    finish_parser.add_argument("--result", action="append", default=[])
    add_external_arguments(finish_parser)

    reconcile_parser = subparsers.add_parser("reconcile-run")
    reconcile_parser.add_argument("--event", required=True)
    reconcile_parser.add_argument("--config", required=True)
    reconcile_parser.add_argument("--repository", required=True)

    sweep_parser = subparsers.add_parser("sweep")
    sweep_parser.add_argument("--config", required=True)
    sweep_parser.add_argument("--repository", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if args.command == "authorize":
        auth = authorize(
            require_mapping(load_json(args.event), "event"),
            config,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            environment(),
        )
        write_github_outputs(args.github_output, auth.github_outputs())
        print(f"Authorized pull request #{auth.pull_number} at {auth.head_sha}.")
        return 0

    if args.command == "dispatch-comment":
        dispatched = dispatch_comment(
            require_mapping(load_json(args.event), "event"),
            config,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            environment(),
        )
        print("Dispatched protected validation." if dispatched else "Ignored non-command comment.")
        return 0

    if args.command == "authorize-dispatch":
        auth = authorize_dispatch(
            require_mapping(load_json(args.event), "event"),
            config,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            environment(),
        )
        write_github_outputs(args.github_output, auth.github_outputs())
        print(f"Authorized pull request #{auth.pull_number} at {auth.head_sha}.")
        return 0

    if args.command == "start-check":
        check_id, external_id = start_check(
            GitHubApi(required_env("APP_TOKEN"), api_url),
            config,
            external_from_args(args),
            required_env("APP_SLUG"),
        )
        write_github_outputs(
            args.github_output,
            {"check_id": str(check_id), "external_id": external_id},
        )
        print(f"Started App check {check_id}.")
        return 0

    if args.command == "finish-check":
        finish_check(
            GitHubApi(required_env("APP_TOKEN"), api_url),
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            config,
            require_mapping(load_json(args.event), "event"),
            environment(),
            external_from_args(args),
            args.check_id,
            args.result,
            required_env("APP_SLUG"),
        )
        print(f"Finished App check {args.check_id}.")
        return 0

    repository = validate_repository(args.repository)
    app_api = GitHubApi(required_env("APP_TOKEN"), api_url)
    app_slug = required_env("APP_SLUG")
    if args.command == "reconcile-run":
        count = reconcile_run(
            app_api,
            config,
            require_mapping(load_json(args.event), "event"),
            repository,
            app_slug,
        )
        print(f"Reconciled {count} pending check(s).")
        return 0
    if args.command == "sweep":
        count = sweep_runs(
            app_api,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            config,
            repository,
            app_slug,
        )
        print(f"Closed {count} orphaned check(s).")
        return 0
    raise PolicyError(f"unknown command {args.command!r}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as error:
        print(f"policy error: {error}", file=sys.stderr)
        raise SystemExit(1) from error

#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Authorize and report protected-main pull-request validation.

The workflow that invokes this module is loaded from the protected default
branch.  Candidate commits are treated only as data until ``authorize`` has
checked the exact command, current repository state, live permissions, and
contributor-commit policy.  Check runs are created and updated only with the
repository's narrowly scoped GitHub App token.

This module intentionally uses only the Python standard library so privileged
check jobs can download it at an immutable policy commit without checking out
a candidate or installing packages.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
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


API_VERSION = "2026-03-10"
COMMAND_RE = re.compile(r"/ok to (test|test-and-adopt) ([0-9a-f]{40})")
SHA_RE = re.compile(r"[0-9a-f]{40}")
JOB_BINDING_MARKER = "protected-ci|"
CALLER_JOB_NAME = "Run authorized protected CI"
JOB_BINDING_RE = re.compile(
    rf"(?:{re.escape(CALLER_JOB_NAME)} / )?"
    r"protected-ci\|pr=([1-9][0-9]*)"
    r"\|head=([0-9a-f]{40})"
    r"\|comment=([1-9][0-9]*)"
)
CALLER_WORKFLOW_NAME = "Protected pull request command"
WRITER_PERMISSIONS = frozenset({"write", "push", "maintain", "admin"})
TERMINAL_CHECK_STATUSES = frozenset({"completed"})
CHECK_NAME = "Required CI"
MAX_API_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_API_ERROR_DETAIL_BYTES = 500
MAX_CHANGED_PATHS = 3_000
MAX_PULL_COMMITS = 250
MAX_SIGNATURE_BATCH = 50
MAX_SIGNATURE_REQUESTS = 5
MAX_SIGNATURE_JSON_NODES = 25_000
MAX_SIGNATURE_CURSOR_BYTES = 1_024
MAX_TREE_ENTRIES = 10_000
MAX_SENSITIVE_FILES = 512
MAX_PATH_METADATA_BYTES = 4 * 1024 * 1024
MAX_WORKFLOW_JOBS = 1_000
MAX_PAGES = 100

POLICY_CONTROLLER = ".github/scripts/protected_pr_ci.py"
POLICY_TESTS = ".github/scripts/test_protected_pr_ci.py"
CHECKOUT_VERIFIER = ".github/scripts/protected_checkout.py"
CANDIDATE_CHECKOUT_ACTION = ".github/actions/protected-candidate-checkout/action.yml"
TERMINAL_CANDIDATE_DRIVER = ".github/scripts/terminal_candidate.py"
TERMINAL_CANDIDATE_SHELL = ".github/scripts/run-terminal-candidate.sh"
POLICY_CONFIG = ".github/protected-pr-ci.json"
RECONCILE_WORKFLOW = ".github/workflows/pr-ci-reconcile.yml"
REUSABLE_WORKFLOW = ".github/workflows/pr-ci.yml"
COMMIT_POLICY = ".github/scripts/check-pull-request-commits.sh"


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


def validate_digest(value: Any, label: str) -> str:
    digest = require_string(value, label)
    require(
        re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
        f"{label} must be a lowercase SHA-256 digest",
    )
    return digest


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
        "repository",
        "repository_kind",
        "default_branch",
        "workflow_file",
        "required_check",
        "release_app",
        "expected_jobs",
        "supplemental_candidate_ci",
        "trusted_gitlinks",
    }
    require(set(config) == required, "policy configuration keys are incomplete or ambiguous")
    require(config["version"] == 4, "unsupported policy configuration version")
    validate_repository(config["repository"], "repository")
    require(
        config["repository_kind"] in {"spec", "traits", "rs"},
        "repository_kind is unsupported",
    )
    require(config["default_branch"] == "main", "the protected branch must be exact main")
    workflow_file = validate_path(config["workflow_file"], "workflow_file")
    require(
        isinstance(config["supplemental_candidate_ci"], bool),
        "supplemental_candidate_ci must be boolean",
    )
    require(
        config["supplemental_candidate_ci"]
        == (config["repository_kind"] != "spec"),
        "supplemental candidate CI must be disabled only for spec",
    )
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

    trusted_gitlinks = require_sequence(config["trusted_gitlinks"], "trusted_gitlinks")
    parsed_gitlinks = []
    for index, value in enumerate(trusted_gitlinks):
        item = require_mapping(value, f"trusted_gitlinks[{index}]")
        require(
            set(item) == {"path", "repository", "branch"},
            f"trusted_gitlinks[{index}] keys are incomplete or ambiguous",
        )
        parsed_gitlinks.append(
            {
                "path": validate_path(item["path"], f"trusted_gitlinks[{index}].path"),
                "repository": validate_repository(
                    item["repository"], f"trusted_gitlinks[{index}].repository"
                ),
                "branch": require_string(
                    item["branch"], f"trusted_gitlinks[{index}].branch"
                ),
            }
        )
    require(
        len({item["path"] for item in parsed_gitlinks}) == len(parsed_gitlinks),
        "trusted_gitlinks paths must be unique",
    )
    expected_gitlinks = (
        [
            {
                "path": "source-spec",
                "repository": "NVIDIA/yaml-sigil-spec",
                "branch": "main",
            }
        ]
        if config["repository_kind"] == "traits"
        else []
    )
    require(
        parsed_gitlinks == expected_gitlinks,
        "trusted_gitlinks do not match the repository policy",
    )

    protected_paths = {
        POLICY_CONTROLLER,
        POLICY_TESTS,
        CHECKOUT_VERIFIER,
        CANDIDATE_CHECKOUT_ACTION,
        TERMINAL_CANDIDATE_DRIVER,
        TERMINAL_CANDIDATE_SHELL,
        POLICY_CONFIG,
        workflow_file,
        RECONCILE_WORKFLOW,
        REUSABLE_WORKFLOW,
        COMMIT_POLICY,
    }
    require(
        all(is_sensitive_path(item, config["repository_kind"]) for item in protected_paths),
        "protected CI policy files are not all sensitive",
    )

    return config


class GitHubApi:
    """Small fail-closed GitHub REST and GraphQL client."""

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
                raw = response.read(MAX_API_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= MAX_API_RESPONSE_BYTES,
                    "GitHub API response exceeds the supported size limit",
                )
                require(200 <= response.status < 300, f"GitHub API returned HTTP {response.status}")
        except urllib.error.HTTPError as error:
            raw_detail = error.read(MAX_API_ERROR_DETAIL_BYTES + 1)
            truncated = len(raw_detail) > MAX_API_ERROR_DETAIL_BYTES
            detail = raw_detail[:MAX_API_ERROR_DETAIL_BYTES].decode(
                "utf-8", "replace"
            )
            if truncated:
                detail = f"{detail}..."
            raise PolicyError(
                f"GitHub API {method} {path} failed with HTTP {error.code}: {detail}"
            ) from error
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

    def commit_signatures(
        self, repository: str, pull_number: int, oids: Sequence[str]
    ) -> Mapping[str, Mapping[str, Any]]:
        """Read exact PR commit-signature identities within one aggregate budget."""

        require(
            1 <= len(oids) <= MAX_PULL_COMMITS,
            "signature inventory is outside the supported commit limit",
        )
        require(
            len(set(oids)) == len(oids),
            "signature inventory contains duplicate commit OIDs",
        )
        require(
            isinstance(pull_number, int) and not isinstance(pull_number, bool)
            and pull_number > 0,
            "signature pull request number must be positive",
        )
        owner, name = validate_repository(repository).split("/", 1)
        observed: dict[str, Mapping[str, Any]] = {}
        aggregate_bytes = 0
        aggregate_nodes = 0
        request_count = 0
        cursor: str | None = None

        for offset in range(0, len(oids), MAX_SIGNATURE_BATCH):
            batch = list(oids[offset : offset + MAX_SIGNATURE_BATCH])
            request_count += 1
            require(
                request_count <= MAX_SIGNATURE_REQUESTS,
                "commit signatures require too many GraphQL requests",
            )
            for index, oid in enumerate(batch):
                validate_sha(oid, f"signature OID {offset + index}")
            variables: dict[str, Any] = {
                "owner": owner,
                "name": name,
                "number": pull_number,
                "first": len(batch),
                "after": cursor,
            }
            query = (
                "query($owner:String!,$name:String!,$number:Int!,"
                "$first:Int!,$after:String){repository(owner:$owner,name:$name){"
                "pullRequest(number:$number){commits(first:$first,after:$after){"
                "totalCount nodes{commit{oid signature{__typename email isValid "
                "state wasSignedByGitHub signer{databaseId login __typename}}}}"
                "pageInfo{hasNextPage endCursor}}}}}"
            )
            payload = json.dumps(
                {"query": query, "variables": variables},
                separators=(",", ":"),
            ).encode("utf-8")
            request = urllib.request.Request(
                f"{self.api_url}/graphql",
                data=payload,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "User-Agent": "yaml-sigil-protected-pr-ci/2",
                    "X-GitHub-Api-Version": API_VERSION,
                },
                method="POST",
            )
            remaining = MAX_API_RESPONSE_BYTES - aggregate_bytes
            require(remaining >= 0, "commit signature response budget is exhausted")
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read(remaining + 1)
                    require(
                        len(raw) <= remaining,
                        "aggregate commit signature responses exceed the 32 MiB limit",
                    )
                    require(
                        200 <= response.status < 300,
                        f"GitHub GraphQL returned HTTP {response.status}",
                    )
            except urllib.error.HTTPError as error:
                raw_detail = error.read(MAX_API_ERROR_DETAIL_BYTES + 1)
                detail = raw_detail[:MAX_API_ERROR_DETAIL_BYTES].decode("utf-8", "replace")
                if len(raw_detail) > MAX_API_ERROR_DETAIL_BYTES:
                    detail = f"{detail}..."
                raise PolicyError(
                    f"GitHub GraphQL failed with HTTP {error.code}: {detail}"
                ) from error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                raise PolicyError(f"GitHub GraphQL failed: {error}") from error
            aggregate_bytes += len(raw)
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as error:
                raise PolicyError("GitHub GraphQL returned invalid JSON") from error
            aggregate_nodes += json_node_count(value)
            require(
                aggregate_nodes <= MAX_SIGNATURE_JSON_NODES,
                "commit signature responses contain too many JSON nodes",
            )
            envelope = require_mapping(value, "GraphQL response")
            require("errors" not in envelope, "GraphQL signature response contains errors")
            data = require_mapping(envelope.get("data"), "GraphQL data")
            repo = require_mapping(data.get("repository"), "GraphQL repository")
            pull = require_mapping(repo.get("pullRequest"), "GraphQL pull request")
            commits = require_mapping(
                pull.get("commits"), "GraphQL pull request commits"
            )
            require(
                set(commits) == {"totalCount", "nodes", "pageInfo"},
                "GraphQL signature response fields are incomplete or ambiguous",
            )
            total_count = require_integer(
                commits.get("totalCount"), "GraphQL signature total count"
            )
            require(
                total_count == len(oids),
                "GraphQL signature total count changed",
            )
            nodes = require_sequence(commits.get("nodes"), "GraphQL signature results")
            require(
                len(nodes) == len(batch),
                "GraphQL signature response has missing or unrequested results",
            )
            for index, requested_oid in enumerate(batch):
                node = require_mapping(nodes[index], f"signature node {offset + index}")
                require(
                    set(node) == {"commit"},
                    f"signature node {offset + index} fields are ambiguous",
                )
                commit = require_mapping(
                    node.get("commit"), f"signature result {offset + index}"
                )
                oid = validate_sha(commit.get("oid"), f"signature result {index} OID")
                require(oid == requested_oid, "GraphQL signature result OID is out of order")
                require(oid not in observed, "GraphQL signature result is duplicated")
                observed[oid] = commit

            page_info = require_mapping(
                commits.get("pageInfo"), "GraphQL signature page info"
            )
            require(
                set(page_info) == {"hasNextPage", "endCursor"},
                "GraphQL signature page info fields are incomplete or ambiguous",
            )
            has_next = page_info.get("hasNextPage")
            require(
                isinstance(has_next, bool),
                "GraphQL signature pagination state is missing",
            )
            more_expected = offset + len(batch) < len(oids)
            require(
                has_next is more_expected,
                "GraphQL signature pagination does not match the commit inventory",
            )
            if more_expected:
                cursor = require_string(
                    page_info.get("endCursor"), "GraphQL signature cursor"
                )
                require(
                    len(cursor.encode("utf-8")) <= MAX_SIGNATURE_CURSOR_BYTES,
                    "GraphQL signature cursor exceeds the supported size limit",
                )

        require(
            list(observed) == list(oids),
            "GraphQL signature results do not exactly match the requested OIDs",
        )
        return observed

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


def json_node_count(value: Any) -> int:
    """Count aggregate JSON values without recursive call-stack growth."""

    count = 0
    pending = [value]
    while pending:
        current = pending.pop()
        count += 1
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return count


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


def require_app_token_repository_scope(api: GitHubApi, repository: str) -> None:
    """Require an installation token scoped to exactly one named repository."""

    repositories = api.paginate_key(
        "/installation/repositories",
        "repositories",
        max_items=2,
        label="App token repository inventory",
    )
    require(
        len(repositories) == 1,
        "App token repository inventory is not exactly one repository",
    )
    selected = require_mapping(repositories[0], "App token repository")
    require(
        validate_repository(selected.get("full_name"), "App token repository name")
        == repository,
        "App token is scoped to an unexpected repository",
    )
    require(
        require_integer(selected.get("id"), "App token repository ID") > 0,
        "App token repository ID must be positive",
    )


def require_writer(api: GitHubApi, repository: str, login: str, label: str) -> None:
    permission = permission_for(api, repository, login)
    require(permission in WRITER_PERMISSIONS, f"{label} does not currently have write authority")


@dataclass(frozen=True)
class CommandRequest:
    mode: str
    head_sha: str

    @property
    def adoption(self) -> bool:
        return self.mode == "test-and-adopt"


def command_request(body: Any) -> CommandRequest | None:
    if not isinstance(body, str):
        return None
    match = COMMAND_RE.fullmatch(body)
    if match is None:
        return None
    return CommandRequest(mode=match.group(1), head_sha=match.group(2))


def command_sha(body: Any) -> str | None:
    request = command_request(body)
    return request.head_sha if request is not None else None


def exact_command(body: Any) -> CommandRequest:
    requested = command_request(body)
    require(
        requested is not None,
        "comment must be exactly /ok to test or /ok to test-and-adopt "
        "followed by a lowercase full head SHA",
    )
    assert requested is not None
    return requested


def normalized_casefold(value: str) -> str:
    """Return the compatibility-normalized, case-insensitive identity."""

    normalized = unicodedata.normalize("NFKC", value)
    return unicodedata.normalize("NFKC", normalized.casefold())


def normalized_components(path: str) -> tuple[str, ...]:
    return tuple(normalized_casefold(part) for part in validate_path(path, "path").split("/"))


def is_sensitive_path(path: str, repository_kind: str) -> bool:
    """Classify one normalized repository path under the shared policy."""

    parts = normalized_components(path)
    name = parts[-1]
    if "~" in path or any("~" in part for part in parts):
        return True
    if parts[0] == ".github":
        return True
    if name == ".gitattributes" or parts == (".gitmodules",):
        return True
    if parts in {
        ("codeowners",),
        (".github", "codeowners"),
        ("docs", "codeowners"),
    }:
        return True
    if name in {
        "cargo.toml",
        "cargo.lock",
        "build.rs",
        "rust-toolchain",
        "rust-toolchain.toml",
        "rustfmt.toml",
        ".rustfmt.toml",
        "clippy.toml",
        ".clippy.toml",
        "deny.toml",
        ".deny.toml",
        "deny.exceptions.toml",
        ".deny.exceptions.toml",
        "cargo-deny.toml",
        ".cargo-deny.toml",
        "cargo-machete.toml",
        ".cargo-machete.toml",
        "audit.toml",
        ".release-plz.toml",
        "release-plz.toml",
    }:
        return True
    if ".cargo" in parts or parts[0] == "xtask" or name == "releasing.md":
        return True
    if repository_kind == "traits" and parts == ("source-spec",):
        return True
    buf_policy_names = {"buf.yaml", "buf.lock", "buf.gen.yaml"}
    if repository_kind == "rs" and name in buf_policy_names:
        return True
    if repository_kind == "spec":
        if parts[:1] == ("proto",) and len(parts) == 2 and name in buf_policy_names:
            return True
        acvp_root = ("conformance", "rebuild-rs")
        if parts[: len(acvp_root)] == acvp_root and (
            parts[:4] == (*acvp_root, "vendor", "acvp")
            or parts[:3] == (*acvp_root, "pinned-dir")
            or parts[:3] == (*acvp_root, "xtask")
            or parts[:3] == (*acvp_root, "src")
        ):
            return True
    return False


def commit_author_identity(commit: Mapping[str, Any]) -> str:
    details = require_mapping(commit.get("commit"), "commit details")
    author = require_mapping(details.get("author"), "commit author")
    return f"{require_string(author.get('name'), 'commit author name')} <{require_string(author.get('email'), 'commit author email')}>"


def signoffs(message: Any) -> set[str]:
    text = require_string(message, "commit message")
    found = set()
    for line in text.splitlines():
        match = re.fullmatch(r"Signed-off-by:\s*(.+)", line, flags=re.IGNORECASE)
        if match:
            found.add(match.group(1))
    return found


@dataclass(frozen=True)
class SignatureIdentity:
    oid: str
    kind: str
    email: str
    signer_id: int
    signer_login: str
    signer_type: str
    was_signed_by_github: bool


def signature_identity(value: Mapping[str, Any], label: str) -> SignatureIdentity:
    require(
        set(value) == {"oid", "signature"},
        f"{label} signature result fields are incomplete or ambiguous",
    )
    oid = validate_sha(value.get("oid"), f"{label} OID")
    signature = require_mapping(value.get("signature"), f"{label} signature")
    require(
        set(signature)
        == {
            "__typename",
            "email",
            "isValid",
            "state",
            "wasSignedByGitHub",
            "signer",
        },
        f"{label} signature fields are incomplete or ambiguous",
    )
    kind = require_string(signature.get("__typename"), f"{label} signature type")
    require(
        kind in {"GpgSignature", "SshSignature", "SmimeSignature"},
        f"{label} signature type is unsupported",
    )
    require(signature.get("isValid") is True, f"{label} is not GitHub Verified")
    require(signature.get("state") == "VALID", f"{label} signature state is not valid")
    require(
        isinstance(signature.get("wasSignedByGitHub"), bool),
        f"{label} GitHub-signing state is missing",
    )
    signer = require_mapping(signature.get("signer"), f"{label} signer")
    require(
        set(signer) == {"databaseId", "login", "__typename"},
        f"{label} signer fields are incomplete or ambiguous",
    )
    signer_id = require_integer(signer.get("databaseId"), f"{label} signer ID")
    require(signer_id > 0, f"{label} signer ID must be positive")
    signer_type = require_string(signer.get("__typename"), f"{label} signer type")
    require(signer_type == "User", f"{label} signer is not a GitHub User")
    return SignatureIdentity(
        oid=oid,
        kind=kind,
        email=require_string(signature.get("email"), f"{label} signature email"),
        signer_id=signer_id,
        signer_login=validate_login(signer.get("login"), f"{label} signer login"),
        signer_type=signer_type,
        was_signed_by_github=signature.get("wasSignedByGitHub") is True,
    )


def rest_account(value: Any, label: str) -> tuple[int, str, str]:
    account = require_mapping(value, label)
    account_id = require_integer(account.get("id"), f"{label} ID")
    require(account_id > 0, f"{label} ID must be positive")
    account_type = require_string(account.get("type"), f"{label} type")
    require(account_type in {"User", "Bot"}, f"{label} type is unsupported")
    return account_id, validate_login(account.get("login"), f"{label} login"), account_type


def require_rest_signature_account(
    account: Any, signature: SignatureIdentity, label: str
) -> tuple[int, str, str]:
    identity = rest_account(account, label)
    require(
        identity == (signature.signer_id, signature.signer_login, signature.signer_type),
        f"{label} does not match the verified signer",
    )
    return identity


def require_author_dco(commit: Mapping[str, Any], *, label: str) -> None:
    details = require_mapping(commit.get("commit"), f"{label} details")
    found = signoffs(details.get("message"))
    author = commit_author_identity(commit)
    require(author in found, f"{label} lacks the author's DCO sign-off")


def raw_identity(commit: Mapping[str, Any], role: str, label: str) -> tuple[str, str, str]:
    details = require_mapping(commit.get("commit"), f"{label} details")
    actor = require_mapping(details.get(role), f"{label} raw {role}")
    name = require_string(actor.get("name"), f"{label} raw {role} name")
    email = require_string(actor.get("email"), f"{label} raw {role} email")
    return name, email, f"{name} <{email}>"


def require_direct_contributor_commit(
    commit: Mapping[str, Any], signature: SignatureIdentity, label: str
) -> None:
    require(not signature.was_signed_by_github, f"{label} uses an unsupported GitHub web-flow signature")
    author_account = require_rest_signature_account(commit.get("author"), signature, f"{label} author")
    committer_account = require_rest_signature_account(
        commit.get("committer"), signature, f"{label} committer"
    )
    require(author_account == committer_account, f"{label} author and committer identities differ")
    _, author_email, author_dco = raw_identity(commit, "author", label)
    _, committer_email, _ = raw_identity(commit, "committer", label)
    require(
        author_email == committer_email == signature.email,
        f"{label} signature email does not match the raw author and committer",
    )
    require(
        author_dco in signoffs(require_mapping(commit.get("commit"), f"{label} details").get("message")),
        f"{label} lacks the author's DCO sign-off",
    )


def require_adopted_commit(
    api: GitHubApi,
    repository: str,
    commit: Mapping[str, Any],
    signature: SignatureIdentity,
    label: str,
) -> None:
    require(not signature.was_signed_by_github, f"{label} uses an unsupported GitHub web-flow signature")
    author_account = rest_account(commit.get("author"), f"{label} author")
    committer_account = require_rest_signature_account(
        commit.get("committer"), signature, f"{label} committer"
    )
    require(author_account[2] == "User", f"{label} original author is not a GitHub User")
    require(committer_account[2] == "User", f"{label} adopting committer is not a GitHub User")
    require_writer(api, repository, signature.signer_login, f"{label} adopting signer")
    _, _, author_dco = raw_identity(commit, "author", label)
    _, committer_email, committer_dco = raw_identity(commit, "committer", label)
    require(
        committer_email == signature.email,
        f"{label} signature email does not match the adopting committer",
    )
    found = signoffs(require_mapping(commit.get("commit"), f"{label} details").get("message"))
    require(author_dco in found, f"{label} lacks the original author's DCO sign-off")
    require(committer_dco in found, f"{label} lacks the adopting committer's DCO sign-off")


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
        require(
            all("~" not in part for part in normalized_components(path)),
            "candidate tree contains a Windows short-name-shaped path component",
        )
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
        elif base.leaves[path][:2] != head.leaves[path][:2]:
            statuses.append("mode-or-type-changed")
        else:
            statuses.append("modified")
    return paths, statuses


@dataclass(frozen=True)
class SensitiveInventory:
    entries: tuple[Mapping[str, Any], ...]
    digest: str

    @property
    def present(self) -> bool:
        return bool(self.entries)


def sensitive_inventory(
    base: GitTree,
    head: GitTree,
    paths: Sequence[str],
    statuses: Sequence[str],
    repository_kind: str,
) -> SensitiveInventory:
    require(len(paths) == len(statuses), "tree diff paths and statuses are misaligned")
    entries: list[Mapping[str, Any]] = []
    for path, status in zip(paths, statuses, strict=True):
        base_leaf = base.leaves.get(path)
        head_leaf = head.leaves.get(path)
        gitlink_changed = any(
            leaf is not None and leaf[:2] == ("commit", "160000")
            for leaf in (base_leaf, head_leaf)
        )
        if not gitlink_changed and not is_sensitive_path(path, repository_kind):
            continue
        entries.append(
            {
                "path": path,
                "status": status,
                "base": list(base.leaves[path]) if path in base.leaves else None,
                "head": list(head.leaves[path]) if path in head.leaves else None,
            }
        )
    require(
        len(entries) <= MAX_SENSITIVE_FILES,
        f"sensitive diff exceeds the supported limit of {MAX_SENSITIVE_FILES} files",
    )
    encoded = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    require(
        len(encoded) <= MAX_PATH_METADATA_BYTES,
        "sensitive diff metadata exceeds the 4 MiB limit",
    )
    return SensitiveInventory(
        entries=tuple(entries),
        digest=hashlib.sha256(encoded).hexdigest(),
    )


def require_ancestor(
    api: GitHubApi,
    repository: str,
    ancestor: str,
    descendant: str,
    label: str,
) -> None:
    """Require one exact commit to be in the approved descendant lineage."""

    validate_sha(ancestor, f"{label} ancestor")
    validate_sha(descendant, f"{label} descendant")
    if ancestor == descendant:
        return
    comparison = require_mapping(
        api.get(repo_api_path(repository, f"/compare/{ancestor}...{descendant}")),
        f"{label} comparison",
    )
    merge_base = require_mapping(comparison.get("merge_base_commit"), f"{label} merge base")
    base_commit = require_mapping(comparison.get("base_commit"), f"{label} base commit")
    head_commit = require_mapping(comparison.get("head_commit"), f"{label} head commit")
    require(
        validate_sha(merge_base.get("sha"), f"{label} merge-base SHA") == ancestor
        and validate_sha(base_commit.get("sha"), f"{label} base SHA") == ancestor
        and validate_sha(head_commit.get("sha"), f"{label} head SHA") == descendant
        and comparison.get("status") == "ahead",
        f"{label} does not prove approved forward ancestry",
    )


def require_trusted_gitlink_lineage(
    api: GitHubApi,
    config: Mapping[str, Any],
    base: GitTree,
    head: GitTree,
    paths: Sequence[str],
) -> None:
    """Bind every changed gitlink to its configured upstream forward lineage."""

    trusted = {
        require_string(item.get("path"), "trusted gitlink path"): item
        for item in require_sequence(config.get("trusted_gitlinks"), "trusted_gitlinks")
        if isinstance(item, Mapping)
    }
    for path in paths:
        base_leaf = base.leaves.get(path)
        head_leaf = head.leaves.get(path)
        if not any(
            leaf is not None and leaf[:2] == ("commit", "160000")
            for leaf in (base_leaf, head_leaf)
        ):
            continue
        policy = require_mapping(trusted.get(path), f"trusted lineage policy for {path}")
        require(
            base_leaf is not None
            and head_leaf is not None
            and base_leaf[:2] == ("commit", "160000")
            and head_leaf[:2] == ("commit", "160000"),
            f"trusted gitlink {path} must remain an exact commit gitlink",
        )
        upstream = validate_repository(policy.get("repository"), f"{path} upstream repository")
        branch = require_string(policy.get("branch"), f"{path} upstream branch")
        require(branch == "main", f"{path} upstream branch must be exact main")
        reference = require_mapping(
            api.get(repo_api_path(upstream, f"/git/ref/heads/{branch}")),
            f"{path} upstream branch",
        )
        target = require_mapping(reference.get("object"), f"{path} upstream branch object")
        require(target.get("type") == "commit", f"{path} upstream branch is not a commit")
        upstream_sha = validate_sha(target.get("sha"), f"{path} upstream branch SHA")
        base_sha = validate_sha(base_leaf[2], f"{path} base gitlink SHA")
        head_sha = validate_sha(head_leaf[2], f"{path} candidate gitlink SHA")
        require_ancestor(api, upstream, base_sha, head_sha, f"{path} forward update")
        require_ancestor(api, upstream, head_sha, upstream_sha, f"{path} upstream lineage")


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
    signatures: Mapping[str, Mapping[str, Any]],
) -> None:
    require(release_app.get("enabled") is True, "release App exception is disabled")
    user = rest_account(pull.get("user"), "pull request author")
    require(
        user
        == (
            release_app.get("bot_user_id"),
            release_app.get("login"),
            "Bot",
        ),
        "pull request is not owned by the exact release App identity",
    )
    require(
        user[0] == release_app.get("bot_user_id"),
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
    signature = signature_identity(
        require_mapping(signatures.get(sha), "release App signature result"),
        "release App commit",
    )
    require(signature.oid == sha, "release App signature OID is unexpected")
    parents = require_sequence(commit.get("parents"), "release App commit parents")
    require(len(parents) == 1, "release App commit must have exactly one parent")
    parent = require_mapping(parents[0], "release App commit parent")
    require(parent.get("sha") == main_sha, "release App commit parent is not current main")
    author = rest_account(commit.get("author"), "release App commit author")
    require(
        author
        == (
            release_app.get("bot_user_id"),
            release_app.get("login"),
            "Bot",
        ),
        "release App commit author is unexpected",
    )
    require(
        author[0] == release_app.get("bot_user_id"),
        "release App commit author ID is unexpected",
    )
    committer = rest_account(commit.get("committer"), "release App commit committer")
    require(
        committer
        == (
            release_app.get("commit_committer_user_id"),
            release_app.get("commit_committer_login"),
            "User",
        ),
        "release App commit committer is unexpected",
    )
    require(
        committer[0] == release_app.get("commit_committer_user_id"),
        "release App commit committer ID is unexpected",
    )
    require(
        signature.kind == "GpgSignature"
        and signature.was_signed_by_github
        and signature.signer_id == release_app.get("commit_committer_user_id")
        and signature.signer_login == release_app.get("commit_committer_login")
        and signature.email == release_app.get("commit_committer_email"),
        "release App commit does not have the exact GitHub web-flow signature",
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
    require_author_dco(commit, label="release App commit")


def require_contributor_change(
    api: GitHubApi,
    repository: str,
    commits: Sequence[Mapping[str, Any]],
    signatures: Mapping[str, Mapping[str, Any]],
    *,
    adopted: bool,
) -> None:
    for index, summary in enumerate(commits):
        sha = validate_sha(summary.get("sha"), f"contributor commit {index} SHA")
        commit = full_commit(api, repository, sha)
        parents = require_sequence(
            commit.get("parents"), f"contributor commit {index} parents"
        )
        require(len(parents) == 1, f"contributor commit {index} must be linear")
        label = f"contributor commit {index}"
        signature = signature_identity(
            require_mapping(signatures.get(sha), f"{label} signature result"),
            label,
        )
        require(signature.oid == sha, f"{label} signature OID is unexpected")
        if adopted:
            require_adopted_commit(api, repository, commit, signature, label)
        else:
            require_direct_contributor_commit(commit, signature, label)


@dataclass(frozen=True)
class Authorization:
    repository: str
    pull_number: int
    commenter: str
    commenter_id: int
    commenter_type: str
    head_sha: str
    base_sha: str
    head_repository: str
    head_ref: str
    policy_sha: str
    comment_id: int
    comment_body: str
    comment_created_at: str
    comment_updated_at: str
    command_mode: str
    sensitive_inventory_digest: str
    sensitive: bool
    candidate_ci_required: bool

    def canonical_binding(self) -> bytes:
        value = {
            "version": 2,
            "repository": self.repository,
            "pull_number": self.pull_number,
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "head_repository": self.head_repository,
            "head_ref": self.head_ref,
            "policy_sha": self.policy_sha,
            "comment": {
                "id": self.comment_id,
                "body": self.comment_body,
                "created_at": self.comment_created_at,
                "updated_at": self.comment_updated_at,
                "user": {
                    "id": self.commenter_id,
                    "login": self.commenter,
                    "type": self.commenter_type,
                },
            },
            "command_mode": self.command_mode,
            "sensitive_inventory_digest": self.sensitive_inventory_digest,
            "sensitive": self.sensitive,
            "candidate_ci_required": self.candidate_ci_required,
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def binding_digest(self) -> str:
        return hashlib.sha256(self.canonical_binding()).hexdigest()

    def github_outputs(self) -> Mapping[str, str]:
        return {
            "repository": self.repository,
            "pull_number": str(self.pull_number),
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "head_repository": self.head_repository,
            "policy_sha": self.policy_sha,
            "comment_id": str(self.comment_id),
            "binding_digest": self.binding_digest,
            "command_mode": self.command_mode,
            "sensitive": str(self.sensitive).lower(),
            "candidate_ci_required": str(self.candidate_ci_required).lower(),
        }


@dataclass(frozen=True)
class CallBinding:
    pull_number: int
    head_sha: str
    comment_id: int

    def encode_job_name(self) -> str:
        require(
            self.pull_number > 0 and self.comment_id > 0,
            "call binding integers must be positive",
        )
        validate_sha(self.head_sha, "call binding head SHA")
        return (
            f"{JOB_BINDING_MARKER}pr={self.pull_number}"
            f"|head={self.head_sha}|comment={self.comment_id}"
        )

    @staticmethod
    def decode_job_name(value: Any) -> "CallBinding | None":
        name = require_string(value, "workflow job name")
        if JOB_BINDING_MARKER not in name:
            return None
        match = JOB_BINDING_RE.fullmatch(name)
        require(
            match is not None,
            "workflow job binding is malformed or truncated",
        )
        return CallBinding(
            pull_number=int(match.group(1)),
            head_sha=match.group(2),
            comment_id=int(match.group(3)),
        )


@dataclass(frozen=True)
class CommentBinding:
    comment_id: int
    body: str
    created_at: str
    updated_at: str
    user_id: int
    user_login: str
    user_type: str


def timestamp(value: Any, label: str) -> str:
    encoded = require_string(value, label)
    try:
        parsed = dt.datetime.fromisoformat(encoded.replace("Z", "+00:00"))
    except ValueError as error:
        raise PolicyError(f"{label} is not an ISO-8601 timestamp") from error
    require(parsed.tzinfo is not None, f"{label} must include a timezone")
    return encoded


def comment_binding(value: Mapping[str, Any], label: str) -> CommentBinding:
    user = require_mapping(value.get("user"), f"{label} user")
    user_id = require_integer(user.get("id"), f"{label} user ID")
    require(user_id > 0, f"{label} user ID must be positive")
    user_type = require_string(user.get("type"), f"{label} user type")
    require(user_type == "User", f"{label} must be authored by a GitHub User")
    comment_id = require_integer(value.get("id"), f"{label} ID")
    require(comment_id > 0, f"{label} ID must be positive")
    return CommentBinding(
        comment_id=comment_id,
        body=require_string(value.get("body"), f"{label} body"),
        created_at=timestamp(value.get("created_at"), f"{label} created_at"),
        updated_at=timestamp(value.get("updated_at"), f"{label} updated_at"),
        user_id=user_id,
        user_login=validate_login(user.get("login"), f"{label} user login"),
        user_type=user_type,
    )


def require_comment_unchanged(
    api: GitHubApi,
    repository: str,
    pull_number: int,
    expected: CommentBinding,
    phase: str,
) -> None:
    current = require_mapping(
        api.get(repo_api_path(repository, f"/issues/comments/{expected.comment_id}")),
        "rechecked authorization comment",
    )
    expected_issue_url = f"{api.api_url}{repo_api_path(repository, f'/issues/{pull_number}')}"
    require(
        current.get("issue_url") == expected_issue_url,
        f"authorization comment moved during {phase}",
    )
    require(
        comment_binding(current, "rechecked authorization comment") == expected,
        f"authorization comment or identity changed during {phase}",
    )
    require_writer(api, repository, expected.user_login, "comment author")


def authorize(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
) -> Authorization:
    require(event.get("action") == "created", "only newly created comments are accepted")
    repository = validate_repository(environment.get("GITHUB_REPOSITORY"), "GITHUB_REPOSITORY")
    require(repository == config.get("repository"), "policy repository does not match the workflow repository")
    event_repo = require_mapping(event.get("repository"), "event repository")
    require(event_repo.get("full_name") == repository, "event repository does not match the workflow repository")

    issue = require_mapping(event.get("issue"), "event issue")
    require(isinstance(issue.get("pull_request"), dict), "the comment is not on a pull request")
    pull_number = require_integer(issue.get("number"), "pull request number")
    require(pull_number > 0, "pull request number must be positive")
    comment = require_mapping(event.get("comment"), "event comment")
    event_comment = comment_binding(comment, "event comment")
    requested = exact_command(event_comment.body)
    comment_id = event_comment.comment_id
    commenter = event_comment.user_login
    sender = require_mapping(event.get("sender"), "event sender")
    require(
        rest_account(sender, "event sender")
        == (event_comment.user_id, event_comment.user_login, event_comment.user_type),
        "event sender does not match the comment author",
    )
    actor = validate_login(environment.get("GITHUB_ACTOR"), "GITHUB_ACTOR")
    triggering_actor = validate_login(environment.get("GITHUB_TRIGGERING_ACTOR"), "GITHUB_TRIGGERING_ACTOR")
    require(commenter == actor, "workflow actor does not match the comment author")
    require_writer(api, repository, commenter, "comment author")
    require_writer(api, repository, triggering_actor, "triggering actor")
    require_comment_unchanged(
        api,
        repository,
        pull_number,
        event_comment,
        "initial authorization",
    )

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
    require(head_sha == requested.head_sha, "comment SHA is not the exact current pull request head")
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
    commit_oids = [
        validate_sha(commit.get("sha"), f"pull request commit {index} SHA")
        for index, commit in enumerate(commits)
    ]
    signatures = api.commit_signatures(repository, pull_number, commit_oids)

    repository_kind = require_string(config.get("repository_kind"), "repository_kind")
    inventory = sensitive_inventory(base_tree, head_tree, paths, statuses, repository_kind)
    require_trusted_gitlink_lineage(api, config, base_tree, head_tree, paths)

    release_app = require_mapping(config.get("release_app"), "release_app")
    user = require_mapping(pull.get("user"), "pull request author")
    is_release_app = (
        user.get("login") == release_app.get("login")
        or user.get("id") == release_app.get("bot_user_id")
    )
    if is_release_app:
        require(not requested.adoption, "release App proposals use the ordinary authorization command")
        require_release_app_change(
            api,
            repository,
            pull,
            commits,
            paths,
            statuses,
            main_sha,
            release_app,
            signatures,
        )
    else:
        require(
            requested.adoption == inventory.present,
            "sensitive changes require /ok to test-and-adopt; ordinary changes require /ok to test",
        )
        if inventory.present and head_repository != repository:
            require(
                pull.get("maintainer_can_modify") is True,
                "sensitive fork changes require maintainer edits on the original pull request",
            )
        require_contributor_change(
            api,
            repository,
            commits,
            signatures,
            adopted=inventory.present,
        )

    candidate_ci_required = bool(config.get("supplemental_candidate_ci")) and inventory.present

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
    require_comment_unchanged(
        api,
        repository,
        pull_number,
        event_comment,
        "final authorization",
    )

    return Authorization(
        repository=repository,
        pull_number=pull_number,
        commenter=commenter,
        commenter_id=event_comment.user_id,
        commenter_type=event_comment.user_type,
        head_sha=head_sha,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        policy_sha=policy_sha,
        comment_id=comment_id,
        comment_body=event_comment.body,
        comment_created_at=event_comment.created_at,
        comment_updated_at=event_comment.updated_at,
        command_mode=requested.mode,
        sensitive_inventory_digest=inventory.digest,
        sensitive=inventory.present,
        candidate_ci_required=candidate_ci_required,
    )


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
        "sender": comment.get("user"),
    }


def require_authorization_values(
    authorization: Authorization,
    *,
    repository: str,
    pull_number: int,
    head_sha: str,
    base_sha: str,
    policy_sha: str,
    comment_id: int,
    binding_digest: str | None = None,
) -> None:
    require(authorization.repository == repository, "authorized repository changed")
    require(authorization.pull_number == pull_number, "authorized pull request changed")
    require(authorization.head_sha == head_sha, "authorized head SHA changed")
    require(authorization.base_sha == base_sha, "authorized base SHA changed")
    require(authorization.policy_sha == policy_sha, "authorized policy SHA changed")
    require(authorization.comment_id == comment_id, "authorized comment changed")
    if binding_digest is not None:
        require(
            authorization.binding_digest == binding_digest,
            "authorization binding digest changed",
        )


def authorize_live_comment(
    api: GitHubApi,
    config: Mapping[str, Any],
    repository: str,
    pull_number: int,
    comment_id: int,
    policy_sha: str,
    triggering_actor: str,
) -> Authorization:
    comment_event = original_comment_event(api, repository, pull_number, comment_id)
    original_comment = require_mapping(comment_event.get("comment"), "original comment")
    original_user = require_mapping(original_comment.get("user"), "original comment user")
    commenter = validate_login(original_user.get("login"), "original commenter")
    synthetic_environment = {
        "GITHUB_REPOSITORY": repository,
        "GITHUB_ACTOR": commenter,
        "GITHUB_TRIGGERING_ACTOR": validate_login(
            triggering_actor, "triggering actor"
        ),
        "POLICY_SHA": policy_sha,
    }
    return authorize(comment_event, config, api, synthetic_environment)


def authorize_comment(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
) -> Authorization | None:
    require(
        environment.get("GITHUB_EVENT_NAME") == "issue_comment",
        "the command receiver must retain the issue_comment event",
    )
    comment = event.get("comment")
    if not isinstance(comment, dict) or command_sha(comment.get("body")) is None:
        return None
    return authorize(event, config, api, environment)


def authorize_call(
    event: Mapping[str, Any],
    config: Mapping[str, Any],
    api: GitHubApi,
    environment: Mapping[str, str],
    *,
    repository: str,
    pull_number: int,
    head_sha: str,
    base_sha: str,
    policy_sha: str,
    comment_id: int,
    run_id: int,
    run_attempt: int,
) -> Authorization:
    repository = validate_repository(repository)
    require(
        environment.get("GITHUB_REPOSITORY") == repository,
        "called repository does not match GITHUB_REPOSITORY",
    )
    branch = require_string(config.get("default_branch"), "default_branch")
    require(
        environment.get("GITHUB_REF") == f"refs/heads/{branch}",
        "protected validation must be called on exact main",
    )
    require(
        environment.get("GITHUB_EVENT_NAME") == "issue_comment",
        "protected validation must retain the issue_comment event",
    )
    require(
        validate_sha(environment.get("POLICY_SHA"), "POLICY_SHA") == policy_sha,
        "call policy SHA is not the workflow policy SHA",
    )
    require(pull_number > 0 and comment_id > 0, "call identifiers must be positive")
    validate_sha(head_sha, "called head SHA")
    validate_sha(base_sha, "called base SHA")
    validate_sha(policy_sha, "called policy SHA")
    require(run_id > 0 and run_attempt > 0, "workflow run identity must be positive")

    event_authorization = authorize(event, config, api, environment)
    require_authorization_values(
        event_authorization,
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        policy_sha=policy_sha,
        comment_id=comment_id,
    )

    run = protected_run_identity(
        api,
        config,
        repository,
        run_id,
        run_attempt,
        policy_sha,
        require_binding=True,
    )
    assert run is not None
    require(
        run.binding == CallBinding(pull_number, head_sha, comment_id),
        "reusable-call job does not match the authorized request",
    )

    triggering_actor = validate_login(
        environment.get("GITHUB_TRIGGERING_ACTOR"), "GITHUB_TRIGGERING_ACTOR"
    )
    require(
        run.actor == event_authorization.commenter,
        "workflow run actor is not the comment author",
    )
    require(
        run.triggering_actor == triggering_actor,
        "workflow run triggering actor is ambiguous",
    )
    live_authorization = authorize_live_comment(
        api,
        config,
        repository,
        pull_number,
        comment_id,
        policy_sha,
        triggering_actor,
    )
    require_authorization_values(
        live_authorization,
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        policy_sha=policy_sha,
        comment_id=comment_id,
        binding_digest=event_authorization.binding_digest,
    )
    return live_authorization


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
    binding_digest: str
    run_id: int
    run_attempt: int

    def encode(self) -> str:
        fields = (
            "v2",
            str(self.pull_number),
            self.head_sha,
            validate_digest(self.binding_digest, "authorization binding digest"),
            str(self.run_id),
            str(self.run_attempt),
        )
        require(not any("|" in value for value in fields), "external ID field contains a delimiter")
        encoded = "|".join(fields)
        require(len(encoded) <= 255, "external ID exceeds GitHub's limit")
        return encoded

    @staticmethod
    def decode(
        value: Any,
        *,
        repository: str = "unknown/unknown",
        base_sha: str = "0000000000000000000000000000000000000000",
        policy_sha: str = "0000000000000000000000000000000000000000",
    ) -> "ExternalId":
        encoded = require_string(value, "check external ID")
        fields = encoded.split("|")
        require(len(fields) == 6 and fields[0] == "v2", "check external ID is invalid")
        try:
            pull_number = int(fields[1])
            run_id = int(fields[4])
            run_attempt = int(fields[5])
        except ValueError as error:
            raise PolicyError("check external ID contains a non-integer field") from error
        require(pull_number > 0 and run_id > 0 and run_attempt > 0, "check external ID integers must be positive")
        return ExternalId(
            repository=validate_repository(repository, "external ID repository context"),
            pull_number=pull_number,
            head_sha=validate_sha(fields[2], "external ID head SHA"),
            base_sha=validate_sha(base_sha, "external ID base SHA context"),
            policy_sha=validate_sha(policy_sha, "external ID policy SHA context"),
            binding_digest=validate_digest(fields[3], "external ID binding digest"),
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
        prior = ExternalId.decode(
            check.get("external_id"),
            repository=external.repository,
            base_sha=external.base_sha,
            policy_sha=external.policy_sha,
        )
        if prior.pull_number == external.pull_number and prior.head_sha == external.head_sha:
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


def parse_results_json(value: str, expected_jobs: Sequence[str]) -> Mapping[str, str]:
    require(len(value.encode("utf-8")) <= 16 * 1024, "job result JSON exceeds its limit")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise PolicyError("job result JSON is invalid") from error
    mapping = require_mapping(decoded, "job results")
    require(
        set(mapping) == set(expected_jobs),
        "reported jobs do not exactly match the protected inventory",
    )
    results: dict[str, str] = {}
    for job in expected_jobs:
        result = require_string(mapping.get(job), f"job {job} result")
        require(
            result in {"success", "failure", "cancelled", "skipped"},
            f"job {job!r} has unknown result {result!r}",
        )
        results[job] = result
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
    comment_id: int,
    check_id: int,
    results_json: str,
    observed_app_slug: str,
) -> None:
    check = validate_check(app_api, config, external, check_id, observed_app_slug)
    require(check.get("status") not in TERMINAL_CHECK_STATUSES, "check run is already completed")
    error: PolicyError | None = None
    try:
        current = authorize_call(
            event,
            config,
            auth_api,
            environment,
            repository=external.repository,
            pull_number=external.pull_number,
            head_sha=external.head_sha,
            base_sha=external.base_sha,
            policy_sha=external.policy_sha,
            comment_id=comment_id,
            run_id=external.run_id,
            run_attempt=external.run_attempt,
        )
        require(
            current.binding_digest == external.binding_digest,
            "authorization binding changed before finalization",
        )
        expected = [require_string(value, "expected job") for value in require_sequence(config.get("expected_jobs"), "expected_jobs")]
        results = parse_results_json(results_json, expected)
        failed = [
            (job, result)
            for job, result in results.items()
            if result != "success"
            and not (
                job == "candidate_ci"
                and result == "skipped"
                and not current.candidate_ci_required
            )
        ]
        if failed:
            details = ", ".join(f"{job}={result}" for job, result in failed)
            raise PolicyError(f"required candidate jobs did not all succeed: {details}")

        current = authorize_call(
            event,
            config,
            auth_api,
            environment,
            repository=external.repository,
            pull_number=external.pull_number,
            head_sha=external.head_sha,
            base_sha=external.base_sha,
            policy_sha=external.policy_sha,
            comment_id=comment_id,
            run_id=external.run_id,
            run_attempt=external.run_attempt,
        )
        require(
            current.binding_digest == external.binding_digest,
            "authorization binding changed immediately before success",
        )
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
            phase="pre-success authorization",
        )
        require_comment_unchanged(
            auth_api,
            external.repository,
            external.pull_number,
            CommentBinding(
                comment_id=current.comment_id,
                body=current.comment_body,
                created_at=current.comment_created_at,
                updated_at=current.comment_updated_at,
                user_id=current.commenter_id,
                user_login=current.commenter,
                user_type=current.commenter_type,
            ),
            "pre-success authorization",
        )
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
            require_comment_unchanged(
                auth_api,
                external.repository,
                external.pull_number,
                CommentBinding(
                    comment_id=current.comment_id,
                    body=current.comment_body,
                    created_at=current.comment_created_at,
                    updated_at=current.comment_updated_at,
                    user_id=current.commenter_id,
                    user_login=current.commenter,
                    user_type=current.commenter_type,
                ),
                "final check reconciliation",
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


@dataclass(frozen=True)
class ProtectedRun:
    run_id: int
    run_attempt: int
    policy_sha: str
    status: str
    conclusion: str | None
    actor: str
    triggering_actor: str
    binding: CallBinding


def workflow_actor(run: Mapping[str, Any], field: str) -> str:
    actor = require_mapping(run.get(field), f"workflow run {field}")
    return validate_login(actor.get("login"), f"workflow run {field} login")


def caller_workflow_id(
    api: GitHubApi,
    repository: str,
    config: Mapping[str, Any],
) -> int:
    workflow_file = validate_path(config.get("workflow_file"), "workflow_file")
    encoded = urllib.parse.quote(workflow_file, safe="")
    workflow = require_mapping(
        api.get(repo_api_path(repository, f"/actions/workflows/{encoded}")),
        "caller workflow",
    )
    workflow_id = require_integer(workflow.get("id"), "caller workflow ID")
    require(workflow_id > 0, "caller workflow ID must be positive")
    require(workflow.get("name") == CALLER_WORKFLOW_NAME, "caller workflow name is unexpected")
    require(workflow.get("path") == workflow_file, "caller workflow path is unexpected")
    require(workflow.get("state") == "active", "caller workflow is not active")
    return workflow_id


def validate_run_metadata(
    run: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    run_id: int,
    run_attempt: int,
    policy_sha: str,
    workflow_id: int,
) -> tuple[str, str | None, str, str]:
    require(run.get("id") == run_id, "workflow run ID is ambiguous")
    require(
        run.get("run_attempt") == run_attempt,
        "workflow run attempt is ambiguous",
    )
    require(run_id > 0 and run_attempt > 0, "workflow run identity must be positive")
    require(run.get("workflow_id") == workflow_id, "unexpected workflow ID")
    require(run.get("event") == "issue_comment", "unexpected workflow event")
    require(run.get("path") == config.get("workflow_file"), "unexpected workflow path")
    require(
        run.get("head_branch") == config.get("default_branch"),
        "unexpected workflow branch",
    )
    require(
        validate_sha(run.get("head_sha"), "workflow policy SHA") == policy_sha,
        "workflow policy SHA is unexpected",
    )
    status = require_string(run.get("status"), "workflow run status")
    conclusion = run.get("conclusion")
    require(
        conclusion is None
        or conclusion
        in {
            "success",
            "failure",
            "cancelled",
            "skipped",
            "timed_out",
            "action_required",
            "neutral",
            "stale",
        },
        "workflow run conclusion is unexpected",
    )
    return (
        status,
        conclusion,
        workflow_actor(run, "actor"),
        workflow_actor(run, "triggering_actor"),
    )


def call_binding_for_run(
    api: GitHubApi,
    repository: str,
    run_id: int,
    run_attempt: int,
    policy_sha: str,
    *,
    required: bool,
) -> CallBinding | None:
    jobs = api.paginate_key(
        repo_api_path(repository, f"/actions/runs/{run_id}/jobs?filter=all"),
        "jobs",
        max_items=MAX_WORKFLOW_JOBS,
        label="workflow run jobs",
    )
    bindings: list[CallBinding] = []
    for index, value in enumerate(jobs):
        job = require_mapping(value, f"workflow job {index}")
        name = require_string(job.get("name"), f"workflow job {index} name")
        if JOB_BINDING_MARKER not in name:
            continue
        attempt = require_integer(
            job.get("run_attempt"), f"workflow job {index} run attempt"
        )
        if attempt != run_attempt:
            continue
        require(job.get("run_id") == run_id, "workflow job run ID is ambiguous")
        require(
            validate_sha(job.get("head_sha"), "workflow job policy SHA")
            == policy_sha,
            "workflow job policy SHA is unexpected",
        )
        require(
            require_integer(job.get("id"), "workflow job ID") > 0,
            "workflow job ID must be positive",
        )
        binding = CallBinding.decode_job_name(name)
        assert binding is not None
        bindings.append(binding)
    require(len(bindings) <= 1, "multiple reusable-call binding jobs were found")
    if not bindings:
        require(not required, "reusable-call binding job is missing")
        return None
    return bindings[0]


def protected_run_identity(
    api: GitHubApi,
    config: Mapping[str, Any],
    repository: str,
    run_id: int,
    run_attempt: int,
    policy_sha: str,
    *,
    require_binding: bool,
) -> ProtectedRun | None:
    workflow_id = caller_workflow_id(api, repository, config)
    run = require_mapping(
        api.get(repo_api_path(repository, f"/actions/runs/{run_id}")),
        "workflow run",
    )
    status, conclusion, actor, triggering_actor = validate_run_metadata(
        run,
        config,
        run_id=run_id,
        run_attempt=run_attempt,
        policy_sha=policy_sha,
        workflow_id=workflow_id,
    )
    binding = call_binding_for_run(
        api,
        repository,
        run_id,
        run_attempt,
        policy_sha,
        required=require_binding,
    )
    if binding is None:
        return None
    return ProtectedRun(
        run_id=run_id,
        run_attempt=run_attempt,
        policy_sha=policy_sha,
        status=status,
        conclusion=conclusion,
        actor=actor,
        triggering_actor=triggering_actor,
        binding=binding,
    )


def completed_run_from_event(
    api: GitHubApi,
    config: Mapping[str, Any],
    event: Mapping[str, Any],
    repository: str,
) -> ProtectedRun | None:
    require(event.get("action") == "completed", "only completed workflow runs are reconciled")
    event_repository = require_mapping(event.get("repository"), "event repository")
    require(
        event_repository.get("full_name") == repository,
        "event repository does not match the workflow repository",
    )
    event_run = require_mapping(event.get("workflow_run"), "workflow_run")
    run_id = require_integer(event_run.get("id"), "workflow run id")
    run_attempt = require_integer(event_run.get("run_attempt"), "workflow run attempt")
    policy_sha = validate_sha(event_run.get("head_sha"), "workflow policy SHA")
    workflow_id = caller_workflow_id(api, repository, config)
    validate_run_metadata(
        event_run,
        config,
        run_id=run_id,
        run_attempt=run_attempt,
        policy_sha=policy_sha,
        workflow_id=workflow_id,
    )
    run = protected_run_identity(
        api,
        config,
        repository,
        run_id,
        run_attempt,
        policy_sha,
        require_binding=False,
    )
    if run is None:
        return None
    require(run.status == "completed", "reconciled workflow run is not completed")
    require(
        run.conclusion == event_run.get("conclusion"),
        "workflow run conclusion changed during reconciliation",
    )
    return run


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
        external = ExternalId.decode(
            check.get("external_id"),
            repository=repository,
            policy_sha=policy_sha,
        )
        if (
            external.pull_number == pull_number
            and external.head_sha == head_sha
            and external.run_id == run_id
            and external.run_attempt == run_attempt
        ):
            matches.append((check, external))
    return matches


def close_pending_check_for_run(
    app_api: GitHubApi,
    auth_api: GitHubApi,
    config: Mapping[str, Any],
    repository: str,
    observed_app_slug: str,
    run: ProtectedRun,
    title: str,
    summary: str,
) -> int:
    matches = pending_checks_for_run(
        app_api,
        config,
        repository,
        run.binding.pull_number,
        run.binding.head_sha,
        run.run_id,
        run.run_attempt,
        run.policy_sha,
    )
    require(len(matches) <= 1, "multiple pending checks match one workflow run")
    if not matches:
        return 0
    check, external = matches[0]
    try:
        authorization = authorize_live_comment(
            auth_api,
            config,
            repository,
            run.binding.pull_number,
            run.binding.comment_id,
            run.policy_sha,
            run.triggering_actor,
        )
        require(
            run.actor == authorization.commenter,
            "workflow run actor is not the comment author",
        )
        require_authorization_values(
            authorization,
            repository=external.repository,
            pull_number=external.pull_number,
            head_sha=external.head_sha,
            base_sha=authorization.base_sha,
            policy_sha=external.policy_sha,
            comment_id=run.binding.comment_id,
            binding_digest=external.binding_digest,
        )
    except PolicyError as error:
        summary = f"{summary} Final state validation failed: {error}"
    check_id = require_integer(check.get("id"), "check run id")
    updated = complete_check(
        app_api,
        repository,
        check_id,
        "cancelled" if run.conclusion == "cancelled" else "failure",
        title,
        summary,
    )
    validate_check_value(
        updated,
        config,
        external,
        check_id,
        observed_app_slug,
    )
    return 1


def reconcile_run(
    app_api: GitHubApi,
    auth_api: GitHubApi,
    config: Mapping[str, Any],
    event: Mapping[str, Any],
    repository: str,
    observed_app_slug: str,
) -> int:
    release_app = require_mapping(config.get("release_app"), "release_app")
    require_app_slug(observed_app_slug, validate_login(release_app.get("slug"), "release App slug"))
    run = completed_run_from_event(auth_api, config, event, repository)
    if run is None:
        return 0
    if run.conclusion == "cancelled":
        title = "Validation run was cancelled"
    else:
        title = "Validation run ended without a final report"
    summary = (
        f"Workflow run {run.run_id} attempt {run.run_attempt} completed with "
        f"conclusion {run.conclusion!r} before its protected finalizer "
        "completed the check."
    )
    return close_pending_check_for_run(
        app_api,
        auth_api,
        config,
        repository,
        observed_app_slug,
        run,
        title,
        summary,
    )


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
    workflow_id = caller_workflow_id(actions_api, repository, config)
    for value in runs:
        run_value = require_mapping(value, "protected workflow run")
        try:
            run_id = require_integer(run_value.get("id"), "workflow run id")
            run_attempt = require_integer(
                run_value.get("run_attempt"), "workflow run attempt"
            )
            policy_sha = validate_sha(
                run_value.get("head_sha"), "workflow policy SHA"
            )
            validate_run_metadata(
                run_value,
                config,
                run_id=run_id,
                run_attempt=run_attempt,
                policy_sha=policy_sha,
                workflow_id=workflow_id,
            )
            if run_value.get("status") != "completed":
                continue
            run = protected_run_identity(
                actions_api,
                config,
                repository,
                run_id,
                run_attempt,
                policy_sha,
                require_binding=False,
            )
        except PolicyError:
            continue
        if run is None:
            continue
        summary = (
            f"Workflow run {run.run_id} attempt {run.run_attempt} is complete "
            "and no protected finalizer completed this check."
        )
        completed += close_pending_check_for_run(
            app_api,
            actions_api,
            config,
            repository,
            observed_app_slug,
            run,
            "Orphaned validation check closed",
            summary,
        )
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
        binding_digest=validate_digest(args.binding_digest, "binding digest"),
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )


def add_external_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-number", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--policy-sha", required=True)
    parser.add_argument("--binding-digest", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    authorize_comment_parser = subparsers.add_parser("authorize-comment")
    authorize_comment_parser.add_argument("--event", required=True)
    authorize_comment_parser.add_argument("--config", required=True)
    authorize_comment_parser.add_argument("--github-output", required=True)

    authorize_call_parser = subparsers.add_parser("authorize-call")
    authorize_call_parser.add_argument("--event", required=True)
    authorize_call_parser.add_argument("--config", required=True)
    authorize_call_parser.add_argument("--github-output", required=True)
    authorize_call_parser.add_argument("--comment-id", required=True, type=int)
    add_external_arguments(authorize_call_parser)

    start_parser = subparsers.add_parser("start-check")
    start_parser.add_argument("--config", required=True)
    start_parser.add_argument("--github-output", required=True)
    add_external_arguments(start_parser)

    finish_parser = subparsers.add_parser("finish-check")
    finish_parser.add_argument("--event", required=True)
    finish_parser.add_argument("--config", required=True)
    finish_parser.add_argument("--check-id", required=True, type=int)
    finish_parser.add_argument("--comment-id", required=True, type=int)
    finish_parser.add_argument("--results-json", required=True)
    add_external_arguments(finish_parser)

    inspect_parser = subparsers.add_parser("inspect-run")
    inspect_parser.add_argument("--event", required=True)
    inspect_parser.add_argument("--config", required=True)
    inspect_parser.add_argument("--github-output", required=True)
    inspect_parser.add_argument("--repository", required=True)

    reconcile_parser = subparsers.add_parser("reconcile-run")
    reconcile_parser.add_argument("--event", required=True)
    reconcile_parser.add_argument("--config", required=True)
    reconcile_parser.add_argument("--repository", required=True)

    sweep_parser = subparsers.add_parser("sweep")
    sweep_parser.add_argument("--config", required=True)
    sweep_parser.add_argument("--repository", required=True)

    verify_token_parser = subparsers.add_parser("verify-app-token")
    verify_token_parser.add_argument("--config", required=True)
    verify_token_parser.add_argument("--repository", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if args.command == "authorize-comment":
        auth = authorize_comment(
            require_mapping(load_json(args.event), "event"),
            config,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            environment(),
        )
        if auth is None:
            write_github_outputs(args.github_output, {"authorized": "false"})
            print("Ignored non-command comment.")
            return 0
        outputs = dict(auth.github_outputs())
        outputs["authorized"] = "true"
        write_github_outputs(args.github_output, outputs)
        print(f"Authorized pull request #{auth.pull_number} at {auth.head_sha}.")
        return 0

    if args.command == "authorize-call":
        external = external_from_args(args)
        auth = authorize_call(
            require_mapping(load_json(args.event), "event"),
            config,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            environment(),
            repository=external.repository,
            pull_number=external.pull_number,
            head_sha=external.head_sha,
            base_sha=external.base_sha,
            policy_sha=external.policy_sha,
            comment_id=args.comment_id,
            run_id=external.run_id,
            run_attempt=external.run_attempt,
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
            args.comment_id,
            args.check_id,
            args.results_json,
            required_env("APP_SLUG"),
        )
        print(f"Finished App check {args.check_id}.")
        return 0

    repository = validate_repository(args.repository)
    if args.command == "verify-app-token":
        require_app_token_repository_scope(
            GitHubApi(required_env("APP_TOKEN"), api_url), repository
        )
        print(f"Verified App token repository scope for {repository}.")
        return 0

    if args.command == "inspect-run":
        protected = completed_run_from_event(
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
            config,
            require_mapping(load_json(args.event), "event"),
            repository,
        )
        write_github_outputs(
            args.github_output,
            {"protected": "true" if protected is not None else "false"},
        )
        print("Recognized protected reusable call." if protected else "Ignored ordinary command run.")
        return 0

    app_api = GitHubApi(required_env("APP_TOKEN"), api_url)
    app_slug = required_env("APP_SLUG")
    if args.command == "reconcile-run":
        count = reconcile_run(
            app_api,
            GitHubApi(required_env("GITHUB_TOKEN"), api_url),
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

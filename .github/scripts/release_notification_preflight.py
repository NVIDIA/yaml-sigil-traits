#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Validate one protected source-only release notification without checkout."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

API_VERSION = "2026-03-10"
EVENT_TYPE = "official-release-published"
INTENT_NAME = "Release finalization intent"
INTENT_TITLE = "Attested source-only release train"
MAX_EVENT_BYTES = 128 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_NOTIFICATION_BYTES = 8 * 1024
MAX_INTENT_BYTES = 64 * 1024
MAX_PLAN_BYTES = 48 * 1024
MAX_RELEASE_BODY_BYTES = 16 * 1024
MAX_API_CALLS = 96
MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_API_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_CONTENT_BYTES = 128 * 1024 * 1024
MAX_VCS_BYTES = 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?\Z")
REPLAY_TRAILER = "YamlSigil-Release-Replay: "
REPLAY_COMMENT = "<!-- yaml-sigil-release-replay-v1:{} -->"


class PreflightError(RuntimeError):
    """A closed validation boundary rejected the notification."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def require_keys(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == set(keys), f"{label} has missing or unknown fields")
    return value


def require_string(value: Any, label: str, limit: int = 512) -> str:
    require(type(value) is str, f"{label} must be a string")
    require(0 < len(value.encode("utf-8")) <= limit, f"{label} is empty or oversized")
    require(not any(character in value for character in "\x00\r\n"), f"{label} must be one line")
    return value


def require_positive(value: Any, label: str) -> int:
    require(type(value) is int and 0 < value < 2**63, f"{label} must be a positive integer")
    return value


def require_sha(value: Any, label: str) -> str:
    value = require_string(value, label, 40)
    require(SHA_RE.fullmatch(value) is not None, f"{label} must be a lowercase SHA-1")
    return value


def require_digest(value: Any, label: str) -> str:
    value = require_string(value, label, 64)
    require(DIGEST_RE.fullmatch(value) is not None, f"{label} must be a lowercase SHA-256")
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def read_json(path: Path, limit: int, label: str) -> dict[str, Any]:
    with path.open("rb") as handle:
        body = handle.read(limit + 1)
    require(0 < len(body) <= limit, f"{label} is empty or oversized")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"{label} is not valid UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must contain one object")
    return value


@dataclass(frozen=True)
class PackagePolicy:
    name: str
    tag_prefix: str
    path_in_vcs: str


@dataclass(frozen=True)
class Policy:
    repository: str
    default_branch: str
    sender_id: int
    sender_login: str
    app_id: int
    app_slug: str
    app_email: str
    release_branch: str
    packages: tuple[PackagePolicy, ...]


def parse_policy(raw: dict[str, Any]) -> Policy:
    raw = require_keys(
        raw,
        (
            "schema_version",
            "api_version",
            "repository",
            "default_branch",
            "sender",
            "app",
            "release_branch",
            "packages",
        ),
        "release notification policy",
    )
    require(raw["schema_version"] == 1, "release notification policy version is unsupported")
    require(raw["api_version"] == API_VERSION, "release notification API version is unsupported")
    sender = require_keys(raw["sender"], ("id", "login", "type"), "sender policy")
    app = require_keys(raw["app"], ("id", "slug", "email"), "App policy")
    require(sender["type"] == "Bot", "sender policy must require a Bot")
    packages_raw = raw["packages"]
    require(type(packages_raw) is list and 0 < len(packages_raw) <= 8, "package policy is empty or oversized")
    packages: list[PackagePolicy] = []
    names: set[str] = set()
    prefixes: set[str] = set()
    for index, item in enumerate(packages_raw):
        item = require_keys(item, ("name", "tag_prefix", "path_in_vcs"), f"package policy {index}")
        name = require_string(item["name"], f"package policy {index} name", 128)
        prefix = require_string(item["tag_prefix"], f"package policy {index} tag prefix", 160)
        path = item["path_in_vcs"]
        require(type(path) is str and len(path.encode("utf-8")) <= 256, "path_in_vcs is invalid")
        require(name not in names and prefix not in prefixes, "package policy contains duplicates")
        names.add(name)
        prefixes.add(prefix)
        packages.append(PackagePolicy(name, prefix, path))
    return Policy(
        repository=require_string(raw["repository"], "policy repository", 256),
        default_branch=require_string(raw["default_branch"], "policy default branch", 64),
        sender_id=require_positive(sender["id"], "policy sender ID"),
        sender_login=require_string(sender["login"], "policy sender login", 128),
        app_id=require_positive(app["id"], "policy App ID"),
        app_slug=require_string(app["slug"], "policy App slug", 128),
        app_email=require_string(app["email"], "policy App email", 256),
        release_branch=require_string(raw["release_branch"], "release branch", 128),
        packages=tuple(packages),
    )


class Api:
    """Bounded GitHub and crates.io reads with host-isolated credentials."""

    def __init__(self, token: str, github_api_url: str = "https://api.github.com") -> None:
        self.token = require_string(token, "GITHUB_TOKEN", 4096)
        self.github_api_url = github_api_url.rstrip("/")
        self.calls = 0
        self.total = 0

    def _read(self, url: str, github: bool, optional: bool, limit: int) -> bytes | None:
        self.calls += 1
        require(self.calls <= MAX_API_CALLS, "API request count exceeded its bound")
        headers = {"User-Agent": "yaml-sigil-release-preflight/1.0"}
        if github:
            headers.update(
                {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": API_VERSION,
                }
            )
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            detail = error.read(501)[:500].decode("utf-8", "replace")
            if optional and error.code == 404:
                return None
            raise PreflightError(f"bounded API read returned HTTP {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise PreflightError(f"bounded API read failed: {error.reason}") from error
        require(len(body) <= limit, "API response exceeded its per-response bound")
        self.total += len(body)
        require(self.total <= MAX_TOTAL_API_BYTES, "aggregate API response bytes exceeded their bound")
        return body

    def github_json(self, path: str, optional: bool = False) -> Any:
        body = self._read(f"{self.github_api_url}/{path.lstrip('/')}", True, optional, MAX_API_RESPONSE_BYTES)
        if body is None:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PreflightError(f"GitHub returned invalid UTF-8 JSON: {error}") from error

    def crates_json(self, path: str) -> Any:
        body = self._read(f"https://crates.io/api/v1/{path.lstrip('/')}", False, False, MAX_API_RESPONSE_BYTES)
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PreflightError(f"crates.io returned invalid UTF-8 JSON: {error}") from error

    def crate_archive(self, package: str, version: str) -> bytes:
        body = self._read(
            f"https://crates.io/api/v1/crates/{urllib.parse.quote(package, safe='')}/{urllib.parse.quote(version, safe='')}/download",
            False,
            False,
            MAX_ARCHIVE_BYTES,
        )
        assert body is not None
        return body


def validate_plan(raw: Any, policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    plan = require_keys(
        raw,
        (
            "schema_version",
            "repository",
            "release_sha",
            "authorization",
            "release_plz_version",
            "release_config_sha256",
            "publish_workflow_sha256",
            "proposal_workflow_sha256",
            "tagger_epoch",
            "tagger_date",
            "packages",
        ),
        "embedded release plan",
    )
    require(plan["schema_version"] == 1, "release plan version is unsupported")
    require(plan["repository"] == policy.repository, "release plan repository is wrong")
    require(plan["release_sha"] == payload["captured_sha"], "release plan SHA is wrong")
    require(plan["release_plz_version"] == "0.3.160", "release-plz version is wrong")
    for field in ("release_config_sha256", "publish_workflow_sha256", "proposal_workflow_sha256"):
        require_digest(plan[field], f"release plan {field}")
    require_positive(plan["tagger_epoch"], "release plan tagger epoch")
    require_string(plan["tagger_date"], "release plan tagger date", 64)
    authorization = require_keys(
        plan["authorization"],
        ("pull_request", "proposal_commit", "base_commit", "owner_id", "merger_id"),
        "release authorization",
    )
    require_positive(authorization["pull_request"], "release pull request")
    require_sha(authorization["proposal_commit"], "proposal commit")
    require_sha(authorization["base_commit"], "base commit")
    require_positive(authorization["owner_id"], "proposal owner ID")
    require_positive(authorization["merger_id"], "proposal merger ID")
    packages = plan["packages"]
    require(type(packages) is list and len(packages) == len(policy.packages), "release plan package set is incomplete")
    for index, (item, expected) in enumerate(zip(packages, policy.packages, strict=True)):
        item = require_keys(
            item,
            (
                "package",
                "version",
                "tag",
                "prerelease",
                "source_archive_sha256",
                "package_inventory_sha256",
                "release_body",
                "release_body_sha256",
                "registry",
            ),
            f"release plan package {index}",
        )
        version = require_string(item["version"], f"release plan package {index} version", 128)
        require(VERSION_RE.fullmatch(version) is not None, "release plan contains a noncanonical version")
        require(item["package"] == expected.name, "release plan package order is wrong")
        require(item["tag"] == f"{expected.tag_prefix}{version}", "release plan tag is wrong")
        require(type(item["prerelease"]) is bool and item["prerelease"] == ("-" in version), "release prerelease state is wrong")
        require_digest(item["source_archive_sha256"], "source archive digest")
        require_digest(item["package_inventory_sha256"], "package inventory digest")
        body = item["release_body"]
        require(type(body) is str and 0 < len(body.encode("utf-8")) <= MAX_RELEASE_BODY_BYTES, "release body is empty or oversized")
        require(sha256(body.encode("utf-8")) == require_digest(item["release_body_sha256"], "release body digest"), "release body digest is wrong")
        registry = require_keys(item["registry"], ("state", "checksum"), "registry baseline")
        require(registry["state"] in ("absent", "present"), "registry baseline state is invalid")
        if registry["state"] == "absent":
            require(registry["checksum"] is None, "absent registry baseline has a checksum")
        else:
            require_digest(registry["checksum"], "registry baseline checksum")
    return plan


def validate_intent(check: dict[str, Any], policy: Policy, payload: dict[str, Any]) -> dict[str, Any]:
    require(type(check) is dict, "intent Check must be an object")
    require(check["id"] == payload["intent_check_id"], "intent Check ID is wrong")
    require(check["name"] == INTENT_NAME, "intent Check name is wrong")
    require(check["head_sha"] == payload["captured_sha"], "intent Check SHA is wrong")
    require(check["external_id"] == payload["intent_external_id"], "intent Check external ID is wrong")
    require(check["status"] == "completed" and check["conclusion"] == "neutral", "intent Check state is wrong")
    app = check.get("app")
    require(type(app) is dict, "intent Check App is missing")
    require(app["id"] == policy.app_id and app["slug"] == policy.app_slug, "intent Check App is wrong")
    output = check.get("output")
    require(type(output) is dict, "intent Check output is missing")
    require(output["title"] == INTENT_TITLE, "intent Check title is wrong")
    summary = output["summary"]
    require(type(summary) is str and 0 < len(summary.encode("utf-8")) <= MAX_INTENT_BYTES, "intent Check summary is empty or oversized")
    try:
        intent = json.loads(summary)
    except json.JSONDecodeError as error:
        raise PreflightError(f"intent Check summary is invalid JSON: {error}") from error
    intent = require_keys(
        intent,
        (
            "schema_version",
            "repository",
            "release_sha",
            "plan_digest",
            "external_id",
            "origin_run_id",
            "origin_run_attempt",
            "ruleset_evidence_sha256",
            "plan",
            "tags",
        ),
        "release intent",
    )
    require(canonical(intent) == summary, "release intent is not canonical")
    require(intent["schema_version"] == 1, "release intent version is unsupported")
    require(intent["repository"] == policy.repository, "release intent repository is wrong")
    require(intent["release_sha"] == payload["captured_sha"], "release intent SHA is wrong")
    require(intent["plan_digest"] == payload["release_plan_digest"], "release intent plan digest is wrong")
    require(intent["external_id"] == payload["intent_external_id"], "release intent external ID is wrong")
    require_positive(intent["origin_run_id"], "release intent origin run")
    require_positive(intent["origin_run_attempt"], "release intent origin attempt")
    require_digest(intent["ruleset_evidence_sha256"], "ruleset evidence digest")
    plan = validate_plan(intent["plan"], policy, payload)
    plan_body = canonical(plan)
    require(len(plan_body.encode("utf-8")) <= MAX_PLAN_BYTES, "embedded release plan is oversized")
    require(sha256(plan_body.encode("utf-8")) == payload["release_plan_digest"], "embedded release plan digest is wrong")
    tags = intent["tags"]
    require(type(tags) is list and len(tags) == len(policy.packages), "release intent tag set is incomplete")
    for index, (tag, package, release) in enumerate(zip(tags, plan["packages"], payload["releases"], strict=True)):
        tag = require_keys(tag, ("package", "tag", "tag_object_id", "tag_message", "release_body_sha256"), f"intent tag {index}")
        require(tag["package"] == package["package"] == release["package"], "intent package order is wrong")
        require(tag["tag"] == package["tag"] == release["tag"], "intent tag is wrong")
        require(require_sha(tag["tag_object_id"], "intent tag object") == release["tag_object_id"], "intent tag object is wrong")
        require(tag["tag_message"] == f"chore: Release package {package['package']} version {package['version']}", "intent tag message is wrong")
        require(tag["release_body_sha256"] == package["release_body_sha256"] == release["release_body_sha256"], "intent Release body digest is wrong")
    return intent


def inspect_archive(archive: bytes, package: PackagePolicy, version: str, commit: str) -> None:
    require(0 < len(archive) <= MAX_ARCHIVE_BYTES, "crate archive is empty or oversized")
    prefix = f"{package.name}-{version}"
    total = 0
    count = 0
    vcs_body: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as cargo:
            for member in cargo:
                count += 1
                require(count <= MAX_ARCHIVE_FILES, "crate archive file count exceeded its bound")
                require(member.isfile(), "crate archive contains a non-file entry")
                parts = member.name.split("/")
                require(parts[0] == prefix and all(part not in ("", ".", "..") for part in parts), "crate archive contains an unsafe path")
                require(member.size >= 0, "crate archive contains an invalid size")
                total += member.size
                require(total <= MAX_ARCHIVE_CONTENT_BYTES, "crate archive content exceeded its bound")
                if member.name == f"{prefix}/.cargo_vcs_info.json":
                    require(vcs_body is None and member.size <= MAX_VCS_BYTES, "crate VCS metadata is duplicate or oversized")
                    handle = cargo.extractfile(member)
                    require(handle is not None, "crate VCS metadata is unreadable")
                    vcs_body = handle.read(MAX_VCS_BYTES + 1)
                    require(len(vcs_body) == member.size, "crate VCS metadata is truncated")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise PreflightError(f"crate archive is invalid: {error}") from error
    require(vcs_body is not None, "crate archive lacks VCS metadata")
    try:
        vcs = json.loads(vcs_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightError(f"crate VCS metadata is invalid: {error}") from error
    vcs = require_keys(vcs, ("git", "path_in_vcs"), "crate VCS metadata")
    require(type(vcs["git"]) is dict, "crate Git metadata must be an object")
    git_keys = set(vcs["git"])
    require(
        git_keys in ({"sha1"}, {"sha1", "dirty"}),
        "crate Git metadata has missing or unknown fields",
    )
    git = vcs["git"]
    require(git["sha1"] == commit and git.get("dirty", False) is False, "crate VCS commit is wrong or dirty")
    require(vcs["path_in_vcs"] == package.path_in_vcs, "crate VCS path is wrong")


def validate_registry(api: Api, policy: Policy, plan: dict[str, Any]) -> None:
    for expected, package in zip(policy.packages, plan["packages"], strict=True):
        response = api.crates_json(f"crates/{urllib.parse.quote(expected.name, safe='')}/{urllib.parse.quote(package['version'], safe='')}")
        require(type(response) is dict, "crates.io exact-version response is invalid")
        version = response.get("version")
        require(type(version) is dict, "crates.io version is invalid")
        require(version.get("num") == package["version"] and version.get("yanked") is False, "crates.io version state is wrong")
        checksum = require_digest(version.get("checksum"), "crates.io checksum")
        require(checksum == package["source_archive_sha256"], "crates.io checksum differs from the release plan")
        archive = api.crate_archive(expected.name, package["version"])
        require(sha256(archive) == checksum, "downloaded crate checksum is wrong")
        inspect_archive(archive, expected, package["version"], plan["release_sha"])


def validate_release_set(api: Api, policy: Policy, payload: dict[str, Any], intent: dict[str, Any]) -> None:
    plan_packages = intent["plan"]["packages"]
    intent_tags = intent["tags"]
    for release_entry, package, tag_intent in zip(payload["releases"], plan_packages, intent_tags, strict=True):
        release = api.github_json(f"repos/{policy.repository}/releases/{release_entry['release_id']}")
        require(type(release) is dict, "GitHub Release response is invalid")
        author = release.get("author")
        require(type(author) is dict, "GitHub Release author is missing")
        require(
            release.get("id") == release_entry["release_id"]
            and release.get("tag_name") == package["tag"]
            and release.get("target_commitish") == policy.default_branch
            and release.get("name") == package["tag"]
            and release.get("body") == package["release_body"]
            and release.get("draft") is False
            and release.get("prerelease") is package["prerelease"]
            and release.get("immutable") is True
            and author.get("id") == policy.sender_id
            and author.get("login") == policy.sender_login
            and author.get("type") == "Bot"
            and release.get("assets") == [],
            "GitHub Release is not exact, immutable, App-authored, and asset-free",
        )
        by_tag = api.github_json(f"repos/{policy.repository}/releases/tags/{urllib.parse.quote(package['tag'], safe='')}")
        require(type(by_tag) is dict and by_tag.get("id") == release_entry["release_id"], "GitHub Release tag lookup disagrees")
        reference = api.github_json(f"repos/{policy.repository}/git/ref/tags/{urllib.parse.quote(package['tag'], safe='')}")
        require(type(reference) is dict and reference.get("ref") == f"refs/tags/{package['tag']}", "annotated tag ref is wrong")
        target = reference.get("object")
        require(type(target) is dict and target.get("type") == "tag" and target.get("sha") == tag_intent["tag_object_id"], "annotated tag ref target is wrong")
        tag = api.github_json(f"repos/{policy.repository}/git/tags/{tag_intent['tag_object_id']}")
        require(type(tag) is dict, "annotated tag object is invalid")
        tagger = tag.get("tagger")
        target = tag.get("object")
        require(
            tag.get("sha") == tag_intent["tag_object_id"]
            and tag.get("tag") == package["tag"]
            and tag.get("message") == tag_intent["tag_message"]
            and type(tagger) is dict
            and tagger.get("name") == policy.sender_login
            and tagger.get("email") == policy.app_email
            and type(tagger.get("date")) is str
            and type(target) is dict
            and target.get("type") == "commit"
            and target.get("sha") == payload["captured_sha"],
            "annotated tag object is not the attested App object",
        )


def replay_marker(value: str, prefix: str) -> str | None:
    matches = [line[len(prefix):] for line in value.splitlines() if line.startswith(prefix)]
    require(len(matches) <= 1, "release proposal contains duplicate replay markers")
    if not matches:
        return None
    return require_digest(matches[0], "release replay marker")


def replay_comment(value: str) -> str | None:
    matches = re.findall(r"^<!-- yaml-sigil-release-replay-v1:([0-9a-f]{64}) -->$", value, re.MULTILINE)
    require(len(matches) <= 1, "release proposal contains duplicate replay comments")
    return matches[0] if matches else None


def replay_state(api: Api, policy: Policy, key: str) -> str:
    branch = urllib.parse.quote(policy.release_branch, safe="")
    reference = api.github_json(f"repos/{policy.repository}/git/ref/heads/{branch}", optional=True)
    owner = policy.repository.split("/", 1)[0]
    pulls = api.github_json(
        f"repos/{policy.repository}/pulls?state=open&head={urllib.parse.quote(f'{owner}:{policy.release_branch}', safe='')}&per_page=100"
    )
    require(type(pulls) is list and len(pulls) <= 1, "release proposal pull-request state is ambiguous")
    if reference is None:
        require(not pulls, "release proposal exists without its durable branch")
        return "new"
    require(type(reference) is dict, "release proposal ref is invalid")
    target = reference.get("object")
    require(type(target) is dict and target.get("type") == "commit", "release proposal ref is not a commit")
    commit_sha = require_sha(target.get("sha"), "release proposal commit")
    commit = api.github_json(f"repos/{policy.repository}/commits/{commit_sha}")
    require(type(commit) is dict and type(commit.get("commit")) is dict, "release proposal commit is invalid")
    marker = replay_marker(commit["commit"].get("message", ""), REPLAY_TRAILER)
    if pulls:
        pull = pulls[0]
        body_marker = replay_comment(pull.get("body") or "")
        require(marker == key and body_marker == key, "an active release proposal has a different replay identity")
        raise PreflightError("release notification replay is already durably consumed")
    comparison = api.github_json(
        f"repos/{policy.repository}/compare/{urllib.parse.quote(policy.default_branch, safe='')}...{branch}"
    )
    require(type(comparison) is dict and type(comparison.get("ahead_by")) is int, "release branch comparison is invalid")
    if comparison["ahead_by"] == 0:
        return "new"
    require(comparison["ahead_by"] == 1 and marker == key, "release proposal branch is not an exact abandoned replay")
    return "recover"


def validate_event(event: dict[str, Any], policy: Policy, api: Api, repository: str, policy_sha: str) -> dict[str, str]:
    require(repository == policy.repository, "workflow repository differs from policy")
    require_sha(policy_sha, "policy SHA")
    require(type(event) is dict, "repository dispatch event must be an object")
    require(event.get("action") == EVENT_TYPE, "repository dispatch event type is wrong")
    sender = event.get("sender")
    require(type(sender) is dict, "repository dispatch sender is missing")
    require(sender.get("id") == policy.sender_id and sender.get("login") == policy.sender_login and sender.get("type") == "Bot", "repository dispatch sender is wrong")
    event_repository = event.get("repository")
    require(type(event_repository) is dict, "repository dispatch repository is missing")
    require(event_repository.get("full_name") == policy.repository and event_repository.get("default_branch") == policy.default_branch, "repository dispatch repository identity is wrong")
    live_repository = api.github_json(f"repos/{policy.repository}")
    require(type(live_repository) is dict and live_repository.get("full_name") == policy.repository and live_repository.get("default_branch") == policy.default_branch, "live repository identity is wrong")
    main = api.github_json(f"repos/{policy.repository}/git/ref/heads/{urllib.parse.quote(policy.default_branch, safe='')}")
    require(type(main) is dict and type(main.get("object")) is dict and main["object"].get("sha") == policy_sha, "protected policy SHA is not exact current main")
    user = api.github_json(f"users/{urllib.parse.quote(policy.sender_login, safe='')}")
    require(type(user) is dict and user.get("id") == policy.sender_id and user.get("login") == policy.sender_login and user.get("type") == "Bot", "live sender identity is wrong")
    payload = require_keys(
        event.get("client_payload"),
        ("schema_version", "repository", "captured_sha", "release_plan_digest", "intent_check_id", "intent_external_id", "releases"),
        "release notification",
    )
    require(len(canonical(payload).encode("utf-8")) <= MAX_NOTIFICATION_BYTES, "release notification is oversized")
    require(payload["schema_version"] == 1, "release notification version is unsupported")
    require(payload["repository"] == policy.repository, "release notification repository is wrong")
    require_sha(payload["captured_sha"], "captured release SHA")
    require_digest(payload["release_plan_digest"], "release plan digest")
    require_positive(payload["intent_check_id"], "intent Check ID")
    require_digest(payload["intent_external_id"], "intent external ID")
    releases = payload["releases"]
    require(type(releases) is list and len(releases) == len(policy.packages), "release notification package set is incomplete")
    seen_ids: set[int] = set()
    seen_tags: set[str] = set()
    for index, (release, package) in enumerate(zip(releases, policy.packages, strict=True)):
        release = require_keys(release, ("package", "version", "release_id", "tag", "tag_object_id", "release_body_sha256"), f"release entry {index}")
        version = require_string(release["version"], f"release entry {index} version", 128)
        require(VERSION_RE.fullmatch(version) is not None, "release notification version is noncanonical")
        require(release["package"] == package.name and release["tag"] == f"{package.tag_prefix}{version}", "release notification order or tag is wrong")
        release_id = require_positive(release["release_id"], "GitHub Release ID")
        require_sha(release["tag_object_id"], "tag object ID")
        require_digest(release["release_body_sha256"], "Release body digest")
        require(release_id not in seen_ids and release["tag"] not in seen_tags, "release notification contains duplicates")
        seen_ids.add(release_id)
        seen_tags.add(release["tag"])
    check = api.github_json(f"repos/{policy.repository}/check-runs/{payload['intent_check_id']}")
    intent = validate_intent(check, policy, payload)
    validate_registry(api, policy, intent["plan"])
    validate_release_set(api, policy, payload, intent)
    replay_document = {
        "schema_version": 1,
        "repository": policy.repository,
        "release_ids": [entry["release_id"] for entry in releases],
        "tags": [entry["tag"] for entry in releases],
        "captured_sha": payload["captured_sha"],
        "release_plan_digest": payload["release_plan_digest"],
        "intent_check_id": payload["intent_check_id"],
    }
    key = sha256(canonical(replay_document).encode("utf-8"))
    state = replay_state(api, policy, key)
    return {
        "authorized": "true",
        "replay_key": key,
        "replay_state": state,
        "captured_release_sha": payload["captured_sha"],
        "release_plan_digest": payload["release_plan_digest"],
        "intent_check_id": str(payload["intent_check_id"]),
    }


def append_outputs(path: Path, values: dict[str, str]) -> None:
    for name, value in values.items():
        require(re.fullmatch(r"[a-z_]+", name) is not None, "workflow output name is invalid")
        require("\n" not in value and "\r" not in value and "\x00" not in value, "workflow output value is invalid")
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--policy-sha", required=True)
    args = parser.parse_args()
    try:
        event = read_json(args.event, MAX_EVENT_BYTES, "repository dispatch event")
        policy = parse_policy(read_json(args.config, MAX_CONFIG_BYTES, "release notification policy"))
        token = os.environ.get("GITHUB_TOKEN", "")
        api = Api(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        outputs = validate_event(event, policy, api, args.repository, args.policy_sha)
        append_outputs(args.github_output, outputs)
    except PreflightError as error:
        print(f"release notification rejected: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

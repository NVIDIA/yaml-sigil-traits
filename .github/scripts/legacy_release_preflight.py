#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Fail closed on drift in the exact historical GitHub Release inventory."""

from __future__ import annotations

import argparse
import os
import re
import urllib.parse
from pathlib import Path
from typing import Any

from release_notification_preflight import (
    API_VERSION,
    MAX_CONFIG_BYTES,
    Api,
    PackagePolicy,
    PreflightError,
    append_outputs,
    inspect_archive,
    read_json,
    require,
    require_digest,
    require_keys,
    require_positive,
    require_sha,
    require_string,
    sha256,
)

MAX_RELEASE_BODY_BYTES = 1024 * 1024
MAX_RELEASES = 64
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?\Z"
)
ENTRY_KEYS = (
    "release_id",
    "package",
    "version",
    "tag",
    "tag_object_sha",
    "peeled_commit_sha",
    "target_commitish",
    "draft",
    "prerelease",
    "immutable",
    "asset_count",
    "body_sha256",
    "source_archive_sha256",
    "path_in_vcs",
)


def parse_author(value: Any, label: str) -> dict[str, Any]:
    author = require_keys(value, ("id", "login", "type"), label)
    require_positive(author["id"], f"{label} ID")
    require_string(author["login"], f"{label} login", 128)
    require(author["type"] == "Bot", f"{label} must be a Bot")
    return author


def parse_inventory(raw: dict[str, Any]) -> dict[str, Any]:
    raw = require_keys(
        raw,
        (
            "schema_version",
            "api_version",
            "repository",
            "legacy_author",
            "prospective_author",
            "entries",
        ),
        "legacy Release inventory",
    )
    require(raw["schema_version"] == 1, "legacy Release inventory version is unsupported")
    require(raw["api_version"] == API_VERSION, "legacy Release API version is unsupported")
    require_string(raw["repository"], "legacy Release repository", 256)
    parse_author(raw["legacy_author"], "legacy Release author")
    parse_author(raw["prospective_author"], "prospective Release author")
    entries = raw["entries"]
    require(type(entries) is list and 0 < len(entries) <= MAX_RELEASES, "legacy Release entries are empty or oversized")
    ids: set[int] = set()
    tags: set[str] = set()
    for index, entry in enumerate(entries):
        entry = require_keys(entry, ENTRY_KEYS, f"legacy Release entry {index}")
        release_id = require_positive(entry["release_id"], f"legacy Release entry {index} ID")
        package = require_string(entry["package"], f"legacy Release entry {index} package", 128)
        version = require_string(entry["version"], f"legacy Release entry {index} version", 128)
        tag = require_string(entry["tag"], f"legacy Release entry {index} tag", 256)
        require(VERSION_RE.fullmatch(version) is not None, "legacy Release version is noncanonical")
        require(version in tag, "legacy Release version and tag disagree")
        require_sha(entry["tag_object_sha"], "legacy tag object")
        require_sha(entry["peeled_commit_sha"], "legacy peeled commit")
        require(entry["target_commitish"] == "main", "legacy target_commitish is not exact main")
        require(type(entry["draft"]) is bool and type(entry["prerelease"]) is bool, "legacy Release state is invalid")
        require(entry["immutable"] is False and entry["asset_count"] == 0, "legacy Release mutability or asset state is wrong")
        require_digest(entry["body_sha256"], "legacy Release body digest")
        require_digest(entry["source_archive_sha256"], "legacy source archive digest")
        path = entry["path_in_vcs"]
        require(type(path) is str and len(path.encode("utf-8")) <= 256, "legacy VCS path is invalid")
        require(release_id not in ids and tag not in tags, "legacy Release inventory contains duplicates")
        ids.add(release_id)
        tags.add(tag)
    return raw


def require_author(actual: Any, expected: dict[str, Any], label: str) -> None:
    require(type(actual) is dict, f"{label} is missing")
    require(
        actual.get("id") == expected["id"]
        and actual.get("login") == expected["login"]
        and actual.get("type") == expected["type"],
        f"{label} identity drifted",
    )


def validate_legacy_entry(
    api: Api,
    repository: str,
    author: dict[str, Any],
    entry: dict[str, Any],
) -> None:
    release = api.github_json(f"repos/{repository}/releases/{entry['release_id']}")
    require(type(release) is dict, "legacy GitHub Release response is invalid")
    body = release.get("body")
    assets = release.get("assets")
    require(type(body) is str and len(body.encode("utf-8")) <= MAX_RELEASE_BODY_BYTES, "legacy Release body is invalid")
    require(type(assets) is list, "legacy Release assets are invalid")
    require_author(release.get("author"), author, "legacy Release author")
    require(
        release.get("id") == entry["release_id"]
        and release.get("tag_name") == entry["tag"]
        and release.get("target_commitish") == entry["target_commitish"]
        and release.get("draft") is entry["draft"]
        and release.get("prerelease") is entry["prerelease"]
        and release.get("immutable") is entry["immutable"]
        and len(assets) == entry["asset_count"]
        and sha256(body.encode("utf-8")) == entry["body_sha256"],
        f"legacy Release {entry['release_id']} drifted",
    )

    encoded_tag = urllib.parse.quote(entry["tag"], safe="")
    reference = api.github_json(f"repos/{repository}/git/ref/tags/{encoded_tag}")
    require(type(reference) is dict and type(reference.get("object")) is dict, "legacy tag ref is invalid")
    require(
        reference.get("ref") == f"refs/tags/{entry['tag']}"
        and reference["object"].get("type") == "tag"
        and reference["object"].get("sha") == entry["tag_object_sha"],
        "legacy annotated tag ref drifted",
    )
    tag = api.github_json(f"repos/{repository}/git/tags/{entry['tag_object_sha']}")
    require(type(tag) is dict and type(tag.get("object")) is dict, "legacy tag object is invalid")
    require(
        tag.get("sha") == entry["tag_object_sha"]
        and tag.get("tag") == entry["tag"]
        and tag["object"].get("type") == "commit"
        and tag["object"].get("sha") == entry["peeled_commit_sha"],
        "legacy annotated tag object drifted",
    )

    package = urllib.parse.quote(entry["package"], safe="")
    version = urllib.parse.quote(entry["version"], safe="")
    registry = api.crates_json(f"crates/{package}/{version}")
    require(type(registry) is dict and type(registry.get("version")) is dict, "legacy registry response is invalid")
    record = registry["version"]
    require(
        record.get("num") == entry["version"]
        and record.get("yanked") is False
        and record.get("checksum") == entry["source_archive_sha256"],
        "legacy registry record drifted",
    )
    archive = api.crate_archive(entry["package"], entry["version"])
    require(sha256(archive) == entry["source_archive_sha256"], "legacy source archive checksum drifted")
    inspect_archive(
        archive,
        PackagePolicy(entry["package"], "", entry["path_in_vcs"]),
        entry["version"],
        entry["peeled_commit_sha"],
    )


def validate_inventory(raw: dict[str, Any], api: Api) -> None:
    inventory = parse_inventory(raw)
    repository = inventory["repository"]
    entries = {entry["release_id"]: entry for entry in inventory["entries"]}
    releases = api.github_json(f"repos/{repository}/releases?per_page=100")
    require(type(releases) is list and len(releases) < 100, "GitHub Release inventory is invalid or truncated")
    listed_ids: set[int] = set()
    for release in releases:
        require(type(release) is dict, "listed GitHub Release is invalid")
        release_id = require_positive(release.get("id"), "listed GitHub Release ID")
        require(release_id not in listed_ids, "GitHub listed a duplicate Release")
        listed_ids.add(release_id)
        if release_id in entries:
            require(release.get("tag_name") == entries[release_id]["tag"], "listed legacy Release tag drifted")
            continue
        assets = release.get("assets")
        require(type(assets) is list and not assets, "a prospective Release retained assets")
        require_author(release.get("author"), inventory["prospective_author"], "prospective Release author")
        require(
            release.get("immutable") is True
            and release.get("draft") is False
            and release.get("target_commitish") == "main",
            "an unpinned mutable or draft Release exists",
        )
    require(set(entries) <= listed_ids, "a pinned legacy Release is missing")
    for entry in inventory["entries"]:
        validate_legacy_entry(api, repository, inventory["legacy_author"], entry)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw_bytes = args.inventory.read_bytes()
        require(0 < len(raw_bytes) <= MAX_CONFIG_BYTES, "legacy inventory file is empty or oversized")
        inventory = read_json(args.inventory, MAX_CONFIG_BYTES, "legacy Release inventory")
        api = Api(os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        validate_inventory(inventory, api)
        append_outputs(args.github_output, {"legacy_inventory_digest": sha256(raw_bytes)})
    except (OSError, PreflightError) as error:
        print(f"legacy Release inventory rejected: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

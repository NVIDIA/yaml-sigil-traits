#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Prepare the last official tagged release as release-plz's baseline."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


SHA_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?")
READ_ONLY_PUSH_URL = "disabled://yaml-sigil-release-proposal"
INVENTORY_SCHEMA = 1
REPOSITORY_TAGS = {
    "NVIDIA/yaml-sigil-traits": ("v{version}",),
    "NVIDIA/yaml-sigil-rs": (
        "yaml-sigil-core-v{version}",
        "yaml-sigil-transcription-v{version}",
        "yaml-sigil-signing-v{version}",
        "yaml-sigil-verification-v{version}",
    ),
}
TAG_PATTERNS = {
    "NVIDIA/yaml-sigil-traits": re.compile(
        r"v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)"
    ),
    "NVIDIA/yaml-sigil-rs": re.compile(
        r"yaml-sigil-(?:core|transcription|signing|verification)-v"
        r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)"
    ),
}


class BaselineError(RuntimeError):
    """A release baseline invariant was not satisfied."""


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    """Return Git's exact ancestry result and reject every operational error."""

    result = git(
        root, "merge-base", "--is-ancestor", ancestor, descendant, check=False
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = result.stderr.strip() or result.stdout.strip()
    suffix = f": {detail}" if detail else ""
    raise BaselineError(f"git merge-base --is-ancestor failed{suffix}")


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise BaselineError(f"git {' '.join(args)} failed: {detail}")
    return result


def manifest_version(manifest: Path, repository: str) -> str:
    try:
        with manifest.open("rb") as manifest_file:
            data = tomllib.load(manifest_file)
        if repository == "NVIDIA/yaml-sigil-traits":
            value = data["package"]["version"]
        else:
            value = data["workspace"]["package"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise BaselineError("the detached baseline has no valid release version") from error
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise BaselineError("the detached baseline has an unsupported release version")
    return value


def remote_refs(root: Path, *refs: str) -> dict[str, str]:
    result = git(root, "ls-remote", "--exit-code", "origin", *refs)
    parsed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2 or not SHA_RE.fullmatch(fields[0]):
            raise BaselineError("origin returned an invalid ref response")
        if fields[1] in parsed:
            raise BaselineError(f"origin returned duplicate state for {fields[1]}")
        parsed[fields[1]] = fields[0]
    if set(parsed) != set(refs):
        missing = sorted(set(refs) - set(parsed))
        raise BaselineError(f"origin lacks required refs: {', '.join(missing)}")
    return parsed


def local_official_tag_inventory(
    root: Path, repository: str
) -> dict[str, tuple[str, str]]:
    """Return every relevant local annotated tag object and peeled commit."""

    pattern = TAG_PATTERNS[repository]
    result = git(
        root,
        "for-each-ref",
        "--format=%(refname:strip=2)%09%(objecttype)%09%(objectname)",
        "refs/tags",
    )
    inventory: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise BaselineError("git returned an invalid local tag inventory")
        tag, object_type, tag_object = fields
        if pattern.fullmatch(tag) is None:
            continue
        if object_type != "tag":
            raise BaselineError(f"official tag {tag} is not annotated")
        if SHA_RE.fullmatch(tag_object) is None:
            raise BaselineError(f"official tag {tag} has an invalid object")
        commit = git(
            root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"
        ).stdout.strip()
        if SHA_RE.fullmatch(commit) is None:
            raise BaselineError(f"official tag {tag} has an invalid commit")
        inventory[tag] = (tag_object, commit)
    return inventory


def remote_official_tag_inventory(
    root: Path, repository: str
) -> dict[str, tuple[str, str]]:
    """Return every relevant remote annotated tag object and peeled commit."""

    pattern = TAG_PATTERNS[repository]
    result = git(root, "ls-remote", "--tags", "origin")
    raw: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2 or SHA_RE.fullmatch(fields[0]) is None:
            raise BaselineError("origin returned an invalid tag inventory")
        ref = fields[1]
        peeled = ref.endswith("^{}")
        base_ref = ref[:-3] if peeled else ref
        prefix = "refs/tags/"
        if not base_ref.startswith(prefix):
            continue
        tag = base_ref[len(prefix) :]
        if pattern.fullmatch(tag) is None:
            continue
        field = "commit" if peeled else "object"
        entry = raw.setdefault(tag, {})
        if field in entry:
            raise BaselineError(f"origin returned duplicate state for {ref}")
        entry[field] = fields[0]

    inventory: dict[str, tuple[str, str]] = {}
    for tag, entry in raw.items():
        if set(entry) != {"object", "commit"}:
            raise BaselineError(f"official tag {tag} is not annotated on origin")
        inventory[tag] = (entry["object"], entry["commit"])
    return inventory


def synchronized_official_tag_inventory(
    root: Path, repository: str
) -> dict[str, tuple[str, str]]:
    """Require the complete relevant local and remote inventories to match."""

    local = local_official_tag_inventory(root, repository)
    remote = remote_official_tag_inventory(root, repository)
    if local != remote:
        raise BaselineError("local official tag inventory differs from origin")
    return local


def official_tag_versions(
    root: Path,
    repository: str,
    head: str,
    inventory: dict[str, tuple[str, str]] | None = None,
) -> dict[str, str]:
    pattern = TAG_PATTERNS[repository]
    if inventory is None:
        inventory = synchronized_official_tag_inventory(root, repository)
    grouped: dict[str, dict[str, str]] = {}
    for tag, (_, commit) in inventory.items():
        match = pattern.fullmatch(tag)
        if match is None:  # The synchronized inventory already filtered this.
            raise BaselineError("the official tag inventory contains an invalid name")
        grouped.setdefault(match.group("version"), {})[tag] = commit
    versions: dict[str, str] = {}
    for version, tagged_commits in grouped.items():
        expected = {
            template.format(version=version) for template in REPOSITORY_TAGS[repository]
        }
        if set(tagged_commits) != expected:
            raise BaselineError(
                f"official version {version} has an incomplete official tag set"
            )
        commits = set(tagged_commits.values())
        if len(commits) != 1:
            raise BaselineError(
                f"official version {version} tags resolve to different commits"
            )
        commit = commits.pop()
        if is_ancestor(root, commit, head):
            versions[version] = commit
    return versions


def last_official_version(
    root: Path,
    repository: str,
    head: str,
    exclude_version: str | None = None,
    inventory: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, str]:
    if repository not in REPOSITORY_TAGS:
        raise BaselineError(f"unsupported release repository: {repository}")
    if exclude_version is not None and VERSION_RE.fullmatch(exclude_version) is None:
        raise BaselineError(f"unsupported excluded release version: {exclude_version}")
    versions = official_tag_versions(root, repository, head, inventory)
    if exclude_version is not None:
        versions.pop(exclude_version, None)
    distances = {
        candidate: int(git(root, "rev-list", "--count", f"{commit}..{head}").stdout)
        for candidate, commit in versions.items()
    }
    if not distances:
        raise BaselineError("no reachable official annotated release tag exists")
    nearest_distance = min(distances.values())
    nearest_versions = sorted(
        candidate for candidate, distance in distances.items() if distance == nearest_distance
    )
    if len(nearest_versions) != 1:
        raise BaselineError(
            "the last official annotated release is not unique"
        )
    version = nearest_versions[0]
    return version, versions[version]


def require_last_official_version(
    root: Path,
    repository: str,
    version: str,
    head: str,
    baseline: str,
    exclude_version: str | None,
    inventory: dict[str, tuple[str, str]],
) -> None:
    last_version, last_commit = last_official_version(
        root, repository, head, exclude_version, inventory
    )
    if (last_version, last_commit) != (version, baseline):
        raise BaselineError(
            "the requested version is not the unique last official annotated release"
        )


def normalized_inventory_snapshot(
    repository: str,
    head: str,
    expected_fetch_url: str,
    expected_push_url: str,
    inventory: dict[str, tuple[str, str]],
) -> dict[str, object]:
    """Return the strict, canonical state persisted across release analysis."""

    return {
        "schema": INVENTORY_SCHEMA,
        "repository": repository,
        "head": head,
        "fetch_url": expected_fetch_url,
        "push_url": expected_push_url,
        "official_tags": [
            {"name": tag, "object": tag_object, "commit": commit}
            for tag, (tag_object, commit) in sorted(inventory.items())
        ],
    }


def canonical_snapshot_bytes(snapshot: dict[str, object]) -> bytes:
    """Serialize a snapshot with one accepted representation."""

    return (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_inventory_snapshot(path: Path) -> dict[str, object]:
    """Load an inventory only when its schema and representation are exact."""

    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineError("the official tag inventory snapshot is unreadable") from error
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "repository",
        "head",
        "fetch_url",
        "push_url",
        "official_tags",
    }:
        raise BaselineError("the official tag inventory snapshot has an invalid schema")
    if value.get("schema") != INVENTORY_SCHEMA:
        raise BaselineError("the official tag inventory snapshot has an invalid schema")
    if any(
        not isinstance(value.get(field), str)
        for field in ("repository", "head", "fetch_url", "push_url")
    ):
        raise BaselineError("the official tag inventory snapshot has an invalid schema")
    tags = value.get("official_tags")
    if not isinstance(tags, list):
        raise BaselineError("the official tag inventory snapshot has an invalid schema")
    names: list[str] = []
    for item in tags:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "object", "commit"}
            or not all(isinstance(item.get(field), str) for field in item)
            or SHA_RE.fullmatch(item["object"]) is None
            or SHA_RE.fullmatch(item["commit"]) is None
        ):
            raise BaselineError("the official tag inventory snapshot has an invalid schema")
        names.append(item["name"])
    if names != sorted(set(names)):
        raise BaselineError("the official tag inventory snapshot is not normalized")
    if raw != canonical_snapshot_bytes(value):
        raise BaselineError("the official tag inventory snapshot is not normalized")
    return value


def require_repository_state(
    root: Path,
    repository: str,
    head: str,
    expected_fetch_url: str,
    expected_push_url: str,
) -> None:
    """Require the immutable local and remote authority for release analysis."""

    if repository not in REPOSITORY_TAGS:
        raise BaselineError(f"unsupported release repository: {repository}")
    if SHA_RE.fullmatch(head) is None:
        raise BaselineError("the expected main commit must be a lowercase full SHA")
    if git(root, "rev-parse", "HEAD").stdout.strip() != head:
        raise BaselineError("the checkout is not at the exact expected main commit")
    if git(root, "remote", "get-url", "origin").stdout.strip() != expected_fetch_url:
        raise BaselineError("origin does not use the expected read-only fetch URL")
    push_urls = git(root, "config", "--get-all", "remote.origin.pushurl").stdout.splitlines()
    if push_urls != [expected_push_url]:
        raise BaselineError("origin does not have the exact disabled push URL")
    main_ref = "refs/heads/main"
    if remote_refs(root, main_ref)[main_ref] != head:
        raise BaselineError("origin/main advanced beyond the checked-out commit")


def verify_inventory_snapshot(
    root: Path,
    repository: str,
    head: str,
    expected_fetch_url: str,
    expected_push_url: str,
    snapshot_path: Path,
) -> None:
    """Revalidate the exact persisted authorities immediately before mutation."""

    root = root.resolve()
    snapshot = parse_inventory_snapshot(snapshot_path.resolve())
    expected = {
        "repository": repository,
        "head": head,
        "fetch_url": expected_fetch_url,
        "push_url": expected_push_url,
    }
    for field, value in expected.items():
        if snapshot[field] != value:
            raise BaselineError(
                f"the official tag inventory snapshot has unexpected {field}"
            )
    require_repository_state(
        root, repository, head, expected_fetch_url, expected_push_url
    )
    inventory = synchronized_official_tag_inventory(root, repository)
    if normalized_inventory_snapshot(
        repository, head, expected_fetch_url, expected_push_url, inventory
    ) != snapshot:
        raise BaselineError("the official tag inventory changed after release analysis")
    # Re-read both remote authorities so a race during verification also fails.
    require_repository_state(
        root, repository, head, expected_fetch_url, expected_push_url
    )
    if synchronized_official_tag_inventory(root, repository) != inventory:
        raise BaselineError("the official tag inventory changed during verification")


def prepare_baseline(
    root: Path,
    repository: str,
    version: str,
    head: str,
    output: Path,
    expected_fetch_url: str,
    expected_push_url: str,
    exclude_version: str | None = None,
    inventory_output: Path | None = None,
) -> tuple[str, Path, tuple[str, ...]]:
    if repository not in REPOSITORY_TAGS:
        raise BaselineError(f"unsupported release repository: {repository}")
    if VERSION_RE.fullmatch(version) is None:
        raise BaselineError(f"unsupported official release version: {version}")
    root = root.resolve()
    require_repository_state(
        root, repository, head, expected_fetch_url, expected_push_url
    )
    main_ref = "refs/heads/main"

    inventory = synchronized_official_tag_inventory(root, repository)
    if exclude_version is not None:
        if VERSION_RE.fullmatch(exclude_version) is None:
            raise BaselineError(f"unsupported excluded release version: {exclude_version}")
        if manifest_version(root / "Cargo.toml", repository) != exclude_version:
            raise BaselineError(
                "the excluded retry version does not match current main"
            )
        expected_excluded = {
            template.format(version=exclude_version)
            for template in REPOSITORY_TAGS[repository]
        }
        present_excluded = expected_excluded.intersection(inventory)
        if present_excluded:
            if present_excluded != expected_excluded:
                raise BaselineError(
                    "the excluded retry version has an incomplete official tag set"
                )
            excluded_commits = {
                inventory[tag][1] for tag in expected_excluded
            }
            if excluded_commits != {head}:
                raise BaselineError(
                    "the excluded retry version does not tag exact current main"
                )

    tags = tuple(template.format(version=version) for template in REPOSITORY_TAGS[repository])
    commits: set[str] = set()
    for tag in tags:
        if tag not in inventory:
            raise BaselineError(f"origin lacks required official tag {tag}")
        tag_object, commit = inventory[tag]
        if git(root, "cat-file", "-t", tag_object).stdout.strip() != "tag":
            raise BaselineError(f"official tag {tag} is not annotated")
        commits.add(commit)

    if len(commits) != 1:
        raise BaselineError("official workspace tags resolve to different commits")
    baseline = commits.pop()
    if not is_ancestor(root, baseline, head):
        raise BaselineError("the official release tag is not an ancestor of current main")
    require_last_official_version(
        root, repository, version, head, baseline, exclude_version, inventory
    )

    output = output.resolve()
    if output.exists():
        raise BaselineError(f"baseline output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    git(root, "worktree", "add", "--detach", "--quiet", str(output), baseline)
    if git(output, "rev-parse", "HEAD").stdout.strip() != baseline:
        raise BaselineError("the detached baseline checkout changed commit")
    if git(output, "status", "--porcelain").stdout:
        raise BaselineError("the detached baseline checkout is not clean")
    manifest = output / "Cargo.toml"
    if not manifest.is_file():
        raise BaselineError("the detached baseline lacks Cargo.toml")
    if manifest_version(manifest, repository) != version:
        raise BaselineError("the detached baseline manifest does not match its tag version")

    # Re-read both remote authorities after extraction so a tag or main race
    # cannot silently change the selected baseline during this operation.
    if synchronized_official_tag_inventory(root, repository) != inventory:
        raise BaselineError("the official tag inventory changed during baseline preparation")
    if remote_refs(root, main_ref)[main_ref] != head:
        raise BaselineError("origin/main advanced during baseline preparation")
    if inventory_output is not None:
        inventory_output = inventory_output.resolve()
        if inventory_output.exists():
            raise BaselineError(
                f"official tag inventory output already exists: {inventory_output}"
            )
        inventory_output.parent.mkdir(parents=True, exist_ok=True)
        snapshot = normalized_inventory_snapshot(
            repository, head, expected_fetch_url, expected_push_url, inventory
        )
        try:
            inventory_output.write_bytes(canonical_snapshot_bytes(snapshot))
        except OSError as error:
            raise BaselineError("could not persist official tag inventory") from error
        verify_inventory_snapshot(
            root,
            repository,
            head,
            expected_fetch_url,
            expected_push_url,
            inventory_output,
        )
    return baseline, manifest, tags


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version")
    parser.add_argument("--exclude-version")
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory-output", type=Path)
    parser.add_argument("--verify-inventory", type=Path)
    parser.add_argument("--root", default=Path.cwd(), type=Path)
    parser.add_argument("--expected-fetch-url", required=True)
    parser.add_argument("--expected-push-url", default=READ_ONLY_PUSH_URL)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_inventory is not None:
            if any(
                value is not None
                for value in (
                    args.version,
                    args.exclude_version,
                    args.output,
                    args.inventory_output,
                )
            ):
                raise BaselineError(
                    "--verify-inventory cannot be combined with baseline preparation"
                )
            verify_inventory_snapshot(
                args.root,
                args.repository,
                args.head,
                args.expected_fetch_url,
                args.expected_push_url,
                args.verify_inventory,
            )
            print("Verified the unchanged official tag inventory and current main.")
            return 0
        if args.output is None:
            raise BaselineError("--output is required for baseline preparation")
        version = args.version
        if version is None:
            version, _ = last_official_version(
                args.root.resolve(),
                args.repository,
                args.head,
                args.exclude_version,
            )
        elif args.exclude_version is not None:
            raise BaselineError("--version and --exclude-version cannot be combined")
        inventory_output = args.inventory_output
        if inventory_output is None:
            inventory_output = args.output.parent / f"{args.output.name}-official-tags.json"
        baseline, manifest, tags = prepare_baseline(
            args.root,
            args.repository,
            version,
            args.head,
            args.output,
            args.expected_fetch_url,
            args.expected_push_url,
            args.exclude_version,
            inventory_output,
        )
    except BaselineError as error:
        print(f"release baseline failed: {error}", file=sys.stderr)
        return 1
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as output_file:
            output_file.write(f"commit={baseline}\n")
            output_file.write(f"manifest={manifest}\n")
            output_file.write(f"tags={','.join(tags)}\n")
            output_file.write(f"version={version}\n")
            output_file.write(f"inventory={inventory_output.resolve()}\n")
    print(f"Prepared official release baseline {baseline} at {manifest}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

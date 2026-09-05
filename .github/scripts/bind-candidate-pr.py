#!/usr/bin/env python3
"""Bind anonymous copied-ref PR metadata before candidate materialization."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 1024 * 1024
RELEASE_BRANCH_PREFIX = "release-plz-manual-"
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)


class BindingError(RuntimeError):
    """A copied-ref or release-branch binding failed closed."""


class Api(Protocol):
    """Minimal anonymous GitHub read boundary used by fixtures and production."""

    def get(self, path: str) -> Any:
        """Fetch and decode one JSON response."""


class AnonymousGitHubApi:
    """Bounded GitHub API client that never accepts or sends a credential."""

    def get(self, path: str) -> Any:
        if path.startswith("/") or ".." in path or any(c in path for c in "\r\n"):
            raise BindingError("GitHub API path is malformed")
        request = urllib.request.Request(
            f"{API_ROOT}/{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "yaml-sigil-candidate-pr-binding/1",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise BindingError(f"GitHub API read returned HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise BindingError("GitHub API read failed") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise BindingError("GitHub API response is oversized")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BindingError("GitHub API returned invalid JSON") from error


@dataclass(frozen=True)
class CandidatePrBinding:
    """The optional canonical release branch bound to one copied head."""

    release_branch: str | None


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BindingError(f"{label} is not an object")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BindingError(f"{label} is not an array")
    return value


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BindingError(f"{label} is not a positive integer")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in "\r\n"):
        raise BindingError(f"{label} is not one nonempty line")
    return value


def _sha(value: Any, label: str) -> str:
    value = _text(value, label)
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise BindingError(f"{label} is not a lowercase full SHA")
    return value


def _repository(value: Any, label: str) -> str:
    return _text(_mapping(value, label).get("full_name"), f"{label} full name")


def bind_candidate_pr(
    api: Api,
    repository: str,
    copied_ref: str,
    head_sha: str,
    base_sha: str,
) -> CandidatePrBinding:
    """Rebind one open PR, copied ref, and current main without a token."""

    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise BindingError("repository is malformed")
    copied = re.fullmatch(r"pull-request/([1-9][0-9]*)", copied_ref)
    if copied is None:
        raise BindingError("copied ref is malformed")
    head_sha = _sha(head_sha, "expected head SHA")
    base_sha = _sha(base_sha, "expected base SHA")
    number = int(copied.group(1))

    prefix = f"repos/{repository}"
    pull = _mapping(api.get(f"{prefix}/pulls/{number}"), "pull request")
    base = _mapping(pull.get("base"), "pull request base")
    head = _mapping(pull.get("head"), "pull request head")
    if (
        pull.get("number") != number
        or pull.get("state") != "open"
        or _text(base.get("ref"), "pull request base ref") != "main"
        or _repository(base.get("repo"), "pull request base repository")
        != repository
        or _sha(base.get("sha"), "pull request base SHA") != base_sha
        or _sha(head.get("sha"), "pull request head SHA") != head_sha
    ):
        raise BindingError("pull request no longer binds the copied candidate")

    expected_commits = _integer(pull.get("commits"), "pull request commit count")
    if expected_commits > 100:
        raise BindingError("pull request commit inventory exceeds its bound")
    commits = _sequence(
        api.get(f"{prefix}/pulls/{number}/commits?per_page=100"),
        "pull request commits",
    )
    if len(commits) != expected_commits:
        raise BindingError("pull request commit inventory is incomplete")
    commit_shas = []
    for item in commits:
        commit = _mapping(item, "pull request commit")
        commit_shas.append(_sha(commit.get("sha"), "pull request commit SHA"))
        verification = _mapping(
            _mapping(commit.get("commit"), "pull request commit body").get(
                "verification"
            ),
            "pull request commit verification",
        )
        if (
            verification.get("verified") is not True
            or verification.get("reason") != "valid"
        ):
            raise BindingError("pull request commit is not GitHub Verified")
    if commit_shas[-1] != head_sha:
        raise BindingError("pull request commit inventory does not end at the head")

    copied_readback = _mapping(
        api.get(f"{prefix}/git/ref/heads/{copied_ref}"), "copied ref"
    )
    copied_object = _mapping(copied_readback.get("object"), "copied ref object")
    if (
        copied_readback.get("ref") != f"refs/heads/{copied_ref}"
        or copied_object.get("type") != "commit"
        or _sha(copied_object.get("sha"), "copied ref SHA") != head_sha
    ):
        raise BindingError("copied ref no longer points to the reviewed head")

    main_readback = _mapping(api.get(f"{prefix}/git/ref/heads/main"), "main ref")
    main_object = _mapping(main_readback.get("object"), "main ref object")
    if (
        main_readback.get("ref") != "refs/heads/main"
        or main_object.get("type") != "commit"
        or _sha(main_object.get("sha"), "main ref SHA") != base_sha
    ):
        raise BindingError("main changed after protected policy was staged")

    head_ref = _text(head.get("ref"), "pull request head ref")
    if not head_ref.startswith(RELEASE_BRANCH_PREFIX):
        return CandidatePrBinding(release_branch=None)
    version = head_ref.removeprefix(RELEASE_BRANCH_PREFIX)
    if SEMVER.fullmatch(version) is None or _repository(
        head.get("repo"), "pull request head repository"
    ) != repository:
        raise BindingError("release branch is not one canonical repository branch")
    return CandidatePrBinding(release_branch=head_ref)


def append_output(path: Path, binding: CandidatePrBinding) -> None:
    """Append only the validated branch scalar to the runner output file."""

    value = binding.release_branch or ""
    if any(c in value for c in "\r\n"):
        raise BindingError("release branch output is malformed")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"release_branch={value}\n")
    except OSError as error:
        raise BindingError("cannot write the runner output") from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--copied-ref", required=True)
    result.add_argument("--head-sha", required=True)
    result.add_argument("--base-sha", required=True)
    result.add_argument("--output", required=True, type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        binding = bind_candidate_pr(
            AnonymousGitHubApi(),
            arguments.repository,
            arguments.copied_ref,
            arguments.head_sha,
            arguments.base_sha,
        )
        append_output(arguments.output, binding)
    except BindingError as error:
        print(f"candidate PR binding: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Python is justified here because the credential-free candidate job must bind
# structured GitHub metadata before materializing or executing candidate source.
# A Cargo xtask would require compiling repository-controlled Rust at the wrong
# trust boundary; shell would make the bounded JSON checks harder to type and
# fixture-test. Keep this pre-checkout binder standard-library-only.
"""Bind anonymous copied-ref PR metadata before candidate materialization.

This provider-specific trust-boundary helper accepts the repository, copied
ref, reviewed candidate SHA, protected-policy SHA, and runner-output path. It
performs bounded, anonymous GitHub reads to prove that the pull request remains
open; its candidate, contribution base, copied ref, ordered commit inventory,
and protected ``main`` are current; and any release branch has the canonical
same-repository shape.

On success it appends only validated single-line base and release scalars to
the caller-supplied runner-output file. That append is its sole mutation. It
does not accept a token, check out source, execute candidate code, create a
check, or change repository state. Missing, malformed, oversized, ambiguous,
or stale evidence fails closed before candidate materialization. Commit DCO is
validated later by protected policy; ordinary contributors need not sign
commits cryptographically.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 1024 * 1024
RELEASE_BRANCH_PREFIX = "release-plz-manual-"
MAIN_REF = "refs/heads/main"
MAIN_CHECK = "Required CI"
SUPPORTED_REPOSITORIES = {
    "NVIDIA/yaml-sigil-rs",
    "NVIDIA/yaml-sigil-spec",
    "NVIDIA/yaml-sigil-traits",
}
VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,8})"
RUST_COORDINATION_BRANCH = re.compile(
    rf"dev/{VERSION_COMPONENT}\.{VERSION_COMPONENT}\.{VERSION_COMPONENT}"
)
SPEC_COORDINATION_BRANCH = re.compile(
    r"v[1-9][0-9]{0,8}(?:(?:alpha|beta)[1-9][0-9]{0,8})?"
)
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
        """Fetch one bounded anonymous JSON response from a relative API path."""

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
    """One copied head bound to independent policy and contribution bases."""

    base_ref: str
    base_sha: str
    check_name: str
    release_branch: str | None


def _mapping(value: Any, label: str) -> dict[str, Any]:
    """Return one JSON object or reject the named field."""

    if not isinstance(value, dict):
        raise BindingError(f"{label} is not an object")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    """Return one JSON array or reject the named field."""

    if not isinstance(value, list):
        raise BindingError(f"{label} is not an array")
    return value


def _integer(value: Any, label: str) -> int:
    """Return one positive JSON integer, excluding booleans."""

    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BindingError(f"{label} is not a positive integer")
    return value


def _text(value: Any, label: str) -> str:
    """Return one nonempty line of text suitable for runner output."""

    if not isinstance(value, str) or not value or any(c in value for c in "\r\n"):
        raise BindingError(f"{label} is not one nonempty line")
    return value


def _sha(value: Any, label: str) -> str:
    """Return one canonical lowercase full Git object ID."""

    value = _text(value, label)
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise BindingError(f"{label} is not a lowercase full SHA")
    return value


def _repository(value: Any, label: str) -> str:
    """Extract one repository's nonempty ``full_name`` field."""

    return _text(_mapping(value, label).get("full_name"), f"{label} full name")


def base_policy(repository: str, branch: str) -> tuple[str, str]:
    """Return the canonical full ref and App check for one allowed PR base."""

    branch = _text(branch, "pull request base ref")
    if repository not in SUPPORTED_REPOSITORIES:
        raise BindingError("repository has no protected candidate policy")
    if branch == "main":
        return MAIN_REF, MAIN_CHECK
    if repository in {
        "NVIDIA/yaml-sigil-rs",
        "NVIDIA/yaml-sigil-traits",
    }:
        allowed = RUST_COORDINATION_BRANCH.fullmatch(branch) is not None
    else:
        allowed = SPEC_COORDINATION_BRANCH.fullmatch(branch) is not None
    if not allowed:
        raise BindingError("pull request base is not an allowed coordination branch")
    full_ref = f"refs/heads/{branch}"
    check_name = f"Required CI [{full_ref}]"
    if len(check_name) > 128:
        raise BindingError("coordination required-check name is oversized")
    return full_ref, check_name


def bind_candidate_pr(
    api: Api,
    repository: str,
    copied_ref: str,
    head_sha: str,
    policy_sha: str,
) -> CandidatePrBinding:
    """Rebind one PR base, copied ref, and protected policy without a token."""

    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise BindingError("repository is malformed")
    copied = re.fullmatch(r"pull-request/([1-9][0-9]*)", copied_ref)
    if copied is None:
        raise BindingError("copied ref is malformed")
    head_sha = _sha(head_sha, "expected head SHA")
    policy_sha = _sha(policy_sha, "expected policy SHA")
    number = int(copied.group(1))

    prefix = f"repos/{repository}"
    pull = _mapping(api.get(f"{prefix}/pulls/{number}"), "pull request")
    base = _mapping(pull.get("base"), "pull request base")
    head = _mapping(pull.get("head"), "pull request head")
    if pull.get("number") != number or pull.get("state") != "open":
        raise BindingError("pull request no longer binds the copied candidate")
    if _repository(base.get("repo"), "pull request base repository") != repository:
        raise BindingError("pull request no longer binds the copied candidate")
    if _sha(head.get("sha"), "pull request head SHA") != head_sha:
        raise BindingError("pull request no longer binds the copied candidate")
    base_ref, check_name = base_policy(
        repository, _text(base.get("ref"), "pull request base ref")
    )
    base_sha = _sha(base.get("sha"), "pull request base SHA")

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

    main_readback = _mapping(
        api.get(f"{prefix}/git/ref/heads/main"), "protected policy ref"
    )
    main_object = _mapping(main_readback.get("object"), "main ref object")
    if (
        main_readback.get("ref") != MAIN_REF
        or main_object.get("type") != "commit"
        or _sha(main_object.get("sha"), "protected policy SHA") != policy_sha
    ):
        raise BindingError("main changed after protected policy was staged")

    if base_ref == MAIN_REF:
        base_readback = main_readback
    else:
        encoded_ref = urllib.parse.quote(base_ref.removeprefix("refs/"), safe="/")
        base_readback = _mapping(
            api.get(f"{prefix}/git/ref/{encoded_ref}"), "contribution base ref"
        )
    base_object = _mapping(base_readback.get("object"), "contribution base object")
    if (
        base_readback.get("ref") != base_ref
        or base_object.get("type") != "commit"
        or _sha(base_object.get("sha"), "contribution base SHA") != base_sha
    ):
        raise BindingError("pull request contribution base is not current")

    head_ref = _text(head.get("ref"), "pull request head ref")
    if not head_ref.startswith(RELEASE_BRANCH_PREFIX):
        return CandidatePrBinding(
            base_ref=base_ref,
            base_sha=base_sha,
            check_name=check_name,
            release_branch=None,
        )
    version = head_ref.removeprefix(RELEASE_BRANCH_PREFIX)
    if SEMVER.fullmatch(version) is None or _repository(
        head.get("repo"), "pull request head repository"
    ) != repository or base_ref != MAIN_REF:
        raise BindingError("release branch is not one canonical repository branch")
    return CandidatePrBinding(
        base_ref=base_ref,
        base_sha=base_sha,
        check_name=check_name,
        release_branch=head_ref,
    )


def append_output(path: Path, binding: CandidatePrBinding) -> None:
    """Append only validated one-line binding scalars to runner output."""

    values = {
        "base_ref": binding.base_ref,
        "base_sha": binding.base_sha,
        "check_name": binding.check_name,
        "release_branch": binding.release_branch or "",
    }
    if any(any(c in value for c in "\r\n") for value in values.values()):
        raise BindingError("candidate binding output is malformed")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as output:
            for name, value in values.items():
                output.write(f"{name}={value}\n")
    except OSError as error:
        raise BindingError("cannot write the runner output") from error


def parser() -> argparse.ArgumentParser:
    """Build the fixed command-line interface used by candidate CI."""

    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", required=True)
    result.add_argument("--copied-ref", required=True)
    result.add_argument("--head-sha", required=True)
    result.add_argument("--policy-sha", required=True)
    result.add_argument("--output", required=True, type=Path)
    return result


def main() -> int:
    """Bind current GitHub state and append outputs, returning failure closed."""

    arguments = parser().parse_args()
    try:
        binding = bind_candidate_pr(
            AnonymousGitHubApi(),
            arguments.repository,
            arguments.copied_ref,
            arguments.head_sha,
            arguments.policy_sha,
        )
        append_output(arguments.output, binding)
    except BindingError as error:
        print(f"candidate PR binding: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Authorize publication only for an exact merged release proposal."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any, Protocol
import urllib.error
import urllib.parse
import urllib.request


API_VERSION = "2022-11-28"
BOT_LOGIN = "nvidia-yamlsigil-release-pr[bot]"
BOT_ID = 318780254
BOT_EMAIL = "318780254+nvidia-yamlsigil-release-pr[bot]@users.noreply.github.com"
WEB_FLOW_ID = 19864447
SHA_RE = re.compile(r"[0-9a-f]{40}")
RELEASE_VERSION_RE = re.compile(
    r"(?P<core>(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
    r"(?:-rc\.(?P<rc>[1-9][0-9]*))?"
)
WRITER_PERMISSIONS = {"admin", "maintain", "write"}
ALLOWED_PATHS = {
    "NVIDIA/yaml-sigil-traits": {"Cargo.toml", "CHANGELOG.md"},
    "NVIDIA/yaml-sigil-rs": {
        "Cargo.toml",
        "crates/yaml-sigil-core/CHANGELOG.md",
        "crates/yaml-sigil-transcription/CHANGELOG.md",
        "crates/yaml-sigil-signing/CHANGELOG.md",
        "crates/yaml-sigil-verification/CHANGELOG.md",
    },
}


class SourceAuthorizationError(RuntimeError):
    """The merged source does not have exact release authorization."""


class GitHubReader(Protocol):
    def get(self, path: str) -> Any: ...

    def paginate(self, path: str) -> list[Any]: ...


class LiveGitHubReader:
    """Read GitHub REST data with explicit pagination and no write method."""

    def __init__(self, token: str) -> None:
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "yaml-sigil-release-workflow/1.0",
            "X-GitHub-Api-Version": API_VERSION,
        }

    def request(self, url: str) -> tuple[Any, str | None]:
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=self.headers, method="GET"),
                timeout=30,
            ) as response:
                body = response.read()
                link = response.headers.get("Link")
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
            raise SourceAuthorizationError("GitHub source authorization lookup failed") from error
        try:
            return json.loads(body), link
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SourceAuthorizationError("GitHub returned invalid source authorization data") from error

    def get(self, path: str) -> Any:
        value, link = self.request(f"https://api.github.com{path}")
        if link is not None:
            raise SourceAuthorizationError("an object lookup returned ambiguous pagination")
        return value

    def paginate(self, path: str) -> list[Any]:
        separator = "&" if "?" in path else "?"
        url: str | None = f"https://api.github.com{path}{separator}per_page=100"
        values: list[Any] = []
        pages = 0
        while url is not None:
            pages += 1
            if pages > 100:
                raise SourceAuthorizationError("GitHub pagination exceeded its bound")
            value, link = self.request(url)
            if not isinstance(value, list):
                raise SourceAuthorizationError("GitHub returned a non-list page")
            values.extend(value)
            next_urls = []
            if link:
                for item in link.split(","):
                    match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', item)
                    if match is None:
                        raise SourceAuthorizationError("GitHub returned an invalid Link header")
                    if match.group(2) == "next":
                        next_urls.append(match.group(1))
            if len(next_urls) > 1:
                raise SourceAuthorizationError("GitHub returned ambiguous pagination")
            url = next_urls[0] if next_urls else None
        return values


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceAuthorizationError(f"{label} is not an object")
    return value


def sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise SourceAuthorizationError(f"{label} is not an exact commit SHA")
    return value


def user_id(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SourceAuthorizationError(f"{label} is not an immutable user ID")
    return value


def manifest_release_version(root: Path, repository: str) -> str:
    """Read the synchronized release version from the authorized checkout."""

    try:
        with (root / "Cargo.toml").open("rb") as manifest_file:
            manifest = tomllib.load(manifest_file)
        value = (
            manifest["package"]["version"]
            if repository == "NVIDIA/yaml-sigil-traits"
            else manifest["workspace"]["package"]["version"]
        )
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise SourceAuthorizationError(
            "release source has no exact manifest version"
        ) from error
    if not isinstance(value, str) or RELEASE_VERSION_RE.fullmatch(value) is None:
        raise SourceAuthorizationError("release source has an unsupported manifest version")
    return value


def is_stable_promotion(baseline_version: str, current_version: str) -> bool:
    """Identify the sole transition whose source must equal its tagged RC."""

    baseline = RELEASE_VERSION_RE.fullmatch(baseline_version)
    current = RELEASE_VERSION_RE.fullmatch(current_version)
    if baseline is None or current is None:
        raise SourceAuthorizationError("release baseline or current version is unsupported")
    return (
        baseline.group("rc") is not None
        and current.group("rc") is None
        and current.group("core") == baseline.group("core")
    )


def authorize_source(
    api: GitHubReader,
    repository: str,
    commit: str,
    root: Path,
    baseline_version: str,
    baseline_commit: str,
) -> int:
    if (
        repository not in ALLOWED_PATHS
        or SHA_RE.fullmatch(commit) is None
        or SHA_RE.fullmatch(baseline_commit) is None
    ):
        raise SourceAuthorizationError("repository or release commit is unsupported")
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or result.stdout.strip() != commit:
        raise SourceAuthorizationError("checkout does not identify the release commit")
    current_version = manifest_release_version(root, repository)
    stable_promotion = is_stable_promotion(baseline_version, current_version)
    expected_manual_branch = f"release-plz-manual-{current_version}"

    pulls = api.paginate(f"/repos/{repository}/commits/{commit}/pulls")
    matches: list[dict[str, Any]] = []
    for value in pulls:
        pull = require_mapping(value, "associated pull request")
        head = require_mapping(pull.get("head"), "associated pull request head")
        base = require_mapping(pull.get("base"), "associated pull request base")
        head_repo = require_mapping(head.get("repo"), "associated head repository")
        base_repo = require_mapping(base.get("repo"), "associated base repository")
        user = require_mapping(pull.get("user"), "associated pull request author")
        branch = head.get("ref")
        app_proposal = (
            branch == "release-plz-next"
            and user.get("login") == BOT_LOGIN
            and user.get("id") == BOT_ID
        )
        manual_proposal = (
            branch == expected_manual_branch and user.get("login") != BOT_LOGIN
        )
        if (
            pull.get("state") == "closed"
            and isinstance(pull.get("merged_at"), str)
            and pull.get("merge_commit_sha") == commit
            and (app_proposal or manual_proposal)
            and head_repo.get("full_name") == repository
            and base_repo.get("full_name") == repository
            and base.get("ref") == "main"
        ):
            matches.append(pull)
    if len(matches) != 1:
        raise SourceAuthorizationError("release commit lacks one exact merged proposal")

    number = matches[0].get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        raise SourceAuthorizationError("merged release pull request number is invalid")
    pull = require_mapping(api.get(f"/repos/{repository}/pulls/{number}"), "release pull request")
    detailed_head = require_mapping(pull.get("head"), "release pull request head")
    detailed_base = require_mapping(pull.get("base"), "release pull request base")
    detailed_user = require_mapping(pull.get("user"), "release pull request author")
    changed_files = pull.get("changed_files")
    if (
        pull.get("commits") != 1
        or not isinstance(changed_files, int)
        or isinstance(changed_files, bool)
        or changed_files <= 0
    ):
        raise SourceAuthorizationError("release pull request summary is incomplete")
    if not (
        pull.get("state") == "closed"
        and pull.get("merge_commit_sha") == commit
        and pull.get("merged_at") == matches[0].get("merged_at")
        and detailed_user.get("login")
        == require_mapping(matches[0].get("user"), "associated author").get("login")
        and detailed_user.get("id")
        == require_mapping(matches[0].get("user"), "associated author").get("id")
        and require_mapping(detailed_head.get("repo"), "release head repository").get("full_name")
        == repository
        and detailed_head.get("ref")
        == require_mapping(matches[0].get("head"), "associated head").get("ref")
        and detailed_head.get("sha")
        == require_mapping(matches[0].get("head"), "associated head").get("sha")
        and require_mapping(detailed_base.get("repo"), "release base repository").get("full_name")
        == repository
        and detailed_base.get("ref") == "main"
        and detailed_base.get("sha")
        == require_mapping(matches[0].get("base"), "associated base").get("sha")
    ):
        raise SourceAuthorizationError("release pull request changed during authorization")
    merged_by = require_mapping(pull.get("merged_by"), "release pull request merger")
    merger = merged_by.get("login")
    if not isinstance(merger, str) or not merger:
        raise SourceAuthorizationError("release pull request has no exact merger")
    merger_id = user_id(merged_by.get("id"), "release pull request merger")
    encoded_merger = urllib.parse.quote(merger, safe="")
    permission = require_mapping(
        api.get(f"/repos/{repository}/collaborators/{encoded_merger}/permission"),
        "release merger permission",
    )
    permission_user = require_mapping(permission.get("user"), "release merger identity")
    if (
        permission.get("permission") not in WRITER_PERMISSIONS
        or permission_user.get("login") != merger
        or user_id(permission_user.get("id"), "release merger permission identity")
        != merger_id
    ):
        raise SourceAuthorizationError("release pull request merger lacks current write authority")
    owner = detailed_user.get("login")
    if not isinstance(owner, str) or not owner:
        raise SourceAuthorizationError("release pull request owner is invalid")
    owner_id = user_id(detailed_user.get("id"), "release pull request owner")
    branch = detailed_head.get("ref")
    app_proposal = branch == "release-plz-next" and owner == BOT_LOGIN and owner_id == BOT_ID
    manual_proposal = branch == expected_manual_branch and owner != BOT_LOGIN
    if not app_proposal and not manual_proposal:
        raise SourceAuthorizationError("release pull request ownership is invalid")
    # A human-created fallback remains authorized only while its exact owner is
    # a current writer. The App bot is bound to its immutable ID because it is
    # not itself a repository collaborator.
    if manual_proposal:
        owner_permission = require_mapping(
            api.get(
                f"/repos/{repository}/collaborators/"
                f"{urllib.parse.quote(owner, safe='')}/permission"
            ),
            "release owner permission",
        )
        owner_identity = require_mapping(
            owner_permission.get("user"), "release owner identity"
        )
        if (
            owner_permission.get("permission") not in WRITER_PERMISSIONS
            or owner_identity.get("login") != owner
            or user_id(owner_identity.get("id"), "release owner permission identity")
            != owner_id
        ):
            raise SourceAuthorizationError(
                "release pull request owner lacks current write authority"
            )

    commits = api.paginate(f"/repos/{repository}/pulls/{number}/commits")
    if len(commits) != 1:
        raise SourceAuthorizationError("release pull request does not have one commit")
    summary = require_mapping(commits[0], "release proposal commit summary")
    proposal_sha = sha(summary.get("sha"), "release proposal commit")
    if proposal_sha != require_mapping(pull.get("head"), "release pull request head").get("sha"):
        raise SourceAuthorizationError("release pull request head changed during authorization")
    proposal = require_mapping(
        api.get(f"/repos/{repository}/commits/{proposal_sha}"),
        "release proposal commit",
    )
    if proposal.get("sha") != proposal_sha:
        raise SourceAuthorizationError("release proposal commit response is mismatched")
    author = require_mapping(proposal.get("author"), "release proposal REST author")
    committer = require_mapping(proposal.get("committer"), "release proposal REST committer")
    details = require_mapping(proposal.get("commit"), "release proposal raw commit")
    raw_author = require_mapping(details.get("author"), "release proposal raw author")
    raw_committer = require_mapping(details.get("committer"), "release proposal raw committer")
    verification = require_mapping(details.get("verification"), "release proposal signature")
    tree = require_mapping(details.get("tree"), "release proposal tree")
    parents = proposal.get("parents")
    base_sha = sha(require_mapping(pull.get("base"), "release pull request base").get("sha"), "release base")
    if stable_promotion and base_sha != baseline_commit:
        raise SourceAuthorizationError(
            "stable promotion base does not match the exact tagged RC commit"
        )
    expected_dco = f"Signed-off-by: {BOT_LOGIN} <{BOT_EMAIL}>"
    message = details.get("message")
    dco_lines = (
        [line for line in message.splitlines() if line.startswith("Signed-off-by: ")]
        if isinstance(message, str)
        else []
    )
    common_valid = (
        verification.get("verified") is True
        and verification.get("reason") == "valid"
        and isinstance(parents, list)
        and len(parents) == 1
        and require_mapping(parents[0], "release proposal parent").get("sha") == base_sha
        and SHA_RE.fullmatch(str(tree.get("sha"))) is not None
    )
    app_identity = (
        app_proposal
        and author.get("login") == BOT_LOGIN
        and author.get("id") == BOT_ID
        and committer.get("login") == "web-flow"
        and committer.get("id") == WEB_FLOW_ID
        and raw_author.get("name") == BOT_LOGIN
        and raw_author.get("email") == BOT_EMAIL
        and raw_committer.get("name") == "GitHub"
        and raw_committer.get("email") == "noreply@github.com"
        and dco_lines == [expected_dco]
    )
    raw_author_name = raw_author.get("name")
    raw_author_email = raw_author.get("email")
    raw_author_identity = f"{raw_author_name} <{raw_author_email}>"
    manual_identity = (
        manual_proposal
        and isinstance(raw_author_name, str)
        and bool(raw_author_name)
        and isinstance(raw_author_email, str)
        and bool(raw_author_email)
        and author.get("login") == owner
        and author.get("id") == owner_id
        and committer.get("login") == owner
        and committer.get("id") == owner_id
        and raw_author_name == raw_committer.get("name")
        and raw_author_email == raw_committer.get("email")
        and dco_lines == [f"Signed-off-by: {raw_author_identity}"]
    )
    if not common_valid or not (app_identity or manual_identity):
        raise SourceAuthorizationError("release proposal commit identity is invalid")

    integrated = require_mapping(
        api.get(f"/repos/{repository}/commits/{commit}"),
        "current main release commit",
    )
    if integrated.get("sha") != commit:
        raise SourceAuthorizationError("current main commit response is mismatched")
    integrated_author = require_mapping(
        integrated.get("author"), "current main REST author"
    )
    integrated_committer = require_mapping(
        integrated.get("committer"), "current main REST committer"
    )
    integrated_details = require_mapping(
        integrated.get("commit"), "current main raw commit"
    )
    integrated_raw_author = require_mapping(
        integrated_details.get("author"), "current main raw author"
    )
    integrated_raw_committer = require_mapping(
        integrated_details.get("committer"), "current main raw committer"
    )
    integrated_verification = require_mapping(
        integrated_details.get("verification"), "current main signature"
    )
    integrated_tree = require_mapping(integrated_details.get("tree"), "current main tree")
    integrated_parents = integrated.get("parents")
    integrated_message = integrated_details.get("message")
    integrated_dco_lines = (
        [
            line
            for line in integrated_message.splitlines()
            if line.startswith("Signed-off-by: ")
        ]
        if isinstance(integrated_message, str)
        else []
    )
    integrated_common = (
        integrated_verification.get("verified") is True
        and integrated_verification.get("reason") == "valid"
        and isinstance(integrated_parents, list)
        and len(integrated_parents) == 1
        and require_mapping(integrated_parents[0], "current main parent").get("sha")
        == base_sha
        and integrated_tree.get("sha") == tree.get("sha")
    )
    integrated_web_flow = (
        integrated_committer.get("login") == "web-flow"
        and integrated_committer.get("id") == WEB_FLOW_ID
        and integrated_raw_committer.get("name") == "GitHub"
        and integrated_raw_committer.get("email") == "noreply@github.com"
    )
    integrated_app_identity = (
        app_identity
        and integrated_web_flow
        and integrated_author.get("login") == BOT_LOGIN
        and integrated_author.get("id") == BOT_ID
        and integrated_raw_author.get("name") == BOT_LOGIN
        and integrated_raw_author.get("email") == BOT_EMAIL
        and integrated_dco_lines == [expected_dco]
    )
    integrated_manual_squash = (
        manual_identity
        and commit != proposal_sha
        and integrated_web_flow
        and integrated_author.get("login") == owner
        and integrated_author.get("id") == owner_id
        and integrated_raw_author.get("name") == raw_author_name
        and integrated_raw_author.get("email") == raw_author_email
        and integrated_dco_lines == [f"Signed-off-by: {raw_author_identity}"]
    )
    integrated_manual_fast_forward = (
        manual_identity
        and commit == proposal_sha
        and integrated_author.get("login") == owner
        and integrated_author.get("id") == owner_id
        and integrated_committer.get("login") == owner
        and integrated_committer.get("id") == owner_id
        and integrated_raw_author.get("name") == raw_author_name
        and integrated_raw_author.get("email") == raw_author_email
        and integrated_raw_committer.get("name") == raw_committer.get("name")
        and integrated_raw_committer.get("email") == raw_committer.get("email")
        and integrated_dco_lines == [f"Signed-off-by: {raw_author_identity}"]
    )
    if not integrated_common or not (
        integrated_app_identity
        or integrated_manual_squash
        or integrated_manual_fast_forward
    ):
        raise SourceAuthorizationError("current main integration is invalid")

    files = api.paginate(f"/repos/{repository}/pulls/{number}/files")
    if len(files) != changed_files or not files:
        raise SourceAuthorizationError("release pull request file inventory is incomplete")
    paths = set()
    for value in files:
        item = require_mapping(value, "release pull request file")
        path = item.get("filename")
        if (
            item.get("status") != "modified"
            or not isinstance(path, str)
            or item.get("previous_filename") is not None
        ):
            raise SourceAuthorizationError("release proposal changed a non-existing file")
        paths.add(path)
    if len(paths) != len(files) or not paths <= ALLOWED_PATHS[repository]:
        raise SourceAuthorizationError("release proposal exceeds its generated-file allowlist")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--baseline-version", required=True)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--root", default=Path.cwd(), type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("release source authorization failed: GitHub token is required", file=sys.stderr)
        return 1
    try:
        number = authorize_source(
            LiveGitHubReader(token),
            args.repository,
            args.commit,
            args.root.resolve(),
            args.baseline_version,
            args.baseline_commit,
        )
    except SourceAuthorizationError as error:
        print(f"release source authorization failed: {error}", file=sys.stderr)
        return 1
    print(f"Authorized exact merged release proposal PR #{number}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

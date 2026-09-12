#!/usr/bin/env python3
# Python is justified here because this checkout-free, protected-main policy
# must authenticate GitHub state before any candidate checkout or App token
# exists. A Cargo xtask would require compiling repository-controlled Rust at
# the wrong trust boundary; shell would make the structured API and manifest
# checks harder to type, bound, and fixture-test. Keep this file standard-
# library-only and keep every subprocess fixed-argument, bounded, and shell-free.
"""Bind copied-ref CI and cumulative promotion before one App-owned check.

Why this is Python instead of a Cargo xtask: the reporter is protected GitHub
policy, not repository-neutral build or release logic. It must run checkout-
free from exact live ``main``, before the checks-only App token exists, without
compiling or executing candidate-controlled Rust, shell, or repository files.
The standard-library-only implementation also keeps its network and subprocess
surface explicit and fixture-testable on the GitHub-hosted reporter runner.

The automatic path accepts only a completed copied-ref run and requires each
commit's raw author DCO without requiring an external contributor signature.
The separately selected manual path accepts a bounded manifest from a current
trusted writer, rebinds every signed commit retained in the final series and
its logical patch, and never executes candidate code. Both paths repeat all
mutable checks after App-token creation immediately before the sole mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_EVENT_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PULL_COMMITS = 100
MAX_PROMOTION_MANIFEST_BYTES = 48 * 1024
MAX_PROMOTION_PATCH_BYTES = 2 * 1024 * 1024
MAX_PROMOTION_PATCH_TOTAL_BYTES = 64 * 1024 * 1024
MAX_COORDINATOR_ENTRIES = 8
MAX_COORDINATOR_PATHS = 64
MAIN_REF = "refs/heads/main"
MAIN_CHECK = "Required CI"
REPORTER_WORKFLOW_PATH = ".github/workflows/required-ci.yml"
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
SIGNATURE_QUERY = """
query($owner:String!,$name:String!,$number:Int!,$first:Int!){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      commits(first:$first){
        totalCount
        nodes{
          commit{
            oid
            signature{
              __typename
              email
              isValid
              state
              wasSignedByGitHub
              signer{databaseId login __typename}
            }
          }
        }
        pageInfo{hasNextPage}
      }
    }
  }
}
"""
TERMINAL_JOB_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "success",
    "timed_out",
}


class ReporterError(RuntimeError):
    """A fail-closed reporter validation error."""


class Api(Protocol):
    """Minimal GitHub API boundary used by production and fixture tests."""

    def get(self, path: str) -> Any:
        """Fetch and decode one JSON response."""

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        """Create one GitHub object and decode its JSON response."""

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        """Run one bounded read-only GraphQL query."""

    def diff(self, path: str) -> bytes:
        """Fetch one bounded unified diff."""


class GitHubApi:
    """Bounded JSON client for api.github.com."""

    def __init__(self, token: str) -> None:
        """Create a client from one process-scoped token without logging it."""

        if not token or "\n" in token or "\r" in token:
            raise ReporterError("GitHub API token is missing or malformed")
        self._token = token

    def get(self, path: str) -> Any:
        """Fetch one bounded GitHub JSON object."""

        return self._request("GET", path, None)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        """Create one bounded GitHub JSON object."""

        return self._request("POST", path, payload)

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        """Run the fixed signature query through the bounded JSON client."""

        return self._request(
            "POST", "graphql", {"query": query, "variables": variables}
        )

    def diff(self, path: str) -> bytes:
        """Fetch one bounded commit diff without decoding or normalizing it."""

        return self._request_bytes(
            "GET",
            path,
            None,
            "application/vnd.github.diff",
            MAX_PROMOTION_PATCH_BYTES,
        )

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None
    ) -> Any:
        """Perform one bounded request whose response must be valid JSON."""

        raw = self._request_bytes(
            method,
            path,
            payload,
            "application/vnd.github+json",
            MAX_RESPONSE_BYTES,
        )
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReporterError(
                f"GitHub API {method} {path} returned invalid JSON"
            ) from error

    def _request_bytes(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        accept: str,
        maximum: int,
    ) -> bytes:
        """Perform one authenticated request with a caller-selected byte cap."""

        if path.startswith("/") or ".." in path or any(c in path for c in "\r\n"):
            raise ReporterError("GitHub API path is malformed")
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{API_ROOT}/{path}",
            data=body,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "yaml-sigil-required-ci-reporter/1",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(maximum + 1)
        except urllib.error.HTTPError as error:
            raise ReporterError(
                f"GitHub API {method} {path} returned HTTP {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise ReporterError(f"GitHub API {method} {path} failed") from error
        if len(raw) > maximum:
            raise ReporterError(f"GitHub API {method} {path} response is oversized")
        return raw


@dataclass(frozen=True)
class Policy:
    """Protected constants supplied by the default-branch workflow."""

    repository: str
    policy_sha: str
    workflow_id: int
    workflow_path: str
    job_name: str
    app_slug: str

    def validate(self) -> None:
        """Reject malformed or unsupported protected workflow constants."""

        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ReporterError("expected repository is malformed")
        _sha(self.policy_sha, "protected policy SHA")
        if self.workflow_id <= 0:
            raise ReporterError("expected workflow ID is malformed")
        if not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", self.workflow_path):
            raise ReporterError("expected workflow path is malformed")
        for label, value in (
            ("job name", self.job_name),
            ("App slug", self.app_slug),
        ):
            if not value or len(value) > 128 or any(c in value for c in "\r\n"):
                raise ReporterError(f"expected {label} is malformed")


@dataclass(frozen=True)
class Binding:
    """Freshly verified candidate run state."""

    run_id: int
    run_attempt: int
    pull_number: int
    head_branch: str
    head_sha: str
    base_ref: str
    base_sha: str
    check_name: str
    conclusion: str
    details_url: str
    mode: str = "candidate"
    provenance_digest: str = ""

    @property
    def check_conclusion(self) -> str:
        """Map every non-successful terminal CI result to a failed check."""

        return "success" if self.conclusion == "success" else "failure"

    @property
    def external_id(self) -> str:
        """Return the immutable idempotency key for this exact evidence set."""

        if self.mode == "promotion":
            return (
                f"yaml-sigil-promotion-ci:{self.provenance_digest}:"
                f"{self.run_id}:{self.run_attempt}:{self.base_sha}"
            )
        return (
            f"yaml-sigil-required-ci:{self.run_id}:{self.run_attempt}:"
            f"{self.base_sha}"
        )


@dataclass(frozen=True)
class SignatureIdentity:
    """GitHub's verified signer identity for one exact commit OID."""

    oid: str
    kind: str
    email: str
    signer_id: int
    signer_login: str


@dataclass(frozen=True)
class CandidateEvidence:
    """Bound candidate state retained for promotion-provenance checks."""

    binding: Binding
    pull: dict[str, Any]
    commits: tuple[dict[str, Any], ...]
    signatures: tuple[SignatureIdentity, ...]


@dataclass(frozen=True)
class PromotionEntry:
    """One exact promotion commit and its protected classification."""

    kind: str
    sha: str
    patch_id: str
    source_pull: int | None = None
    original_sha: str | None = None
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class PromotionManifest:
    """Bound trusted-writer input for one cumulative promotion."""

    digest: str
    repository: str
    policy_sha: str
    promotion_pull: int
    base_sha: str
    head_sha: str
    coordination_ref: str
    candidate_run_id: int
    candidate_run_attempt: int
    coordinator_id: int
    coordinator_login: str
    entries: tuple[PromotionEntry, ...]


@dataclass(frozen=True)
class PromotionContext:
    """Server-owned workflow context for one manual promotion verification."""

    event_name: str
    ref: str
    sha: str
    workflow_ref: str
    actor: str
    actor_id: int
    triggering_actor: str
    run_attempt: int

    @classmethod
    def from_environment(cls) -> PromotionContext:
        """Capture only GitHub's server-owned dispatch identity fields."""

        return cls(
            event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
            ref=os.environ.get("GITHUB_REF", ""),
            sha=os.environ.get("GITHUB_SHA", ""),
            workflow_ref=os.environ.get("GITHUB_WORKFLOW_REF", ""),
            actor=os.environ.get("GITHUB_ACTOR", ""),
            actor_id=_environment_integer("GITHUB_ACTOR_ID", "workflow actor ID"),
            triggering_actor=os.environ.get("GITHUB_TRIGGERING_ACTOR", ""),
            run_attempt=_environment_integer(
                "GITHUB_RUN_ATTEMPT", "reporter workflow run attempt"
            ),
        )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    """Require a JSON object without coercing another input type."""

    if not isinstance(value, dict):
        raise ReporterError(f"{label} is not an object")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    """Require a JSON array without accepting another iterable type."""

    if not isinstance(value, list):
        raise ReporterError(f"{label} is not an array")
    return value


def _integer(value: Any, label: str) -> int:
    """Require a positive JSON integer and reject booleans."""

    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReporterError(f"{label} is not a positive integer")
    return value


def _text(value: Any, label: str) -> str:
    """Require one nonempty line suitable for exact comparison and output."""

    if not isinstance(value, str) or not value or any(c in value for c in "\r\n"):
        raise ReporterError(f"{label} is not one nonempty line")
    return value


def _sha(value: Any, label: str) -> str:
    """Require one canonical lowercase full Git object ID."""

    value = _text(value, label)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ReporterError(f"{label} is not a lowercase full SHA")
    return value


def _patch_id(value: Any, label: str) -> str:
    """Require one canonical lowercase Git patch ID."""

    value = _text(value, label)
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ReporterError(f"{label} is not a lowercase stable patch ID")
    return value


def _manifest_integer(value: Any, label: str) -> int:
    """Bound an untrusted manifest integer to signed 64-bit range."""

    value = _integer(value, label)
    if value > 2**63 - 1:
        raise ReporterError(f"{label} exceeds its bound")
    return value


def _environment_integer(name: str, label: str) -> int:
    """Read one bounded positive integer from GitHub's environment."""

    raw = os.environ.get(name, "")
    if re.fullmatch(r"[1-9][0-9]{0,18}", raw) is None:
        raise ReporterError(f"{label} is malformed")
    return _manifest_integer(int(raw), label)


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    """Reject omitted and forward-ambiguous JSON object fields."""

    if set(value) != expected:
        raise ReporterError(f"{label} fields are incomplete or ambiguous")


def _repository_path(value: Any, label: str) -> str:
    """Require a short, relative, non-control repository path."""

    path = _text(value, label)
    components = path.split("/")
    if (
        len(path.encode("utf-8")) > 256
        or path.startswith("/")
        or "\\" in path
        or any(component in {"", ".", ".."} for component in components)
        or any(component.lower() == ".git" for component in components)
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise ReporterError(f"{label} is not a safe repository path")
    return path


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode a JSON object while rejecting duplicate field names."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReporterError("promotion manifest contains a duplicate field")
        result[key] = value
    return result


def _repository_name(value: Any, label: str) -> str:
    """Read one exact full_name from a GitHub repository object."""

    return _text(_mapping(value, label).get("full_name"), f"{label} full name")


def base_policy(repository: str, branch: str) -> tuple[str, str]:
    """Return the canonical full ref and App check for one allowed PR base."""

    branch = _text(branch, "pull request base branch")
    if repository not in SUPPORTED_REPOSITORIES:
        raise ReporterError("repository has no protected candidate policy")
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
        raise ReporterError("pull request base is not an allowed coordination branch")
    full_ref = f"refs/heads/{branch}"
    check_name = f"Required CI [{full_ref}]"
    if len(check_name) > 128:
        raise ReporterError("coordination required-check name is oversized")
    return full_ref, check_name


def read_promotion_manifest(raw: str) -> PromotionManifest:
    """Parse one strictly bounded, canonical promotion-provenance manifest."""

    if not raw:
        raise ReporterError("promotion manifest is missing")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReporterError("promotion manifest is not valid UTF-8") from error
    if len(encoded) > MAX_PROMOTION_MANIFEST_BYTES:
        raise ReporterError("promotion manifest is oversized")
    try:
        value = json.loads(encoded, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReporterError("promotion manifest is not valid JSON") from error
    root = _mapping(value, "promotion manifest")
    _exact_fields(
        root,
        {
            "version",
            "repository",
            "policy_sha",
            "promotion_pull",
            "base_ref",
            "base_sha",
            "head_sha",
            "coordination_ref",
            "candidate_run_id",
            "candidate_run_attempt",
            "coordinator",
            "entries",
        },
        "promotion manifest",
    )
    if not isinstance(root.get("version"), int) or isinstance(
        root.get("version"), bool
    ) or root.get("version") != 1:
        raise ReporterError("promotion manifest version is unsupported")
    repository = _text(root.get("repository"), "promotion repository")
    if repository not in SUPPORTED_REPOSITORIES:
        raise ReporterError("promotion repository has no protected policy")
    if root.get("base_ref") != MAIN_REF:
        raise ReporterError("promotion base ref is not protected main")
    coordination_ref = _text(
        root.get("coordination_ref"), "promotion coordination ref"
    )
    if not coordination_ref.startswith("refs/heads/"):
        raise ReporterError("promotion coordination ref is not a full branch ref")
    short_coordination = coordination_ref.removeprefix("refs/heads/")
    canonical_coordination, _ = base_policy(repository, short_coordination)
    if canonical_coordination != coordination_ref or coordination_ref == MAIN_REF:
        raise ReporterError("promotion coordination ref is not canonical")

    coordinator = _mapping(root.get("coordinator"), "promotion coordinator")
    _exact_fields(coordinator, {"id", "login"}, "promotion coordinator")
    coordinator_id = _manifest_integer(
        coordinator.get("id"), "promotion coordinator ID"
    )
    coordinator_login = _text(
        coordinator.get("login"), "promotion coordinator login"
    )
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", coordinator_login) is None:
        raise ReporterError("promotion coordinator login is malformed")

    raw_entries = _sequence(root.get("entries"), "promotion entries")
    if not 1 <= len(raw_entries) <= MAX_PULL_COMMITS:
        raise ReporterError("promotion entry inventory exceeds its bound")
    entries: list[PromotionEntry] = []
    coordinator_entries = 0
    activation_entries = 0
    for index, raw_entry in enumerate(raw_entries, 1):
        entry = _mapping(raw_entry, f"promotion entry {index}")
        kind = _text(entry.get("kind"), f"promotion entry {index} kind")
        common = {"kind", "sha", "patch_id"}
        sha = _sha(entry.get("sha"), f"promotion entry {index} SHA")
        patch_id = _patch_id(
            entry.get("patch_id"), f"promotion entry {index} patch ID"
        )
        if kind == "source":
            _exact_fields(
                entry,
                common | {"source_pull", "original_sha"},
                f"promotion entry {index}",
            )
            entries.append(
                PromotionEntry(
                    kind=kind,
                    sha=sha,
                    patch_id=patch_id,
                    source_pull=_manifest_integer(
                        entry.get("source_pull"),
                        f"promotion entry {index} source pull request",
                    ),
                    original_sha=_sha(
                        entry.get("original_sha"),
                        f"promotion entry {index} original SHA",
                    ),
                )
            )
        elif kind in {"activation", "integration"}:
            _exact_fields(entry, common | {"paths"}, f"promotion entry {index}")
            raw_paths = _sequence(
                entry.get("paths"), f"promotion entry {index} paths"
            )
            if not 1 <= len(raw_paths) <= MAX_COORDINATOR_PATHS:
                raise ReporterError(
                    f"promotion entry {index} path inventory exceeds its bound"
                )
            paths = tuple(
                _repository_path(path, f"promotion entry {index} path")
                for path in raw_paths
            )
            if len(set(paths)) != len(paths) or tuple(sorted(paths)) != paths:
                raise ReporterError(
                    f"promotion entry {index} paths are duplicated or unordered"
                )
            coordinator_entries += 1
            activation_entries += kind == "activation"
            entries.append(
                PromotionEntry(
                    kind=kind,
                    sha=sha,
                    patch_id=patch_id,
                    paths=paths,
                )
            )
        else:
            raise ReporterError(f"promotion entry {index} kind is unsupported")
    if coordinator_entries > MAX_COORDINATOR_ENTRIES or activation_entries > 1:
        raise ReporterError("promotion coordinator entry inventory exceeds its bound")
    if repository == "NVIDIA/yaml-sigil-spec":
        if activation_entries:
            raise ReporterError("specification promotion cannot contain activation")
    else:
        if activation_entries != 1 or entries[0].kind != "activation":
            raise ReporterError(
                "Rust promotion must begin with exactly one activation commit"
            )
        if entries[0].paths != ("Cargo.toml",):
            raise ReporterError(
                "Rust activation commit must change only the workspace manifest"
            )
    entry_shas = [entry.sha for entry in entries]
    if len(set(entry_shas)) != len(entry_shas):
        raise ReporterError("promotion entry inventory contains duplicate SHAs")

    canonical = json.dumps(
        root, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return PromotionManifest(
        digest=hashlib.sha256(canonical).hexdigest(),
        repository=repository,
        policy_sha=_sha(root.get("policy_sha"), "promotion policy SHA"),
        promotion_pull=_manifest_integer(
            root.get("promotion_pull"), "promotion pull request"
        ),
        base_sha=_sha(root.get("base_sha"), "promotion base SHA"),
        head_sha=_sha(root.get("head_sha"), "promotion head SHA"),
        coordination_ref=coordination_ref,
        candidate_run_id=_manifest_integer(
            root.get("candidate_run_id"), "promotion candidate run ID"
        ),
        candidate_run_attempt=_manifest_integer(
            root.get("candidate_run_attempt"), "promotion candidate run attempt"
        ),
        coordinator_id=coordinator_id,
        coordinator_login=coordinator_login,
        entries=tuple(entries),
    )


def attested_job_name(
    prefix: str,
    policy_sha: str,
    base_ref: str,
    base_sha: str,
) -> str:
    """Encode the pre-execution policy and base binding in one job name."""

    prefix = _text(prefix, "authoritative job name")
    policy_sha = _sha(policy_sha, "attested policy SHA")
    base_ref = _text(base_ref, "attested contribution base ref")
    base_sha = _sha(base_sha, "attested contribution base SHA")
    result = f"{prefix} [policy={policy_sha};base={base_ref}@{base_sha}]"
    if len(result) > 200:
        raise ReporterError("attested authoritative job name is oversized")
    return result


def _workflow_blob(
    api: Api,
    repository_path: str,
    workflow_path: str,
    ref: str,
    label: str,
) -> tuple[str, int]:
    """Read the exact workflow blob identity and size at one commit."""

    encoded_path = urllib.parse.quote(workflow_path, safe="/")
    query = urllib.parse.urlencode({"ref": ref})
    entry = _mapping(
        api.get(f"{repository_path}/contents/{encoded_path}?{query}"),
        f"{label} workflow",
    )
    if entry.get("type") != "file" or entry.get("path") != workflow_path:
        raise ReporterError(f"{label} workflow is not the expected file")
    return (
        _sha(entry.get("sha"), f"{label} workflow blob SHA"),
        _integer(entry.get("size"), f"{label} workflow size"),
    )


def _account(value: Any, label: str) -> tuple[int, str, str]:
    """Bind a GitHub User by immutable database ID and canonical login."""

    account = _mapping(value, label)
    account_id = _integer(account.get("id"), f"{label} ID")
    login = _text(account.get("login"), f"{label} login")
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login) is None:
        raise ReporterError(f"{label} login is malformed")
    kind = _text(account.get("type"), f"{label} type")
    if kind != "User":
        raise ReporterError(f"{label} is not a GitHub User")
    return account_id, login, kind


def _raw_identity(
    commit: dict[str, Any], role: str, label: str
) -> tuple[str, str, str]:
    """Return one commit's literal name, email, and matching DCO identity."""

    body = _mapping(commit.get("commit"), f"{label} body")
    actor = _mapping(body.get(role), f"{label} raw {role}")
    name = _text(actor.get("name"), f"{label} raw {role} name")
    email = _text(actor.get("email"), f"{label} raw {role} email")
    return name, email, f"{name} <{email}>"


def _signoffs(value: Any, label: str) -> set[str]:
    """Extract exact DCO identities from complete commit-message text."""

    if not isinstance(value, str):
        raise ReporterError(f"{label} is not text")
    found = set()
    for line in value.splitlines():
        match = re.fullmatch(r"Signed-off-by:\s*(.+)", line, flags=re.IGNORECASE)
        if match:
            found.add(match.group(1))
    return found


def _signature_identity(value: Any, expected_oid: str, label: str) -> SignatureIdentity:
    """Validate one exact, user-owned GitHub signature result."""

    node = _mapping(value, f"{label} node")
    if set(node) != {"commit"}:
        raise ReporterError(f"{label} node fields are incomplete or ambiguous")
    commit = _mapping(node.get("commit"), f"{label} result")
    if set(commit) != {"oid", "signature"}:
        raise ReporterError(f"{label} result fields are incomplete or ambiguous")
    oid = _sha(commit.get("oid"), f"{label} OID")
    if oid != expected_oid:
        raise ReporterError(f"{label} OID is out of order")
    signature = _mapping(commit.get("signature"), f"{label} signature")
    if set(signature) != {
        "__typename",
        "email",
        "isValid",
        "state",
        "wasSignedByGitHub",
        "signer",
    }:
        raise ReporterError(f"{label} signature fields are incomplete or ambiguous")
    kind = _text(signature.get("__typename"), f"{label} signature type")
    if kind not in {"GpgSignature", "SshSignature", "SmimeSignature"}:
        raise ReporterError(f"{label} signature type is unsupported")
    if signature.get("isValid") is not True or signature.get("state") != "VALID":
        raise ReporterError(f"{label} is not GitHub Verified")
    if signature.get("wasSignedByGitHub") is not False:
        raise ReporterError(f"{label} uses an unsupported GitHub-generated signature")
    signer = _mapping(signature.get("signer"), f"{label} signer")
    if set(signer) != {"databaseId", "login", "__typename"}:
        raise ReporterError(f"{label} signer fields are incomplete or ambiguous")
    signer_id = _integer(signer.get("databaseId"), f"{label} signer ID")
    signer_login = _text(signer.get("login"), f"{label} signer login")
    if signer.get("__typename") != "User":
        raise ReporterError(f"{label} signer is not a GitHub User")
    return SignatureIdentity(
        oid=oid,
        kind=kind,
        email=_text(signature.get("email"), f"{label} signature email"),
        signer_id=signer_id,
        signer_login=signer_login,
    )


def _signature_inventory(
    api: Api,
    repository: str,
    pull_number: int,
    commit_shas: list[str],
) -> list[SignatureIdentity]:
    """Read one complete, ordered signature inventory for a bounded PR."""

    if not 1 <= len(commit_shas) <= MAX_PULL_COMMITS:
        raise ReporterError("pull request signature inventory exceeds its bound")
    if len(set(commit_shas)) != len(commit_shas):
        raise ReporterError("pull request commit inventory contains duplicate OIDs")
    owner, name = repository.split("/", 1)
    envelope = _mapping(
        api.graphql(
            SIGNATURE_QUERY,
            {
                "owner": owner,
                "name": name,
                "number": pull_number,
                "first": len(commit_shas),
            },
        ),
        "GraphQL response",
    )
    if envelope.get("errors") not in (None, []):
        raise ReporterError("GraphQL signature response contains errors")
    data = _mapping(envelope.get("data"), "GraphQL data")
    graph_repository = _mapping(data.get("repository"), "GraphQL repository")
    pull = _mapping(graph_repository.get("pullRequest"), "GraphQL pull request")
    commits = _mapping(pull.get("commits"), "GraphQL pull request commits")
    if set(commits) != {"totalCount", "nodes", "pageInfo"}:
        raise ReporterError("GraphQL signature inventory fields are incomplete or ambiguous")
    if commits.get("totalCount") != len(commit_shas):
        raise ReporterError("GraphQL signature inventory count changed")
    nodes = _sequence(commits.get("nodes"), "GraphQL signature nodes")
    page_info = _mapping(commits.get("pageInfo"), "GraphQL signature page info")
    if set(page_info) != {"hasNextPage"} or page_info.get("hasNextPage") is not False:
        raise ReporterError("GraphQL signature inventory is incomplete")
    if len(nodes) != len(commit_shas):
        raise ReporterError("GraphQL signature inventory is incomplete")
    return [
        _signature_identity(node, sha, f"pull request commit {index}")
        for index, (node, sha) in enumerate(zip(nodes, commit_shas, strict=True), 1)
    ]


def _commit_details(
    api: Api, repository: str, commit_sha: str, label: str
) -> dict[str, Any]:
    """Fetch one linear commit with complete, textual changed-file evidence.

    GitHub omits the per-file ``patch`` field for binary or otherwise
    undisplayable changes. Such a commit cannot be authenticated by the
    text-only verbatim patch-ID policy below, so omission is a hard failure
    instead of an invitation to infer content from filenames or statistics.
    """

    commit = _mapping(
        api.get(f"repos/{repository}/commits/{commit_sha}?per_page=100&page=1"),
        label,
    )
    if _sha(commit.get("sha"), f"{label} SHA") != commit_sha:
        raise ReporterError(f"{label} SHA changed")
    body = _mapping(commit.get("commit"), f"{label} body")
    verification = _mapping(body.get("verification"), f"{label} verification")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise ReporterError(f"{label} is not GitHub Verified")
    parents = _sequence(commit.get("parents"), f"{label} parents")
    if len(parents) != 1:
        raise ReporterError(f"{label} is not one linear commit")
    _sha(_mapping(parents[0], f"{label} parent").get("sha"), f"{label} parent SHA")
    files = _sequence(commit.get("files"), f"{label} changed files")
    if not files or len(files) >= 100:
        raise ReporterError(f"{label} changed-path inventory is empty or ambiguous")
    paths = []
    for index, file_value in enumerate(files, 1):
        file_entry = _mapping(file_value, f"{label} changed file {index}")
        paths.append(
            _repository_path(
                file_entry.get("filename"), f"{label} changed file {index} path"
            )
        )
        if _text(
            file_entry.get("status"), f"{label} changed file {index} status"
        ) not in {"added", "copied", "modified", "removed", "renamed", "changed"}:
            raise ReporterError(f"{label} changed file {index} status is unsupported")
        patch = file_entry.get("patch")
        if not isinstance(patch, str) or not patch:
            raise ReporterError(
                f"{label} changed file {index} lacks a complete textual patch"
            )
    if len(set(paths)) != len(paths):
        raise ReporterError(f"{label} changed-path inventory contains duplicates")
    return commit


def _changed_paths(commit: dict[str, Any], label: str) -> tuple[str, ...]:
    """Return every canonical path affected by a coordinator commit.

    A rename or copy has two security-relevant names: its source and
    destination. Recording only GitHub's destination ``filename`` could make a
    rename into a policy file appear to be a simple modification, so both
    endpoints are mandatory and all returned paths are unique and sorted.
    """

    paths: list[str] = []
    files = _sequence(commit.get("files"), f"{label} changed files")
    for index, file_value in enumerate(files, 1):
        file_entry = _mapping(file_value, f"{label} changed file {index}")
        destination = _repository_path(
            file_entry.get("filename"), f"{label} changed file {index} path"
        )
        status = _text(
            file_entry.get("status"), f"{label} changed file {index} status"
        )
        paths.append(destination)
        previous = file_entry.get("previous_filename")
        if status in {"renamed", "copied"}:
            source = _repository_path(
                previous, f"{label} changed file {index} previous path"
            )
            if source == destination:
                raise ReporterError(f"{label} changed file {index} has one path twice")
            paths.append(source)
        elif previous is not None:
            raise ReporterError(
                f"{label} changed file {index} has an unexpected previous path"
            )
    if len(set(paths)) != len(paths):
        raise ReporterError(f"{label} changed-path inventory contains duplicates")
    return tuple(sorted(paths))


def _require_plain_activation(commit: dict[str, Any], label: str) -> None:
    """Require Rust activation to modify, not rename or copy, Cargo.toml."""

    files = _sequence(commit.get("files"), f"{label} changed files")
    if len(files) != 1:
        raise ReporterError("Rust activation is not one ordinary Cargo.toml change")
    file_entry = _mapping(files[0], f"{label} changed file 1")
    if (
        file_entry.get("filename") != "Cargo.toml"
        or file_entry.get("status") != "modified"
        or file_entry.get("previous_filename") is not None
    ):
        raise ReporterError("Rust activation is not one ordinary Cargo.toml change")


class PatchInventory:
    """Compute bounded whitespace-sensitive patch IDs without a checkout.

    Promotion must compare logical changes while preserving indentation in
    formats such as YAML and Python. The protected reporter therefore invokes
    Git's reviewed ``patch-id --verbatim`` primitive with fixed arguments,
    bounded API diff bytes, no shell, and an environment that ignores user and
    system Git configuration. It rejects every ambiguous process result rather
    than implementing a second diff parser in Python.
    """

    def __init__(self, api: Api, repository: str) -> None:
        """Start one aggregate-bounded diff inventory for a repository."""

        self.api = api
        self.repository = repository
        self.total_bytes = 0
        self.cache: dict[str, str] = {}

    def patch_id(self, commit_sha: str, label: str) -> str:
        """Return one cached or freshly computed verbatim patch ID."""

        if commit_sha in self.cache:
            return self.cache[commit_sha]
        raw = self.api.diff(f"repos/{self.repository}/commits/{commit_sha}")
        if not isinstance(raw, bytes) or not raw:
            raise ReporterError(f"{label} diff is missing")
        if len(raw) > MAX_PROMOTION_PATCH_BYTES:
            raise ReporterError(f"{label} diff is oversized")
        self.total_bytes += len(raw)
        if self.total_bytes > MAX_PROMOTION_PATCH_TOTAL_BYTES:
            raise ReporterError("promotion diff inventory is oversized")
        try:
            completed = subprocess.run(
                ["git", "patch-id", "--verbatim"],
                input=raw,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
                env={
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                },
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReporterError(f"cannot compute {label} stable patch ID") from error
        try:
            lines = completed.stdout.decode("ascii", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise ReporterError(f"{label} verbatim patch ID is malformed") from error
        if completed.returncode != 0 or completed.stderr or len(lines) != 1:
            raise ReporterError(f"{label} verbatim patch ID is ambiguous")
        fields = lines[0].split()
        if len(fields) != 2:
            raise ReporterError(f"{label} verbatim patch ID is malformed")
        result = _patch_id(fields[0], f"{label} verbatim patch ID")
        _sha(fields[1], f"{label} verbatim patch source SHA")
        self.cache[commit_sha] = result
        return result


def _require_coordinator_signature(
    commit: dict[str, Any],
    signature: SignatureIdentity,
    coordinator: tuple[int, str, str],
    label: str,
) -> None:
    """Require the authorized coordinator to sign and commit a replay."""

    if (signature.signer_id, signature.signer_login, "User") != coordinator:
        raise ReporterError(f"{label} signer is not the authorized coordinator")
    if _account(commit.get("committer"), f"{label} committer") != coordinator:
        raise ReporterError(f"{label} committer is not the authorized coordinator")
    _, committer_email, _ = _raw_identity(commit, "committer", label)
    if committer_email != signature.email:
        raise ReporterError(f"{label} signature email does not match its committer")


def _require_raw_author_dco(commit: dict[str, Any], label: str) -> None:
    """Require the literal Git author to supply its exact DCO trailer."""

    _, _, author_dco = _raw_identity(commit, "author", label)
    body = _mapping(commit.get("commit"), f"{label} body")
    if author_dco not in _signoffs(body.get("message"), f"{label} message"):
        raise ReporterError(f"{label} lacks the exact raw-author DCO sign-off")


def _require_author_dco(commit: dict[str, Any], label: str) -> tuple[int, str, str]:
    """Require an attributed author's exact DCO for a preserved replay."""

    author = _account(commit.get("author"), f"{label} author")
    _require_raw_author_dco(commit, label)
    return author


def _require_preserved_author(
    current: dict[str, Any], original: dict[str, Any], label: str
) -> None:
    """Require a replay to preserve author identity and full message bytes."""

    if _require_author_dco(current, label) != _require_author_dco(
        original, f"{label} original"
    ):
        raise ReporterError(f"{label} does not preserve the original author")
    current_raw = _raw_identity(current, "author", label)
    original_raw = _raw_identity(original, "author", f"{label} original")
    if current_raw != original_raw:
        raise ReporterError(f"{label} does not preserve the raw original author")
    current_message = _mapping(current.get("commit"), f"{label} body").get(
        "message"
    )
    original_message = _mapping(
        original.get("commit"), f"{label} original body"
    ).get("message")
    if (
        not isinstance(current_message, str)
        or not current_message
        or not isinstance(original_message, str)
        or not original_message
        or current_message != original_message
    ):
        raise ReporterError(f"{label} does not preserve the complete commit message")


def read_event(path: Path) -> dict[str, Any]:
    """Read one bounded GitHub event document."""

    try:
        metadata = path.stat()
    except OSError as error:
        raise ReporterError("cannot inspect the workflow event") from error
    if not path.is_file() or metadata.st_size > MAX_EVENT_BYTES:
        raise ReporterError("workflow event is missing or oversized")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReporterError("workflow event is not valid JSON") from error
    return _mapping(value, "workflow event")


def _bind_candidate_evidence(
    api: Api,
    event: dict[str, Any],
    policy: Policy,
    *,
    require_signatures: bool,
) -> CandidateEvidence:
    """Bind one copied-ref run and retain its exact commit evidence."""

    policy.validate()
    if event.get("action") != "completed":
        raise ReporterError("workflow event action is not completed")
    if _repository_name(event.get("repository"), "event repository") != policy.repository:
        raise ReporterError("workflow event repository is unexpected")

    delivered = _mapping(event.get("workflow_run"), "delivered workflow run")
    run_id = _integer(delivered.get("id"), "delivered run ID")
    run_attempt = _integer(delivered.get("run_attempt"), "delivered run attempt")
    if _integer(delivered.get("workflow_id"), "delivered workflow ID") != policy.workflow_id:
        raise ReporterError("delivered workflow ID is unexpected")

    repository_path = f"repos/{policy.repository}"
    run = _mapping(api.get(f"{repository_path}/actions/runs/{run_id}"), "workflow run")
    if _integer(run.get("id"), "run ID") != run_id:
        raise ReporterError("fetched run ID does not match the delivery")
    if _integer(run.get("run_attempt"), "run attempt") != run_attempt:
        raise ReporterError("the delivered run attempt is stale")
    if _integer(run.get("workflow_id"), "workflow ID") != policy.workflow_id:
        raise ReporterError("workflow ID is unexpected")
    if _text(run.get("path"), "workflow path") != policy.workflow_path:
        raise ReporterError("workflow path is unexpected")
    if _text(run.get("event"), "workflow event") != "push":
        raise ReporterError("candidate workflow was not triggered by a push")
    if _text(run.get("status"), "workflow status") != "completed":
        raise ReporterError("candidate workflow is not completed")
    if _repository_name(run.get("repository"), "run repository") != policy.repository:
        raise ReporterError("workflow run repository is unexpected")

    head_branch = _text(run.get("head_branch"), "run head branch")
    branch_match = re.fullmatch(r"pull-request/([1-9][0-9]*)", head_branch)
    if branch_match is None:
        raise ReporterError("workflow run is not an exact copied pull-request ref")
    pull_number = int(branch_match.group(1))
    head_sha = _sha(run.get("head_sha"), "run head SHA")
    details_url = _text(run.get("html_url"), "run URL")

    main_ref = _mapping(
        api.get(f"{repository_path}/git/ref/heads/main"),
        "protected main ref",
    )
    if main_ref.get("ref") != MAIN_REF:
        raise ReporterError("protected main ref name is unexpected")
    main_object = _mapping(main_ref.get("object"), "protected main object")
    if (
        main_object.get("type") != "commit"
        or _sha(main_object.get("sha"), "protected main SHA") != policy.policy_sha
    ):
        raise ReporterError("reporter policy is not current protected main")

    protected_workflow = _workflow_blob(
        api,
        repository_path,
        policy.workflow_path,
        policy.policy_sha,
        "protected",
    )
    candidate_workflow = _workflow_blob(
        api,
        repository_path,
        policy.workflow_path,
        head_sha,
        "candidate",
    )
    if candidate_workflow != protected_workflow:
        raise ReporterError("candidate workflow differs from protected policy")

    for field, expected, label in (
        ("id", run_id, "delivered run ID"),
        ("run_attempt", run_attempt, "delivered run attempt"),
        ("workflow_id", policy.workflow_id, "delivered workflow ID"),
        ("head_branch", head_branch, "delivered head branch"),
        ("head_sha", head_sha, "delivered head SHA"),
    ):
        if delivered.get(field) != expected:
            raise ReporterError(f"{label} does not match fetched state")
    if _repository_name(delivered.get("repository"), "delivered repository") != policy.repository:
        raise ReporterError("delivered run repository is unexpected")

    pull = _mapping(api.get(f"{repository_path}/pulls/{pull_number}"), "pull request")
    if _integer(pull.get("number"), "pull request number") != pull_number:
        raise ReporterError("pull request number is unexpected")
    if pull.get("state") != "open":
        raise ReporterError("pull request is not open")
    pull_base = _mapping(pull.get("base"), "pull request base")
    if _repository_name(pull_base.get("repo"), "base repository") != policy.repository:
        raise ReporterError("pull request base repository is unexpected")
    base_ref, check_name = base_policy(
        policy.repository,
        _text(pull_base.get("ref"), "pull request base branch"),
    )
    base_sha = _sha(pull_base.get("sha"), "pull request base SHA")
    if base_ref == MAIN_REF:
        base_readback = main_ref
    else:
        encoded_base_ref = urllib.parse.quote(
            base_ref.removeprefix("refs/"), safe="/"
        )
        base_readback = _mapping(
            api.get(f"{repository_path}/git/ref/{encoded_base_ref}"),
            "contribution base ref",
        )
    base_object = _mapping(base_readback.get("object"), "contribution base object")
    if (
        base_readback.get("ref") != base_ref
        or base_object.get("type") != "commit"
        or _sha(base_object.get("sha"), "current contribution base SHA")
        != base_sha
    ):
        raise ReporterError("pull request contribution base is not current")
    pull_head = _mapping(pull.get("head"), "pull request head")
    if _sha(pull_head.get("sha"), "current pull request head SHA") != head_sha:
        raise ReporterError("pull request head moved after candidate execution")

    expected_commits = _integer(pull.get("commits"), "pull request commit count")
    if expected_commits > MAX_PULL_COMMITS:
        raise ReporterError("pull request commit inventory exceeds its bound")
    commits = _sequence(
        api.get(f"{repository_path}/pulls/{pull_number}/commits?per_page=100&page=1"),
        "pull request commits",
    )
    if len(commits) != expected_commits:
        raise ReporterError("pull request commit inventory is incomplete")
    commit_shas: list[str] = []
    for index, value in enumerate(commits, 1):
        label = f"pull request commit {index}"
        commit = _mapping(value, label)
        commit_shas.append(_sha(commit.get("sha"), f"{label} SHA"))
        if require_signatures:
            verification = _mapping(
                _mapping(commit.get("commit"), f"{label} body").get("verification"),
                f"{label} verification",
            )
            if (
                verification.get("verified") is not True
                or verification.get("reason") != "valid"
            ):
                raise ReporterError(f"{label} is not GitHub Verified")
        else:
            _require_raw_author_dco(commit, label)
    if commit_shas[-1] != head_sha:
        raise ReporterError("pull request commit inventory does not end at the head")
    signatures = (
        _signature_inventory(api, policy.repository, pull_number, commit_shas)
        if require_signatures
        else []
    )

    encoded_ref = urllib.parse.quote(f"heads/{head_branch}", safe="/")
    copied_ref = _mapping(
        api.get(f"{repository_path}/git/ref/{encoded_ref}"), "copied Git ref"
    )
    if copied_ref.get("ref") != f"refs/heads/{head_branch}":
        raise ReporterError("copied Git ref name is unexpected")
    copied_object = _mapping(copied_ref.get("object"), "copied Git object")
    if copied_object.get("type") != "commit" or _sha(
        copied_object.get("sha"), "copied Git ref SHA"
    ) != head_sha:
        raise ReporterError("copied Git ref does not equal the current pull request head")

    jobs = _mapping(
        api.get(
            f"{repository_path}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100"
        ),
        "job inventory",
    )
    job_items = _sequence(jobs.get("jobs"), "job inventory jobs")
    if jobs.get("total_count") != len(job_items) or len(job_items) > 100:
        raise ReporterError("job inventory is incomplete or oversized")
    authoritative_name = attested_job_name(
        policy.job_name,
        policy.policy_sha,
        base_ref,
        base_sha,
    )
    authoritative = [
        job
        for job in job_items
        if isinstance(job, dict) and job.get("name") == authoritative_name
    ]
    if len(authoritative) != 1:
        raise ReporterError("attested authoritative Linux job is missing or duplicated")
    job = authoritative[0]
    if _integer(job.get("run_id"), "job run ID") != run_id:
        raise ReporterError("authoritative job belongs to another run")
    if _integer(job.get("run_attempt"), "job run attempt") != run_attempt:
        raise ReporterError("authoritative job belongs to another attempt")
    if _sha(job.get("head_sha"), "job head SHA") != head_sha:
        raise ReporterError("authoritative job ran another head")
    if job.get("status") != "completed":
        raise ReporterError("authoritative job is not completed")
    conclusion = job.get("conclusion")
    if conclusion not in TERMINAL_JOB_CONCLUSIONS:
        raise ReporterError("authoritative job conclusion is not a bounded terminal result")

    artifacts = _mapping(
        api.get(f"{repository_path}/actions/runs/{run_id}/artifacts?per_page=1"),
        "artifact inventory",
    )
    artifact_items = _sequence(artifacts.get("artifacts"), "artifact inventory artifacts")
    if artifacts.get("total_count") != 0 or artifact_items:
        raise ReporterError("candidate workflow retained an artifact")

    return CandidateEvidence(
        binding=Binding(
            run_id=run_id,
            run_attempt=run_attempt,
            pull_number=pull_number,
            head_branch=head_branch,
            head_sha=head_sha,
            base_ref=base_ref,
            base_sha=base_sha,
            check_name=check_name,
            conclusion=conclusion,
            details_url=details_url,
        ),
        pull=pull,
        commits=tuple(_mapping(commit, "pull request commit") for commit in commits),
        signatures=tuple(signatures),
    )


def bind_candidate(api: Api, event: dict[str, Any], policy: Policy) -> Binding:
    """Bind the triggering delivery to one fresh copied-ref CI attempt."""

    return _bind_candidate_evidence(
        api, event, policy, require_signatures=False
    ).binding


def _require_promotion_context(
    api: Api,
    event: dict[str, Any],
    policy: Policy,
    manifest: PromotionManifest,
    manifest_raw: str,
    context: PromotionContext,
) -> tuple[int, str, str]:
    """Authenticate the main-only manual dispatch and its current writer."""

    policy.validate()
    if manifest.repository != policy.repository:
        raise ReporterError("promotion manifest repository is unexpected")
    if manifest.policy_sha != policy.policy_sha:
        raise ReporterError("promotion manifest policy SHA is unexpected")
    if (
        context.event_name != "workflow_dispatch"
        or context.ref != MAIN_REF
        or context.sha != policy.policy_sha
        or context.workflow_ref
        != f"{policy.repository}/{REPORTER_WORKFLOW_PATH}@{MAIN_REF}"
        or context.run_attempt != 1
    ):
        raise ReporterError("promotion reporter did not run once from protected main")
    if (
        context.actor != manifest.coordinator_login
        or context.actor_id != manifest.coordinator_id
        or context.triggering_actor != context.actor
    ):
        raise ReporterError("promotion workflow actor is not the exact coordinator")
    if _repository_name(event.get("repository"), "event repository") != policy.repository:
        raise ReporterError("promotion event repository is unexpected")
    if event.get("ref") != "main":
        raise ReporterError("promotion dispatch selected an alternate ref")
    sender = _account(event.get("sender"), "promotion event sender")
    coordinator = (
        manifest.coordinator_id,
        manifest.coordinator_login,
        "User",
    )
    if sender != coordinator:
        raise ReporterError("promotion event sender is not the exact coordinator")
    inputs = _mapping(event.get("inputs"), "promotion event inputs")
    _exact_fields(inputs, {"manifest"}, "promotion event inputs")
    if inputs.get("manifest") != manifest_raw:
        raise ReporterError("promotion event manifest does not match the process input")

    permission = _mapping(
        api.get(
            f"repos/{policy.repository}/collaborators/"
            f"{urllib.parse.quote(manifest.coordinator_login, safe='')}/permission"
        ),
        "promotion coordinator permission",
    )
    if _account(permission.get("user"), "promotion permission user") != coordinator:
        raise ReporterError("promotion permission belongs to another user")
    if permission.get("permission") not in {"write", "admin"}:
        raise ReporterError("promotion coordinator is not a current trusted writer")
    return coordinator


def _promotion_delivery(policy: Policy, manifest: PromotionManifest) -> dict[str, Any]:
    """Build the exact candidate delivery expected from trusted manifest data."""

    return {
        "action": "completed",
        "repository": {"full_name": policy.repository},
        "workflow_run": {
            "id": manifest.candidate_run_id,
            "run_attempt": manifest.candidate_run_attempt,
            "workflow_id": policy.workflow_id,
            "head_branch": f"pull-request/{manifest.promotion_pull}",
            "head_sha": manifest.head_sha,
            "repository": {"full_name": policy.repository},
        },
    }


def _source_pull_originals(
    api: Api,
    repository: str,
    coordination_branch: str,
    promotion_pull: int,
    source_pull_number: int,
) -> tuple[str, ...]:
    """Return the complete retained commit set for one merged source PR."""

    if source_pull_number == promotion_pull:
        raise ReporterError("promotion pull request cannot be its own source")
    repository_path = f"repos/{repository}"
    pull = _mapping(
        api.get(f"{repository_path}/pulls/{source_pull_number}"),
        "source pull request",
    )
    if (
        _integer(pull.get("number"), "source pull request number")
        != source_pull_number
        or pull.get("state") != "closed"
        or pull.get("merged") is not True
        or not _text(pull.get("merged_at"), "source pull request merge time")
    ):
        raise ReporterError("source pull request is not terminally merged")
    base = _mapping(pull.get("base"), "source pull request base")
    if (
        _repository_name(base.get("repo"), "source pull request base repository")
        != repository
        or _text(base.get("ref"), "source pull request base branch")
        != coordination_branch
    ):
        raise ReporterError("source pull request targeted another base")
    expected_commits = _integer(
        pull.get("commits"), "source pull request commit count"
    )
    if expected_commits > MAX_PULL_COMMITS:
        raise ReporterError("source pull request commit inventory exceeds its bound")
    source_commits = _sequence(
        api.get(
            f"{repository_path}/pulls/{source_pull_number}/commits?per_page=100&page=1"
        ),
        "source pull request commits",
    )
    if len(source_commits) != expected_commits:
        raise ReporterError("source pull request commit inventory is incomplete")
    source_shas = [
        _sha(
            _mapping(commit, "source pull request commit").get("sha"),
            "source pull request commit SHA",
        )
        for commit in source_commits
    ]
    if len(set(source_shas)) != len(source_shas):
        raise ReporterError("source pull request commit inventory contains duplicates")
    merge_sha = _sha(pull.get("merge_commit_sha"), "source merge commit SHA")
    # Squash contributes its generated merge object. Exact-history intake
    # contributes every original PR commit, including the final head object.
    if merge_sha in source_shas:
        if source_shas[-1] != merge_sha:
            raise ReporterError("source pull request merge object is out of order")
        return tuple(source_shas)
    return (merge_sha,)


def _require_original_association(
    api: Api,
    repository: str,
    source_pull_number: int,
    original_sha: str,
) -> None:
    """Require GitHub to associate one retained original with its source PR."""

    repository_path = f"repos/{repository}"
    associated = _sequence(
        api.get(
            f"{repository_path}/commits/{original_sha}/pulls?per_page=100&page=1"
        ),
        "original commit pull-request associations",
    )
    if len(associated) >= 100:
        raise ReporterError("original commit association inventory is ambiguous")
    matches = [
        candidate
        for candidate in associated
        if isinstance(candidate, dict)
        and candidate.get("number") == source_pull_number
        and isinstance(candidate.get("base"), dict)
        and isinstance(candidate["base"].get("repo"), dict)
        and candidate["base"]["repo"].get("full_name") == repository
    ]
    if len(matches) != 1:
        raise ReporterError("original commit lacks one exact source pull association")


def bind_promotion(
    api: Api,
    event: dict[str, Any],
    policy: Policy,
    manifest_raw: str,
    context: PromotionContext,
) -> Binding:
    """Bind one cumulative promotion to bounded final-series provenance."""

    manifest = read_promotion_manifest(manifest_raw)
    coordinator = _require_promotion_context(
        api, event, policy, manifest, manifest_raw, context
    )
    if manifest.base_sha != policy.policy_sha:
        raise ReporterError("promotion base is not exact protected main")
    evidence = _bind_candidate_evidence(
        api,
        _promotion_delivery(policy, manifest),
        policy,
        require_signatures=True,
    )
    binding = evidence.binding
    if (
        binding.pull_number != manifest.promotion_pull
        or binding.head_sha != manifest.head_sha
        or binding.base_ref != MAIN_REF
        or binding.base_sha != manifest.base_sha
        or binding.run_id != manifest.candidate_run_id
        or binding.run_attempt != manifest.candidate_run_attempt
        or binding.conclusion != "success"
    ):
        raise ReporterError("promotion candidate run does not match the manifest")

    pull_head = _mapping(evidence.pull.get("head"), "promotion pull request head")
    coordination_branch = manifest.coordination_ref.removeprefix("refs/heads/")
    if (
        _repository_name(pull_head.get("repo"), "promotion head repository")
        != policy.repository
        or _text(pull_head.get("ref"), "promotion head branch")
        != coordination_branch
    ):
        raise ReporterError("promotion pull request does not come from the coordination ref")
    encoded_coordination = urllib.parse.quote(
        manifest.coordination_ref.removeprefix("refs/"), safe="/"
    )
    coordination = _mapping(
        api.get(f"repos/{policy.repository}/git/ref/{encoded_coordination}"),
        "promotion coordination ref",
    )
    coordination_object = _mapping(
        coordination.get("object"), "promotion coordination object"
    )
    if (
        coordination.get("ref") != manifest.coordination_ref
        or coordination_object.get("type") != "commit"
        or _sha(coordination_object.get("sha"), "promotion coordination SHA")
        != manifest.head_sha
    ):
        raise ReporterError("promotion coordination ref moved")

    commit_shas = [
        _sha(commit.get("sha"), "promotion pull request commit SHA")
        for commit in evidence.commits
    ]
    if commit_shas != [entry.sha for entry in manifest.entries]:
        raise ReporterError("promotion manifest commit inventory is incomplete or reordered")

    details: dict[str, dict[str, Any]] = {}

    def commit_details(commit_sha: str, label: str) -> dict[str, Any]:
        """Fetch and cache one already-bounded promotion commit object."""

        if commit_sha not in details:
            details[commit_sha] = _commit_details(
                api, policy.repository, commit_sha, label
            )
        return details[commit_sha]

    patches = PatchInventory(api, policy.repository)
    source_bindings: set[tuple[int, str]] = set()
    original_bindings: set[str] = set()
    expected_originals: dict[int, tuple[str, ...]] = {}
    observed_originals: dict[int, list[str]] = {}
    source_entry_count = sum(
        entry.kind == "source" for entry in manifest.entries
    )
    expected_parent = manifest.base_sha
    for index, (entry, signature) in enumerate(
        zip(manifest.entries, evidence.signatures, strict=True), 1
    ):
        label = f"promotion commit {index}"
        current = commit_details(entry.sha, label)
        parent = _mapping(
            _sequence(current.get("parents"), f"{label} parents")[0],
            f"{label} parent",
        )
        if _sha(parent.get("sha"), f"{label} parent SHA") != expected_parent:
            raise ReporterError("promotion commit order is not one linear base descendant")
        expected_parent = entry.sha
        if patches.patch_id(entry.sha, label) != entry.patch_id:
            raise ReporterError(f"{label} logical patch does not match the manifest")
        _require_coordinator_signature(current, signature, coordinator, label)

        if entry.kind == "source":
            assert entry.source_pull is not None
            assert entry.original_sha is not None
            source_key = (entry.source_pull, entry.original_sha)
            if (
                source_key in source_bindings
                or entry.original_sha in original_bindings
            ):
                raise ReporterError("promotion source binding is duplicated")
            source_bindings.add(source_key)
            original_bindings.add(entry.original_sha)
            if entry.source_pull not in expected_originals:
                expected_originals[entry.source_pull] = _source_pull_originals(
                    api,
                    policy.repository,
                    coordination_branch,
                    manifest.promotion_pull,
                    entry.source_pull,
                )
                if (
                    sum(len(items) for items in expected_originals.values())
                    > source_entry_count
                ):
                    raise ReporterError(
                        "source pull request inventories exceed the promotion series"
                    )
                observed_originals[entry.source_pull] = []
            if entry.original_sha not in expected_originals[entry.source_pull]:
                raise ReporterError(
                    "promotion original is not retained from its source pull request"
                )
            observed_originals[entry.source_pull].append(entry.original_sha)
            _require_original_association(
                api,
                policy.repository,
                entry.source_pull,
                entry.original_sha,
            )
            original = commit_details(entry.original_sha, f"{label} original")
            _require_preserved_author(current, original, label)
            if (
                patches.patch_id(entry.original_sha, f"{label} original")
                != entry.patch_id
            ):
                raise ReporterError(f"{label} does not preserve its logical patch")
        else:
            if _require_author_dco(current, label) != coordinator:
                raise ReporterError(f"{label} author is not the authorized coordinator")
            if entry.kind == "activation":
                _require_plain_activation(current, label)
            if _changed_paths(current, label) != entry.paths:
                raise ReporterError(f"{label} changed paths do not match the manifest")

    for source_pull, expected in expected_originals.items():
        if tuple(observed_originals[source_pull]) != expected:
            raise ReporterError(
                "promotion source pull commit inventory is incomplete, duplicated, or reordered"
            )
    if expected_parent != manifest.head_sha:
        raise ReporterError("promotion inventory does not end at the exact head")
    return Binding(
        run_id=binding.run_id,
        run_attempt=binding.run_attempt,
        pull_number=binding.pull_number,
        head_branch=binding.head_branch,
        head_sha=binding.head_sha,
        base_ref=binding.base_ref,
        base_sha=binding.base_sha,
        check_name=binding.check_name,
        conclusion=binding.conclusion,
        details_url=binding.details_url,
        mode="promotion",
        provenance_digest=manifest.digest,
    )


def verify_app_scope(api: Api, policy: Policy, observed_app_slug: str) -> None:
    """Require the token action's App identity and exact repository scope."""

    if observed_app_slug != policy.app_slug:
        raise ReporterError("reporting token belongs to an unexpected App")
    installation = _mapping(
        api.get("installation/repositories?per_page=100"),
        "installation repository inventory",
    )
    repositories = _sequence(
        installation.get("repositories"), "installation repositories"
    )
    names = [
        repository.get("full_name")
        for repository in repositories
        if isinstance(repository, dict)
    ]
    if installation.get("total_count") != 1 or names != [policy.repository]:
        raise ReporterError("reporting token is not scoped to exactly this repository")


def _validate_check(
    value: Any, policy: Policy, binding: Binding, expected_id: int | None = None
) -> dict[str, Any]:
    """Require an App check readback to equal the intended immutable result."""

    check = _mapping(value, "required check")
    check_id = _integer(check.get("id"), "required check ID")
    if expected_id is not None and check_id != expected_id:
        raise ReporterError("required check ID changed during readback")
    if (
        check.get("name") != binding.check_name
        or check.get("head_sha") != binding.head_sha
        or check.get("external_id") != binding.external_id
        or check.get("status") != "completed"
        or check.get("conclusion") != binding.check_conclusion
        or _mapping(check.get("app"), "required check App").get("slug")
        != policy.app_slug
    ):
        raise ReporterError("App-owned required check readback is not exact")
    return check


def report_check(api: Api, policy: Policy, binding: Binding) -> int:
    """Create one completed check, or accept its exact idempotent readback."""

    repository_path = f"repos/{policy.repository}"
    query = urllib.parse.urlencode(
        {"check_name": binding.check_name, "filter": "all", "per_page": "100"}
    )
    inventory = _mapping(
        api.get(f"{repository_path}/commits/{binding.head_sha}/check-runs?{query}"),
        "required check inventory",
    )
    checks = _sequence(inventory.get("check_runs"), "required checks")
    if inventory.get("total_count") != len(checks) or len(checks) > 100:
        raise ReporterError("required check inventory is incomplete or oversized")
    matches = [
        check
        for check in checks
        if isinstance(check, dict)
        and check.get("external_id") == binding.external_id
        and isinstance(check.get("app"), dict)
        and check["app"].get("slug") == policy.app_slug
    ]
    if len(matches) > 1:
        raise ReporterError("duplicate App-owned checks exist for this run attempt")
    if matches:
        return _integer(
            _validate_check(matches[0], policy, binding).get("id"),
            "required check ID",
        )

    if binding.mode == "promotion":
        title = "Authorized cumulative promotion result"
        summary = (
            "Protected current-main policy verified the exact promotion "
            f"provenance and candidate run for `{binding.base_ref}` at "
            f"`{binding.base_sha}` with conclusion `{binding.conclusion}`."
        )
    else:
        title = "Authorized candidate CI result"
        summary = (
            "The exact copied pull-request head completed the authoritative "
            f"Linux job for `{binding.base_ref}` at `{binding.base_sha}` "
            f"with conclusion `{binding.conclusion}`."
        )
    payload = {
        "name": binding.check_name,
        "head_sha": binding.head_sha,
        "status": "completed",
        "conclusion": binding.check_conclusion,
        "external_id": binding.external_id,
        "details_url": binding.details_url,
        "output": {
            "title": title,
            "summary": summary,
        },
    }
    created = _validate_check(
        api.post(f"{repository_path}/check-runs", payload), policy, binding
    )
    check_id = _integer(created.get("id"), "required check ID")
    readback = api.get(f"{repository_path}/check-runs/{check_id}")
    _validate_check(readback, policy, binding, check_id)
    return check_id


def append_outputs(binding: Binding) -> None:
    """Append bounded scalar outputs to GitHub's runner-owned output file."""

    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise ReporterError("GITHUB_OUTPUT is not set")
    with open(output_path, "a", encoding="utf-8", newline="\n") as output:
        output.write(f"head_sha={binding.head_sha}\n")
        output.write(f"conclusion={binding.conclusion}\n")
        output.write(f"run_id={binding.run_id}\n")
        output.write(f"run_attempt={binding.run_attempt}\n")
        output.write(f"base_ref={binding.base_ref}\n")
        output.write(f"base_sha={binding.base_sha}\n")
        output.write(f"check_name={binding.check_name}\n")


def parser() -> argparse.ArgumentParser:
    """Define the four explicit reporter operations and their fixed inputs."""

    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "operation",
        choices=("inspect", "report", "inspect-promotion", "report-promotion"),
    )
    result.add_argument("--event", required=True, type=Path)
    result.add_argument("--repository", required=True)
    result.add_argument("--policy-sha", required=True)
    result.add_argument("--workflow-id", required=True, type=int)
    result.add_argument("--workflow-path", required=True)
    result.add_argument("--job-name", required=True)
    result.add_argument("--app-slug", required=True)
    return result


def run(arguments: argparse.Namespace) -> None:
    """Inspect evidence, then optionally rebind and emit the sole App check."""

    policy = Policy(
        repository=arguments.repository,
        policy_sha=arguments.policy_sha,
        workflow_id=arguments.workflow_id,
        workflow_path=arguments.workflow_path,
        job_name=arguments.job_name,
        app_slug=arguments.app_slug,
    )
    event = read_event(arguments.event)
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""))
    promotion = arguments.operation.endswith("-promotion")
    if promotion:
        manifest_raw = os.environ.get("PROMOTION_MANIFEST", "")
        context = PromotionContext.from_environment()
        binding = bind_promotion(read_api, event, policy, manifest_raw, context)
    else:
        binding = bind_candidate(read_api, event, policy)
    if arguments.operation in {"inspect", "inspect-promotion"}:
        append_outputs(binding)
        return

    app_api = GitHubApi(os.environ.get("APP_TOKEN", ""))
    verify_app_scope(app_api, policy, os.environ.get("APP_SLUG", ""))
    # Repeat every mutable binding after the App token exists and immediately
    # before the only write. A moved head, rerun, ref, or artifact fails closed.
    if promotion:
        binding = bind_promotion(read_api, event, policy, manifest_raw, context)
    else:
        binding = bind_candidate(read_api, event, policy)
    check_id = report_check(app_api, policy, binding)
    print(f"reported {binding.check_name} check {check_id} for {binding.head_sha}")


def main() -> int:
    """Convert fail-closed policy errors into one terse nonzero CLI result."""

    try:
        run(parser().parse_args())
    except ReporterError as error:
        print(f"required CI reporter: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

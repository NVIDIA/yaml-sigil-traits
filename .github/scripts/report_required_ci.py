#!/usr/bin/env python3
# Python is justified here because this checkout-free protected-main policy
# must authenticate structured GitHub state before any candidate checkout or
# App token exists. A Cargo xtask would compile repository-controlled Rust at
# the wrong trust boundary, while shell would make the bounded API checks
# harder to type and fixture-test. Keep this file standard-library-only.
"""Bind one copied-ref CI run before reporting the App-owned required check.

This protected GitHub policy runs checkout-free from exact live ``main``,
before the checks-only App token exists, without compiling or executing
candidate-controlled Rust, shell, or repository files. It accepts only a
completed copied-ref run, requires every commit's raw-author DCO, and binds the
repository, protected workflow, live base, pull request, copied ref, exact
head, authoritative job, terminal conclusion, and zero artifacts.

The ``inspect`` operation performs the complete read-only binding. The
``report`` operation repeats every mutable check after App-token creation,
verifies that token's App identity and single-repository scope, and creates or
accepts one exact App-owned required check. Every mismatch fails closed.
"""

from __future__ import annotations

import argparse
import json
import os
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
MAX_EVENT_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PULL_COMMITS = 100
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
    @property
    def check_conclusion(self) -> str:
        """Map every non-successful terminal CI result to a failed check."""

        return "success" if self.conclusion == "success" else "failure"

    @property
    def external_id(self) -> str:
        """Return the immutable idempotency key for this exact evidence set."""

        return (
            f"yaml-sigil-required-ci:{self.run_id}:{self.run_attempt}:"
            f"{self.base_sha}"
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


def _raw_identity(
    commit: dict[str, Any], role: str, label: str
) -> tuple[str, str, str]:
    """Read one literal Git commit identity without REST-account inference."""

    body = _mapping(commit.get("commit"), f"{label} body")
    actor = _mapping(body.get(role), f"{label} raw {role}")
    name = _text(actor.get("name"), f"{label} raw {role} name")
    email = _text(actor.get("email"), f"{label} raw {role} email")
    return name, email, f"{name} <{email}>"


def _signoffs(value: Any, label: str) -> set[str]:
    """Return exact DCO identities from well-formed trailer lines."""

    if not isinstance(value, str):
        raise ReporterError(f"{label} is not text")
    found = set()
    for line in value.splitlines():
        match = re.fullmatch(r"Signed-off-by:\s*(.+)", line, flags=re.IGNORECASE)
        if match:
            found.add(match.group(1))
    return found


def _require_raw_author_dco(commit: dict[str, Any], label: str) -> None:
    """Require the literal Git author to supply its exact DCO trailer."""

    _, _, author_dco = _raw_identity(commit, "author", label)
    body = _mapping(commit.get("commit"), f"{label} body")
    if author_dco not in _signoffs(body.get("message"), f"{label} message"):
        raise ReporterError(f"{label} lacks the exact raw-author DCO sign-off")


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


def bind_candidate(api: Api, event: dict[str, Any], policy: Policy) -> Binding:
    """Bind the triggering delivery to one fresh copied-ref CI attempt."""

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
        _require_raw_author_dco(commit, label)
    if commit_shas[-1] != head_sha:
        raise ReporterError("pull request commit inventory does not end at the head")
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

    return Binding(
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
    """Define the two explicit reporter operations and their fixed inputs."""

    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("operation", choices=("inspect", "report"))
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
    binding = bind_candidate(read_api, event, policy)
    if arguments.operation == "inspect":
        append_outputs(binding)
        return

    app_api = GitHubApi(os.environ.get("APP_TOKEN", ""))
    verify_app_scope(app_api, policy, os.environ.get("APP_SLUG", ""))
    # Repeat every mutable binding after the App token exists and immediately
    # before the only write. A moved head, rerun, ref, or artifact fails closed.
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

#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Verify a candidate checkout against immutable protected-main policy.

The caller stages this file and ``protected_pr_ci.py`` from the exact policy
commit before checking out candidate content. This verifier then compares all
sensitive working-tree files with their exact Git blobs before any later step
reads or executes a candidate path.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Iterable

import protected_pr_ci as policy


MAX_SECONDS = 30.0
MAX_POLICY_FILE_BYTES = 4 * 1024 * 1024


def metadata_identity(path: str) -> str:
    return policy.normalized_casefold(path)


def has_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def bounded_regular_bytes(path: pathlib.Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        policy.require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not has_reparse_point(metadata),
            f"{label} is not a regular file",
        )
        policy.require(
            metadata.st_size <= MAX_POLICY_FILE_BYTES,
            f"{label} exceeds the 4 MiB staging limit",
        )
        with path.open("rb") as handle:
            value = handle.read(MAX_POLICY_FILE_BYTES + 1)
    except OSError as error:
        raise policy.PolicyError(f"cannot read {label}: {error}") from error
    policy.require(
        len(value) <= MAX_POLICY_FILE_BYTES,
        f"{label} exceeds the 4 MiB staging limit",
    )
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def portable_tool_path(path: str) -> str:
    """Use slash-separated absolute paths accepted by Bash on every runner."""

    return os.path.realpath(path).replace("\\", "/")


def stage_policy(
    source_root: pathlib.Path,
    destination: pathlib.Path,
    github_output: str,
) -> None:
    """Stage immutable policy and trusted tool identities before checkout."""

    sources = {
        "verifier": source_root / policy.CHECKOUT_VERIFIER,
        "controller": source_root / policy.POLICY_CONTROLLER,
        "config": source_root / policy.POLICY_CONFIG,
    }
    names = {
        "verifier": "protected_checkout.py",
        "controller": "protected_pr_ci.py",
        "config": "protected-pr-ci.json",
    }
    try:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as error:
        raise policy.PolicyError(f"cannot create protected staging directory: {error}") from error

    outputs: dict[str, str] = {}
    for label, source in sources.items():
        value = bounded_regular_bytes(source, f"protected {label}")
        target = destination / names[label]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise policy.PolicyError(f"cannot stage protected {label}: {error}") from error
        outputs[label] = portable_tool_path(os.fspath(target))
        outputs[f"{label}_sha256"] = sha256_bytes(value)

    python = os.path.realpath(sys.executable)
    git = shutil.which("git")
    policy.require(
        os.path.isabs(python) and os.path.isfile(python) and os.access(python, os.X_OK),
        "trusted Python path is invalid",
    )
    policy.require(git is not None, "trusted Git executable is unavailable")
    assert git is not None
    git = os.path.realpath(git)
    policy.require(
        os.path.isabs(git) and os.path.isfile(git) and os.access(git, os.X_OK),
        "trusted Git path is invalid",
    )
    outputs["python"] = portable_tool_path(python)
    outputs["git"] = portable_tool_path(git)
    tool_directories = list(dict.fromkeys((os.path.dirname(python), os.path.dirname(git))))
    outputs["path"] = os.pathsep.join(portable_tool_path(item) for item in tool_directories)
    policy.write_github_outputs(github_output, outputs)


def enumerate_checkout(root: pathlib.Path) -> dict[str, os.stat_result]:
    started = time.monotonic()
    observed: dict[str, os.stat_result] = {}
    identities: dict[str, str] = {}
    pending = [root]
    metadata_bytes = 0
    while pending:
        policy.require(
            time.monotonic() - started <= MAX_SECONDS,
            "candidate checkout enumeration exceeded 30 seconds",
        )
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise policy.PolicyError(f"cannot enumerate candidate checkout: {error}") from error
        for entry in entries:
            if directory == root and entry.name == ".git":
                continue
            relative = entry.path[len(os.fspath(root)) :].lstrip("/\\").replace("\\", "/")
            normalized = policy.validate_path(relative, "candidate checkout path")
            components = policy.normalized_components(normalized)
            policy.require(
                all("~" not in component for component in components),
                "candidate checkout contains a Windows short-name-shaped path",
            )
            identity = metadata_identity(normalized)
            previous = identities.setdefault(identity, normalized)
            policy.require(
                previous == normalized,
                "candidate checkout contains Unicode-normalized casefold aliases",
            )
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise policy.PolicyError(f"cannot inspect candidate path {normalized}: {error}") from error
            metadata_bytes += len(normalized.encode("utf-8")) + 96
            policy.require(
                metadata_bytes <= policy.MAX_PATH_METADATA_BYTES,
                "candidate path metadata exceeds the 4 MiB limit",
            )
            observed[normalized] = metadata
            policy.require(
                len(observed) <= policy.MAX_TREE_ENTRIES,
                f"candidate checkout exceeds {policy.MAX_TREE_ENTRIES} entries",
            )
            if stat.S_ISDIR(metadata.st_mode) and not has_reparse_point(metadata):
                pending.append(pathlib.Path(entry.path))
    return observed


def trusted_git(
    git: str, root: pathlib.Path, arguments: Iterable[str], *, text: bool = True
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    environment = {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "core.fsmonitor",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "PATH": os.path.dirname(git),
    }
    if "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return subprocess.run(
        [git, "--no-pager", "-C", os.fspath(root), *arguments],
        check=False,
        capture_output=True,
        env=environment,
        text=text,
        timeout=10,
    )


def verify(
    root: pathlib.Path,
    git: str,
    repository: str,
    base_sha: str,
    head_sha: str,
    config_path: str,
    api: policy.GitHubApi,
) -> None:
    config = policy.load_config(config_path)
    policy.require(config.get("repository") == repository, "checkout repository does not match policy")
    base = policy.git_tree_for_commit(api, repository, base_sha, "base")
    head = policy.git_tree_for_commit(api, repository, head_sha, "head")
    policy.require_no_path_collisions(head.paths)
    paths, statuses = policy.changed_tree_paths(base, head)
    policy.sensitive_inventory(
        base,
        head,
        paths,
        statuses,
        policy.require_string(config.get("repository_kind"), "repository_kind"),
    )

    resolved_root = root.resolve(strict=True)
    policy.require(resolved_root.is_dir(), "candidate root is not a directory")
    observed = enumerate_checkout(resolved_root)
    kind = policy.require_string(config.get("repository_kind"), "repository_kind")
    expected = {
        path: leaf
        for path, leaf in head.leaves.items()
        if policy.is_sensitive_path(path, kind)
    }
    policy.require(
        len(expected) <= policy.MAX_SENSITIVE_FILES,
        f"candidate tree exceeds {policy.MAX_SENSITIVE_FILES} sensitive files",
    )

    actual_sensitive = {
        path
        for path, metadata in observed.items()
        if policy.is_sensitive_path(path, kind)
        and (not stat.S_ISDIR(metadata.st_mode) or has_reparse_point(metadata))
    }
    policy.require(
        actual_sensitive == set(expected),
        "candidate checkout has missing or untracked sensitive paths",
    )

    head_result = trusted_git(git, resolved_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    policy.require(head_result.returncode == 0, "trusted Git could not resolve candidate HEAD")
    policy.require(
        head_result.stdout.strip() == head_sha,
        "candidate checkout HEAD is not the authorized commit",
    )

    for path, leaf in sorted(expected.items()):
        entry_type, mode, blob = leaf
        policy.require(
            entry_type == "blob" and mode in {"100644", "100755"},
            f"sensitive path {path} is not a regular Git file",
        )
        metadata = observed[path]
        policy.require(
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not has_reparse_point(metadata),
            f"sensitive path {path} is a link, reparse point, or non-regular file",
        )
        result = trusted_git(
            git,
            resolved_root,
            ["hash-object", "--no-filters", "--", path],
        )
        policy.require(result.returncode == 0, f"trusted Git could not hash sensitive path {path}")
        policy.require(
            result.stdout.strip() == blob,
            f"sensitive path {path} differs from its authorized Git blob",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage = subparsers.add_parser("stage")
    stage.add_argument("--source-root", required=True)
    stage.add_argument("--destination", required=True)
    stage.add_argument("--github-output", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--candidate-root", required=True)
    verify_parser.add_argument("--git", required=True)
    verify_parser.add_argument("--repository", required=True)
    verify_parser.add_argument("--base-sha", required=True)
    verify_parser.add_argument("--head-sha", required=True)
    verify_parser.add_argument("--config", required=True)
    verify_parser.add_argument("--expected-verifier-sha256", required=True)
    verify_parser.add_argument("--expected-controller-sha256", required=True)
    verify_parser.add_argument("--expected-config-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "stage":
        stage_policy(
            pathlib.Path(args.source_root).resolve(strict=True),
            pathlib.Path(args.destination),
            args.github_output,
        )
        print("Staged protected checkout policy and trusted tools.")
        return 0

    staged = {
        "verifier": pathlib.Path(__file__),
        "controller": pathlib.Path(policy.__file__),
        "config": pathlib.Path(args.config),
    }
    expected = {
        "verifier": policy.validate_digest(
            args.expected_verifier_sha256, "expected verifier digest"
        ),
        "controller": policy.validate_digest(
            args.expected_controller_sha256, "expected controller digest"
        ),
        "config": policy.validate_digest(
            args.expected_config_sha256, "expected config digest"
        ),
    }
    for label, path in staged.items():
        observed = sha256_bytes(bounded_regular_bytes(path, f"staged {label}"))
        policy.require(
            observed == expected[label],
            f"staged {label} digest changed after candidate checkout",
        )
    git = os.path.realpath(args.git)
    policy.require(os.path.isabs(git) and os.path.isfile(git), "trusted Git path is invalid")
    verify(
        pathlib.Path(args.candidate_root),
        git,
        policy.validate_repository(args.repository),
        policy.validate_sha(args.base_sha, "base SHA"),
        policy.validate_sha(args.head_sha, "head SHA"),
        args.config,
        policy.GitHubApi(os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_API_URL", "https://api.github.com")),
    )
    print("Protected checkout verification succeeded.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except policy.PolicyError as error:
        print(f"policy error: {error}", file=sys.stderr)
        raise SystemExit(1) from error

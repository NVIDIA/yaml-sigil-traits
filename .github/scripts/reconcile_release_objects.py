#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Verify or recover official annotated tags and source-only Releases."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


SHA_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?")
API_VERSION = "2022-11-28"
USER_AGENT = "yaml-sigil-release-workflow/1.0"
MAX_CRATE_BYTES = 32 * 1024 * 1024
MAX_CRATE_FILES = 10_000
MAX_CRATE_UNPACKED_BYTES = 128 * 1024 * 1024
REPOSITORY_RELEASES = {
    "NVIDIA/yaml-sigil-traits": (
        ("yaml-sigil-traits", "v{version}", "CHANGELOG.md", ""),
    ),
    "NVIDIA/yaml-sigil-rs": (
        (
            "yaml-sigil-core",
            "yaml-sigil-core-v{version}",
            "crates/yaml-sigil-core/CHANGELOG.md",
            "crates/yaml-sigil-core",
        ),
        (
            "yaml-sigil-transcription",
            "yaml-sigil-transcription-v{version}",
            "crates/yaml-sigil-transcription/CHANGELOG.md",
            "crates/yaml-sigil-transcription",
        ),
        (
            "yaml-sigil-signing",
            "yaml-sigil-signing-v{version}",
            "crates/yaml-sigil-signing/CHANGELOG.md",
            "crates/yaml-sigil-signing",
        ),
        (
            "yaml-sigil-verification",
            "yaml-sigil-verification-v{version}",
            "crates/yaml-sigil-verification/CHANGELOG.md",
            "crates/yaml-sigil-verification",
        ),
    ),
}


class ReleaseObjectError(RuntimeError):
    """A release-object invariant was not satisfied."""


class GitHubAPI(Protocol):
    """Small API surface used by reconciliation and its fixtures."""

    def get(self, path: str) -> dict[str, object] | None: ...

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]: ...


class RegistryAPI(Protocol):
    """Registry lookup surface used before any recovery mutation."""

    def exact_version(self, package: str, version: str) -> dict[str, object] | None: ...

    def download(self, package: str, version: str) -> bytes: ...


class SourcePackager(Protocol):
    """Create one ephemeral Cargo source package from the bound checkout."""

    def package(self, spec: "ReleaseSpec") -> bytes: ...


class JsonHTTPClient:
    """Perform redacted JSON requests with bounded timeouts."""

    def __init__(self, base_url: str, headers: dict[str, str]) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
        except HTTPError as error:
            if method == "GET" and error.code == 404:
                return None
            raise ReleaseObjectError(
                f"{method} {path} returned HTTP {error.code}"
            ) from error
        except (OSError, URLError) as error:
            raise ReleaseObjectError(f"{method} {path} failed") from error
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseObjectError(f"{method} {path} returned invalid JSON") from error
        if not isinstance(decoded, dict):
            raise ReleaseObjectError(f"{method} {path} returned a non-object response")
        return decoded

    def request_bytes(self, path: str) -> bytes:
        request = Request(
            f"{self.base_url}{path}", headers=self.headers, method="GET"
        )
        try:
            with urlopen(request, timeout=60) as response:
                body = response.read(MAX_CRATE_BYTES + 1)
        except HTTPError as error:
            raise ReleaseObjectError(
                f"GET {path} returned HTTP {error.code}"
            ) from error
        except (OSError, URLError) as error:
            raise ReleaseObjectError(f"GET {path} failed") from error
        if len(body) > MAX_CRATE_BYTES:
            raise ReleaseObjectError(f"GET {path} exceeded the source archive limit")
        return body


class LiveGitHubAPI:
    """GitHub REST implementation with no asset-upload capability."""

    def __init__(self, token: str) -> None:
        self.client = JsonHTTPClient(
            "https://api.github.com",
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )

    def get(self, path: str) -> dict[str, object] | None:
        return self.client.request("GET", path)

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        response = self.client.request("POST", path, payload)
        if response is None:  # POST never treats 404 as an absence state.
            raise ReleaseObjectError(f"POST {path} returned no object")
        return response


class LiveRegistryAPI:
    """Read exact crates.io version records without mutation credentials."""

    def __init__(self) -> None:
        self.client = JsonHTTPClient(
            "https://crates.io/api/v1", {"User-Agent": USER_AGENT}
        )

    def exact_version(self, package: str, version: str) -> dict[str, object] | None:
        return self.client.request(
            "GET", f"/crates/{quote(package, safe='')}/{quote(version, safe='')}"
        )

    def download(self, package: str, version: str) -> bytes:
        return self.client.request_bytes(
            f"/crates/{quote(package, safe='')}/{quote(version, safe='')}/download"
        )


class CargoSourcePackager:
    """Package the clean checkout without retaining or building executables."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def package(self, spec: "ReleaseSpec") -> bytes:
        version = subprocess.run(
            ["cargo", "--version"],
            cwd=self.root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if version.returncode != 0 or not version.stdout.startswith("cargo 1.95.0 "):
            raise ReleaseObjectError("source recovery requires exact Cargo 1.95.0")
        with tempfile.TemporaryDirectory(prefix="release-source-package-") as temporary:
            target = Path(temporary) / "target"
            environment = os.environ.copy()
            environment["CARGO_TARGET_DIR"] = str(target)
            packaged = subprocess.run(
                [
                    "cargo",
                    "package",
                    "--no-verify",
                    "--package",
                    spec.package,
                ],
                cwd=self.root,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if packaged.returncode != 0:
                detail = packaged.stderr.strip() or packaged.stdout.strip()
                raise ReleaseObjectError(
                    f"Cargo could not reproduce {spec.package} {spec.version}: {detail}"
                )
            archive = target / "package" / f"{spec.package}-{spec.version}.crate"
            try:
                return archive.read_bytes()
            except OSError as error:
                raise ReleaseObjectError(
                    f"Cargo did not create exact {spec.package} {spec.version} source"
                ) from error


@dataclass(frozen=True)
class ReleaseSpec:
    package: str
    tag: str
    changelog: Path
    path_in_vcs: str
    body: str
    prerelease: bool

    @property
    def tag_message(self) -> str:
        return f"chore: Release package {self.package} version {self.version}"

    @property
    def version(self) -> str:
        if "-v" in self.tag:
            return self.tag.rsplit("-v", 1)[1]
        return self.tag[1:]


@dataclass(frozen=True)
class ObjectState:
    tag_exists: bool
    release_exists: bool


def changelog_body(path: Path, version: str) -> str:
    """Extract the exact reviewed notes release-plz uses as its default body."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReleaseObjectError(f"cannot read changelog {path}") from error
    heading = re.compile(
        rf"^## \[{re.escape(version)}\](?:\([^\n]+\))? - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$"
    )
    matches = [index for index, line in enumerate(lines) if heading.fullmatch(line)]
    if len(matches) != 1:
        raise ReleaseObjectError(
            f"changelog {path} does not contain one exact {version} release"
        )
    start = matches[0] + 1
    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    body = "\n".join(lines[start:end]).strip()
    if not body:
        raise ReleaseObjectError(f"changelog {path} has an empty {version} release")
    return body


def release_specs(root: Path, repository: str, version: str) -> tuple[ReleaseSpec, ...]:
    if repository not in REPOSITORY_RELEASES:
        raise ReleaseObjectError(f"unsupported release repository: {repository}")
    if VERSION_RE.fullmatch(version) is None:
        raise ReleaseObjectError(f"unsupported release version: {version}")
    prerelease = "-rc." in version
    return tuple(
        ReleaseSpec(
            package=package,
            tag=tag_template.format(version=version),
            changelog=root / changelog,
            path_in_vcs=path_in_vcs,
            body=changelog_body(root / changelog, version),
            prerelease=prerelease,
        )
        for package, tag_template, changelog, path_in_vcs in REPOSITORY_RELEASES[
            repository
        ]
    )


def tag_ref_path(repository: str, tag: str) -> str:
    return f"/repos/{repository}/git/ref/tags/{quote(tag, safe='')}"


def tag_object_path(repository: str, sha: str) -> str:
    return f"/repos/{repository}/git/tags/{sha}"


def release_path(repository: str, tag: str) -> str:
    return f"/repos/{repository}/releases/tags/{quote(tag, safe='')}"


def validate_tag_object(
    value: dict[str, object], spec: ReleaseSpec, commit: str, object_sha: str
) -> None:
    expected_object = {"type": "commit", "sha": commit}
    if (
        value.get("sha") != object_sha
        or value.get("tag") != spec.tag
        or value.get("message") != spec.tag_message
        or value.get("object") != expected_object
    ):
        raise ReleaseObjectError(f"annotated tag {spec.tag} has conflicting state")


def inspect_tag(
    github: GitHubAPI, repository: str, spec: ReleaseSpec, commit: str
) -> bool:
    ref = github.get(tag_ref_path(repository, spec.tag))
    if ref is None:
        return False
    object_value = ref.get("object")
    if not isinstance(object_value, dict):
        raise ReleaseObjectError(f"tag ref {spec.tag} has no exact object")
    object_sha = object_value.get("sha")
    if (
        ref.get("ref") != f"refs/tags/{spec.tag}"
        or object_value.get("type") != "tag"
        or not isinstance(object_sha, str)
        or SHA_RE.fullmatch(object_sha) is None
    ):
        raise ReleaseObjectError(f"tag ref {spec.tag} is not exact and annotated")
    tag_object = github.get(tag_object_path(repository, object_sha))
    if tag_object is None:
        raise ReleaseObjectError(f"annotated tag object {spec.tag} is missing")
    validate_tag_object(tag_object, spec, commit, object_sha)
    return True


def validate_release(value: dict[str, object], spec: ReleaseSpec) -> None:
    if (
        value.get("tag_name") != spec.tag
        or value.get("name") != spec.tag
        or value.get("body") != spec.body
        or value.get("draft") is not False
        or value.get("prerelease") is not spec.prerelease
        or value.get("assets") != []
    ):
        raise ReleaseObjectError(f"GitHub Release {spec.tag} has conflicting state")


def inspect_release(github: GitHubAPI, repository: str, spec: ReleaseSpec) -> bool:
    release = github.get(release_path(repository, spec.tag))
    if release is None:
        return False
    validate_release(release, spec)
    return True


def inspect_objects(
    github: GitHubAPI,
    repository: str,
    specs: tuple[ReleaseSpec, ...],
    commit: str,
) -> tuple[ObjectState, ...]:
    return tuple(
        ObjectState(
            tag_exists=inspect_tag(github, repository, spec, commit),
            release_exists=inspect_release(github, repository, spec),
        )
        for spec in specs
    )


def inspect_crate_archive(
    archive: bytes, spec: ReleaseSpec, commit: str
) -> dict[str, bytes]:
    """Validate one source-only Cargo archive without extracting it."""

    prefix = f"{spec.package}-{spec.version}"
    files: dict[str, bytes] = {}
    if len(archive) > MAX_CRATE_BYTES:
        raise ReleaseObjectError(f"{spec.package} source archive is too large")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            members = package.getmembers()
            if not members:
                raise ReleaseObjectError(f"{spec.package} source archive is empty")
            if len(members) > MAX_CRATE_FILES:
                raise ReleaseObjectError(
                    f"{spec.package} source archive contains too many entries"
                )
            if sum(member.size for member in members) > MAX_CRATE_UNPACKED_BYTES:
                raise ReleaseObjectError(
                    f"{spec.package} source archive expands beyond its limit"
                )
            seen: set[str] = set()
            for member in members:
                name = member.name.rstrip("/")
                path = PurePosixPath(name)
                if (
                    not name
                    or path.is_absolute()
                    or "\\" in name
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not path.parts
                    or path.parts[0] != prefix
                    or str(path) != name
                    or name in seen
                ):
                    raise ReleaseObjectError(
                        f"{spec.package} source archive contains an unsafe path"
                    )
                seen.add(name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ReleaseObjectError(
                        f"{spec.package} source archive contains a non-file entry"
                    )
                source = package.extractfile(member)
                if source is None:
                    raise ReleaseObjectError(
                        f"{spec.package} source archive contains an unreadable file"
                    )
                files["/".join(path.parts[1:])] = source.read()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ReleaseObjectError(
            f"{spec.package} source archive is not a valid .crate"
        ) from error
    vcs_path = ".cargo_vcs_info.json"
    if vcs_path not in files:
        raise ReleaseObjectError(f"{spec.package} source archive lacks {vcs_path}")
    try:
        vcs = json.loads(files[vcs_path])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseObjectError(
            f"{spec.package} source archive has invalid {vcs_path}"
        ) from error
    if not isinstance(vcs, dict) or set(vcs) != {"git", "path_in_vcs"}:
        raise ReleaseObjectError(
            f"{spec.package} source archive has ambiguous {vcs_path}"
        )
    git_state = vcs.get("git")
    if (
        not isinstance(git_state, dict)
        or set(git_state) not in ({"sha1"}, {"sha1", "dirty"})
        or git_state.get("sha1") != commit
        or git_state.get("dirty", False) is not False
        or vcs.get("path_in_vcs") != spec.path_in_vcs
    ):
        raise ReleaseObjectError(
            f"{spec.package} source archive is not bound to the clean release commit"
        )
    return files


def require_generated_cargo_lock(
    files: dict[str, bytes], spec: ReleaseSpec
) -> None:
    """Require a generated lockfile bound to the package being compared."""

    lock_path = "Cargo.lock"
    try:
        lock = tomllib.loads(files[lock_path].decode("utf-8"))
    except KeyError as error:
        raise ReleaseObjectError(
            f"source package lacks generated {lock_path} for "
            f"{spec.package} {spec.version}"
        ) from error
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseObjectError(
            f"source package has invalid generated {lock_path} for "
            f"{spec.package} {spec.version}"
        ) from error
    packages = lock.get("package") if isinstance(lock, dict) else None
    if not isinstance(packages, list):
        raise ReleaseObjectError(
            f"source package has invalid generated {lock_path} for "
            f"{spec.package} {spec.version}"
        )
    matches = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == spec.package
        and package.get("version") == spec.version
    ]
    if (
        len(matches) != 1
        or "source" in matches[0]
        or "checksum" in matches[0]
    ):
        raise ReleaseObjectError(
            f"source package has unbound generated {lock_path} for "
            f"{spec.package} {spec.version}"
        )


def require_registry_publication(
    registry: RegistryAPI,
    packager: SourcePackager,
    specs: tuple[ReleaseSpec, ...],
    commit: str,
) -> dict[str, str]:
    """Bind every immutable registry archive to this exact clean checkout."""

    checksums: dict[str, str] = {}
    for spec in specs:
        record = registry.exact_version(spec.package, spec.version)
        version = record.get("version") if isinstance(record, dict) else None
        if not isinstance(version, dict) or (
            version.get("num") != spec.version or version.get("yanked") is not False
        ):
            raise ReleaseObjectError(
                f"crates.io does not expose {spec.package} {spec.version} as non-yanked"
            )
        checksum = version.get("checksum")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ReleaseObjectError(
                f"crates.io did not report an exact checksum for {spec.package} {spec.version}"
            )
        downloaded = registry.download(spec.package, spec.version)
        if hashlib.sha256(downloaded).hexdigest() != checksum:
            raise ReleaseObjectError(
                f"crates.io archive checksum differs for {spec.package} {spec.version}"
            )
        downloaded_files = inspect_crate_archive(downloaded, spec, commit)
        reproduced_files = inspect_crate_archive(
            packager.package(spec), spec, commit
        )
        # Cargo generates the root package lockfile during packaging. Its exact
        # dependency resolution can legitimately differ when an older release
        # is reproduced, so it is not a stable source-provenance input. Require
        # the file on both sides, then compare every other packaged byte,
        # including both manifests and the exact clean VCS binding.
        require_generated_cargo_lock(downloaded_files, spec)
        require_generated_cargo_lock(reproduced_files, spec)
        del downloaded_files["Cargo.lock"]
        del reproduced_files["Cargo.lock"]
        if reproduced_files != downloaded_files:
            raise ReleaseObjectError(
                f"local source content differs from {spec.package} {spec.version}"
            )
        checksums[spec.package] = checksum
    return checksums


def recheck_registry_publication(
    registry: RegistryAPI,
    specs: tuple[ReleaseSpec, ...],
    checksums: dict[str, str],
) -> None:
    """Require the same immutable non-yanked records after object creation."""

    for spec in specs:
        record = registry.exact_version(spec.package, spec.version)
        version = record.get("version") if isinstance(record, dict) else None
        if not isinstance(version, dict) or (
            version.get("num") != spec.version
            or version.get("yanked") is not False
            or version.get("checksum") != checksums.get(spec.package)
        ):
            raise ReleaseObjectError(
                f"crates.io changed {spec.package} {spec.version} during recovery"
            )


def require_prepublish_state(
    registry: RegistryAPI,
    packager: SourcePackager,
    specs: tuple[ReleaseSpec, ...],
    states: tuple[ObjectState, ...],
    commit: str,
) -> None:
    """Permit absent crates and an exact already-published release subset."""

    if len(specs) != len(states):
        raise ReleaseObjectError("release object inventory is incomplete")
    published: list[ReleaseSpec] = []
    missing_seen = False
    for spec, state in zip(specs, states, strict=True):
        record = registry.exact_version(spec.package, spec.version)
        if record is None:
            missing_seen = True
            # An official object would make release-plz skip a crate whose
            # immutable registry source is still absent.
            if state.tag_exists or state.release_exists:
                raise ReleaseObjectError(
                    f"unpublished crate {spec.package} already has release objects"
                )
            continue
        if missing_seen:
            raise ReleaseObjectError(
                "published crates do not form the exact dependency-order prefix"
            )
        published.append(spec)

    # A prior attempt can publish an earlier workspace crate and create either,
    # both, or neither source-only object before a later crate fails. Bind every
    # such immutable archive to this checkout before allowing release-plz to
    # skip it and continue the remaining train.
    if published:
        require_registry_publication(
            registry, packager, tuple(published), commit
        )


def create_tag(
    github: GitHubAPI,
    repository: str,
    spec: ReleaseSpec,
    commit: str,
) -> None:
    tag_object = github.post(
        f"/repos/{repository}/git/tags",
        {
            "tag": spec.tag,
            "message": spec.tag_message,
            "object": commit,
            "type": "commit",
        },
    )
    object_sha = tag_object.get("sha")
    if not isinstance(object_sha, str) or SHA_RE.fullmatch(object_sha) is None:
        raise ReleaseObjectError(f"GitHub did not create exact tag object {spec.tag}")
    validate_tag_object(tag_object, spec, commit, object_sha)
    ref = github.post(
        f"/repos/{repository}/git/refs",
        {"ref": f"refs/tags/{spec.tag}", "sha": object_sha},
    )
    ref_object = ref.get("object")
    if (
        ref.get("ref") != f"refs/tags/{spec.tag}"
        or not isinstance(ref_object, dict)
        or ref_object.get("type") != "tag"
        or ref_object.get("sha") != object_sha
    ):
        raise ReleaseObjectError(f"GitHub did not create exact tag ref {spec.tag}")


def create_release(github: GitHubAPI, repository: str, spec: ReleaseSpec, commit: str) -> None:
    release = github.post(
        f"/repos/{repository}/releases",
        {
            "tag_name": spec.tag,
            "target_commitish": commit,
            "name": spec.tag,
            "body": spec.body,
            "draft": False,
            "prerelease": spec.prerelease,
        },
    )
    validate_release(release, spec)


def reconcile(
    github: GitHubAPI,
    registry: RegistryAPI,
    repository: str,
    specs: tuple[ReleaseSpec, ...],
    commit: str,
    mode: str,
    packager: SourcePackager | None = None,
) -> None:
    if SHA_RE.fullmatch(commit) is None:
        raise ReleaseObjectError("the release commit must be a lowercase full SHA")
    states = inspect_objects(github, repository, specs, commit)
    if mode == "preflight":
        return
    if mode == "prepublish":
        if packager is None:
            raise ReleaseObjectError("prepublication requires an exact Cargo packager")
        require_prepublish_state(registry, packager, specs, states, commit)
        return
    if mode == "verify":
        if not all(state.tag_exists and state.release_exists for state in states):
            raise ReleaseObjectError("official release objects are incomplete")
        return
    if mode != "recover":
        raise ReleaseObjectError(f"unsupported reconciliation mode: {mode}")

    # Registry success is the irreversible boundary that permits source-only
    # metadata recovery. No GitHub mutation occurs before this exact check.
    if packager is None:
        raise ReleaseObjectError("source recovery requires an exact Cargo packager")
    checksums = require_registry_publication(registry, packager, specs, commit)
    for spec, state in zip(specs, states, strict=True):
        if not state.tag_exists:
            create_tag(github, repository, spec, commit)
    for spec, state in zip(specs, states, strict=True):
        if not state.release_exists:
            create_release(github, repository, spec, commit)

    final = inspect_objects(github, repository, specs, commit)
    if not all(state.tag_exists and state.release_exists for state in final):
        raise ReleaseObjectError("official release objects remain incomplete")
    recheck_registry_publication(registry, specs, checksums)


def require_source(root: Path, repository: str, version: str, commit: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or result.stdout.strip() != commit:
        raise ReleaseObjectError("the release source is not at the expected commit")
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if status.returncode != 0 or status.stdout:
        raise ReleaseObjectError("the release source is not a clean checkout")
    try:
        with (root / "Cargo.toml").open("rb") as manifest_file:
            manifest = tomllib.load(manifest_file)
        actual = (
            manifest["package"]["version"]
            if repository == "NVIDIA/yaml-sigil-traits"
            else manifest["workspace"]["package"]["version"]
        )
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise ReleaseObjectError("the release manifest has no exact version") from error
    if actual != version:
        raise ReleaseObjectError("the release manifest version is unexpected")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--root", default=Path.cwd(), type=Path)
    parser.add_argument(
        "--mode",
        required=True,
        choices=("preflight", "prepublish", "recover", "verify"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = args.root.resolve()
        require_source(root, args.repository, args.version, args.commit)
        specs = release_specs(root, args.repository, args.version)
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ReleaseObjectError("a GitHub workflow token is required")
        reconcile(
            LiveGitHubAPI(token),
            LiveRegistryAPI(),
            args.repository,
            specs,
            args.commit,
            args.mode,
            CargoSourcePackager(root),
        )
    except ReleaseObjectError as error:
        print(f"release object reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(f"Release objects passed {args.mode} reconciliation for {args.version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

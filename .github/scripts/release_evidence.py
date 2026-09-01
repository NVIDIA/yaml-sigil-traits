#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Canonical release-setting and Cargo archive evidence encodings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path

APP_ID = 4_653_064
INTENT_NAME = "Release finalization intent"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_CONTENT_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_DECOMPRESSED_BYTES = 160 * 1024 * 1024
MAX_VCS_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
CARGO_ARCHIVE_MTIME = 1_153_704_088
CARGO_ARCHIVE_MODES = frozenset((0o644, 0o755))
GNU_NUL_ZERO = b"\0" * 8
GNU_OCTAL_ZERO = b"0000000\0"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")

TAG_PATTERNS = {
    "NVIDIA/yaml-sigil-traits": ("refs/tags/v*",),
    "NVIDIA/yaml-sigil-rs": (
        "refs/tags/yaml-sigil-core-v*",
        "refs/tags/yaml-sigil-transcription-v*",
        "refs/tags/yaml-sigil-signing-v*",
        "refs/tags/yaml-sigil-verification-v*",
    ),
}


class EvidenceError(RuntimeError):
    """A canonical evidence boundary rejected its input."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def settings_evidence_values(
    repository: str,
    release_sha: str,
    run_id: int,
    run_attempt: int,
) -> tuple[str, ...]:
    require(repository in TAG_PATTERNS, "repository is outside the settings-evidence policy")
    require(SHA_RE.fullmatch(release_sha) is not None, "release SHA is invalid")
    require(type(run_id) is int and run_id > 0, "workflow run ID is invalid")
    require(type(run_attempt) is int and run_attempt > 0, "workflow run attempt is invalid")
    values = [
        "yaml-sigil-release-setting-evidence-v1",
        repository,
        str(run_id),
        str(run_attempt),
        release_sha,
        "immutable-releases=true",
    ]
    values.extend(
        f"creation={pattern}:Integration:{APP_ID}:always"
        for pattern in TAG_PATTERNS[repository]
    )
    values.extend(
        f"update-delete={pattern}:no-bypass"
        for pattern in TAG_PATTERNS[repository]
    )
    values.append(f"forbidden-required-check={INTENT_NAME}")
    return tuple(values)


def settings_evidence_sha256(
    repository: str,
    release_sha: str,
    run_id: int,
    run_attempt: int,
) -> str:
    body = b"".join(
        value.encode("utf-8") + b"\0"
        for value in settings_evidence_values(repository, release_sha, run_id, run_attempt)
    )
    return sha256(body)


def _decompress_single_gzip(archive: bytes) -> bytes:
    require(0 < len(archive) <= MAX_ARCHIVE_BYTES, "crate archive is empty or oversized")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        body = decoder.decompress(archive, MAX_ARCHIVE_DECOMPRESSED_BYTES + 1)
        require(
            len(body) <= MAX_ARCHIVE_DECOMPRESSED_BYTES and not decoder.unconsumed_tail,
            "crate archive expands beyond its limit",
        )
        body += decoder.flush(MAX_ARCHIVE_DECOMPRESSED_BYTES + 1 - len(body))
    except zlib.error as error:
        raise EvidenceError(f"crate archive gzip stream is invalid: {error}") from error
    require(len(body) <= MAX_ARCHIVE_DECOMPRESSED_BYTES, "crate archive expands beyond its limit")
    require(decoder.eof, "crate archive gzip stream is truncated")
    require(not decoder.unused_data, "crate archive contains another gzip member or trailing bytes")
    return body


def _tar_number(raw: bytes, label: str) -> int:
    value = raw.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    require(all(ord("0") <= byte <= ord("7") for byte in value), f"{label} is noncanonical")
    return int(value, 8)


def _raw_name(raw: bytes) -> str:
    end = raw.find(b"\0")
    if end < 0:
        end = len(raw)
    require(not any(raw[end:]), "crate archive contains a noncanonical raw path")
    try:
        return raw[:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("crate archive contains a non-UTF-8 path") from error


def _validate_path(path: str, prefix: str) -> str:
    require(
        path
        and not path.startswith("/")
        and not any(character in path for character in "\0\r\n\\")
        and all(part not in ("", ".", "..") for part in path.split("/"))
        and path.startswith(f"{prefix}/"),
        "crate archive contains an unsafe or noncanonical path",
    )
    return path[len(prefix) + 1 :]


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    header_sha256: str
    entry_type: int
    mode: int
    uid: bytes
    gid: bytes
    mtime: int
    username: bytes
    groupname: bytes
    device_major: bytes
    device_minor: bytes
    body: bytes


def _inventory_value(digest: hashlib._Hash, value: str) -> None:  # type: ignore[name-defined]
    digest.update(value.encode("utf-8"))
    digest.update(b"\0")


def _inventory_sha256(entries: dict[str, ArchiveEntry]) -> str:
    digest = hashlib.sha256()
    _inventory_value(digest, "yaml-sigil-crate-inventory-v1")
    for path in sorted(entries):
        entry = entries[path]
        for value in (
            path,
            f"header-sha256={entry.header_sha256}",
            f"entry-type={entry.entry_type}",
            f"mode={entry.mode}",
            f"uid={entry.uid.hex()}",
            f"gid={entry.gid.hex()}",
            f"mtime={entry.mtime}",
            f"username={entry.username.hex()}",
            f"groupname={entry.groupname.hex()}",
            f"device-major={entry.device_major.hex()}",
            f"device-minor={entry.device_minor.hex()}",
            f"size={len(entry.body)}",
            f"sha256={sha256(entry.body)}",
        ):
            _inventory_value(digest, value)
    return digest.hexdigest()


def crate_inventory_sha256(
    archive: bytes,
    package: str,
    version: str,
    commit: str,
    path_in_vcs: str,
) -> str:
    require(SHA_RE.fullmatch(commit) is not None, "crate VCS commit is invalid")
    prefix = f"{package}-{version}"
    tar = _decompress_single_gzip(archive)
    require(
        len(tar) >= TAR_BLOCK_BYTES * 2 and len(tar) % TAR_BLOCK_BYTES == 0,
        "crate archive has a noncanonical tar length",
    )
    entries: dict[str, ArchiveEntry] = {}
    offset = 0
    total = 0
    count = 0
    terminator = False
    while offset < len(tar):
        header = tar[offset : offset + TAR_BLOCK_BYTES]
        if not any(header):
            require(
                offset + TAR_BLOCK_BYTES * 2 <= len(tar)
                and not any(tar[offset + TAR_BLOCK_BYTES : offset + TAR_BLOCK_BYTES * 2])
                and not any(tar[offset + TAR_BLOCK_BYTES * 2 :]),
                "crate archive contains records after its tar terminator",
            )
            terminator = True
            break
        count += 1
        require(count <= MAX_ARCHIVE_FILES, "crate archive file count exceeded its bound")
        checksum = _tar_number(header[148:156], "crate archive header checksum")
        computed = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
        require(checksum == computed, "crate archive header checksum is wrong")
        require(
            header[257:263] == b"ustar " and header[263:265] == b" \0",
            "crate archive entry is not a Cargo GNU header",
        )
        entry_type = header[156]
        require(entry_type == ord("0"), "crate archive contains a noncanonical entry type")
        require(not any(header[157:257]), "crate archive regular entry contains a link target")
        path = _raw_name(header[:100])
        relative = _validate_path(path, prefix)
        mode = _tar_number(header[100:108], "crate archive mode")
        require(mode in CARGO_ARCHIVE_MODES, "crate archive contains a noncanonical mode")
        uid = header[108:116]
        gid = header[116:124]
        require(
            uid in (GNU_NUL_ZERO, GNU_OCTAL_ZERO) and gid in (GNU_NUL_ZERO, GNU_OCTAL_ZERO),
            "crate archive contains noncanonical ownership",
        )
        size = _tar_number(header[124:136], "crate archive size")
        mtime = _tar_number(header[136:148], "crate archive mtime")
        require(mtime == CARGO_ARCHIVE_MTIME, "crate archive contains a noncanonical mtime")
        username = header[265:297]
        groupname = header[297:329]
        require(not any(username) and not any(groupname), "crate archive owner names are noncanonical")
        device_major = header[329:337]
        device_minor = header[337:345]
        require(
            device_major in (GNU_NUL_ZERO, GNU_OCTAL_ZERO)
            and device_minor in (GNU_NUL_ZERO, GNU_OCTAL_ZERO),
            "crate archive device metadata is noncanonical",
        )
        body_start = offset + TAR_BLOCK_BYTES
        body_end = body_start + size
        padded_end = body_start + ((size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
        require(padded_end <= len(tar), "crate archive contains a truncated physical entry")
        require(not any(tar[body_end:padded_end]), "crate archive entry padding is noncanonical")
        total += size
        require(total <= MAX_ARCHIVE_CONTENT_BYTES, "crate archive content exceeded its bound")
        body = tar[body_start:body_end]
        require(relative not in entries, "crate archive contains a duplicate path")
        entries[relative] = ArchiveEntry(
            relative,
            sha256(header),
            entry_type,
            mode,
            uid,
            gid,
            mtime,
            username.rstrip(b"\0"),
            groupname.rstrip(b"\0"),
            device_major,
            device_minor,
            body,
        )
        offset = padded_end
    require(terminator and entries, "crate archive lacks its canonical tar terminator")
    vcs_entry = entries.get(".cargo_vcs_info.json")
    require(vcs_entry is not None, "crate archive lacks VCS metadata")
    require(len(vcs_entry.body) <= MAX_VCS_BYTES, "crate VCS metadata is oversized")
    try:
        vcs = json.loads(vcs_entry.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"crate VCS metadata is invalid: {error}") from error
    require(type(vcs) is dict and set(vcs) == {"git", "path_in_vcs"}, "crate VCS metadata is invalid")
    git = vcs.get("git")
    require(
        type(git) is dict
        and set(git) in ({"sha1"}, {"sha1", "dirty"})
        and git.get("sha1") == commit
        and git.get("dirty", False) is False,
        "crate VCS commit is wrong or dirty",
    )
    require(vcs.get("path_in_vcs") == path_in_vcs, "crate VCS path is wrong")
    return _inventory_sha256(entries)


def append_output(path: Path, name: str, value: str) -> None:
    require(
        re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None,
        "workflow output name is invalid",
    )
    require(not any(character in value for character in "\0\r\n"), "workflow output value is invalid")
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    settings = subparsers.add_parser("settings")
    settings.add_argument("--repository", required=True)
    settings.add_argument("--release-sha", required=True)
    settings.add_argument("--run-id", type=int, required=True)
    settings.add_argument("--run-attempt", type=int, required=True)
    settings.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = settings_evidence_sha256(
            args.repository,
            args.release_sha,
            args.run_id,
            args.run_attempt,
        )
        append_output(args.github_output, "ruleset_evidence_sha256", digest)
        print(f"ruleset_evidence_sha256={digest}")
    except (EvidenceError, OSError) as error:
        print(f"release evidence rejected: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

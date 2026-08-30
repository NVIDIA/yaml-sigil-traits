#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the closed historical Release inventory."""

from __future__ import annotations

import copy
import io
import tarfile
import unittest
from pathlib import Path
from typing import Any

import legacy_release_preflight as legacy
import release_evidence as evidence
import release_notification_preflight as preflight


class FakeApi:
    def __init__(
        self,
        github: dict[str, Any],
        crates: dict[str, Any],
        archives: dict[tuple[str, str], bytes],
    ) -> None:
        self.github = github
        self.crates = crates
        self.archives = archives

    def github_json(self, path: str, optional: bool = False) -> Any:
        if path not in self.github:
            if optional:
                return None
            raise AssertionError(f"unexpected GitHub read: {path}")
        return copy.deepcopy(self.github[path])

    def crates_json(self, path: str) -> Any:
        return copy.deepcopy(self.crates[path])

    def crate_archive(self, package: str, version: str) -> bytes:
        return self.archives[(package, version)]


def source_archive(package: str, version: str, commit: str, path_in_vcs: str) -> bytes:
    vcs = preflight.canonical(
        {"git": {"sha1": commit}, "path_in_vcs": path_in_vcs}
    ).encode()
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:gz",
        format=tarfile.GNU_FORMAT,
    ) as archive:
        info = tarfile.TarInfo(f"{package}-{version}/.cargo_vcs_info.json")
        info.size = len(vcs)
        info.mode = 0o644
        info.mtime = evidence.CARGO_ARCHIVE_MTIME
        archive.addfile(info, io.BytesIO(vcs))
        source = b"pub fn historical_source_fixture() {}\n"
        info = tarfile.TarInfo(f"{package}-{version}/src/lib.rs")
        info.size = len(source)
        info.mode = 0o644
        info.mtime = evidence.CARGO_ARCHIVE_MTIME
        archive.addfile(info, io.BytesIO(source))
    return output.getvalue()


class Fixture:
    def __init__(self) -> None:
        inventory_path = Path(__file__).parents[1] / "legacy-release-inventory.json"
        self.inventory = copy.deepcopy(
            preflight.read_json(
                inventory_path,
                preflight.MAX_CONFIG_BYTES,
                "test legacy inventory",
            )
        )
        self.github: dict[str, Any] = {}
        self.crates: dict[str, Any] = {}
        self.archives: dict[tuple[str, str], bytes] = {}
        releases: list[dict[str, Any]] = []
        for entry in self.inventory["entries"]:
            body = f"historical notes for {entry['tag']}"
            entry["body_sha256"] = preflight.sha256(body.encode())
            archive = source_archive(
                entry["package"],
                entry["version"],
                entry["peeled_commit_sha"],
                entry["path_in_vcs"],
            )
            digest = preflight.sha256(archive)
            entry["source_archive_sha256"] = digest
            release = {
                "id": entry["release_id"],
                "tag_name": entry["tag"],
                "target_commitish": "main",
                "author": copy.deepcopy(self.inventory["legacy_author"]),
                "draft": entry["draft"],
                "prerelease": entry["prerelease"],
                "immutable": False,
                "assets": [],
                "body": body,
            }
            releases.append(copy.deepcopy(release))
            repository = self.inventory["repository"]
            self.github[f"repos/{repository}/releases/{entry['release_id']}"] = release
            encoded = preflight.urllib.parse.quote(entry["tag"], safe="")
            self.github[f"repos/{repository}/git/ref/tags/{encoded}"] = {
                "ref": f"refs/tags/{entry['tag']}",
                "object": {"type": "tag", "sha": entry["tag_object_sha"]},
            }
            self.github[f"repos/{repository}/git/tags/{entry['tag_object_sha']}"] = {
                "sha": entry["tag_object_sha"],
                "tag": entry["tag"],
                "object": {"type": "commit", "sha": entry["peeled_commit_sha"]},
            }
            package = preflight.urllib.parse.quote(entry["package"], safe="")
            version = preflight.urllib.parse.quote(entry["version"], safe="")
            self.crates[f"crates/{package}/{version}"] = {
                "version": {
                    "num": entry["version"],
                    "yanked": False,
                    "checksum": digest,
                }
            }
            self.archives[(entry["package"], entry["version"])] = archive
        self.github[
            f"repos/{self.inventory['repository']}/releases?per_page=100"
        ] = releases

    def api(self) -> FakeApi:
        return FakeApi(self.github, self.crates, self.archives)


class LegacyReleaseTests(unittest.TestCase):
    def test_exact_legacy_inventory_is_accepted(self) -> None:
        fixture = Fixture()
        legacy.validate_inventory(fixture.inventory, fixture.api())

    def test_release_body_tag_and_archive_drift_fail(self) -> None:
        fixture = Fixture()
        entry = fixture.inventory["entries"][0]
        fixture.github[
            f"repos/{fixture.inventory['repository']}/releases/{entry['release_id']}"
        ]["body"] += " drift"
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())

        fixture = Fixture()
        entry = fixture.inventory["entries"][0]
        encoded = preflight.urllib.parse.quote(entry["tag"], safe="")
        fixture.github[
            f"repos/{fixture.inventory['repository']}/git/ref/tags/{encoded}"
        ]["object"]["sha"] = "f" * 40
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())

        fixture = Fixture()
        entry = fixture.inventory["entries"][0]
        fixture.archives[(entry["package"], entry["version"])] += b"drift"
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())

    def test_unpinned_release_must_be_immutable_app_authored_and_asset_free(self) -> None:
        fixture = Fixture()
        releases_path = f"repos/{fixture.inventory['repository']}/releases?per_page=100"
        prospective = {
            "id": 999,
            "tag_name": "future-v1.0.0",
            "target_commitish": "main",
            "author": copy.deepcopy(fixture.inventory["prospective_author"]),
            "draft": False,
            "immutable": False,
            "assets": [],
        }
        fixture.github[releases_path].append(prospective)
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())
        fixture.github[releases_path][-1]["immutable"] = True
        legacy.validate_inventory(fixture.inventory, fixture.api())
        fixture.github[releases_path][-1]["assets"] = [{"id": 1}]
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())

    def test_inventory_schema_rejects_unknown_fields(self) -> None:
        fixture = Fixture()
        fixture.inventory["unknown"] = True
        with self.assertRaises(preflight.PreflightError):
            legacy.validate_inventory(fixture.inventory, fixture.api())


if __name__ == "__main__":
    unittest.main()

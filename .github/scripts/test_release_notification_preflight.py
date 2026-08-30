#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the checkout-free release notification preflight."""

from __future__ import annotations

import copy
import io
import json
import tarfile
import unittest
from pathlib import Path
from typing import Any

import release_notification_preflight as preflight


class FakeApi:
    def __init__(self, github: dict[str, Any], crates: dict[str, Any], archives: dict[tuple[str, str], bytes]) -> None:
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
        if path not in self.crates:
            raise AssertionError(f"unexpected crates.io read: {path}")
        return copy.deepcopy(self.crates[path])

    def crate_archive(self, package: str, version: str) -> bytes:
        return self.archives[(package, version)]


def crate_archive(package: preflight.PackagePolicy, version: str, commit: str) -> bytes:
    vcs = preflight.canonical(
        {"git": {"sha1": commit}, "path_in_vcs": package.path_in_vcs}
    ).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo(f"{package.name}-{version}/.cargo_vcs_info.json")
        info.size = len(vcs)
        info.mode = 0o644
        info.mtime = 1_153_704_088
        archive.addfile(info, io.BytesIO(vcs))
        source = b"pub fn source_only_fixture() {}\n"
        info = tarfile.TarInfo(f"{package.name}-{version}/src/lib.rs")
        info.size = len(source)
        info.mode = 0o644
        info.mtime = 1_153_704_088
        archive.addfile(info, io.BytesIO(source))
    return output.getvalue()


class Fixture:
    def __init__(self) -> None:
        config = Path(__file__).parents[1] / "release-notification-policy.json"
        self.policy = preflight.parse_policy(
            preflight.read_json(config, preflight.MAX_CONFIG_BYTES, "test policy")
        )
        self.policy_sha = "d" * 40
        self.captured_sha = "a" * 40
        self.version = "0.9.0-rc.1"
        self.archives: dict[tuple[str, str], bytes] = {}
        plan_packages: list[dict[str, Any]] = []
        intent_tags: list[dict[str, Any]] = []
        releases: list[dict[str, Any]] = []
        self.github: dict[str, Any] = {
            f"repos/{self.policy.repository}": {
                "full_name": self.policy.repository,
                "default_branch": self.policy.default_branch,
                "extra": True,
            },
            f"repos/{self.policy.repository}/git/ref/heads/{self.policy.default_branch}": {
                "ref": f"refs/heads/{self.policy.default_branch}",
                "object": {"type": "commit", "sha": self.policy_sha},
            },
            f"users/{preflight.urllib.parse.quote(self.policy.sender_login, safe='')}": {
                "id": self.policy.sender_id,
                "login": self.policy.sender_login,
                "type": "Bot",
            },
            f"repos/{self.policy.repository}/pulls?state=open&head={preflight.urllib.parse.quote(f'{self.policy.repository.split('/', 1)[0]}:{self.policy.release_branch}', safe='')}&per_page=100": [],
        }
        self.crates: dict[str, Any] = {}
        for index, package in enumerate(self.policy.packages):
            archive = crate_archive(package, self.version, self.captured_sha)
            digest = preflight.sha256(archive)
            inventory_digest = preflight.inspect_archive(
                archive,
                package,
                self.version,
                self.captured_sha,
            )
            self.archives[(package.name, self.version)] = archive
            body = f"### Changes\n\n- Source-only notes for {package.name}."
            body_digest = preflight.sha256(body.encode())
            tag = f"{package.tag_prefix}{self.version}"
            tag_object = f"{index + 1:040x}"
            plan_packages.append(
                {
                    "package": package.name,
                    "version": self.version,
                    "tag": tag,
                    "prerelease": True,
                    "source_archive_sha256": digest,
                    "package_inventory_sha256": inventory_digest,
                    "release_body": body,
                    "release_body_sha256": body_digest,
                    "registry": {"state": "absent", "checksum": None},
                }
            )
            message = f"chore: Release package {package.name} version {self.version}"
            intent_tags.append(
                {
                    "package": package.name,
                    "tag": tag,
                    "tag_object_id": tag_object,
                    "tag_message": message,
                    "release_body_sha256": body_digest,
                }
            )
            release_id = 1000 + index
            releases.append(
                {
                    "package": package.name,
                    "version": self.version,
                    "release_id": release_id,
                    "tag": tag,
                    "tag_object_id": tag_object,
                    "release_body_sha256": body_digest,
                }
            )
            release = {
                "id": release_id,
                "tag_name": tag,
                "target_commitish": self.policy.default_branch,
                "name": tag,
                "body": body,
                "draft": False,
                "prerelease": True,
                "immutable": True,
                "author": {
                    "id": self.policy.sender_id,
                    "login": self.policy.sender_login,
                    "type": "Bot",
                },
                "assets": [],
            }
            self.github[f"repos/{self.policy.repository}/releases/{release_id}"] = release
            self.github[
                f"repos/{self.policy.repository}/releases/tags/{preflight.urllib.parse.quote(tag, safe='')}"
            ] = release
            self.github[
                f"repos/{self.policy.repository}/git/ref/tags/{preflight.urllib.parse.quote(tag, safe='')}"
            ] = {
                "ref": f"refs/tags/{tag}",
                "object": {"type": "tag", "sha": tag_object},
            }
            self.github[f"repos/{self.policy.repository}/git/tags/{tag_object}"] = {
                "sha": tag_object,
                "tag": tag,
                "message": message,
                "tagger": {
                    "name": self.policy.sender_login,
                    "email": self.policy.app_email,
                    "date": "2026-08-28T12:00:00Z",
                },
                "object": {"type": "commit", "sha": self.captured_sha},
            }
            self.crates[
                f"crates/{preflight.urllib.parse.quote(package.name, safe='')}/{preflight.urllib.parse.quote(self.version, safe='')}"
            ] = {
                "version": {
                    "num": self.version,
                    "yanked": False,
                    "checksum": digest,
                    "extra": "ignored",
                },
                "meta": {},
            }
        self.plan = {
            "schema_version": 1,
            "repository": self.policy.repository,
            "release_sha": self.captured_sha,
            "authorization": {
                "pull_request": 50,
                "proposal_commit": "b" * 40,
                "base_commit": "c" * 40,
                "owner_id": 11,
                "merger_id": 12,
            },
            "release_plz_version": "0.3.160",
            "release_config_sha256": "3" * 64,
            "publish_workflow_sha256": "4" * 64,
            "proposal_workflow_sha256": "5" * 64,
            "tagger_epoch": 1_777_777_777,
            "tagger_date": "2026-05-02T00:29:37+00:00",
            "packages": plan_packages,
        }
        self.plan_digest = preflight.sha256(preflight.canonical(self.plan).encode())
        self.intent = {
            "schema_version": 1,
            "repository": self.policy.repository,
            "release_sha": self.captured_sha,
            "plan_digest": self.plan_digest,
            "external_id": "6" * 64,
            "origin_run_id": 100,
            "origin_run_attempt": 1,
            "ruleset_evidence_sha256": preflight.settings_evidence_sha256(
                self.policy.repository,
                self.captured_sha,
                100,
                1,
            ),
            "plan": self.plan,
            "tags": intent_tags,
        }
        self.payload = {
            "schema_version": 1,
            "repository": self.policy.repository,
            "captured_sha": self.captured_sha,
            "release_plan_digest": self.plan_digest,
            "intent_check_id": 900,
            "intent_external_id": "6" * 64,
            "releases": releases,
        }
        self.event = {
            "action": preflight.EVENT_TYPE,
            "sender": {
                "id": self.policy.sender_id,
                "login": self.policy.sender_login,
                "type": "Bot",
            },
            "repository": {
                "full_name": self.policy.repository,
                "default_branch": self.policy.default_branch,
            },
            "client_payload": self.payload,
        }
        self.github[f"repos/{self.policy.repository}/check-runs/900"] = {
            "id": 900,
            "name": preflight.INTENT_NAME,
            "head_sha": self.captured_sha,
            "external_id": "6" * 64,
            "status": "completed",
            "conclusion": "success",
            "app": {"id": self.policy.app_id, "slug": self.policy.app_slug, "extra": True},
            "output": {"title": preflight.INTENT_TITLE, "summary": preflight.canonical(self.intent), "text": None},
            "extra": True,
        }
        self.github[f"repos/{self.policy.repository}/actions/runs/100"] = {
            "id": 100,
            "run_attempt": 1,
            "head_sha": self.captured_sha,
            "head_branch": self.policy.default_branch,
            "event": "workflow_dispatch",
            "path": ".github/workflows/publish.yml",
            "status": "in_progress",
            "conclusion": None,
            "repository": {"full_name": self.policy.repository},
        }

    def api(self) -> FakeApi:
        return FakeApi(self.github, self.crates, self.archives)

    def validate(self) -> dict[str, str]:
        return preflight.validate_event(
            self.event,
            self.policy,
            self.api(),
            self.policy.repository,
            self.policy_sha,
        )


class PreflightTests(unittest.TestCase):
    def test_complete_release_train_is_accepted(self) -> None:
        outputs = Fixture().validate()
        self.assertEqual(outputs["authorized"], "true")
        self.assertEqual(outputs["replay_state"], "new")
        self.assertRegex(outputs["replay_key"], r"^[0-9a-f]{64}$")

    def test_legacy_unknown_missing_wrong_version_and_oversized_payloads_fail(self) -> None:
        mutations = [
            lambda fixture: fixture.event.__setitem__("client_payload", {"version": "0.9.0"}),
            lambda fixture: fixture.payload.__setitem__("unknown", True),
            lambda fixture: fixture.payload.pop("intent_check_id"),
            lambda fixture: fixture.payload.__setitem__("schema_version", 2),
            lambda fixture: fixture.payload.__setitem__("repository", "x" * preflight.MAX_NOTIFICATION_BYTES),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = Fixture()
                mutate(fixture)
                with self.assertRaises(preflight.PreflightError):
                    fixture.validate()

    def test_wrong_sender_or_intent_app_fails(self) -> None:
        fixture = Fixture()
        fixture.event["sender"]["id"] += 1
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()
        fixture = Fixture()
        fixture.github[f"repos/{fixture.policy.repository}/check-runs/900"]["app"]["id"] += 1
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()

    def test_partial_duplicate_and_reordered_release_sets_fail(self) -> None:
        fixture = Fixture()
        fixture.payload["releases"] = fixture.payload["releases"][:-1]
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()
        fixture = Fixture()
        fixture.payload["releases"] = fixture.payload["releases"] + [copy.deepcopy(fixture.payload["releases"][0])]
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()
        fixture = Fixture()
        if len(fixture.payload["releases"]) > 1:
            fixture.payload["releases"].reverse()
            with self.assertRaises(preflight.PreflightError):
                fixture.validate()

    def test_mutable_or_asset_bearing_release_fails(self) -> None:
        fixture = Fixture()
        release_id = fixture.payload["releases"][0]["release_id"]
        fixture.github[f"repos/{fixture.policy.repository}/releases/{release_id}"]["immutable"] = False
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()
        fixture = Fixture()
        release_id = fixture.payload["releases"][0]["release_id"]
        fixture.github[f"repos/{fixture.policy.repository}/releases/{release_id}"]["assets"] = [{"id": 1}]
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()

    def test_plan_intent_registry_and_archive_drift_fail(self) -> None:
        fixture = Fixture()
        check = fixture.github[f"repos/{fixture.policy.repository}/check-runs/900"]
        altered = copy.deepcopy(fixture.intent)
        altered["unknown"] = True
        check["output"]["summary"] = preflight.canonical(altered)
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()

    def test_origin_run_and_recomputed_evidence_are_required(self) -> None:
        fixture = Fixture()
        fixture.github[f"repos/{fixture.policy.repository}/actions/runs/100"][
            "run_attempt"
        ] = 2
        with self.assertRaisesRegex(preflight.PreflightError, "originating workflow"):
            fixture.validate()

        fixture = Fixture()
        fixture.intent["ruleset_evidence_sha256"] = "0" * 64
        fixture.github[f"repos/{fixture.policy.repository}/check-runs/900"]["output"][
            "summary"
        ] = preflight.canonical(fixture.intent)
        with self.assertRaisesRegex(preflight.PreflightError, "ruleset evidence"):
            fixture.validate()

    def test_recomputed_archive_inventory_is_required(self) -> None:
        fixture = Fixture()
        fixture.plan["packages"][0]["package_inventory_sha256"] = "0" * 64
        fixture.plan_digest = preflight.sha256(preflight.canonical(fixture.plan).encode())
        fixture.intent["plan_digest"] = fixture.plan_digest
        fixture.payload["release_plan_digest"] = fixture.plan_digest
        fixture.github[f"repos/{fixture.policy.repository}/check-runs/900"]["output"][
            "summary"
        ] = preflight.canonical(fixture.intent)
        with self.assertRaisesRegex(preflight.PreflightError, "crate inventory"):
            fixture.validate()

    def test_release_source_authority_is_the_exact_attested_tag(self) -> None:
        fixture = Fixture()
        release_id = fixture.payload["releases"][0]["release_id"]
        fixture.github[f"repos/{fixture.policy.repository}/releases/{release_id}"][
            "target_commitish"
        ] = "a-non-authoritative-response-field"
        self.assertEqual(fixture.validate()["authorized"], "true")

        fixture = Fixture()
        tag_object = fixture.payload["releases"][0]["tag_object_id"]
        fixture.github[f"repos/{fixture.policy.repository}/git/tags/{tag_object}"]["object"][
            "sha"
        ] = "e" * 40
        with self.assertRaisesRegex(preflight.PreflightError, "attested App object"):
            fixture.validate()

    def test_archive_vcs_metadata_is_closed_and_commit_bound(self) -> None:
        fixture = Fixture()
        package = fixture.policy.packages[0]
        archive = crate_archive(package, fixture.version, "e" * 40)
        with self.assertRaisesRegex(preflight.PreflightError, "VCS commit"):
            preflight.inspect_archive(
                archive,
                package,
                fixture.version,
                fixture.captured_sha,
            )

        malformed = io.BytesIO()
        vcs = preflight.canonical({"git": "not-an-object", "path_in_vcs": package.path_in_vcs}).encode()
        with tarfile.open(
            fileobj=malformed,
            mode="w:gz",
            format=tarfile.GNU_FORMAT,
        ) as cargo:
            info = tarfile.TarInfo(
                f"{package.name}-{fixture.version}/.cargo_vcs_info.json"
            )
            info.size = len(vcs)
            info.mode = 0o644
            info.mtime = 1_153_704_088
            cargo.addfile(info, io.BytesIO(vcs))
        with self.assertRaisesRegex(preflight.PreflightError, "VCS commit"):
            preflight.inspect_archive(
                malformed.getvalue(),
                package,
                fixture.version,
                fixture.captured_sha,
            )
        fixture = Fixture()
        crate_path = next(iter(fixture.crates))
        fixture.crates[crate_path]["version"]["checksum"] = "8" * 64
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()
        fixture = Fixture()
        package_version = next(iter(fixture.archives))
        fixture.archives[package_version] = crate_archive(
            fixture.policy.packages[0], fixture.version, "e" * 40
        )
        with self.assertRaises(preflight.PreflightError):
            fixture.validate()

    def test_consumed_replay_fails_and_abandoned_branch_recovers(self) -> None:
        fixture = Fixture()
        key = fixture.validate()["replay_key"]
        branch_path = f"repos/{fixture.policy.repository}/git/ref/heads/{fixture.policy.release_branch}"
        commit_sha = "e" * 40
        pulls_path = next(path for path in fixture.github if "/pulls?state=open&head=" in path)
        fixture.github[branch_path] = {
            "ref": f"refs/heads/{fixture.policy.release_branch}",
            "object": {"type": "commit", "sha": commit_sha},
        }
        fixture.github[f"repos/{fixture.policy.repository}/commits/{commit_sha}"] = {
            "commit": {"message": f"proposal\n\n{preflight.REPLAY_TRAILER}{key}"}
        }
        fixture.github[pulls_path] = [
            {"body": f"proposal\n\n{preflight.REPLAY_COMMENT.format(key)}"}
        ]
        with self.assertRaisesRegex(preflight.PreflightError, "durably consumed"):
            fixture.validate()
        fixture.github[pulls_path] = []
        fixture.github[
            f"repos/{fixture.policy.repository}/compare/{fixture.policy.default_branch}...{fixture.policy.release_branch}"
        ] = {"ahead_by": 1}
        self.assertEqual(fixture.validate()["replay_state"], "recover")


if __name__ == "__main__":
    unittest.main()

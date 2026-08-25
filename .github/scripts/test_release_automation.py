#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for hosted release automation."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent.parent
IS_RS_REPOSITORY = (REPOSITORY_ROOT / "crates" / "yaml-sigil-core").is_dir()
EXPECTED_REPOSITORY = (
    "NVIDIA/yaml-sigil-rs" if IS_RS_REPOSITORY else "NVIDIA/yaml-sigil-traits"
)
BASELINE_PATH = SCRIPT_DIR / "prepare_release_baseline.py"
UPDATE_PR_PATH = SCRIPT_DIR / "update-release-pull-request.sh"
RECONCILE_PATH = SCRIPT_DIR / "reconcile_release_objects.py"
CONFIGURE_GIT_PATH = SCRIPT_DIR / "configure-release-git-user.sh"
RESOLVE_INTENT_PATH = SCRIPT_DIR / "resolve-release-intent.sh"
GENERATE_PROPOSAL_PATH = SCRIPT_DIR / "generate-release-proposal.sh"
SOURCE_AUTHORIZATION_PATH = SCRIPT_DIR / "verify_release_publication_source.py"
VERIFY_TRAITS_PATH = SCRIPT_DIR / "verify-release-traits.sh"
SPEC = importlib.util.spec_from_file_location("prepare_release_baseline", BASELINE_PATH)
assert SPEC is not None and SPEC.loader is not None
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)
RECONCILE_SPEC = importlib.util.spec_from_file_location(
    "reconcile_release_objects", RECONCILE_PATH
)
assert RECONCILE_SPEC is not None and RECONCILE_SPEC.loader is not None
RECONCILE = importlib.util.module_from_spec(RECONCILE_SPEC)
sys.modules[RECONCILE_SPEC.name] = RECONCILE
RECONCILE_SPEC.loader.exec_module(RECONCILE)
SOURCE_AUTHORIZATION_SPEC = importlib.util.spec_from_file_location(
    "verify_release_publication_source", SOURCE_AUTHORIZATION_PATH
)
assert SOURCE_AUTHORIZATION_SPEC is not None and SOURCE_AUTHORIZATION_SPEC.loader is not None
SOURCE_AUTHORIZATION = importlib.util.module_from_spec(SOURCE_AUTHORIZATION_SPEC)
SOURCE_AUTHORIZATION_SPEC.loader.exec_module(SOURCE_AUTHORIZATION)


def command(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


WORKFLOW_MAPPING_ENTRY = re.compile(
    r'''^(?P<indent> *)(?:(?P<plain>[A-Za-z0-9_-]+)|'''
    r'''['](?P<single>[A-Za-z0-9_-]+)[']|"(?P<double>[A-Za-z0-9_-]+)")'''
    r'''(?P<separator>:(?:\s.*)?)$'''
)


def workflow_mapping_entry(line: str) -> tuple[int, str, str] | None:
    """Parse the restricted workflow mapping keys used by these regressions."""

    match = WORKFLOW_MAPPING_ENTRY.fullmatch(line)
    if match is None:
        return None
    key = match.group("plain") or match.group("single") or match.group("double")
    return len(match.group("indent")), key, match.group("separator")


def workflow_mapping_starts_block(entry: tuple[int, str, str]) -> bool:
    """Return whether an entry has no value other than an optional comment."""

    value = entry[2][1:].strip()
    return not value or value.startswith("#")


def workflow_block(lines: list[str], path: tuple[str, ...]) -> tuple[int, int, int]:
    """Locate one exact block-style workflow mapping path."""

    start = 0
    end = len(lines)
    indent = 0
    for key in path:
        matches = [
            index
            for index in range(start, end)
            if (entry := workflow_mapping_entry(lines[index])) is not None
            and entry[0] == indent
            and entry[1] == key
            and workflow_mapping_starts_block(entry)
        ]
        if len(matches) != 1:
            raise AssertionError(f"workflow path {'/'.join(path)} is not exact")
        item = matches[0]
        block_end = end
        for index in range(item + 1, end):
            line = lines[index]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            leading = len(line) - len(line.lstrip(" "))
            if leading <= indent:
                block_end = index
                break
        start = item + 1
        end = block_end
        indent += 2
    return start, end, indent


def workflow_direct_keys(lines: list[str], path: tuple[str, ...]) -> list[str]:
    start, end, indent = workflow_block(lines, path)
    return [
        entry[1]
        for line in lines[start:end]
        if (entry := workflow_mapping_entry(line)) is not None
        and entry[0] == indent
    ]


def workflow_oidc_locations(bodies: dict[str, str]) -> list[tuple[str, str | None]]:
    locations: list[tuple[str, str | None]] = []
    for name, body in bodies.items():
        lines = body.splitlines()
        jobs = workflow_direct_keys(lines, ("jobs",))
        job_blocks = [
            (job, *workflow_block(lines, ("jobs", job))) for job in jobs
        ]
        for index, line in enumerate(lines):
            id_token_write = re.search(
                r'''(?:^|[ {])(?:id-token|[']id-token[']|"id-token"):\s*'''
                r'''(?:write|[']write[']|"write")(?:$|[ },])''',
                line,
            ) is not None
            owner = None
            owner_indent = None
            for job, start, end, indent in job_blocks:
                if start <= index < end:
                    owner = job
                    owner_indent = indent
                    break
            entry = workflow_mapping_entry(line)
            write_all = False
            if entry is not None and entry[1] == "permissions":
                value = entry[2][1:].strip()
                value = value.split("#", 1)[0].rstrip()
                write_all = value in {"write-all", "'write-all'", '"write-all"'}
                write_all = write_all and (
                    (owner is None and entry[0] == 0)
                    or (owner is not None and entry[0] == owner_indent)
                )
            if not id_token_write and not write_all:
                continue
            locations.append((name, owner))
    return locations


class GitFixture:
    def __init__(
        self,
        repository: str,
        *,
        lightweight: bool = False,
        mismatched_workspace_tags: bool = False,
        nonancestor: bool = False,
        higher_snapshot: bool = False,
        current_version: str = "0.4.0-rc.1",
    ) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-baseline-")
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        self.source = self.root / "source"
        self.checkout = self.root / "checkout"
        self.output = self.root / "baseline"
        self.repository = repository
        self.version = "0.4.0-rc.1"
        command("git", "init", "--bare", "--initial-branch=main", str(self.remote), cwd=self.root)
        command("git", "init", "--initial-branch=main", str(self.source), cwd=self.root)
        command("git", "config", "user.name", "Release Test", cwd=self.source)
        command("git", "config", "user.email", "release-test@example.com", cwd=self.source)
        self.write_commit("version = \"0.4.0-rc.1\"\n", "baseline")
        baseline = command("git", "rev-parse", "HEAD", cwd=self.source).stdout.strip()

        if nonancestor:
            command("git", "switch", "--orphan", "tag-source", cwd=self.source)
            self.write_commit("version = \"0.4.0-rc.1\"\n", "unrelated baseline")

        tags = tuple(
            template.format(version=self.version)
            for template in BASELINE.REPOSITORY_TAGS[repository]
        )
        for index, tag in enumerate(tags):
            if mismatched_workspace_tags and index == len(tags) - 1:
                self.write_commit("version = \"0.4.0-rc.1\"\n# split\n", "split tag")
            tag_args = ("git", "tag", tag) if lightweight else (
                "git",
                "tag",
                "-a",
                tag,
                "-m",
                f"Release {tag}",
            )
            command(*tag_args, cwd=self.source)

        if nonancestor:
            command("git", "switch", "main", cwd=self.source)
            self.write_commit("version = \"0.4.0-rc.1\"\n# main\n", "main work")
        elif not mismatched_workspace_tags:
            self.write_commit(
                f'version = "{current_version}"\n# current\n', "current main"
            )

        if higher_snapshot:
            snapshot_tag = "v99.0.0-0.pr.99.commit.sha0123456789ab"
            if repository == "NVIDIA/yaml-sigil-rs":
                snapshot_tag = (
                    "yaml-sigil-core-v99.0.0-0.pr.99.commit.sha0123456789ab"
                )
            command(
                "git",
                "tag",
                "-a",
                snapshot_tag,
                "-m",
                "Unrelated snapshot marker",
                cwd=self.source,
            )

        command("git", "remote", "add", "origin", str(self.remote), cwd=self.source)
        command("git", "push", "origin", "main", cwd=self.source)
        command("git", "push", "origin", "--tags", cwd=self.source)
        command("git", "clone", str(self.remote), str(self.checkout), cwd=self.root)
        command(
            "git",
            "config",
            "remote.origin.pushurl",
            BASELINE.READ_ONLY_PUSH_URL,
            cwd=self.checkout,
        )
        self.head = command("git", "rev-parse", "HEAD", cwd=self.checkout).stdout.strip()
        self.baseline = baseline

    def write_commit(self, contents: str, message: str) -> None:
        section = (
            "[package]"
            if self.repository == "NVIDIA/yaml-sigil-traits"
            else "[workspace.package]"
        )
        contents = f"{section}\n{contents}"
        (self.source / "Cargo.toml").write_text(contents, encoding="utf-8")
        command("git", "add", "Cargo.toml", cwd=self.source)
        command("git", "commit", "-m", message, cwd=self.source)

    def prepare(self) -> tuple[str, Path, tuple[str, ...]]:
        return BASELINE.prepare_baseline(
            self.checkout,
            self.repository,
            self.version,
            self.head,
            self.output,
            str(self.remote),
            BASELINE.READ_ONLY_PUSH_URL,
        )

    def close(self) -> None:
        self.temporary.cleanup()


class ReleaseBaselineTests(unittest.TestCase):
    def test_cli_reports_the_discovered_baseline_version(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        github_output = fixture.root / "github-output"
        environment = os.environ.copy()
        environment["GITHUB_OUTPUT"] = str(github_output)
        result = subprocess.run(
            [
                "python3",
                str(BASELINE_PATH),
                "--root",
                str(fixture.checkout),
                "--repository",
                fixture.repository,
                "--head",
                fixture.head,
                "--output",
                str(fixture.root / "cli-baseline"),
                "--expected-fetch-url",
                str(fixture.remote),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"version={fixture.version}\n",
            github_output.read_text(encoding="utf-8"),
        )
        inventory_line = next(
            line
            for line in github_output.read_text(encoding="utf-8").splitlines()
            if line.startswith("inventory=")
        )
        snapshot = Path(inventory_line.removeprefix("inventory="))
        parsed = BASELINE.parse_inventory_snapshot(snapshot)
        self.assertEqual(parsed["repository"], fixture.repository)
        self.assertEqual(parsed["head"], fixture.head)

        verified = subprocess.run(
            [
                "python3",
                str(BASELINE_PATH),
                "--root",
                str(fixture.checkout),
                "--repository",
                fixture.repository,
                "--head",
                fixture.head,
                "--verify-inventory",
                str(snapshot),
                "--expected-fetch-url",
                str(fixture.remote),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_inventory_snapshot_rejects_schema_and_normalization_changes(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        snapshot = fixture.root / "official-tags.json"
        BASELINE.prepare_baseline(
            fixture.checkout,
            fixture.repository,
            fixture.version,
            fixture.head,
            fixture.output,
            str(fixture.remote),
            BASELINE.READ_ONLY_PUSH_URL,
            inventory_output=snapshot,
        )
        value = json.loads(snapshot.read_text(encoding="utf-8"))
        value["unexpected"] = True
        snapshot.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(BASELINE.BaselineError, "invalid schema"):
            BASELINE.verify_inventory_snapshot(
                fixture.checkout,
                fixture.repository,
                fixture.head,
                str(fixture.remote),
                BASELINE.READ_ONLY_PUSH_URL,
                snapshot,
            )

    def test_inventory_snapshot_detects_a_post_analysis_tag_race(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        snapshot = fixture.root / "official-tags.json"
        BASELINE.prepare_baseline(
            fixture.checkout,
            fixture.repository,
            fixture.version,
            fixture.head,
            fixture.output,
            str(fixture.remote),
            BASELINE.READ_ONLY_PUSH_URL,
            inventory_output=snapshot,
        )
        tag = "v0.4.1-rc.1"
        command(
            "git", "tag", "-a", tag, "-m", f"Release {tag}", fixture.head,
            cwd=fixture.source,
        )
        command("git", "push", "origin", tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        with self.assertRaisesRegex(BASELINE.BaselineError, "changed after release analysis"):
            BASELINE.verify_inventory_snapshot(
                fixture.checkout,
                fixture.repository,
                fixture.head,
                str(fixture.remote),
                BASELINE.READ_ONLY_PUSH_URL,
                snapshot,
            )

    def test_merge_base_operational_error_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        original = BASELINE.git

        def fail_merge(root: Path, *args: str, check: bool = True):
            if args[:2] == ("merge-base", "--is-ancestor"):
                return subprocess.CompletedProcess(args, 2, "", "fixture failure")
            return original(root, *args, check=check)

        with mock.patch.object(BASELINE, "git", fail_merge):
            with self.assertRaisesRegex(BASELINE.BaselineError, "merge-base.*failed"):
                BASELINE.last_official_version(
                    fixture.checkout, fixture.repository, fixture.head
                )

    def test_traits_discovers_unique_last_official_version(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits", higher_snapshot=True)
        self.addCleanup(fixture.close)
        version, commit = BASELINE.last_official_version(
            fixture.checkout,
            fixture.repository,
            fixture.head,
        )
        self.assertEqual((version, commit), (fixture.version, fixture.baseline))

    def test_publication_retry_excludes_the_candidate_tag(self) -> None:
        candidate_version = "0.4.1-rc.1"
        fixture = GitFixture(
            "NVIDIA/yaml-sigil-traits", current_version=candidate_version
        )
        self.addCleanup(fixture.close)
        candidate_tag = f"v{candidate_version}"
        command(
            "git",
            "tag",
            "-a",
            candidate_tag,
            "-m",
            f"Release {candidate_tag}",
            fixture.head,
            cwd=fixture.source,
        )
        command("git", "push", "origin", candidate_tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        self.assertEqual(
            BASELINE.last_official_version(
                fixture.checkout,
                fixture.repository,
                fixture.head,
            ),
            (candidate_version, fixture.head),
        )
        self.assertEqual(
            BASELINE.last_official_version(
                fixture.checkout,
                fixture.repository,
                fixture.head,
                candidate_version,
            ),
            (fixture.version, fixture.baseline),
        )
        commit, _, _ = BASELINE.prepare_baseline(
            fixture.checkout,
            fixture.repository,
            fixture.version,
            fixture.head,
            fixture.output,
            str(fixture.remote),
            BASELINE.READ_ONLY_PUSH_URL,
            candidate_version,
        )
        self.assertEqual(commit, fixture.baseline)

    def test_retry_exclusion_rejects_a_candidate_tag_away_from_main(self) -> None:
        candidate_version = "0.4.1-rc.1"
        fixture = GitFixture(
            "NVIDIA/yaml-sigil-traits", current_version=candidate_version
        )
        self.addCleanup(fixture.close)
        candidate_tag = f"v{candidate_version}"
        command(
            "git",
            "tag",
            "-a",
            candidate_tag,
            "-m",
            f"Release {candidate_tag}",
            fixture.baseline,
            cwd=fixture.source,
        )
        command("git", "push", "origin", candidate_tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        with self.assertRaisesRegex(BASELINE.BaselineError, "exact current main"):
            BASELINE.prepare_baseline(
                fixture.checkout,
                fixture.repository,
                fixture.version,
                fixture.head,
                fixture.output,
                str(fixture.remote),
                BASELINE.READ_ONLY_PUSH_URL,
                candidate_version,
            )

    def test_workspace_retry_exclusion_allows_an_exact_current_tag_subset(self) -> None:
        candidate_version = "0.4.1-rc.1"
        fixture = GitFixture(
            "NVIDIA/yaml-sigil-rs", current_version=candidate_version
        )
        self.addCleanup(fixture.close)
        tag = f"yaml-sigil-core-v{candidate_version}"
        command(
            "git", "tag", "-a", tag, "-m", f"Release {tag}", fixture.head,
            cwd=fixture.source,
        )
        command("git", "push", "origin", tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        commit, _, tags = BASELINE.prepare_baseline(
            fixture.checkout,
            fixture.repository,
            fixture.version,
            fixture.head,
            fixture.output,
            str(fixture.remote),
            BASELINE.READ_ONLY_PUSH_URL,
            candidate_version,
        )
        self.assertEqual(commit, fixture.baseline)
        self.assertEqual(len(tags), 4)

    def test_workspace_retry_exclusion_rejects_a_partial_tag_away_from_main(self) -> None:
        candidate_version = "0.4.1-rc.1"
        fixture = GitFixture(
            "NVIDIA/yaml-sigil-rs", current_version=candidate_version
        )
        self.addCleanup(fixture.close)
        tag = f"yaml-sigil-core-v{candidate_version}"
        command(
            "git", "tag", "-a", tag, "-m", f"Release {tag}", fixture.baseline,
            cwd=fixture.source,
        )
        command("git", "push", "origin", tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        with self.assertRaisesRegex(BASELINE.BaselineError, "exact current main"):
            BASELINE.prepare_baseline(
                fixture.checkout,
                fixture.repository,
                fixture.version,
                fixture.head,
                fixture.output,
                str(fixture.remote),
                BASELINE.READ_ONLY_PUSH_URL,
                candidate_version,
            )

    def test_retry_exclusion_must_match_the_current_manifest(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        with self.assertRaisesRegex(BASELINE.BaselineError, "current main"):
            BASELINE.prepare_baseline(
                fixture.checkout,
                fixture.repository,
                fixture.version,
                fixture.head,
                fixture.output,
                str(fixture.remote),
                BASELINE.READ_ONLY_PUSH_URL,
                "0.4.1-rc.1",
            )

    def test_unfetched_remote_official_tag_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        tag = "v0.4.1-rc.1"
        command(
            "git", "tag", "-a", tag, "-m", f"Release {tag}", fixture.head,
            cwd=fixture.source,
        )
        command("git", "push", "origin", tag, cwd=fixture.source)
        with self.assertRaisesRegex(BASELINE.BaselineError, "inventory differs"):
            fixture.prepare()

    def test_remote_tag_race_fails_after_baseline_extraction(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        original = BASELINE.remote_official_tag_inventory
        calls = 0

        def race(root: Path, repository: str) -> dict[str, tuple[str, str]]:
            nonlocal calls
            inventory = original(root, repository)
            calls += 1
            if calls == 1:
                tag = "v0.4.1-rc.1"
                command(
                    "git",
                    "tag",
                    "-a",
                    tag,
                    "-m",
                    f"Release {tag}",
                    fixture.head,
                    cwd=fixture.source,
                )
                command("git", "push", "origin", tag, cwd=fixture.source)
            return inventory

        with mock.patch.object(BASELINE, "remote_official_tag_inventory", race):
            with self.assertRaisesRegex(BASELINE.BaselineError, "inventory differs"):
                fixture.prepare()

    def test_traits_uses_tagged_commit_and_ignores_snapshot_marker(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits", higher_snapshot=True)
        self.addCleanup(fixture.close)
        commit, manifest, tags = fixture.prepare()
        self.assertEqual(commit, fixture.baseline)
        self.assertEqual(manifest.parent, fixture.output)
        self.assertEqual(tags, ("v0.4.0-rc.1",))

    def test_workspace_requires_all_tags_at_one_commit(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs")
        self.addCleanup(fixture.close)
        commit, _, tags = fixture.prepare()
        self.assertEqual(commit, fixture.baseline)
        self.assertEqual(len(tags), 4)

    def test_workspace_ignores_higher_unofficial_snapshot_marker(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs", higher_snapshot=True)
        self.addCleanup(fixture.close)
        commit, _, _ = fixture.prepare()
        self.assertEqual(commit, fixture.baseline)

    def test_workspace_rejects_an_older_mismatched_official_tag_group(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs")
        self.addCleanup(fixture.close)
        prefixes = ("core", "transcription", "signing", "verification")
        for index, prefix in enumerate(prefixes):
            target = fixture.baseline if index < 2 else fixture.head
            tag = f"yaml-sigil-{prefix}-v0.3.0-rc.1"
            command("git", "tag", "-a", tag, "-m", f"Release {tag}", target, cwd=fixture.source)
        command("git", "push", "origin", "--tags", cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        with self.assertRaisesRegex(BASELINE.BaselineError, "different commits"):
            fixture.prepare()

    def test_workspace_accepts_only_strictly_superseded_legacy_split_tags(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs")
        self.addCleanup(fixture.close)
        prefixes = ("core", "transcription", "signing", "verification")
        for index, prefix in enumerate(prefixes):
            target = fixture.baseline if index < 2 else fixture.head
            tag = f"yaml-sigil-{prefix}-v0.3.0-rc.1"
            command(
                "git", "tag", "-a", tag, "-m", f"Release {tag}", target,
                cwd=fixture.source,
            )
        fixture.write_commit('version = "0.5.0-rc.1"\n', "later synchronized release")
        later = command("git", "rev-parse", "HEAD", cwd=fixture.source).stdout.strip()
        for prefix in prefixes:
            tag = f"yaml-sigil-{prefix}-v0.5.0-rc.1"
            command("git", "tag", "-a", tag, "-m", f"Release {tag}", cwd=fixture.source)
        command("git", "push", "origin", "main", "--tags", cwd=fixture.source)
        command("git", "fetch", "origin", "main", "--tags", cwd=fixture.checkout)
        command("git", "checkout", "--detach", later, cwd=fixture.checkout)
        self.assertEqual(
            BASELINE.last_official_version(
                fixture.checkout, fixture.repository, later
            ),
            ("0.5.0-rc.1", later),
        )

    def test_workspace_rejects_newer_split_tags_even_when_ancestry_matches(self) -> None:
        older = "1" * 40
        newer = "2" * 40
        valid = "3" * 40
        with mock.patch.object(BASELINE, "is_ancestor", return_value=True):
            with self.assertRaisesRegex(BASELINE.BaselineError, "different commits"):
                BASELINE.require_selected_baseline_supersedes_split_tags(
                    Path("."), {"0.5.0-rc.1": {older, newer}}, "0.4.0-rc.1", valid
                )

    def test_workspace_split_tolerance_binds_the_selected_nearest_baseline(self) -> None:
        versions = {
            "0.6.0-rc.1": "3" * 40,
            "0.4.0-rc.1": "4" * 40,
        }
        mismatched = {"0.5.0-rc.1": {"1" * 40, "2" * 40}}

        def rev_list(
            root: Path, *args: str, check: bool = True
        ) -> subprocess.CompletedProcess[str]:
            self.assertEqual(args[:2], ("rev-list", "--count"))
            distance = "10" if args[2].startswith("3" * 40) else "1"
            return subprocess.CompletedProcess(args, 0, distance, "")

        with (
            mock.patch.object(
                BASELINE,
                "classified_official_tag_versions",
                return_value=(versions, mismatched),
            ),
            mock.patch.object(BASELINE, "git", rev_list),
            mock.patch.object(BASELINE, "is_ancestor", return_value=True),
            self.assertRaisesRegex(BASELINE.BaselineError, "different commits"),
        ):
            BASELINE.last_official_version(
                Path("."), "NVIDIA/yaml-sigil-rs", "f" * 40, inventory={}
            )

    def test_workspace_rejects_a_partial_official_tag_group(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs")
        self.addCleanup(fixture.close)
        tag = "yaml-sigil-core-v0.3.0-rc.1"
        command(
            "git", "tag", "-a", tag, "-m", f"Release {tag}", fixture.baseline,
            cwd=fixture.source,
        )
        command("git", "push", "origin", tag, cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        with self.assertRaisesRegex(BASELINE.BaselineError, "incomplete official tag set"):
            fixture.prepare()

    def test_workspace_filters_a_complete_nonancestor_official_tag_group(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs")
        self.addCleanup(fixture.close)
        command("git", "switch", "--orphan", "older-unrelated", cwd=fixture.source)
        fixture.write_commit("version = \"0.3.0-rc.1\"\n", "unrelated release")
        for prefix in ("core", "transcription", "signing", "verification"):
            tag = f"yaml-sigil-{prefix}-v0.3.0-rc.1"
            command("git", "tag", "-a", tag, "-m", f"Release {tag}", cwd=fixture.source)
        command("git", "switch", "main", cwd=fixture.source)
        command("git", "push", "origin", "--tags", cwd=fixture.source)
        command("git", "fetch", "origin", "--tags", cwd=fixture.checkout)
        commit, _, _ = fixture.prepare()
        self.assertEqual(commit, fixture.baseline)

    def test_workspace_rejects_mismatched_tags(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-rs", mismatched_workspace_tags=True)
        self.addCleanup(fixture.close)
        with self.assertRaisesRegex(BASELINE.BaselineError, "different commits"):
            fixture.prepare()

    def test_missing_tag_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        command("git", "tag", "-d", "v0.4.0-rc.1", cwd=fixture.checkout)
        with self.assertRaises(BASELINE.BaselineError):
            fixture.prepare()

    def test_lightweight_tag_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits", lightweight=True)
        self.addCleanup(fixture.close)
        with self.assertRaises(BASELINE.BaselineError):
            fixture.prepare()

    def test_unreachable_tag_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits", nonancestor=True)
        self.addCleanup(fixture.close)
        with self.assertRaises(BASELINE.BaselineError):
            fixture.prepare()

    def test_remote_main_advance_fails_closed(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        fixture.write_commit("version = \"0.4.0-rc.1\"\n# later\n", "later main")
        command("git", "push", "origin", "main", cwd=fixture.source)
        with self.assertRaises(BASELINE.BaselineError):
            fixture.prepare()

    def test_push_url_must_be_disabled(self) -> None:
        fixture = GitFixture("NVIDIA/yaml-sigil-traits")
        self.addCleanup(fixture.close)
        command(
            "git",
            "config",
            "remote.origin.pushurl",
            str(fixture.remote),
            cwd=fixture.checkout,
        )
        with self.assertRaises(BASELINE.BaselineError):
            fixture.prepare()


class ReleaseIntentResolverTests(unittest.TestCase):
    def resolve(
        self,
        *,
        manual: str,
        bump: str,
        mode: str = "next-candidate",
        existing_prs: object | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        with tempfile.TemporaryDirectory(prefix="release-intent-") as temporary:
            root = Path(temporary)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"${FAKE_EXISTING_PRS}\"\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            output = root / "output"
            if existing_prs is None:
                existing_prs = []
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_EXISTING_PRS": json.dumps(existing_prs),
                    "GH_TOKEN": "fixture",
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_REPOSITORY": EXPECTED_REPOSITORY,
                    "MANUAL_DISPATCH": manual,
                    "PATH": f"{root}:{environment['PATH']}",
                    "REQUESTED_BUMP": bump,
                    "REQUESTED_MODE": mode,
                }
            )
            result = subprocess.run(
                ["bash", str(RESOLVE_INTENT_PATH)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            values = {}
            if output.exists():
                values = dict(
                    line.split("=", 1)
                    for line in output.read_text(encoding="utf-8").splitlines()
                )
            return result, values

    @staticmethod
    def exact_proposal(*, body: object = None) -> dict[str, object]:
        return {
            "state": "open",
            "user": {
                "login": SOURCE_AUTHORIZATION.BOT_LOGIN,
                "id": SOURCE_AUTHORIZATION.BOT_ID,
            },
            "head": {
                "ref": "release-plz-next",
                "repo": {"full_name": EXPECTED_REPOSITORY},
            },
            "base": {
                "ref": "main",
                "repo": {"full_name": EXPECTED_REPOSITORY},
            },
            "body": body,
        }

    def test_manual_candidate_uses_explicit_intent(self) -> None:
        result, values = self.resolve(manual="true", bump="minor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {"proceed": "true", "mode": "next-candidate", "bump": "minor"},
        )

    def test_background_seeds_default_patch_without_a_proposal(self) -> None:
        result, values = self.resolve(manual="false", bump="patch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {"proceed": "true", "mode": "next-candidate", "bump": "patch"},
        )

    def test_background_leaves_an_existing_exact_proposal_untouched(self) -> None:
        result, values = self.resolve(
            manual="false",
            bump="patch",
            existing_prs=[
                self.exact_proposal(body="This proposal discusses major changes.")
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {"proceed": "false", "mode": "next-candidate", "bump": "patch"},
        )
        self.assertIn("no background update is needed", result.stdout)

    def test_manual_dispatch_may_update_an_existing_exact_proposal(self) -> None:
        result, values = self.resolve(
            manual="true",
            bump="major",
            existing_prs=[
                self.exact_proposal(body="Body text is not release authority.")
            ],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {"proceed": "true", "mode": "next-candidate", "bump": "major"},
        )

    def test_manual_stable_promotion_uses_deterministic_patch_intent(self) -> None:
        result, values = self.resolve(
            manual="true", bump="major", mode="promote-stable"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            values,
            {"proceed": "true", "mode": "promote-stable", "bump": "patch"},
        )

    def test_background_events_reject_nondefault_intent(self) -> None:
        for bump, mode in (
            ("minor", "next-candidate"),
            ("patch", "promote-stable"),
        ):
            with self.subTest(bump=bump, mode=mode):
                result, values = self.resolve(manual="false", bump=bump, mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(values, {})

    def test_automatic_bump_is_rejected(self) -> None:
        result, values = self.resolve(manual="true", bump="auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(values, {})

    def test_proposal_lookup_rejects_ambiguous_or_foreign_state(self) -> None:
        valid = self.exact_proposal()
        for payload in (
            [valid, valid],
            [{**valid, "user": {"login": "writer", "id": 55}}],
            [
                {
                    **valid,
                    "head": {
                        "ref": "release-plz-next",
                        "repo": {"full_name": "outside/fork"},
                    },
                }
            ],
        ):
            with self.subTest(payload=payload):
                result, values = self.resolve(
                    manual="false", bump="patch", existing_prs=payload
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(values, {})

    def test_manual_dispatch_state_must_be_exact(self) -> None:
        result, values = self.resolve(manual="yes", bump="patch")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(values, {})


class ReleaseProposalGeneratorTests(unittest.TestCase):
    FAKE_COMMAND = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

program = Path(sys.argv[0]).name
with Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps([program, *sys.argv[1:]]) + "\n")
if program == "date":
    print("2026-08-24")
elif program == "cargo" and sys.argv[1:4] == ["xtask", "release-version", "candidate"]:
    print(os.environ["FAKE_TARGET"])
elif program == "git" and sys.argv[1:3] == ["diff", "--quiet"]:
    raise SystemExit(int(os.environ["FAKE_CHANGELOG_STATUS"]))
'''

    def generate(
        self, repository: str
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]], dict[str, str], str]:
        with tempfile.TemporaryDirectory(prefix="release-generator-") as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for program in ("cargo", "date", "git", "release-plz"):
                executable = fake_bin / program
                executable.write_text(self.FAKE_COMMAND, encoding="utf-8")
                executable.chmod(0o755)

            baseline = root / "official-baseline" / "Cargo.toml"
            baseline.parent.mkdir()
            baseline.write_text("[workspace]\n", encoding="utf-8")
            output = root / "output"
            log = root / "commands.jsonl"
            published, target = (
                ("0.4.0-rc.1", "0.4.0-rc.2")
                if repository == "NVIDIA/yaml-sigil-traits"
                else ("0.5.0-rc.1", "0.5.0-rc.2")
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "EFFECTIVE_BUMP": "patch",
                    "FAKE_CHANGELOG_STATUS": "1",
                    "FAKE_COMMAND_LOG": str(log),
                    "FAKE_TARGET": target,
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_REPOSITORY": repository,
                    "GITHUB_SHA": "a" * 40,
                    "MODE": "next-candidate",
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "PUBLISHED_VERSION": published,
                    "REGISTRY_MANIFEST_PATH": str(baseline),
                    "RUNNER_TEMP": str(root),
                }
            )
            result = subprocess.run(
                ["bash", str(GENERATE_PROPOSAL_PATH)],
                cwd=root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            values = dict(
                line.split("=", 1)
                for line in output.read_text(encoding="utf-8").splitlines()
            )
            body = (root / "release-pr-body.md").read_text(encoding="utf-8")
            return result, calls, values, body

    @staticmethod
    def cargo_calls(calls: list[list[str]], command: list[str]) -> list[list[str]]:
        return [
            call
            for call in calls
            if call[0] == "cargo" and call[1 : 1 + len(command)] == command
        ]

    def test_traits_generator_scopes_compatibility_and_changelog(self) -> None:
        result, calls, values, body = self.generate("NVIDIA/yaml-sigil-traits")
        self.assertEqual(result.returncode, 0, result.stderr)
        compatibility = self.cargo_calls(
            calls, ["xtask", "release-version", "check-compatibility"]
        )
        self.assertEqual(len(compatibility), 1)
        self.assertIn("--package", compatibility[0])
        package = compatibility[0].index("--package")
        self.assertEqual(compatibility[0][package + 1], "yaml-sigil-traits")
        self.assertEqual(
            self.cargo_calls(calls, ["xtask", "sync-workspace-versions"]), []
        )
        self.assertIn(["git", "diff", "--quiet", "--", "CHANGELOG.md"], calls)
        self.assertEqual(values["target"], "0.4.0-rc.2")
        self.assertEqual(values["draft"], "false")
        self.assertIn("prepares yaml-sigil-traits", body)
        self.assertIn("GitHub Release is source-only", body)

    def test_rs_generator_uses_workspace_mode_without_a_package_argument(self) -> None:
        result, calls, values, body = self.generate("NVIDIA/yaml-sigil-rs")
        self.assertEqual(result.returncode, 0, result.stderr)
        compatibility = self.cargo_calls(
            calls, ["xtask", "release-version", "check-compatibility"]
        )
        self.assertEqual(len(compatibility), 1)
        self.assertNotIn("--package", compatibility[0])
        self.assertEqual(
            self.cargo_calls(calls, ["xtask", "sync-workspace-versions"]),
            [
                ["cargo", "xtask", "sync-workspace-versions"],
                ["cargo", "xtask", "sync-workspace-versions", "--check"],
            ],
        )
        self.assertIn(
            ["git", "diff", "--quiet", "--", "crates/*/CHANGELOG.md"], calls
        )
        self.assertEqual(values["target"], "0.5.0-rc.2")
        self.assertEqual(values["draft"], "false")
        self.assertIn("prepares all four YamlSigil Rust crates", body)
        self.assertIn("GitHub Releases are source-only", body)


def crate_archive(
    spec: object,
    commit: str,
    *,
    path: str | None = None,
    dirty: bool = False,
    vcs_path_in_vcs: str | None = None,
    cargo_lock: bytes | None = None,
    include_cargo_lock: bool = True,
    cargo_toml_orig: bytes = b"[package]\nname = 'fixture'\n",
    source: bytes = b"pub fn fixture() {}\n",
) -> bytes:
    buffer = io.BytesIO()
    prefix = f"{spec.package}-{spec.version}"
    vcs = {
        "git": {"sha1": commit},
        "path_in_vcs": spec.path_in_vcs
        if vcs_path_in_vcs is None
        else vcs_path_in_vcs,
    }
    if dirty:
        vcs["git"]["dirty"] = True
    files = {
        path or f"{prefix}/.cargo_vcs_info.json": (
            json.dumps(vcs, indent=2) + "\n"
        ).encode(),
        f"{prefix}/Cargo.toml": b"[package]\nname = 'fixture'\n",
        f"{prefix}/Cargo.toml.orig": cargo_toml_orig,
        f"{prefix}/src/lib.rs": source,
    }
    if include_cargo_lock:
        files[f"{prefix}/Cargo.lock"] = cargo_lock or (
            "version = 4\n\n"
            "[[package]]\n"
            f'name = "{spec.package}"\n'
            f'version = "{spec.version}"\n'
        ).encode()
    with tarfile.open(fileobj=buffer, mode="w:gz") as package:
        for name, contents in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mtime = 0
            info.mode = 0o644
            package.addfile(info, io.BytesIO(contents))
    return buffer.getvalue()


class FakeReleaseRegistry:
    def __init__(self, state: str = "exact", archive: bytes = b"") -> None:
        self.state = state
        self.archive = archive
        self.calls: list[tuple[str, str, str]] = []
        self.lookups = 0

    def exact_version(self, package: str, version: str) -> dict[str, object] | None:
        self.calls.append(("exact", package, version))
        self.lookups += 1
        if self.state == "missing":
            return None
        checksum = hashlib.sha256(self.archive).hexdigest()
        if self.state == "checksum-race" and self.lookups > 1:
            checksum = "0" * 64
        return {
            "version": {
                "num": version,
                "yanked": self.state == "yanked",
                "checksum": checksum,
            }
        }

    def download(self, package: str, version: str) -> bytes:
        self.calls.append(("download", package, version))
        if self.state == "bad-download":
            return self.archive + b"corrupt"
        return self.archive


class FakeSourcePackager:
    def __init__(self, archive: bytes) -> None:
        self.archive = archive
        self.calls: list[str] = []

    def package(self, spec: object) -> bytes:
        self.calls.append(spec.package)
        return self.archive


class FakeMultiReleaseRegistry:
    def __init__(
        self,
        archives: dict[str, bytes],
        missing: set[str] | None = None,
    ) -> None:
        self.archives = archives
        self.missing = missing or set()

    def exact_version(self, package: str, version: str) -> dict[str, object] | None:
        if package in self.missing:
            return None
        archive = self.archives[package]
        return {
            "version": {
                "num": version,
                "yanked": False,
                "checksum": hashlib.sha256(archive).hexdigest(),
            }
        }

    def download(self, package: str, version: str) -> bytes:
        return self.archives[package]


class FakeMultiSourcePackager:
    def __init__(self, archives: dict[str, bytes]) -> None:
        self.archives = archives

    def package(self, spec: object) -> bytes:
        return self.archives[spec.package]


class FakeReleaseGitHub:
    def __init__(
        self,
        spec: object,
        commit: str,
        *,
        tag_state: str = "exact",
        release_state: str = "exact",
        post_conflict: bool = False,
    ) -> None:
        self.spec = spec
        self.commit = commit
        self.repository = "NVIDIA/yaml-sigil-traits"
        self.tag_state = tag_state
        self.release_state = release_state
        self.post_conflict = post_conflict
        self.tag_object_sha = "a" * 40
        self.pending_tag: dict[str, object] | None = None
        self.posts: list[tuple[str, dict[str, object]]] = []

    def tag_object(self) -> dict[str, object]:
        target = "b" * 40 if self.tag_state == "wrong-target" else self.commit
        return {
            "sha": self.tag_object_sha,
            "tag": self.spec.tag,
            "message": self.spec.tag_message,
            "object": {"type": "commit", "sha": target},
        }

    def release_object(self) -> dict[str, object]:
        body = "Conflicting body." if self.release_state == "wrong-body" else self.spec.body
        assets: list[dict[str, object]] = []
        if self.release_state == "asset":
            assets = [{"name": "unexpected"}]
        return {
            "tag_name": self.spec.tag,
            "name": self.spec.tag,
            "body": body,
            "draft": False,
            "prerelease": self.spec.prerelease,
            "assets": assets,
            "target_commitish": self.commit,
        }

    def get(self, path: str) -> dict[str, object] | None:
        if path == RECONCILE.tag_ref_path(self.repository, self.spec.tag):
            if self.tag_state == "missing":
                return None
            object_type = "commit" if self.tag_state == "lightweight" else "tag"
            return {
                "ref": f"refs/tags/{self.spec.tag}",
                "object": {"type": object_type, "sha": self.tag_object_sha},
            }
        if path == RECONCILE.tag_object_path(self.repository, self.tag_object_sha):
            if self.pending_tag is not None:
                return self.pending_tag
            return self.tag_object()
        if path == RECONCILE.release_path(self.repository, self.spec.tag):
            if self.release_state == "missing":
                return None
            return self.release_object()
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        self.posts.append((path, payload))
        if self.post_conflict:
            raise RECONCILE.ReleaseObjectError("fixture conflict")
        if path == f"/repos/{self.repository}/git/tags":
            self.pending_tag = {
                "sha": self.tag_object_sha,
                "tag": payload["tag"],
                "message": payload["message"],
                "object": {"type": payload["type"], "sha": payload["object"]},
            }
            return self.pending_tag
        if path == f"/repos/{self.repository}/git/refs":
            self.tag_state = "exact"
            return {
                "ref": payload["ref"],
                "node_id": "fixture",
                "object": {"type": "tag", "sha": payload["sha"]},
            }
        if path == f"/repos/{self.repository}/releases":
            self.release_state = "exact"
            return self.release_object()
        raise AssertionError(f"unexpected POST {path}")


class ReleaseObjectReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-objects-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        changelog = self.root / "CHANGELOG.md"
        changelog.write_text(
            """# Changelog

## [Unreleased]

## [0.4.1-rc.1](https://example.invalid/compare) - 2026-08-24

### Fixed

- Preserve exact release metadata.

## [0.4.0-rc.1] - 2026-08-21

- Earlier release.
""",
            encoding="utf-8",
        )
        self.spec = RECONCILE.release_specs(
            self.root, "NVIDIA/yaml-sigil-traits", "0.4.1-rc.1"
        )[0]
        self.commit = "1" * 40
        self.archive = crate_archive(self.spec, self.commit)

    def reconcile(
        self,
        github: FakeReleaseGitHub,
        registry: FakeReleaseRegistry,
        mode: str,
    ) -> None:
        if not registry.archive:
            registry.archive = self.archive
        RECONCILE.reconcile(
            github,
            registry,
            "NVIDIA/yaml-sigil-traits",
            (self.spec,),
            self.commit,
            mode,
            FakeSourcePackager(self.archive),
        )

    def test_changelog_body_matches_the_reviewed_release_notes(self) -> None:
        self.assertEqual(
            self.spec.body,
            "### Fixed\n\n- Preserve exact release metadata.",
        )

    def test_rs_archives_bind_all_four_exact_workspace_paths(self) -> None:
        rs_packages = (
            "yaml-sigil-core",
            "yaml-sigil-transcription",
            "yaml-sigil-signing",
            "yaml-sigil-verification",
        )
        changelog = self.spec.changelog.read_text(encoding="utf-8")
        for package in rs_packages:
            path = self.root / "crates" / package / "CHANGELOG.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(changelog, encoding="utf-8")

        specs = RECONCILE.release_specs(
            self.root, "NVIDIA/yaml-sigil-rs", "0.4.1-rc.1"
        )
        self.assertEqual(
            {spec.package: spec.path_in_vcs for spec in specs},
            {package: f"crates/{package}" for package in rs_packages},
        )
        archives = {
            spec.package: crate_archive(spec, self.commit) for spec in specs
        }
        self.assertEqual(
            set(
                RECONCILE.require_registry_publication(
                    FakeMultiReleaseRegistry(archives),
                    FakeMultiSourcePackager(archives),
                    specs,
                    self.commit,
                )
            ),
            set(rs_packages),
        )
        for spec in specs:
            with self.subTest(package=spec.package):
                with self.assertRaisesRegex(
                    RECONCILE.ReleaseObjectError, "clean release commit"
                ):
                    RECONCILE.inspect_crate_archive(
                        crate_archive(spec, self.commit, vcs_path_in_vcs=""),
                        spec,
                        self.commit,
                    )

    def test_exact_objects_verify_without_mutation(self) -> None:
        github = FakeReleaseGitHub(self.spec, self.commit)
        registry = FakeReleaseRegistry()
        self.reconcile(github, registry, "verify")
        self.assertEqual(github.posts, [])
        self.assertEqual(registry.calls, [])

    def test_preflight_allows_missing_objects_without_mutation(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        registry = FakeReleaseRegistry()
        self.reconcile(github, registry, "preflight")
        self.assertEqual(github.posts, [])
        self.assertEqual(registry.calls, [])

    def test_prepublish_rejects_objects_for_an_unpublished_crate(self) -> None:
        github = FakeReleaseGitHub(self.spec, self.commit)
        with self.assertRaisesRegex(
            RECONCILE.ReleaseObjectError, "unpublished crate.*release objects"
        ):
            self.reconcile(github, FakeReleaseRegistry("missing"), "prepublish")
        self.assertEqual(github.posts, [])

    def test_prepublish_allows_an_exact_partial_workspace_train(self) -> None:
        later = RECONCILE.ReleaseSpec(
            package="yaml-sigil-signing",
            tag="yaml-sigil-signing-v0.4.1-rc.1",
            changelog=self.spec.changelog,
            path_in_vcs="crates/yaml-sigil-signing",
            body=self.spec.body,
            prerelease=True,
        )
        published_archive = self.archive
        later_archive = crate_archive(later, self.commit)
        registry = FakeMultiReleaseRegistry(
            {
                self.spec.package: published_archive,
                later.package: later_archive,
            },
            missing={later.package},
        )
        RECONCILE.require_prepublish_state(
            registry,
            FakeMultiSourcePackager(
                {
                    self.spec.package: published_archive,
                    later.package: later_archive,
                }
            ),
            (self.spec, later),
            (
                RECONCILE.ObjectState(tag_exists=True, release_exists=True),
                RECONCILE.ObjectState(tag_exists=False, release_exists=False),
            ),
            self.commit,
        )

    def test_prepublish_rejects_objects_ahead_of_the_registry_train(self) -> None:
        later = RECONCILE.ReleaseSpec(
            package="yaml-sigil-signing",
            tag="yaml-sigil-signing-v0.4.1-rc.1",
            changelog=self.spec.changelog,
            path_in_vcs="crates/yaml-sigil-signing",
            body=self.spec.body,
            prerelease=True,
        )
        archives = {
            self.spec.package: self.archive,
            later.package: crate_archive(later, self.commit),
        }
        with self.assertRaisesRegex(
            RECONCILE.ReleaseObjectError, "unpublished crate.*release objects"
        ):
            RECONCILE.require_prepublish_state(
                FakeMultiReleaseRegistry(archives, missing={later.package}),
                FakeMultiSourcePackager(archives),
                (self.spec, later),
                (
                    RECONCILE.ObjectState(tag_exists=True, release_exists=True),
                    RECONCILE.ObjectState(tag_exists=True, release_exists=False),
                ),
                self.commit,
            )

    def test_prepublish_rejects_a_nonprefix_registry_subset(self) -> None:
        later = RECONCILE.ReleaseSpec(
            package="yaml-sigil-signing",
            tag="yaml-sigil-signing-v0.4.1-rc.1",
            changelog=self.spec.changelog,
            path_in_vcs="crates/yaml-sigil-signing",
            body=self.spec.body,
            prerelease=True,
        )
        archives = {
            self.spec.package: self.archive,
            later.package: crate_archive(later, self.commit),
        }
        with self.assertRaisesRegex(
            RECONCILE.ReleaseObjectError, "exact dependency-order prefix"
        ):
            RECONCILE.require_prepublish_state(
                FakeMultiReleaseRegistry(
                    archives, missing={self.spec.package}
                ),
                FakeMultiSourcePackager(archives),
                (self.spec, later),
                (
                    RECONCILE.ObjectState(tag_exists=False, release_exists=False),
                    RECONCILE.ObjectState(tag_exists=True, release_exists=True),
                ),
                self.commit,
            )

    def test_prepublish_rejects_a_partial_registry_source_mismatch(self) -> None:
        later = RECONCILE.ReleaseSpec(
            package="yaml-sigil-signing",
            tag="yaml-sigil-signing-v0.4.1-rc.1",
            changelog=self.spec.changelog,
            path_in_vcs="crates/yaml-sigil-signing",
            body=self.spec.body,
            prerelease=True,
        )
        registry_archives = {
            self.spec.package: self.archive,
            later.package: crate_archive(later, self.commit),
        }
        reproduced_archives = dict(registry_archives)
        reproduced_archives[self.spec.package] = crate_archive(
            self.spec,
            self.commit,
            source=b"pub fn substituted_source() {}\n",
        )
        with self.assertRaisesRegex(
            RECONCILE.ReleaseObjectError, "local source content"
        ):
            RECONCILE.require_prepublish_state(
                FakeMultiReleaseRegistry(
                    registry_archives, missing={later.package}
                ),
                FakeMultiSourcePackager(reproduced_archives),
                (self.spec, later),
                (
                    RECONCILE.ObjectState(tag_exists=True, release_exists=True),
                    RECONCILE.ObjectState(tag_exists=False, release_exists=False),
                ),
                self.commit,
            )

    def test_recovery_creates_only_missing_source_metadata(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        registry = FakeReleaseRegistry()
        self.reconcile(github, registry, "recover")
        self.assertEqual(
            registry.calls,
            [
                ("exact", self.spec.package, self.spec.version),
                ("download", self.spec.package, self.spec.version),
                ("exact", self.spec.package, self.spec.version),
            ],
        )
        endpoints = [path for path, _ in github.posts]
        self.assertEqual(
            endpoints,
            [
                "/repos/NVIDIA/yaml-sigil-traits/git/tags",
                "/repos/NVIDIA/yaml-sigil-traits/git/refs",
                "/repos/NVIDIA/yaml-sigil-traits/releases",
            ],
        )
        self.assertFalse(any("assets" in path for path in endpoints))

    def test_recovery_creates_only_a_missing_release(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, release_state="missing"
        )
        self.reconcile(github, FakeReleaseRegistry(), "recover")
        self.assertEqual(
            [path for path, _ in github.posts],
            ["/repos/NVIDIA/yaml-sigil-traits/releases"],
        )

    def test_lightweight_or_wrong_target_tag_is_a_conflict(self) -> None:
        for tag_state in ("lightweight", "wrong-target"):
            with self.subTest(tag_state=tag_state):
                github = FakeReleaseGitHub(
                    self.spec, self.commit, tag_state=tag_state
                )
                with self.assertRaises(RECONCILE.ReleaseObjectError):
                    self.reconcile(github, FakeReleaseRegistry(), "recover")
                self.assertEqual(github.posts, [])

    def test_wrong_release_body_or_asset_is_a_conflict(self) -> None:
        for release_state in ("wrong-body", "asset"):
            with self.subTest(release_state=release_state):
                github = FakeReleaseGitHub(
                    self.spec, self.commit, release_state=release_state
                )
                with self.assertRaises(RECONCILE.ReleaseObjectError):
                    self.reconcile(github, FakeReleaseRegistry(), "recover")
                self.assertEqual(github.posts, [])

    def test_registry_missing_or_yanked_blocks_every_recovery_write(self) -> None:
        for registry_state in ("missing", "yanked"):
            with self.subTest(registry_state=registry_state):
                github = FakeReleaseGitHub(
                    self.spec,
                    self.commit,
                    tag_state="missing",
                    release_state="missing",
                )
                with self.assertRaises(RECONCILE.ReleaseObjectError):
                    self.reconcile(
                        github, FakeReleaseRegistry(registry_state), "recover"
                    )
                self.assertEqual(github.posts, [])

    def test_registry_checksum_or_archive_mismatch_blocks_recovery(self) -> None:
        for registry_state in ("bad-download",):
            with self.subTest(registry_state=registry_state):
                github = FakeReleaseGitHub(
                    self.spec,
                    self.commit,
                    tag_state="missing",
                    release_state="missing",
                )
                with self.assertRaisesRegex(
                    RECONCILE.ReleaseObjectError, "archive checksum differs"
                ):
                    self.reconcile(
                        github,
                        FakeReleaseRegistry(registry_state, self.archive),
                        "recover",
                    )
                self.assertEqual(github.posts, [])

    def test_registry_archive_requires_safe_paths_and_clean_exact_vcs_commit(self) -> None:
        cases = [
            ("unsafe path", crate_archive(
                self.spec,
                self.commit,
                path=f"{self.spec.package}-{self.spec.version}/../outside",
            )),
            ("clean release commit", crate_archive(
                self.spec, self.commit, dirty=True
            )),
            ("clean release commit", crate_archive(self.spec, "2" * 40)),
        ]
        for error, archive in cases:
            with self.subTest(error=error):
                github = FakeReleaseGitHub(
                    self.spec,
                    self.commit,
                    tag_state="missing",
                    release_state="missing",
                )
                with self.assertRaisesRegex(RECONCILE.ReleaseObjectError, error):
                    self.reconcile(
                        github, FakeReleaseRegistry("exact", archive), "recover"
                    )
                self.assertEqual(github.posts, [])

    def test_local_cargo_package_must_match_registry_source_content(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        local = crate_archive(
            self.spec,
            self.commit,
            source=b"pub fn substituted_source() {}\n",
        )
        with self.assertRaisesRegex(RECONCILE.ReleaseObjectError, "local source content"):
            RECONCILE.reconcile(
                github,
                FakeReleaseRegistry("exact", self.archive),
                "NVIDIA/yaml-sigil-traits",
                (self.spec,),
                self.commit,
                "recover",
                FakeSourcePackager(local),
            )
        self.assertEqual(github.posts, [])

    def test_generated_root_cargo_lock_may_differ_during_recovery(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        local = crate_archive(
            self.spec,
            self.commit,
            cargo_lock=(
                "version = 4\n\n"
                "[[package]]\n"
                'name = "newly-resolved-dependency"\n'
                'version = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{"0" * 64}"\n\n'
                "[[package]]\n"
                f'name = "{self.spec.package}"\n'
                f'version = "{self.spec.version}"\n'
            ).encode(),
        )
        RECONCILE.reconcile(
            github,
            FakeReleaseRegistry("exact", self.archive),
            "NVIDIA/yaml-sigil-traits",
            (self.spec,),
            self.commit,
            "recover",
            FakeSourcePackager(local),
        )
        self.assertEqual(len(github.posts), 3)

    def test_generated_root_cargo_lock_is_required_on_both_sides(self) -> None:
        for registry_archive, local_archive in (
            (
                crate_archive(
                    self.spec, self.commit, include_cargo_lock=False
                ),
                self.archive,
            ),
            (
                self.archive,
                crate_archive(
                    self.spec, self.commit, include_cargo_lock=False
                ),
            ),
        ):
            with self.subTest():
                github = FakeReleaseGitHub(
                    self.spec,
                    self.commit,
                    tag_state="missing",
                    release_state="missing",
                )
                with self.assertRaisesRegex(
                    RECONCILE.ReleaseObjectError, "lacks generated Cargo.lock"
                ):
                    RECONCILE.reconcile(
                        github,
                        FakeReleaseRegistry("exact", registry_archive),
                        "NVIDIA/yaml-sigil-traits",
                        (self.spec,),
                        self.commit,
                        "recover",
                        FakeSourcePackager(local_archive),
                    )
                self.assertEqual(github.posts, [])

    def test_generated_root_cargo_lock_must_be_valid_and_bound(self) -> None:
        invalid_locks = (
            b"not valid = [\n",
            b'version = 4\n\n[[package]]\nname = "other"\nversion = "1.0.0"\n',
            (
                "version = 4\n\n"
                "[[package]]\n"
                f'name = "{self.spec.package}"\n'
                f'version = "{self.spec.version}"\n'
                'source = "registry+https://example.invalid/index"\n'
            ).encode(),
        )
        for cargo_lock in invalid_locks:
            with self.subTest(cargo_lock=cargo_lock):
                github = FakeReleaseGitHub(
                    self.spec,
                    self.commit,
                    tag_state="missing",
                    release_state="missing",
                )
                with self.assertRaisesRegex(
                    RECONCILE.ReleaseObjectError,
                    "(invalid|unbound) generated Cargo.lock",
                ):
                    RECONCILE.reconcile(
                        github,
                        FakeReleaseRegistry("exact", self.archive),
                        "NVIDIA/yaml-sigil-traits",
                        (self.spec,),
                        self.commit,
                        "recover",
                        FakeSourcePackager(
                            crate_archive(
                                self.spec,
                                self.commit,
                                cargo_lock=cargo_lock,
                            )
                        ),
                    )
                self.assertEqual(github.posts, [])

    def test_original_manifest_remains_byte_exact_during_recovery(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        local = crate_archive(
            self.spec,
            self.commit,
            cargo_toml_orig=b"[package]\nname = 'substituted'\n",
        )
        with self.assertRaisesRegex(RECONCILE.ReleaseObjectError, "local source content"):
            RECONCILE.reconcile(
                github,
                FakeReleaseRegistry("exact", self.archive),
                "NVIDIA/yaml-sigil-traits",
                (self.spec,),
                self.commit,
                "recover",
                FakeSourcePackager(local),
            )
        self.assertEqual(github.posts, [])

    def test_registry_checksum_is_rechecked_after_source_object_recovery(self) -> None:
        github = FakeReleaseGitHub(
            self.spec, self.commit, tag_state="missing", release_state="missing"
        )
        with self.assertRaisesRegex(RECONCILE.ReleaseObjectError, "changed.*during recovery"):
            self.reconcile(
                github,
                FakeReleaseRegistry("checksum-race", self.archive),
                "recover",
            )
        self.assertEqual(len(github.posts), 3)

    def test_creation_race_fails_without_overwriting_a_ref(self) -> None:
        github = FakeReleaseGitHub(
            self.spec,
            self.commit,
            tag_state="missing",
            release_state="missing",
            post_conflict=True,
        )
        with self.assertRaises(RECONCILE.ReleaseObjectError):
            self.reconcile(github, FakeReleaseRegistry(), "recover")
        self.assertEqual(len(github.posts), 1)
        self.assertEqual(
            github.posts[0][0], "/repos/NVIDIA/yaml-sigil-traits/git/tags"
        )


class WorkflowBoundaryTests(unittest.TestCase):
    def test_workflows_have_no_pull_request_publication_path(self) -> None:
        workflow_root = SCRIPT_DIR.parent / "workflows"
        bodies = {
            path.name: path.read_text(encoding="utf-8")
            for path in workflow_root.iterdir()
            if path.suffix in {".yml", ".yaml"}
        }
        combined = "\n".join(bodies.values())
        for forbidden in (
            "validate-pr",
            "publish-pr",
            "crates-io-pr",
            "release-plz-snapshot",
            "verify-crates-io-packages.sh",
            "check-release-packages.sh",
            "check_release_semver.py",
            "install-release-tools.sh",
            "prepare_release_plz_publication_config.py",
            "require-current-main.sh",
        ):
            self.assertNotIn(forbidden, combined)
        publish_lines = bodies["publish.yml"].splitlines()
        operation_start, operation_end, operation_indent = workflow_block(
            publish_lines,
            ("on", "workflow_dispatch", "inputs", "operation", "options"),
        )
        operations = [
            line.strip().removeprefix("- ")
            for line in publish_lines[operation_start:operation_end]
            if line.startswith(" " * operation_indent + "- ")
        ]
        self.assertEqual(operations, ["validate", "publish"])
        self.assertNotIn(
            "pr_number",
            workflow_direct_keys(
                publish_lines, ("on", "workflow_dispatch", "inputs")
            ),
        )
        self.assertEqual(
            workflow_direct_keys(publish_lines, ("jobs",)),
            ["validation", "publication"],
        )
        self.assertEqual(
            workflow_oidc_locations(bodies), [("publish.yml", "publication")]
        )
        for name, body in bodies.items():
            events = set(workflow_direct_keys(body.splitlines(), ("on",)))
            if events.intersection({"pull_request", "pull_request_target"}):
                self.assertNotIn((name, "publication"), workflow_oidc_locations(bodies))
                self.assertFalse(
                    any(location[0] == name for location in workflow_oidc_locations(bodies))
                )
        self.assertIn("environment: crates-io\n", bodies["publish.yml"])

    def test_yaml_suffix_is_included_in_oidc_regression(self) -> None:
        fixture = {
            "fixture.yaml": """on:
  pull_request:
jobs:
  preview:
    permissions:
      id-token: write
"""
        }
        self.assertEqual(
            workflow_oidc_locations(fixture), [("fixture.yaml", "preview")]
        )

    def test_quoted_workflow_keys_are_included_in_regression(self) -> None:
        fixture = {
            "quoted.yml": '''"on": # quoted trigger key
  'pull_request_target': # quoted event key
"jobs": # quoted jobs key
  'preview':
    "permissions":
      'id-token': "write"
  "inline-preview":
    permissions: {"id-token": 'write'}
'''
        }
        lines = fixture["quoted.yml"].splitlines()
        self.assertEqual(
            workflow_direct_keys(lines, ("on",)), ["pull_request_target"]
        )
        self.assertEqual(
            workflow_direct_keys(lines, ("jobs",)), ["preview", "inline-preview"]
        )
        self.assertEqual(
            workflow_oidc_locations(fixture),
            [("quoted.yml", "preview"), ("quoted.yml", "inline-preview")],
        )

    def test_write_all_permissions_are_treated_as_oidc_capable(self) -> None:
        fixture = {
            "workflow.yml": '''permissions: write-all
jobs:
  explicit:
    permissions: "write-all" # grants id-token write
    runs-on: ubuntu-latest
  read-only:
    permissions:
      contents: read
    steps:
      - run: echo "permissions: write-all"
'''
        }
        self.assertEqual(
            workflow_oidc_locations(fixture),
            [("workflow.yml", None), ("workflow.yml", "explicit")],
        )

    def test_publication_rechecks_main_and_reconciles_source_objects(self) -> None:
        publish = (SCRIPT_DIR.parent / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("--mode prepublish", publish)
        self.assertIn("--mode recover", publish)
        status = publish.index('registry_status="$?"')
        authorization = publish.index("verify_release_publication_source.py", status)
        inventory = publish.index("--verify-inventory", authorization)
        current_main = publish.index("cargo xtask release require-current-main", inventory)
        branch = publish.index('case "${registry_status}" in', current_main)
        fresh = publish.index("--mode prepublish", branch)
        publish_main = publish.index("cargo xtask release require-current-main", fresh)
        publish_head = publish.index(
            'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"', publish_main
        )
        release = publish.index("release-plz release", publish_head)
        final_head = publish.index('test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"', release)
        recovery = publish.index("--mode recover", release)
        recovery_main = publish.rindex(
            "cargo xtask release require-current-main", release, recovery
        )
        recovery_head = publish.rindex(
            'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"', release, recovery
        )
        self.assertLess(status, authorization)
        self.assertLess(authorization, inventory)
        self.assertLess(inventory, current_main)
        self.assertLess(current_main, branch)
        self.assertLess(branch, fresh)
        self.assertLess(fresh, publish_main)
        self.assertLess(publish_main, publish_head)
        self.assertLess(publish_head, release)
        self.assertLess(release, final_head)
        self.assertLess(final_head, recovery_main)
        self.assertLess(recovery_main, recovery_head)
        self.assertLess(recovery_head, recovery)
        self.assertIn("release-plz-publication.toml", publish)
        self.assertEqual(publish.count("--baseline-version"), 2)
        self.assertEqual(publish.count("--baseline-commit"), 2)
        self.assertEqual(
            publish.count("cargo xtask release require-current-main"), 4
        )
        self.assertEqual(
            len(
                re.findall(
                    r"cargo xtask release require-current-main \\\n"
                    r'\s+--head "\$\{GITHUB_SHA\}" \\\n'
                    r'\s+--fetch-url "https://github.com/'
                    r'\$\{GITHUB_REPOSITORY\}"',
                    publish,
                )
            ),
            4,
        )

    def test_proposal_rechecks_tag_snapshot_immediately_before_app_mutation(self) -> None:
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        analysis = proposal.index("generate-release-proposal.sh")
        recheck = proposal.index("--verify-inventory", analysis)
        mutation = proposal.index("update-release-pull-request.sh", recheck)
        self.assertLess(analysis, recheck)
        self.assertLess(recheck, mutation)

    def test_proposal_holds_draft_until_association_validation(self) -> None:
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        mutation = proposal.index("update-release-pull-request.sh")
        checkout = proposal.index("Check out generated Verified commit", mutation)
        validation = proposal.index("Recheck clean generated release source", checkout)
        finalization = proposal.index("update-release-pull-request.sh", validation)
        update = proposal[mutation - 600 : checkout]
        post_association = proposal[validation:finalization]
        finalized = proposal[finalization - 600 :]
        self.assertIn('RELEASE_HOLD_DRAFT: "true"', update)
        self.assertIn("RELEASE_OPERATION: update", update)
        self.assertIn("release-plz release", post_association)
        self.assertIn("--dry-run", post_association)
        self.assertIn('RELEASE_HOLD_DRAFT: "true"', finalized)
        self.assertIn("RELEASE_OPERATION: finalize", finalized)

    def test_rs_proposal_holds_draft_until_repeated_source_validation(self) -> None:
        if not IS_RS_REPOSITORY:
            self.skipTest("the four-crate proposal transaction belongs to yaml-sigil-rs")
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        generated = proposal.index("Validate generated release source before mutation")
        mutation = proposal.index("update-release-pull-request.sh", generated)
        pre_mutation = proposal[generated:mutation]
        checkout = proposal.index("Check out generated Verified commit", mutation)
        repeated = proposal.index("Recheck clean generated release source", checkout)
        finalization = proposal.rindex("update-release-pull-request.sh", repeated)
        post_association = proposal[repeated:finalization]
        required = (
            "cargo xtask sync-workspace-versions --check",
            "cargo xtask release-version check",
            "cargo xtask release verify-traits",
            "cargo xtask release check-packages",
            "cargo xtask release-version check-compatibility",
            "cargo metadata --no-deps --format-version 1",
            "cargo package --package yaml-sigil-core --all-features",
            "cargo package --package yaml-sigil-transcription",
            "cargo package --package yaml-sigil-signing --all-features",
            "cargo package --package yaml-sigil-verification --all-features",
        )
        for command_text in required:
            self.assertIn(command_text, pre_mutation)
            self.assertIn(command_text, post_association)
        self.assertIn('RELEASE_HOLD_DRAFT: "true"', proposal[mutation - 500 : checkout])
        dry_run = post_association.index("release-plz release")
        self.assertLess(dry_run, len(post_association))
        self.assertIn("RELEASE_OPERATION: finalize", proposal[repeated:])

    def test_oidc_publication_uses_an_unpatched_cargo_home(self) -> None:
        if not IS_RS_REPOSITORY:
            self.skipTest("workspace dependency publication belongs to yaml-sigil-rs")
        publish_lines = (
            SCRIPT_DIR.parent / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8").splitlines()
        validation_start, validation_end, _ = workflow_block(
            publish_lines, ("jobs", "validation")
        )
        publication_start, publication_end, _ = workflow_block(
            publish_lines, ("jobs", "publication")
        )
        validation = "\n".join(publish_lines[validation_start:validation_end])
        publication = "\n".join(publish_lines[publication_start:publication_end])
        self.assertIn("prepare-validation-cargo-home", validation)
        self.assertIn("prepare-publication-cargo-home", publication)
        self.assertNotIn("prepare-validation-cargo-home", publication)

    def test_release_workflows_pin_the_exact_analyzer_bootstrap(self) -> None:
        action = (
            "cargo-bins/cargo-binstall@"
            "732870f031d2fb36309d0deaf36abcc704a7be65 # v1.20.1"
        )
        for workflow in ("release-pr.yml", "publish.yml"):
            body = (SCRIPT_DIR.parent / "workflows" / workflow).read_text(encoding="utf-8")
            self.assertIn(action, body)
            self.assertNotIn("release-plz/action@", body)
            self.assertIn("cargo xtask release install-tools", body)
        release_proposal = (
            SCRIPT_DIR.parent / "workflows" / "release-pr.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("disabled://yaml-sigil-release-proposal", release_proposal)
        generator = (SCRIPT_DIR / "generate-release-proposal.sh").read_text(encoding="utf-8")
        self.assertIn("--registry-manifest-path", generator)
        self.assertIn("cargo xtask release-version check-compatibility", generator)
        self.assertIn(
            "compatibility_package_args=(--package yaml-sigil-traits)", generator
        )
        self.assertIn("compatibility_package_args=()", generator)
        self.assertIn('"${compatibility_package_args[@]}"', generator)

    def test_release_intent_is_explicit_and_not_stored_in_the_pr_body(self) -> None:
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        publish = (SCRIPT_DIR.parent / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        resolver = (SCRIPT_DIR / "resolve-release-intent.sh").read_text(
            encoding="utf-8"
        )
        generator = (SCRIPT_DIR / "generate-release-proposal.sh").read_text(
            encoding="utf-8"
        )
        releasing = (SCRIPT_DIR.parent.parent / "RELEASING.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("default: patch", proposal)
        self.assertNotIn("          - auto\n", proposal)
        self.assertNotIn("--intent auto", publish)
        self.assertNotIn("auto | patch", resolver)
        self.assertNotIn('bump="auto"', releasing)
        self.assertIn('echo "proceed=${proceed}"', resolver)
        self.assertEqual(
            proposal.count("steps.intent.outputs.proceed == 'true'"),
            9 if IS_RS_REPOSITORY else 8,
        )
        hidden_body_field = "yaml-sigil-release-" + "bump"
        retired_environment = "RELEASE_" + "MARKER"
        for body in (proposal, resolver, generator, releasing):
            self.assertNotIn(hidden_body_field, body)
            self.assertNotIn(retired_environment, body)
        self.assertIn("RUSTUP_TOOLCHAIN=1.95.0", releasing)
        self.assertIn("omits release-plz's `--dry-run` CLI", releasing)

    def test_manual_fallback_pins_the_official_fetch_url(self) -> None:
        releasing = (REPOSITORY_ROOT / "RELEASING.md").read_text(
            encoding="utf-8"
        )
        expected = f'fetch_url="https://github.com/{EXPECTED_REPOSITORY}"'
        self.assertIn(expected, releasing)
        self.assertIn(
            'test "$(git remote get-url origin)" = "${fetch_url}"', releasing
        )
        self.assertNotIn('fetch_url="$(git remote get-url origin)"', releasing)

    def test_release_analysis_pins_the_rustdoc_v60_capable_toolchain(self) -> None:
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        publish = (SCRIPT_DIR.parent / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        config = (SCRIPT_DIR.parent.parent / ".release-plz.toml").read_text(
            encoding="utf-8"
        )
        release_task = (
            SCRIPT_DIR.parent.parent / "xtask" / "src" / "release.rs"
        ).read_text(encoding="utf-8")
        self.assertEqual(proposal.count("toolchain: 1.95.0"), 1)
        self.assertEqual(publish.count("toolchain: 1.95.0"), 2)
        self.assertEqual(
            publish.count("cargo xtask release-version check-compatibility"), 2
        )
        self.assertEqual(publish.count("prepare_release_baseline.py"), 3)
        self.assertEqual(
            publish.count("cargo xtask release verify-registry"), 4
        )
        self.assertEqual(
            publish.count("cargo xtask release prepare-publication-config"), 2
        )
        self.assertEqual(
            publish.count("cargo xtask release check-packages"),
            2 if IS_RS_REPOSITORY else 1,
        )
        self.assertEqual(
            proposal.count("cargo xtask release verify-registry"), 1
        )
        self.assertIn('const CARGO_BINSTALL_VERSION: &str = "1.20.1"', release_task)
        self.assertIn('const RELEASE_PLZ_VERSION: &str = "0.3.160"', release_task)
        self.assertIn('const SEMVER_CHECKS_VERSION: &str = "0.50.0"', release_task)
        self.assertIn("semver_check = false", config)
        expected_tags = (
            (
                "yaml-sigil-core",
                "yaml-sigil-transcription",
                "yaml-sigil-signing",
                "yaml-sigil-verification",
            )
            if IS_RS_REPOSITORY
            else ("v",)
        )
        for prefix in expected_tags:
            separator = "-v" if IS_RS_REPOSITORY else ""
            tag = f'{prefix}{separator}{{{{ version }}}}'
            self.assertIn(f'git_tag_name = "{tag}"', config)
            self.assertIn(f'git_release_name = "{tag}"', config)
        self.assertEqual(
            config.count('git_release_body = "{{ changelog }}"'),
            len(expected_tags),
        )

    def test_rs_release_paths_require_exact_traits_identity(self) -> None:
        publish = (SCRIPT_DIR.parent / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        proposal = (SCRIPT_DIR.parent / "workflows" / "release-pr.yml").read_text(
            encoding="utf-8"
        )
        expected = 2 if IS_RS_REPOSITORY else 0
        self.assertEqual(publish.count("cargo xtask release verify-traits"), expected)
        self.assertEqual(
            proposal.count("cargo xtask release verify-traits"),
            3 if IS_RS_REPOSITORY else 0,
        )
        self.assertNotIn("verify-release-traits.sh", publish)
        self.assertNotIn("verify-release-traits.sh", proposal)

    def test_candidate_and_trusted_runner_labels_remain_separate(self) -> None:
        protected = (SCRIPT_DIR.parent / "workflows" / "pr-ci.yml").read_text(
            encoding="utf-8"
        )
        trusted = (SCRIPT_DIR.parent / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for runner in ("ubuntu-latest", "macos-latest", "windows-latest"):
            self.assertIn(f"runner: {runner}", protected)
        self.assertNotIn("linux-amd64-cpu4", protected)
        self.assertNotIn("linux-amd64-cpu8", protected)
        self.assertIn("runs-on: linux-amd64-cpu4", trusted)
        self.assertIn("runner: linux-amd64-cpu8", trusted)


class FakeSourceAuthorizationAPI:
    def __init__(
        self, release_commit: str, release_tree: str, *, fast_forward: bool = False
    ) -> None:
        self.release_commit = release_commit
        self.proposal_commit = release_commit if fast_forward else "a" * 40
        self.base_commit = "b" * 40
        self.requests: list[str] = []
        self.pull = {
            "number": 7,
            "state": "closed",
            "merged_at": "2026-08-24T12:00:00Z",
            "merge_commit_sha": release_commit,
            "user": {
                "login": SOURCE_AUTHORIZATION.BOT_LOGIN,
                "id": SOURCE_AUTHORIZATION.BOT_ID,
            },
            "head": {
                "repo": {"full_name": "NVIDIA/yaml-sigil-traits"},
                "ref": "release-plz-next",
                "sha": self.proposal_commit,
            },
            "base": {
                "repo": {"full_name": "NVIDIA/yaml-sigil-traits"},
                "ref": "main",
                "sha": self.base_commit,
            },
            "commits": 1,
            "changed_files": 1,
            "merged_by": {"login": "maintainer", "id": 55},
        }
        self.commit = {
            "sha": self.proposal_commit,
            "author": {
                "login": SOURCE_AUTHORIZATION.BOT_LOGIN,
                "id": SOURCE_AUTHORIZATION.BOT_ID,
            },
            "committer": {"login": "web-flow", "id": 19864447},
            "commit": {
                "author": {
                    "name": SOURCE_AUTHORIZATION.BOT_LOGIN,
                    "email": SOURCE_AUTHORIZATION.BOT_EMAIL,
                    "date": "2026-08-24T11:00:00Z",
                },
                "committer": {
                    "name": "GitHub",
                    "email": "noreply@github.com",
                    "date": "2026-08-24T11:00:00Z",
                },
                "tree": {"sha": release_tree},
                "message": (
                    "chore(release): prepare candidate\n\nSigned-off-by: "
                    f"{SOURCE_AUTHORIZATION.BOT_LOGIN} "
                    f"<{SOURCE_AUTHORIZATION.BOT_EMAIL}>\n"
                ),
                "verification": {"verified": True, "reason": "valid"},
            },
            "parents": [{"sha": self.base_commit}],
        }
        self.integrated_commit = {
            "sha": self.release_commit,
            "author": {
                "login": SOURCE_AUTHORIZATION.BOT_LOGIN,
                "id": SOURCE_AUTHORIZATION.BOT_ID,
            },
            "committer": {
                "login": "web-flow",
                "id": SOURCE_AUTHORIZATION.WEB_FLOW_ID,
            },
            "commit": {
                "author": {
                    "name": SOURCE_AUTHORIZATION.BOT_LOGIN,
                    "email": SOURCE_AUTHORIZATION.BOT_EMAIL,
                    "date": "2026-08-24T12:00:00Z",
                },
                "committer": {
                    "name": "GitHub",
                    "email": "noreply@github.com",
                    "date": "2026-08-24T12:00:00Z",
                },
                "tree": {"sha": release_tree},
                "message": (
                    "chore(release): prepare candidate\n\nSigned-off-by: "
                    f"{SOURCE_AUTHORIZATION.BOT_LOGIN} "
                    f"<{SOURCE_AUTHORIZATION.BOT_EMAIL}>\n"
                ),
                "verification": {"verified": True, "reason": "valid"},
            },
            "parents": [{"sha": self.base_commit}],
        }

    def use_manual_identity(
        self, branch: str = "release-plz-manual-0.4.1-rc.1"
    ) -> None:
        self.pull["user"] = {"login": "maintainer", "id": 55}
        self.pull["head"]["ref"] = branch
        self.commit["author"] = {"login": "maintainer", "id": 55}
        self.commit["committer"] = {"login": "maintainer", "id": 55}
        raw_identity = {
            "name": "Maintainer",
            "email": "maintainer@example.invalid",
            "date": "2026-08-24T11:00:00Z",
        }
        self.commit["commit"]["author"] = raw_identity.copy()
        self.commit["commit"]["committer"] = raw_identity.copy()
        self.commit["commit"]["message"] = (
            "chore(release): prepare candidate\n\n"
            "Signed-off-by: Maintainer <maintainer@example.invalid>\n"
        )
        self.integrated_commit["author"] = {"login": "maintainer", "id": 55}
        self.integrated_commit["commit"]["author"] = {
            **raw_identity,
            "date": "2026-08-24T12:00:00Z",
        }
        self.integrated_commit["commit"]["message"] = self.commit["commit"]["message"]

    def get(self, path: str) -> object:
        self.requests.append(path)
        if path.endswith("/pulls/7"):
            return self.pull
        if "/collaborators/maintainer/permission" in path:
            return {
                "permission": "write",
                "user": {"login": "maintainer", "id": 55},
            }
        if "/collaborators/" in path:
            return {
                "permission": "none",
                "user": {
                    "login": SOURCE_AUTHORIZATION.BOT_LOGIN,
                    "id": SOURCE_AUTHORIZATION.BOT_ID,
                },
            }
        if path.endswith(f"/commits/{self.proposal_commit}"):
            return self.commit
        if path.endswith(f"/commits/{self.release_commit}"):
            return self.integrated_commit
        raise AssertionError(path)

    def paginate(self, path: str) -> list[object]:
        if path.endswith(f"/commits/{self.release_commit}/pulls"):
            return [self.pull]
        if path.endswith("/pulls/7/commits"):
            return [{"sha": self.proposal_commit}]
        if path.endswith("/pulls/7/files"):
            return [{"filename": "Cargo.toml", "status": "modified"}]
        raise AssertionError(path)


class PublicationSourceAuthorizationTests(unittest.TestCase):
    def fixture(
        self, current_version: str = "0.4.1-rc.1"
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, str, str]:
        temporary = tempfile.TemporaryDirectory(prefix="publication-source-")
        root = Path(temporary.name)
        command("git", "init", "--initial-branch=main", cwd=root)
        command("git", "config", "user.name", "Release Test", cwd=root)
        command("git", "config", "user.email", "release@example.invalid", cwd=root)
        (root / "Cargo.toml").write_text(
            f"[package]\nname='fixture'\nversion='{current_version}'\n",
            encoding="utf-8",
        )
        command("git", "add", "Cargo.toml", cwd=root)
        command("git", "commit", "-m", "release", cwd=root)
        head = command("git", "rev-parse", "HEAD", cwd=root).stdout.strip()
        tree = command("git", "rev-parse", "HEAD^{tree}", cwd=root).stdout.strip()
        return temporary, root, head, tree

    def authorize(
        self,
        api: FakeSourceAuthorizationAPI,
        repository: str,
        commit: str,
        root: Path,
    ) -> int:
        return SOURCE_AUTHORIZATION.authorize_source(
            api,
            repository,
            commit,
            root,
            "0.4.0",
            "c" * 40,
        )

    def test_exact_merged_app_proposal_authorizes_current_release_source(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        self.assertEqual(
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            ),
            7,
        )
        self.assertFalse(
            any(SOURCE_AUTHORIZATION.BOT_LOGIN in path for path in api.requests)
        )

    def test_source_authorization_rejects_identity_and_file_ambiguity(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.commit["committer"]["id"] = 1
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError, "identity"
        ):
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            )

        api = FakeSourceAuthorizationAPI(head, tree)
        api.pull["changed_files"] = 2
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError, "file inventory"
        ):
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            )

    def test_exact_manual_fallback_proposal_remains_authorized(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.use_manual_identity()
        self.assertEqual(
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            ),
            7,
        )

    def test_exact_signed_manual_commit_can_be_fast_forwarded(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree, fast_forward=True)
        api.use_manual_identity()
        self.assertEqual(
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            ),
            7,
        )

    def test_manual_fallback_branch_must_name_the_exact_candidate(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.use_manual_identity("release-plz-manual-9.9.9")
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError,
            "lacks one exact merged proposal",
        ):
            self.authorize(api, "NVIDIA/yaml-sigil-traits", head, root)

    def test_rewritten_manual_integration_requires_github_committer(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.use_manual_identity()
        api.integrated_commit["committer"] = {"login": "maintainer", "id": 55}
        api.integrated_commit["commit"]["committer"] = {
            "name": "Maintainer",
            "email": "maintainer@example.invalid",
            "date": "2026-08-24T12:00:00Z",
        }
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError,
            "current main integration",
        ):
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            )

    def test_stable_promotion_requires_the_tagged_rc_as_its_exact_base(self) -> None:
        temporary, root, head, tree = self.fixture(current_version="0.4.0")
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.use_manual_identity("release-plz-manual-0.4.0")
        self.assertEqual(
            SOURCE_AUTHORIZATION.authorize_source(
                api,
                "NVIDIA/yaml-sigil-traits",
                head,
                root,
                "0.4.0-rc.1",
                api.base_commit,
            ),
            7,
        )

        intervening_main = FakeSourceAuthorizationAPI(head, tree)
        intervening_main.use_manual_identity("release-plz-manual-0.4.0")
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError,
            "stable promotion base",
        ):
            SOURCE_AUTHORIZATION.authorize_source(
                intervening_main,
                "NVIDIA/yaml-sigil-traits",
                head,
                root,
                "0.4.0-rc.1",
                "c" * 40,
            )

    def test_current_main_must_be_the_exact_verified_squash_integration(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        for mutation in ("signature", "parent", "tree", "committer"):
            with self.subTest(mutation=mutation):
                api = FakeSourceAuthorizationAPI(head, tree)
                if mutation == "signature":
                    api.integrated_commit["commit"]["verification"] = {
                        "verified": False,
                        "reason": "unsigned",
                    }
                elif mutation == "parent":
                    api.integrated_commit["parents"] = [{"sha": "d" * 40}]
                elif mutation == "tree":
                    api.integrated_commit["commit"]["tree"] = {"sha": "d" * 40}
                else:
                    api.integrated_commit["committer"] = {
                        "login": "maintainer",
                        "id": 55,
                    }
                with self.assertRaisesRegex(
                    SOURCE_AUTHORIZATION.SourceAuthorizationError,
                    "current main integration",
                ):
                    self.authorize(
                        api, "NVIDIA/yaml-sigil-traits", head, root
                    )

    def test_permission_checks_bind_login_and_immutable_id(self) -> None:
        temporary, root, head, tree = self.fixture()
        self.addCleanup(temporary.cleanup)
        api = FakeSourceAuthorizationAPI(head, tree)
        api.pull["merged_by"]["id"] = 56
        with self.assertRaisesRegex(
            SOURCE_AUTHORIZATION.SourceAuthorizationError,
            "merger lacks current write authority",
        ):
            self.authorize(
                api, "NVIDIA/yaml-sigil-traits", head, root
            )


class ReleaseGitIdentityTests(unittest.TestCase):
    def run_identity(
        self, *, login: str = "github-actions[bot]", database_id: str = "41898282"
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        with tempfile.TemporaryDirectory(prefix="release-git-identity-") as temporary:
            root = Path(temporary)
            command("git", "init", "--initial-branch=main", cwd=root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                """#!/usr/bin/env bash
set -eu
printf '{\"name\":\"\",\"login\":\"%s\",\"databaseId\":%s}\n' \
  \"${FAKE_LOGIN}\" \"${FAKE_DATABASE_ID}\"
""",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_DATABASE_ID": database_id,
                    "FAKE_LOGIN": login,
                    "GITHUB_TOKEN": "fixture-token",
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                }
            )
            result = subprocess.run(
                ["bash", str(CONFIGURE_GIT_PATH)],
                cwd=root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            name = command(
                "git", "config", "--local", "user.name", cwd=root, check=False
            ).stdout.strip()
            email = command(
                "git", "config", "--local", "user.email", cwd=root, check=False
            ).stdout.strip()
            return result, name, email

    def test_workflow_token_identity_is_configured_exactly(self) -> None:
        result, name, email = self.run_identity()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(name, "github-actions[bot]")
        self.assertEqual(
            email,
            "41898282+github-actions[bot]@users.noreply.github.com",
        )

    def test_invalid_workflow_token_identity_fails_closed(self) -> None:
        result, _, _ = self.run_identity(login="unexpected login", database_id="null")
        self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(VERIFY_TRAITS_PATH.exists(), "rs-only exact traits preflight")
class ExactTraitsIdentityTests(unittest.TestCase):
    def run_preflight(self, mode: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory(prefix="traits-identity-") as temporary:
            fake_bin = Path(temporary)
            calls = fake_bin / "cargo.log"
            fake_cargo = fake_bin / "cargo"
            fake_cargo.write_text(
                """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >>"${FAKE_CARGO_LOG}"
if [[ "${1:-}" == "metadata" && " $* " == *" --no-deps "* ]]; then
  source='registry+https://github.com/rust-lang/crates.io-index'
  if [[ "${FAKE_TRAITS_MODE}" == "bad-source" ]]; then
    source='git+https://example.invalid/traits'
  fi
  jq --null-input --arg source "${source}" '{packages:[{dependencies:[{
    name:"yaml-sigil-traits", req:"=0.4.0-rc.1", source:$source,
    registry:null, rename:null}]}]}'
  exit 0
fi
if [[ "${1:-}" == "info" && "$*" == \
  "info --quiet --registry crates-io yaml-sigil-traits@0.4.0-rc.1" ]]; then
  exit 0
fi
if [[ "${1:-}" == "metadata" ]]; then
  if [[ "${FAKE_TRAITS_MODE}" == "extra-source" ]]; then
    jq --null-input '{packages:[
      {name:"yaml-sigil-traits", version:"0.4.0-rc.1",
       source:"registry+https://github.com/rust-lang/crates.io-index"},
      {name:"yaml-sigil-traits", version:"9.9.9",
       source:"git+https://example.invalid/traits"}]}'
  else
    jq --null-input '{packages:[{
      name:"yaml-sigil-traits", version:"0.4.0-rc.1",
      source:"registry+https://github.com/rust-lang/crates.io-index"}]}'
  fi
  exit 0
fi
exit 2
""",
                encoding="utf-8",
            )
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                """#!/usr/bin/env bash
set -eu
output=''
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == '--output' ]]; then
    shift
    output="$1"
  fi
  shift
done
printf '%s' '{"version":{"num":"0.4.0-rc.1","yanked":false}}' >"${output}"
printf '200'
""",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o755)
            fake_curl.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "FAKE_CARGO_LOG": str(calls),
                    "FAKE_TRAITS_MODE": mode,
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                }
            )
            result = subprocess.run(
                ["bash", str(VERIFY_TRAITS_PATH)],
                cwd=SCRIPT_DIR.parent.parent,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            log = calls.read_text(encoding="utf-8") if calls.exists() else ""
            return result, log

    def test_exact_named_registry_traits_identity_passes(self) -> None:
        result, log = self.run_preflight("exact")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "info --quiet --registry crates-io yaml-sigil-traits@0.4.0-rc.1",
            log,
        )

    def test_alternate_traits_source_fails_closed(self) -> None:
        result, _ = self.run_preflight("bad-source")
        self.assertNotEqual(result.returncode, 0)

    def test_additional_resolved_traits_identity_fails_closed(self) -> None:
        result, _ = self.run_preflight("extra-source")
        self.assertNotEqual(result.returncode, 0)


class ReleasePullRequestFixtureTests(unittest.TestCase):
    FAKE_GIT = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
log_path = Path(os.environ["GH_FIXTURE_LOG"])
if os.environ.get("GH_FIXTURE_PHASE") == "finalize" and args == ["rev-parse", "HEAD"]:
    print(os.environ["GH_FIXTURE_COMMIT"])
    raise SystemExit(0)
if "push" in args:
    with log_path.open("a", encoding="utf-8") as log:
        log.write(json.dumps({"method": "GIT", "endpoint": "push", "args": args}) + "\n")
    if os.environ["GH_FIXTURE_MODE"] == "lease-race":
        raise SystemExit(1)
    state_path = Path(os.environ["GH_FIXTURE_STATE_FILE"])
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    state["target_created"] = True
    state_path.write_text(json.dumps(state), encoding="utf-8")
    print("To https://github.com/fixture/repository.git")
    raise SystemExit(0)
if args[:3] == ["fetch", "--no-tags", "--force"]:
    raise SystemExit(0)
if args[:2] == ["rev-parse", "--verify"] and "automation/release-staging" in args[2]:
    print(os.environ["GH_FIXTURE_COMMIT"])
    raise SystemExit(0)
raise SystemExit(subprocess.run([os.environ["FAKE_REAL_GIT"], *args]).returncode)
'''

    FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
method = "GET"
if "--method" in args:
    method = args[args.index("--method") + 1]
endpoint = next(
    value for value in args if value == "graphql" or value.startswith(("repos/", "users/"))
)
payload = sys.stdin.read() if "--input" in args else ""
state_path = Path(os.environ["GH_FIXTURE_STATE_FILE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {}
with Path(os.environ["GH_FIXTURE_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps({
        "method": method,
        "endpoint": endpoint,
        "args": args,
        "payload": payload,
        "expected_base_tree": os.environ["GH_FIXTURE_BASE_TREE"],
    }) + "\n")

def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")

def form(name):
    prefix = f"{name}="
    return next((value[len(prefix):] for value in args if value.startswith(prefix)), "")

repo = os.environ["GITHUB_REPOSITORY"]
head = os.environ["GITHUB_SHA"]
commit = os.environ["GH_FIXTURE_COMMIT"]
existing = os.environ["GH_FIXTURE_EXISTING"]
other = os.environ["GH_FIXTURE_OTHER"]
mode = os.environ["GH_FIXTURE_MODE"]
bot = os.environ["GH_FIXTURE_BOT"]
bot_id = os.environ["GH_FIXTURE_BOT_ID"]
bot_email = f"{bot_id}+{bot}@users.noreply.github.com"
dco = f"Signed-off-by: {bot} <{bot_email}>"
message = f"{os.environ['RELEASE_TITLE']}\n\n{dco}"
main_endpoint = f"repos/{repo}/git/ref/heads/main"
target_endpoint = f"repos/{repo}/git/ref/heads/{os.environ['RELEASE_BRANCH']}"
matching_endpoint = (
    f"repos/{repo}/git/matching-refs/heads/{os.environ['RELEASE_BRANCH']}"
)
staging_branch = (
    f"automation/release-staging-{os.environ['GITHUB_RUN_ID']}-"
    f"{os.environ['GITHUB_RUN_ATTEMPT']}"
)
staging_endpoint = f"repos/{repo}/git/refs/heads/{staging_branch}"
staging_matching_endpoint = f"repos/{repo}/git/matching-refs/heads/{staging_branch}"

if endpoint == main_endpoint:
    state["main_reads"] = state.get("main_reads", 0) + 1
    stale = (
        (mode == "stale" and state["main_reads"] > 1)
        or (mode == "late-stale" and state["main_reads"] > 2)
    )
    value = other if stale else head
    save()
    print(value if "--jq" in args else json.dumps({"object": {"sha": value}}))
elif endpoint == f"users/{bot}":
    print(json.dumps({"login": bot, "id": int(bot_id)}))
elif endpoint == staging_matching_endpoint:
    if state.get("staging_created"):
        print(json.dumps([{
            "ref": f"refs/heads/{staging_branch}",
            "object": {"type": "commit", "sha": commit},
        }]))
    else:
        print("[]")
elif endpoint == matching_endpoint:
    if mode == "ref-lookup-failure":
        sys.exit(1)
    if mode in (
        "foreign",
        "foreign-committer",
        "invalid-existing-committer",
        "invalid-existing-raw-committer",
        "wrong-pr-base",
        "existing-success",
        "existing-ready-success",
        "existing-ready-transition-failure",
        "lease-race",
    ):
        print(json.dumps([{
            "ref": f"refs/heads/{os.environ['RELEASE_BRANCH']}",
            "object": {"type": "commit", "sha": existing},
        }]))
    else:
        print("[]")
elif endpoint == target_endpoint and method == "GET":
    if state.get("target_created"):
        value = other if mode == "wrong-ref" and state.get("target_created") else commit
        print(value if "--jq" in args else json.dumps({
            "ref": f"refs/heads/{os.environ['RELEASE_BRANCH']}",
            "object": {"type": "commit", "sha": value},
        }))
    else:
        sys.exit(1)
elif "/compare/main..." in endpoint:
    author = "someone-else" if mode == "foreign" else bot
    committer = "someone-else" if mode == "foreign-committer" else "web-flow"
    print(json.dumps({
        "ahead_by": 1,
        "commits": [{
            "author": {"login": author, "id": int(bot_id)},
            "committer": {"login": committer, "id": 19864447},
        }],
    }))
elif endpoint == f"repos/{repo}/git/refs" and method == "POST":
    ref = form("ref")
    if ref == f"refs/heads/{os.environ['RELEASE_BRANCH']}":
        state["target_created"] = True
    if ref == f"refs/heads/{staging_branch}":
        state["staging_created"] = True
    save()
    if mode == "malformed-staging-response" and ref == f"refs/heads/{staging_branch}":
        print(json.dumps({"ref": "refs/heads/unexpected", "object": {"type": "commit", "sha": form("sha")}}))
    else:
        print(json.dumps({"ref": ref, "object": {"type": "commit", "sha": form("sha")}}))
elif endpoint == staging_endpoint and method == "DELETE":
    state["staging_created"] = False
    save()
    print("{}")
elif f"repos/{repo}/git/refs/heads/" in endpoint and method == "PATCH":
    ref = "refs/heads/" + endpoint.split("/git/refs/heads/", 1)[1]
    print(json.dumps({"ref": ref, "object": {"type": "commit", "sha": form("sha")}}))
elif endpoint == f"repos/{repo}/git/trees" and method == "POST":
    print(json.dumps({"sha": os.environ["GH_FIXTURE_TREE"]}))
elif endpoint == f"repos/{repo}/git/commits" and method == "POST":
    if mode == "create-failure":
        sys.exit(1)
    print(json.dumps({
        "sha": commit,
        "author": {"name": bot, "email": bot_email},
        "committer": {
            "name": bot if mode == "invalid-created-raw-committer" else "GitHub",
            "email": bot_email
            if mode == "invalid-created-raw-committer" else "noreply@github.com",
        },
        "verification": {"verified": True, "reason": "valid"},
        "tree": {"sha": os.environ["GH_FIXTURE_TREE"]},
        "parents": [{"sha": head}],
        "message": message,
    }))
elif endpoint in (f"repos/{repo}/commits/{commit}", f"repos/{repo}/commits/{existing}"):
    if mode == "unreachable":
        sys.exit(1)
    print(json.dumps({
        "author": {"login": bot, "id": int(bot_id)},
        "committer": {
            "login": "someone-else"
            if mode == "invalid-existing-committer" and endpoint.endswith(existing)
            else "web-flow",
            "id": 19864447,
        },
        "commit": {
            "message": message,
            "author": {"name": bot, "email": bot_email},
            "committer": {
                "name": bot
                if mode == "invalid-existing-raw-committer" and endpoint.endswith(existing)
                else "GitHub",
                "email": bot_email
                if mode == "invalid-existing-raw-committer" and endpoint.endswith(existing)
                else "noreply@github.com",
            },
            "verification": {"verified": True, "reason": "valid"},
        },
        "parents": [{"sha": head}],
    }))
elif endpoint == f"repos/{repo}/pulls" and method == "GET":
    if mode == "wrong-pr-base":
        print(json.dumps([{
            "number": 8,
            "state": "open",
            "user": {"login": bot, "id": int(bot_id)},
            "head": {
                "repo": {"full_name": repo},
                "ref": os.environ["RELEASE_BRANCH"],
                "sha": commit,
            },
            "base": {"repo": {"full_name": repo}, "ref": "develop"},
        }]))
    elif mode in ("existing-ready-success", "existing-ready-transition-failure"):
        print(json.dumps([{
            "number": 7,
            "node_id": "PR_node_7",
            "state": "open",
            "user": {"login": bot, "id": int(bot_id)},
            "head": {
                "repo": {"full_name": repo},
                "ref": os.environ["RELEASE_BRANCH"],
                "sha": existing,
            },
            "base": {"repo": {"full_name": repo}, "ref": "main", "sha": head},
            "commits": 1,
            "draft": False,
        }]))
    else:
        print("[]")
elif endpoint == f"repos/{repo}/pulls" and method == "POST":
    state["pr_draft"] = form("draft") == "true"
    state["pr_title"] = form("title")
    state["pr_body"] = form("body")
    save()
    print(json.dumps({"number": 7}))
elif endpoint == f"repos/{repo}/pulls/7" and method == "PATCH":
    state["pr_title"] = form("title")
    state["pr_body"] = form("body")
    save()
    print(json.dumps({
        "number": 7,
        "node_id": "PR_node_7",
        "draft": state.get("pr_draft", False),
    }))
elif endpoint == f"repos/{repo}/pulls/7" and method == "GET":
    pr_head = commit if state.get("target_created") else existing
    print(json.dumps({
        "number": 7,
        "node_id": "PR_node_7",
        "state": "open",
        "user": {"login": bot, "id": int(bot_id)},
        "head": {
            "repo": {"full_name": repo},
            "ref": os.environ["RELEASE_BRANCH"],
            "sha": pr_head,
        },
        "base": {"repo": {"full_name": repo}, "ref": "main", "sha": head},
        "title": state.get("pr_title", os.environ["RELEASE_TITLE"]),
        "body": state.get("pr_body", "Release body."),
        "commits": 1,
        "draft": state.get("pr_draft", os.environ["RELEASE_DRAFT"] == "true"),
    }))
elif endpoint == "graphql":
    query = form("query")
    if mode == "existing-ready-transition-failure":
        print(json.dumps({"data": {}}))
    elif "convertPullRequestToDraft" in query:
        state["pr_draft"] = True
        save()
        print(json.dumps({"data": {"convertPullRequestToDraft": {
            "pullRequest": {"number": 7, "isDraft": True}
        }}}))
    elif "markPullRequestReadyForReview" in query:
        state["pr_draft"] = False
        save()
        print(json.dumps({"data": {"markPullRequestReadyForReview": {
            "pullRequest": {"number": 7, "isDraft": False}
        }}}))
    else:
        print(json.dumps({"data": {}}))
else:
    print("{}")
'''

    def run_fixture(
        self, mode: str, *, hold_draft: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
        with tempfile.TemporaryDirectory(prefix="release-pr-api-") as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            command("git", "init", "--initial-branch=main", cwd=repository)
            command("git", "config", "user.name", "Release Test", cwd=repository)
            command("git", "config", "user.email", "release-test@example.com", cwd=repository)
            (repository / "Cargo.toml").write_text("version = \"1.0.0\"\n", encoding="utf-8")
            command("git", "add", "Cargo.toml", cwd=repository)
            command("git", "commit", "-m", "baseline", cwd=repository)
            head = command("git", "rev-parse", "HEAD", cwd=repository).stdout.strip()
            base_tree = command(
                "git", "rev-parse", "HEAD^{tree}", cwd=repository
            ).stdout.strip()
            (repository / "Cargo.toml").write_text("version = \"1.0.1\"\n", encoding="utf-8")
            if mode == "added-file":
                (repository / "CHANGELOG.md").write_text("# Added\n", encoding="utf-8")

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(self.FAKE_GH, encoding="utf-8")
            fake_gh.chmod(0o755)
            fake_git = fake_bin / "git"
            fake_git.write_text(self.FAKE_GIT, encoding="utf-8")
            fake_git.chmod(0o755)
            body = root / "body.md"
            body.write_text("Release body.\n", encoding="utf-8")
            output = root / "github-output"
            output.write_text("", encoding="utf-8")
            log = root / "gh.log"
            log.touch()

            environment = os.environ.copy()
            environment.update(
                {
                    "APP_SLUG": "nvidia-yamlsigil-release-pr",
                    "GH_FIXTURE_BOT": "nvidia-yamlsigil-release-pr[bot]",
                    "GH_FIXTURE_BOT_ID": "318780254",
                    "GH_FIXTURE_BASE_TREE": base_tree,
                    "GH_FIXTURE_COMMIT": "2" * 40,
                    "GH_FIXTURE_EXISTING": "5" * 40,
                    "GH_FIXTURE_LOG": str(log),
                    "GH_FIXTURE_MODE": mode,
                    "GH_FIXTURE_OTHER": "3" * 40,
                    "GH_FIXTURE_STATE_FILE": str(root / "state.json"),
                    "GH_FIXTURE_TREE": "4" * 40,
                    "GH_TOKEN": "fixture-token",
                    "FAKE_REAL_GIT": command("which", "git", cwd=repository).stdout.strip(),
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_REPOSITORY": EXPECTED_REPOSITORY,
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_RUN_ID": "99",
                    "GITHUB_SHA": head,
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "RELEASE_BODY_FILE": str(body),
                    "RELEASE_BRANCH": "release-plz-next",
                    "RELEASE_DRAFT": "false",
                    "RELEASE_HOLD_DRAFT": "true" if hold_draft else "false",
                    "RELEASE_OPERATION": "update",
                    "RELEASE_TITLE": "chore(release): prepare test 1.0.1",
                }
            )
            result = subprocess.run(
                ["bash", str(UPDATE_PR_PATH)],
                cwd=repository,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            if result.returncode == 0:
                self.assertIn("commit_sha=" + "2" * 40, output.read_text(encoding="utf-8"))
                self.assertIn("pr_number=7", output.read_text(encoding="utf-8"))
            return result, calls

    def run_finalize_fixture(
        self,
        mode: str = "success",
        *,
        held_draft: bool = True,
        requested_draft: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
        with tempfile.TemporaryDirectory(prefix="release-pr-finalize-") as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            command("git", "init", "--initial-branch=main", cwd=repository)
            command("git", "config", "user.name", "Release Test", cwd=repository)
            command("git", "config", "user.email", "release-test@example.com", cwd=repository)
            (repository / "Cargo.toml").write_text(
                "version = \"1.0.0\"\n", encoding="utf-8"
            )
            command("git", "add", "Cargo.toml", cwd=repository)
            command("git", "commit", "-m", "baseline", cwd=repository)
            head = command("git", "rev-parse", "HEAD", cwd=repository).stdout.strip()
            base_tree = command(
                "git", "rev-parse", "HEAD^{tree}", cwd=repository
            ).stdout.strip()

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(self.FAKE_GH, encoding="utf-8")
            fake_gh.chmod(0o755)
            fake_git = fake_bin / "git"
            fake_git.write_text(self.FAKE_GIT, encoding="utf-8")
            fake_git.chmod(0o755)
            body = root / "body.md"
            body.write_text("Release body.\n", encoding="utf-8")
            output = root / "github-output"
            output.write_text("", encoding="utf-8")
            log = root / "gh.log"
            log.touch()
            state = root / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "target_created": True,
                        "pr_draft": held_draft,
                        "pr_title": "chore(release): prepare test 1.0.1",
                        "pr_body": "Release body.",
                    }
                ),
                encoding="utf-8",
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "APP_SLUG": "nvidia-yamlsigil-release-pr",
                    "GH_FIXTURE_BOT": "nvidia-yamlsigil-release-pr[bot]",
                    "GH_FIXTURE_BOT_ID": "318780254",
                    "GH_FIXTURE_BASE_TREE": base_tree,
                    "GH_FIXTURE_COMMIT": "2" * 40,
                    "GH_FIXTURE_EXISTING": "5" * 40,
                    "GH_FIXTURE_LOG": str(log),
                    "GH_FIXTURE_MODE": mode,
                    "GH_FIXTURE_OTHER": "3" * 40,
                    "GH_FIXTURE_PHASE": "finalize",
                    "GH_FIXTURE_STATE_FILE": str(state),
                    "GH_FIXTURE_TREE": "4" * 40,
                    "GH_TOKEN": "fixture-token",
                    "FAKE_REAL_GIT": command("which", "git", cwd=repository).stdout.strip(),
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_REPOSITORY": EXPECTED_REPOSITORY,
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_RUN_ID": "99",
                    "GITHUB_SHA": head,
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "RELEASE_BODY_FILE": str(body),
                    "RELEASE_BRANCH": "release-plz-next",
                    "RELEASE_COMMIT": "2" * 40,
                    "RELEASE_DRAFT": "true" if requested_draft else "false",
                    "RELEASE_HOLD_DRAFT": "true",
                    "RELEASE_OPERATION": "finalize",
                    "RELEASE_PR_NUMBER": "7",
                    "RELEASE_TITLE": "chore(release): prepare test 1.0.1",
                }
            )
            result = subprocess.run(
                ["bash", str(UPDATE_PR_PATH)],
                cwd=repository,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            if result.returncode == 0:
                self.assertIn("commit_sha=" + "2" * 40, output.read_text(encoding="utf-8"))
                self.assertIn("pr_number=7", output.read_text(encoding="utf-8"))
            return result, calls

    def test_app_git_objects_become_reachable_before_durable_ref(self) -> None:
        result, calls = self.run_fixture("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        endpoints = [(call["method"], call["endpoint"]) for call in calls]
        commit_index = endpoints.index(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/git/commits")
        )
        reachability_index = endpoints.index(
            ("GET", f"repos/{EXPECTED_REPOSITORY}/commits/" + "2" * 40)
        )
        target_index = endpoints.index(("GIT", "push"), reachability_index)
        self.assertLess(commit_index, reachability_index)
        self.assertLess(reachability_index, target_index)
        tree_call = next(
            call
            for call in calls
            if (call["method"], call["endpoint"])
            == ("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees")
        )
        self.assertEqual(
            json.loads(tree_call["payload"])["base_tree"],
            tree_call["expected_base_tree"],
        )
        push = calls[target_index]
        self.assertIn(
            "--force-with-lease=refs/heads/release-plz-next:", push["args"]
        )
        self.assertFalse(any("fixture-token" in arg for arg in push["args"]))

    def test_new_proposal_is_created_as_draft_while_validation_is_held(self) -> None:
        result, calls = self.run_fixture("success", hold_draft=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        create = next(
            call
            for call in calls
            if (call["method"], call["endpoint"])
            == ("POST", f"repos/{EXPECTED_REPOSITORY}/pulls")
        )
        self.assertIn("draft=true", create["args"])
        self.assertFalse(any(call["endpoint"] == "graphql" for call in calls))

    def test_existing_ready_proposal_is_held_before_git_object_mutation(self) -> None:
        result, calls = self.run_fixture(
            "existing-ready-success", hold_draft=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        endpoints = [(call["method"], call["endpoint"]) for call in calls]
        draft = endpoints.index(("GET", "graphql"))
        tree = endpoints.index(("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"))
        branch = endpoints.index(("GIT", "push"))
        self.assertLess(draft, tree)
        self.assertLess(draft, branch)

    def test_failed_draft_hold_never_creates_or_moves_git_objects(self) -> None:
        result, calls = self.run_fixture(
            "existing-ready-transition-failure", hold_draft=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not convert", result.stderr)
        self.assertFalse(
            any(
                call["method"] in {"POST", "PATCH", "GIT"}
                and call["endpoint"] != "graphql"
                for call in calls
            )
        )

    def test_finalize_marks_only_the_exact_held_app_pr_ready(self) -> None:
        result, calls = self.run_finalize_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        endpoints = [(call["method"], call["endpoint"]) for call in calls]
        commit = endpoints.index(
            ("GET", f"repos/{EXPECTED_REPOSITORY}/commits/" + "2" * 40)
        )
        transition = endpoints.index(("GET", "graphql"))
        self.assertLess(commit, transition)
        self.assertFalse(
            any(
                call["method"] in {"POST", "PATCH", "DELETE", "GIT"}
                for call in calls
            )
        )

    def test_finalize_rejects_a_pr_that_is_already_ready(self) -> None:
        result, calls = self.run_finalize_fixture(held_draft=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not the exact held draft", result.stderr)
        self.assertFalse(any(call["endpoint"] == "graphql" for call in calls))

    def test_finalize_requires_an_exact_graphql_transition_response(self) -> None:
        result, calls = self.run_finalize_fixture(
            mode="existing-ready-transition-failure"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not mark", result.stderr)
        self.assertEqual(
            sum(call["endpoint"] == "graphql" for call in calls), 1
        )

    def test_success_removes_and_verifies_the_exact_staging_ref(self) -> None:
        result, calls = self.run_fixture("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        staging = "automation/release-staging-99-1"
        endpoints = [(call["method"], call["endpoint"]) for call in calls]
        delete = (
            "DELETE",
            f"repos/{EXPECTED_REPOSITORY}/git/refs/heads/{staging}",
        )
        verify = (
            "GET",
            f"repos/{EXPECTED_REPOSITORY}/git/matching-refs/heads/{staging}",
        )
        self.assertIn(delete, endpoints)
        self.assertIn(verify, endpoints)
        self.assertLess(endpoints.index(delete), endpoints.index(verify))

    def test_malformed_staging_creation_response_is_cleaned_up(self) -> None:
        result, calls = self.run_fixture("malformed-staging-response")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected staging ref", result.stderr)
        self.assertIn(
            (
                "DELETE",
                f"repos/{EXPECTED_REPOSITORY}/git/refs/heads/"
                "automation/release-staging-99-1",
            ),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_existing_app_branch_uses_the_exact_captured_sha_lease(self) -> None:
        result, calls = self.run_fixture("existing-success")
        self.assertEqual(result.returncode, 0, result.stderr)
        push = next(call for call in calls if call["method"] == "GIT")
        self.assertIn(
            "--force-with-lease=refs/heads/release-plz-next:" + "5" * 40,
            push["args"],
        )

    def test_concurrent_release_branch_change_fails_without_pr_mutation(self) -> None:
        result, calls = self.run_fixture("lease-race")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed before its atomic update", result.stderr)
        self.assertFalse(
            any(
                call["method"] == "POST"
                and call["endpoint"] == f"repos/{EXPECTED_REPOSITORY}/pulls"
                for call in calls
            )
        )

    def test_added_release_file_is_rejected_before_api_writes(self) -> None:
        result, calls = self.run_fixture("added-file")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only modify existing files", result.stderr)
        self.assertFalse(any(call["method"] != "GET" for call in calls))

    def test_stale_main_never_moves_the_durable_ref(self) -> None:
        result, calls = self.run_fixture("stale")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Main advanced", result.stderr)
        self.assertNotIn(("POST", f"repos/{EXPECTED_REPOSITORY}/pulls"), [(c["method"], c["endpoint"]) for c in calls])

    def test_late_stale_main_never_moves_the_durable_ref(self) -> None:
        result, calls = self.run_fixture("late-stale")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("before the durable release branch update", result.stderr)
        self.assertFalse(any(call["method"] == "GIT" for call in calls))
        self.assertNotIn(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/pulls"),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_foreign_release_branch_is_preserved(self) -> None:
        result, calls = self.run_fixture("foreign")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-App commit", result.stderr)
        self.assertNotIn(("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"), [(c["method"], c["endpoint"]) for c in calls])

    def test_foreign_release_branch_committer_is_preserved(self) -> None:
        result, calls = self.run_fixture("foreign-committer")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-App commit", result.stderr)
        self.assertNotIn(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_existing_release_commit_requires_the_exact_app_committer(self) -> None:
        result, calls = self.run_fixture("invalid-existing-committer")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid App commit", result.stderr)
        self.assertNotIn(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_existing_release_commit_requires_exact_raw_github_committer(self) -> None:
        result, calls = self.run_fixture("invalid-existing-raw-committer")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid App commit", result.stderr)
        self.assertNotIn(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_created_release_commit_requires_exact_raw_github_committer(self) -> None:
        result, calls = self.run_fixture("invalid-created-raw-committer")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("generated App commit as valid", result.stderr)
        self.assertFalse(any(call["method"] == "GIT" for call in calls))

    def test_release_ref_lookup_failure_fails_before_api_writes(self) -> None:
        result, calls = self.run_fixture("ref-lookup-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call["method"] != "GET" for call in calls))

    def test_existing_pr_ref_collision_fails_before_git_object_writes(self) -> None:
        result, calls = self.run_fixture("wrong-pr-base")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected ownership or refs", result.stderr)
        self.assertNotIn(
            ("POST", f"repos/{EXPECTED_REPOSITORY}/git/trees"),
            [(call["method"], call["endpoint"]) for call in calls],
        )

    def test_unreachable_commit_never_moves_the_durable_ref(self) -> None:
        result, calls = self.run_fixture("unreachable")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not resolve", result.stderr)
        self.assertNotIn(("POST", f"repos/{EXPECTED_REPOSITORY}/pulls"), [(c["method"], c["endpoint"]) for c in calls])

    def test_wrong_explicit_release_ref_never_opens_a_pull_request(self) -> None:
        result, calls = self.run_fixture("wrong-ref")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not identify", result.stderr)
        self.assertNotIn(("POST", f"repos/{EXPECTED_REPOSITORY}/pulls"), [(c["method"], c["endpoint"]) for c in calls])


if __name__ == "__main__":
    unittest.main()

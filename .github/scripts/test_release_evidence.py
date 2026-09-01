#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for canonical settings and physical archive evidence."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_evidence as evidence


PACKAGE = "yaml-sigil-traits"
VERSION = "0.4.0"
COMMIT = "a" * 40
ROOT = f"{PACKAGE}-{VERSION}"


def archive() -> bytes:
    vcs = json.dumps(
        {"git": {"sha1": COMMIT}, "path_in_vcs": ""},
        separators=(",", ":"),
    ).encode()
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:gz",
        format=tarfile.GNU_FORMAT,
    ) as cargo:
        for path, body in (
            (f"{ROOT}/.cargo_vcs_info.json", vcs),
            (f"{ROOT}/src/lib.rs", b"pub fn fixture() {}\n"),
        ):
            info = tarfile.TarInfo(path)
            info.size = len(body)
            info.mode = 0o644
            info.mtime = evidence.CARGO_ARCHIVE_MTIME
            cargo.addfile(info, io.BytesIO(body))
    return output.getvalue()


def rechecksum(header: bytearray) -> None:
    header[148:156] = b"        "
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode()


def alter_second_header(mutator: object) -> bytes:
    body = bytearray(gzip.decompress(archive()))
    first_size = int(body[124:136].rstrip(b"\0 ") or b"0", 8)
    second = 512 + ((first_size + 511) // 512) * 512
    header = bytearray(body[second : second + 512])
    mutator(header)  # type: ignore[operator]
    rechecksum(header)
    body[second : second + 512] = header
    return gzip.compress(body, mtime=0)


class EvidenceTests(unittest.TestCase):
    def test_settings_command_writes_digit_suffixed_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            with mock.patch(
                "sys.argv",
                [
                    "release_evidence.py",
                    "settings",
                    "--repository",
                    "NVIDIA/yaml-sigil-traits",
                    "--release-sha",
                    COMMIT,
                    "--run-id",
                    "123",
                    "--run-attempt",
                    "1",
                    "--github-output",
                    str(output),
                ],
            ):
                self.assertEqual(evidence.main(), 0)

            digest = evidence.settings_evidence_sha256(
                "NVIDIA/yaml-sigil-traits", COMMIT, 123, 1
            )
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                f"ruleset_evidence_sha256={digest}\n",
            )

    def test_workflow_output_names_remain_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            for name in ("1leading", "Upper", "has-dash"):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(evidence.EvidenceError, "output name"):
                        evidence.append_output(output, name, "value")

    def test_inventory_encoding_matches_the_cross_language_vector(self) -> None:
        entry = evidence.ArchiveEntry(
            "file",
            "a" * 64,
            ord("0"),
            0o644,
            evidence.GNU_OCTAL_ZERO,
            evidence.GNU_OCTAL_ZERO,
            evidence.CARGO_ARCHIVE_MTIME,
            b"",
            b"",
            evidence.GNU_OCTAL_ZERO,
            evidence.GNU_OCTAL_ZERO,
            b"body",
        )
        self.assertEqual(
            evidence._inventory_sha256({"file": entry}),
            "3c31e83038d128e6babaf8adcbcda975c18db383b6999a097d7a30c3f3a87a0d",
        )

    def test_untouched_cargo_shape_is_accepted(self) -> None:
        self.assertRegex(
            evidence.crate_inventory_sha256(archive(), PACKAGE, VERSION, COMMIT, ""),
            r"^[0-9a-f]{64}$",
        )

    def test_hidden_pseudo_entry_and_raw_path_alias_are_rejected(self) -> None:
        pseudo = alter_second_header(lambda header: header.__setitem__(156, ord("x")))
        with self.assertRaisesRegex(evidence.EvidenceError, "entry type"):
            evidence.crate_inventory_sha256(pseudo, PACKAGE, VERSION, COMMIT, "")

        def alias(header: bytearray) -> None:
            path = f"{ROOT}/src//lib.rs".encode()
            header[:100] = path.ljust(100, b"\0")

        with self.assertRaisesRegex(evidence.EvidenceError, "path"):
            evidence.crate_inventory_sha256(
                alter_second_header(alias),
                PACKAGE,
                VERSION,
                COMMIT,
                "",
            )

    def test_second_member_trailing_bytes_and_post_terminator_record_are_rejected(self) -> None:
        original = archive()
        for altered in (original + original, original + b"trailing"):
            with self.subTest(length=len(altered)):
                with self.assertRaisesRegex(evidence.EvidenceError, "gzip member|trailing"):
                    evidence.crate_inventory_sha256(altered, PACKAGE, VERSION, COMMIT, "")

        body = bytearray(gzip.decompress(original))
        record = bytearray(512)
        record[0] = ord("x")
        body.extend(record)
        with self.assertRaisesRegex(evidence.EvidenceError, "after its tar terminator"):
            evidence.crate_inventory_sha256(
                gzip.compress(body, mtime=0),
                PACKAGE,
                VERSION,
                COMMIT,
                "",
            )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Require the exact ordered crates.io package set and reject every implicit or
# explicit Cargo binary target. This is a source-publication boundary, not an
# archive builder or executable-artifact check.

set -euo pipefail

# Reject an empty policy rather than accidentally accepting every package.
if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 CRATE [CRATE ...]" >&2
  exit 2
fi

expected='[]'
for crate in "$@"; do
  # Keep crate names safe for both Cargo metadata matching and diagnostics.
  if [[ ! "${crate}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    echo "Invalid crate name: ${crate}" >&2
    exit 2
  fi
  expected="$(
    jq --compact-output --arg crate "${crate}" '. + [$crate]' <<<"${expected}"
  )"
done

cargo metadata --no-deps --format-version 1 \
  | jq --exit-status --argjson expected "${expected}" '
      [
        .packages[]
        | select(.publish != null and (.publish | index("crates-io")))
      ] as $packages
      | ($packages | map(.name)) == $expected
        and all($packages[]; all(.targets[]; .kind | index("bin") | not))
    ' >/dev/null

echo "Validated library-only crates.io package order: $*."

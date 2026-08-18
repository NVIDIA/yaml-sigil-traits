#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Verify that the versions in the checked-out manifests are available through
# both the crates.io API and Cargo's ordinary registry client.

set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 CRATE [CRATE ...]" >&2
  exit 2
fi

metadata="$(cargo metadata --no-deps --format-version 1)"
user_agent="yaml-sigil-release-workflow/1.0"

for crate in "$@"; do
  if [[ ! "${crate}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    echo "Invalid crate name: ${crate}" >&2
    exit 2
  fi

  package_count="$(
    jq --arg crate "${crate}" \
      '[.packages[] | select(.name == $crate)] | length' <<<"${metadata}"
  )"
  if [[ "${package_count}" != "1" ]]; then
    echo "Expected one workspace package named ${crate}; found ${package_count}." >&2
    exit 1
  fi

  version="$(
    jq --raw-output --arg crate "${crate}" \
      '.packages[] | select(.name == $crate) | .version' <<<"${metadata}"
  )"

  # Registry propagation is asynchronous. Bound the wait so a partial release
  # remains visible and can be inspected before an operator retries it.
  for attempt in {1..30}; do
    if curl --fail --silent --show-error \
      --user-agent "${user_agent}" \
      "https://crates.io/api/v1/crates/${crate}/${version}" \
      | jq -e --arg version "${version}" \
        '.version.num == $version and .version.yanked == false' >/dev/null; then
      break
    fi

    if [[ "${attempt}" -eq 30 ]]; then
      echo "crates.io did not expose ${crate} ${version} as non-yanked." >&2
      exit 1
    fi
    sleep 10
  done

  cargo info --quiet --registry crates-io "${crate}@${version}" >/dev/null
  echo "Verified ${crate} ${version} on crates.io."
done

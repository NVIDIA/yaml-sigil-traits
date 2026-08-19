#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Verify exact non-yanked crate versions through the crates.io API. The default
# mode reads versions from the checked-out manifests, waits for propagation,
# and confirms Cargo can resolve them. `--check-version` performs one readiness
# check and exits 3 when any requested package is not yet available.

set -euo pipefail

mode="wait"
requested_version=""
# Select the non-polling prerequisite check used by release proposals.
if [[ "${1:-}" == "--check-version" ]]; then
  # The readiness form requires one version followed by at least one crate.
  if [[ "$#" -lt 3 ]]; then
    echo "usage: $0 [--check-version VERSION] CRATE [CRATE ...]" >&2
    exit 2
  fi
  mode="check"
  requested_version="$2"
  shift 2
  # Reject strings that cannot represent the Cargo SemVer used in the URL.
  if [[ ! "${requested_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    echo "Invalid package version: ${requested_version}" >&2
    exit 2
  fi
fi

# Require an explicit crate allowlist so a caller cannot verify nothing.
if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 [--check-version VERSION] CRATE [CRATE ...]" >&2
  exit 2
fi

metadata=""
# Publication verification derives each exact version from trusted manifests.
if [[ "${mode}" == "wait" ]]; then
  metadata="$(cargo metadata --no-deps --format-version 1)"
fi

response_file="$(mktemp)"
trap 'rm -f "${response_file}"' EXIT
user_agent="yaml-sigil-release-workflow/1.0"
unavailable=false

for crate in "$@"; do
  # Accept only ordinary crates.io names before interpolating an API URL.
  if [[ ! "${crate}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    echo "Invalid crate name: ${crate}" >&2
    exit 2
  fi

  version="${requested_version}"
  # Publication verification requires exactly one matching workspace package.
  if [[ "${mode}" == "wait" ]]; then
    package_count="$(
      jq --arg crate "${crate}" \
        '[.packages[] | select(.name == $crate)] | length' <<<"${metadata}"
    )"
    # A missing or duplicate package makes manifest-derived verification unsafe.
    if [[ "${package_count}" != "1" ]]; then
      echo "Expected one workspace package named ${crate}; found ${package_count}." >&2
      exit 1
    fi
    version="$(
      jq --raw-output --arg crate "${crate}" \
        '.packages[] | select(.name == $crate) | .version' <<<"${metadata}"
    )"
  fi

  # Readiness checks run once; publication verification allows bounded registry
  # propagation before exposing a partial release for operator inspection.
  attempts=30
  # The non-polling mode must return control to the proposal workflow quickly.
  if [[ "${mode}" == "check" ]]; then
    attempts=1
  fi
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    status="$(
      curl --silent --show-error \
        --output "${response_file}" \
        --write-out '%{http_code}' \
        --user-agent "${user_agent}" \
        "https://crates.io/api/v1/crates/${crate}/${version}"
    )"
    # Registry or authorization errors must not masquerade as publication lag.
    if [[ "${status}" != "200" && "${status}" != "404" ]]; then
      echo "crates.io returned HTTP ${status} for ${crate} ${version}." >&2
      exit 1
    fi
    # Stop only after the exact non-yanked version becomes visible.
    if [[ "${status}" == "200" ]] \
      && jq --exit-status --arg version "${version}" \
        '.version.num == $version and .version.yanked == false' \
        "${response_file}" >/dev/null; then
      break
    fi
    # Readiness absence is an ordered wait state, not a failed workflow.
    if [[ "${mode}" == "check" ]]; then
      unavailable=true
      break
    fi
    # Surface bounded propagation failure instead of waiting indefinitely.
    if [[ "${attempt}" -eq "${attempts}" ]]; then
      echo "crates.io did not expose ${crate} ${version} as non-yanked." >&2
      exit 1
    fi
    sleep 10
  done

  # Cargo resolution is part of post-publication verification, not readiness.
  if [[ "${mode}" == "wait" ]]; then
    cargo info --quiet --registry crates-io "${crate}@${version}" >/dev/null
    echo "Verified ${crate} ${version} on crates.io."
  fi
done

# Exit 3 lets release-proposal automation record a successful ordered wait.
if [[ "${unavailable}" == "true" ]]; then
  exit 3
fi

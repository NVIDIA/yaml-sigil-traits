#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Generate the provider-owned release diff after release-plz analyzes changes.
# Provider-neutral version mutation remains in xtask. This wrapper adds only
# GitHub workflow outputs, exact-tag promotion checks, and the PR body.

set -euo pipefail

: "${EFFECTIVE_BUMP:?EFFECTIVE_BUMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${MODE:?MODE is required}"
: "${PUBLISHED_VERSION:?PUBLISHED_VERSION is required}"
: "${REGISTRY_MANIFEST_PATH:?REGISTRY_MANIFEST_PATH is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
# An empty marker is meaningful because it clears an earlier override.
if [[ ! -v RELEASE_MARKER ]]; then
  echo "RELEASE_MARKER must be set, even when empty." >&2
  exit 2
fi
# The baseline helper must provide one clean detached official manifest.
if [[ ! -f "${REGISTRY_MANIFEST_PATH}" ]]; then
  echo "The official registry baseline manifest is missing." >&2
  exit 2
fi

# Select only repository-specific names, changelogs, tags, and sync behavior.
case "${GITHUB_REPOSITORY}" in
  NVIDIA/yaml-sigil-traits)
    release_subject="yaml-sigil-traits"
    title_subject="yaml-sigil-traits"
    changelog_paths=(CHANGELOG.md)
    published_tags=("v${PUBLISHED_VERSION}")
    release_policy="The resulting GitHub Release is source-only and receives no binary assets."
    sync_commands=false
    ;;
  NVIDIA/yaml-sigil-rs)
    release_subject="all four YamlSigil Rust crates"
    title_subject="YamlSigil"
    changelog_paths=('crates/*/CHANGELOG.md')
    published_tags=(
      "yaml-sigil-core-v${PUBLISHED_VERSION}"
      "yaml-sigil-transcription-v${PUBLISHED_VERSION}"
      "yaml-sigil-signing-v${PUBLISHED_VERSION}"
      "yaml-sigil-verification-v${PUBLISHED_VERSION}"
    )
    release_policy="The resulting GitHub Releases are source-only and receive no binary assets."
    sync_commands=true
    ;;
  *)
    echo "Unsupported release repository: ${GITHUB_REPOSITORY}." >&2
    exit 2
    ;;
esac

date="$(date -u +%F)"
# Stable promotion copies reviewed RC notes and requires exact tag provenance.
if [[ "${MODE}" == "promote-stable" ]]; then
  # Stable promotion is valid only when no source commit follows the published
  # RC. Otherwise another reviewed RC must capture the intervening changes.
  for tag in "${published_tags[@]}"; do
    # Every package tag in a workspace train must resolve to current main.
    if [[ "$(git rev-parse "${tag}^{commit}")" != "${GITHUB_SHA}" ]]; then
      echo "Stable promotion requires main to be the exact published RC source." >&2
      exit 1
    fi
  done
  target="$(cargo xtask release-version promote-stable --date "${date}")"
  draft=false
else
  # release-plz provides Conventional Commit analysis and changelog generation;
  # xtask then normalizes its result into the repository's RC policy.
  release-plz update \
    --config .release-plz.toml \
    --registry-manifest-path "${REGISTRY_MANIFEST_PATH}"
  release_notes=false
  # A changelog diff distinguishes a substantive proposal from an empty seed.
  if ! git diff --quiet -- "${changelog_paths[@]}"; then
    release_notes=true
  fi
  release_notes_arg=()
  # Request complete per-crate changelogs only for a substantive proposal.
  if [[ "${release_notes}" == "true" ]]; then
    release_notes_arg+=(--release-notes)
  fi
  target="$(
    cargo xtask release-version candidate \
      --published "${PUBLISHED_VERSION}" \
      --bump "${EFFECTIVE_BUMP}" \
      --date "${date}" \
      "${release_notes_arg[@]}"
  )"
  # Substantive proposals are reviewable; empty next-version seeds stay draft.
  if [[ "${release_notes}" == "true" ]]; then
    draft=false
  else
    # An empty post-publication seed shows the next version without implying
    # that an otherwise empty release is ready to merge.
    draft=true
  fi
fi

# Only the multi-crate workspace requires internal dependency synchronization.
if [[ "${sync_commands}" == "true" ]]; then
  # The version transaction is incomplete until every internal dependency
  # requirement matches and the non-mutating follow-up check passes.
  cargo xtask sync-workspace-versions
  cargo xtask sync-workspace-versions --check
fi
cargo xtask release-version check
cargo metadata --no-deps --format-version 1 >/dev/null
# Fail closed on analyzer errors after version normalization and before the App
# creates any Git object, branch, or pull request.
cargo xtask release-version check-compatibility \
  --baseline-manifest "${REGISTRY_MANIFEST_PATH}" \
  --current-manifest Cargo.toml \
  --package yaml-sigil-traits \
  --expected-baseline-version "${PUBLISHED_VERSION}" \
  --expected-current-version "${target}" \
  --intent "${EFFECTIVE_BUMP}"
git diff --check

title="chore(release): prepare ${title_subject} ${target}"
body_file="${RUNNER_TEMP}/release-pr-body.md"
{
  echo "This automated proposal prepares ${release_subject} at \`${target}\`."
  echo
  echo "Reviewing and merging this pull request authorizes the protected official publication workflow."
  echo "${release_policy}"
  # Persist only an explicit version-line override in the pull-request body.
  if [[ -n "${RELEASE_MARKER}" ]]; then
    echo
    echo "${RELEASE_MARKER}"
  fi
} >"${body_file}"

{
  echo "target=${target}"
  echo "title=${title}"
  echo "draft=${draft}"
} >>"${GITHUB_OUTPUT}"

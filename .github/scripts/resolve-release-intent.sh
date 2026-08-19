#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Resolve the release mode and version bump. Manual choices replace the prior
# override, while push and post-publication events preserve the hidden marker
# already reviewed in an open release PR. A manual `auto` clears the marker.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${MANUAL_DISPATCH:?MANUAL_DISPATCH is required}"
: "${REQUESTED_BUMP:?REQUESTED_BUMP is required}"
: "${REQUESTED_MODE:?REQUESTED_MODE is required}"

# Accept only the two documented release paths.
case "${REQUESTED_MODE}" in
  next-candidate | promote-stable) ;;
  *)
    echo "Unsupported release mode: ${REQUESTED_MODE}." >&2
    exit 2
    ;;
esac
# Accept only bump values exposed by the manual workflow form.
case "${REQUESTED_BUMP}" in
  auto | patch | minor | major) ;;
  *)
    echo "Unsupported release bump: ${REQUESTED_BUMP}." >&2
    exit 2
    ;;
esac

existing_body="$(
  gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls" \
    -f state=open -f "head=${GITHUB_REPOSITORY%%/*}:release-plz-next" \
    --jq '.[0].body // ""'
)"
retained_bump="$(
  sed -n \
    's/.*<!-- yaml-sigil-release-bump: \(patch\|minor\|major\) -->.*/\1/p' \
    <<<"${existing_body}" | head -1
)"

mode="${REQUESTED_MODE}"
# Stable promotion ignores bump calculation and clears any earlier override.
if [[ "${mode}" == "promote-stable" ]]; then
  bump=auto
  marker=""
# A manual dispatch deliberately replaces the retained release intent.
elif [[ "${MANUAL_DISPATCH}" == "true" ]]; then
  bump="${REQUESTED_BUMP}"
  # Selecting auto is the explicit operation that removes a prior override.
  if [[ "${bump}" == "auto" ]]; then
    marker=""
  else
    marker="<!-- yaml-sigil-release-bump: ${bump} -->"
  fi
# Background updates retain the last reviewed explicit bump selection.
elif [[ -n "${retained_bump}" ]]; then
  bump="${retained_bump}"
  marker="<!-- yaml-sigil-release-bump: ${bump} -->"
else
  bump=auto
  marker=""
fi

{
  echo "mode=${mode}"
  echo "bump=${bump}"
  echo "marker=${marker}"
} >>"${GITHUB_OUTPUT}"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Resolve the release mode and version bump. Manual choices replace the prior
# override, while push and post-publication events preserve the hidden marker
# already reviewed in an open release PR. Every candidate records its intent.

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
  patch | minor | major) ;;
  *)
    echo "Unsupported release bump: ${REQUESTED_BUMP}." >&2
    exit 2
    ;;
esac

release_app_login="nvidia-yamlsigil-release-pr[bot]"
release_app_id=318780254
existing_prs="$(
  gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls" \
    -f state=open -f "head=${GITHUB_REPOSITORY%%/*}:release-plz-next"
)"
# Preserve intent only from at most one exact App-owned same-repository PR.
if ! jq -e \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg login "${release_app_login}" \
  --argjson user_id "${release_app_id}" \
  'type == "array" and length <= 1 and
   (length == 0 or (.[0] |
     .state == "open" and
     .user.login == $login and .user.id == $user_id and
     .head.ref == "release-plz-next" and
     .head.repo.full_name == $repository and
     .base.ref == "main" and .base.repo.full_name == $repository and
     (.body == null or (.body | type == "string"))))' \
  >/dev/null <<<"${existing_prs}"; then
  echo "The existing release proposal lookup is ambiguous or unauthorized." >&2
  exit 1
fi
existing_body="$(
  jq -r 'if length == 0 then "" else (.[0].body // "") end' \
    <<<"${existing_prs}"
)"
marker_like_count="$(
  jq -nr --arg body "${existing_body}" \
    '$body | [match("yaml-sigil-release-bump:"; "g")] | length'
)"
exact_markers="$(
  jq -cn --arg body "${existing_body}" \
    '$body | split("\n") |
     map(select(test("^<!-- yaml-sigil-release-bump: (patch|minor|major) -->$")))'
)"
exact_marker_count="$(jq -r 'length' <<<"${exact_markers}")"
# Reject duplicate markers and every embedded or malformed marker-like value.
if [[ "${marker_like_count}" != "${exact_marker_count}" \
  || "${exact_marker_count}" -gt 1 ]]; then
  echo "The existing release proposal has ambiguous release intent." >&2
  exit 1
fi
retained_bump="$(
  jq -r \
    'if length == 0 then "" else
       (.[0] | capture("yaml-sigil-release-bump: (?<bump>patch|minor|major)").bump)
     end' \
    <<<"${exact_markers}"
)"

mode="${REQUESTED_MODE}"
# Stable promotion keeps a deterministic patch intent for compatibility checks.
if [[ "${mode}" == "promote-stable" ]]; then
  bump="patch"
  marker=""
# A manual dispatch deliberately replaces the retained release intent.
elif [[ "${MANUAL_DISPATCH}" == "true" ]]; then
  bump="${REQUESTED_BUMP}"
  marker="<!-- yaml-sigil-release-bump: ${bump} -->"
# Background updates retain the last reviewed explicit bump selection.
elif [[ -n "${retained_bump}" ]]; then
  bump="${retained_bump}"
  marker="<!-- yaml-sigil-release-bump: ${bump} -->"
else
  bump="patch"
  marker="<!-- yaml-sigil-release-bump: patch -->"
fi

{
  echo "mode=${mode}"
  echo "bump=${bump}"
  echo "marker=${marker}"
} >>"${GITHUB_OUTPUT}"

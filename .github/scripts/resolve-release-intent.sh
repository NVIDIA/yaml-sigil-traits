#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Resolve whether this event may create or update the App-owned release
# proposal and select its explicit release mode and version-line intent.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${MANUAL_DISPATCH:?MANUAL_DISPATCH is required}"
: "${REQUESTED_BUMP:?REQUESTED_BUMP is required}"
: "${REQUESTED_MODE:?REQUESTED_MODE is required}"

# Accept only the event-authority states supplied by the workflow.
case "${MANUAL_DISPATCH}" in
  true | false) ;;
  *)
    echo "Unsupported manual-dispatch state: ${MANUAL_DISPATCH}." >&2
    exit 2
    ;;
esac
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
# Accept only an absent proposal or one exact App-owned same-repository PR.
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
     .base.ref == "main" and .base.repo.full_name == $repository))' \
  >/dev/null <<<"${existing_prs}"; then
  echo "The existing release proposal lookup is ambiguous or unauthorized." >&2
  exit 1
fi
existing_count="$(jq -r 'length' <<<"${existing_prs}")"

mode="${REQUESTED_MODE}"
proceed=true
bump="${REQUESTED_BUMP}"
# Background events may seed one patch proposal but cannot revise one.
if [[ "${MANUAL_DISPATCH}" == "false" ]]; then
  # Background inputs must remain the deterministic next-patch defaults.
  if [[ "${mode}" != "next-candidate" || "${bump}" != "patch" ]]; then
    echo "Background release proposals must use next-candidate patch mode." >&2
    exit 2
  fi
  # Leave an existing exact proposal untouched until a manual dispatch.
  if [[ "${existing_count}" == "1" ]]; then
    proceed=false
    echo "An App-owned release proposal already exists; no background update is needed."
  fi
else
  # Stable promotion always uses patch compatibility intent for the same core.
  if [[ "${mode}" == "promote-stable" ]]; then
    bump="patch"
  fi
fi

{
  echo "proceed=${proceed}"
  echo "mode=${mode}"
  echo "bump=${bump}"
} >>"${GITHUB_OUTPUT}"

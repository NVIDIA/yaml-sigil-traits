#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Prove that copy-pr-bot's current pull-request branch still names the exact
# reviewed head and that ci.yml completed successfully for that trusted push.
# This helper only reads GitHub state; callers retain responsibility for PR
# state, target-branch, actor-permission, and workflow-dispatch checks.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${PR_SHA:?PR_SHA is required}"

# Reject ambiguous or injection-prone ref components.
if [[ ! "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]; then
  echo "PR_NUMBER must be a positive integer." >&2
  exit 1
fi
# Require the immutable full object name returned by GitHub's pull API.
if [[ ! "${PR_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "PR_SHA must be a full lowercase hexadecimal commit SHA." >&2
  exit 1
fi

copied_branch="pull-request/${PR_NUMBER}"
copied_sha="$(
  gh api \
    "repos/${GITHUB_REPOSITORY}/git/ref/heads/${copied_branch}" \
    --jq .object.sha
)"
# A stale, missing, or replaced copied branch cannot authorize PR source.
if [[ "${copied_sha}" != "${PR_SHA}" ]]; then
  echo "${copied_branch} is ${copied_sha}, not PR head ${PR_SHA}." >&2
  exit 1
fi

runs="$(
  gh api --method GET \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs" \
    -f branch="${copied_branch}" \
    -f event=push \
    -f status=completed \
    -f head_sha="${PR_SHA}" \
    -f per_page=100
)"
# Accept only the exact workflow, copied branch, event, and immutable head.
if ! jq --exit-status \
  --arg branch "${copied_branch}" \
  --arg sha "${PR_SHA}" \
  'any(.workflow_runs[];
    .path == ".github/workflows/ci.yml"
    and .event == "push"
    and .status == "completed"
    and .conclusion == "success"
    and .head_branch == $branch
    and .head_sha == $sha)' \
  <<<"${runs}" >/dev/null; then
  echo "${copied_branch} head ${PR_SHA} has no successful copied-head CI run." >&2
  exit 1
fi

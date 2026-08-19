#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Resolve a writer-authorized, open pull request targeting main and prove that
# its exact current head has a completed successful run of ci.yml. The caller
# receives only the immutable PR number and head SHA through GITHUB_OUTPUT.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY is required}"
: "${GITHUB_ACTOR:?GITHUB_ACTOR is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"

# Prevent copied workflows from authorizing another repository.
if [[ "${GITHUB_REPOSITORY}" != "${EXPECTED_REPOSITORY}" ]]; then
  echo "This workflow runs only in ${EXPECTED_REPOSITORY}." >&2
  exit 1
fi
# Load every authorization helper from protected main.
if [[ "${GITHUB_REF}" != "refs/heads/main" ]]; then
  echo "PR publication operations must be dispatched from main." >&2
  exit 1
fi
# Reject ambiguous or injection-prone pull-request selectors.
if [[ ! "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]; then
  echo "pr_number must be a positive integer." >&2
  exit 1
fi

permission="$(
  gh api "repos/${GITHUB_REPOSITORY}/collaborators/${GITHUB_ACTOR}/permission" \
    --jq .permission
)"
# Only repository roles that can normally write source may request a snapshot.
case "${permission}" in
  admin | maintain | push) ;;
  *)
    echo "${GITHUB_ACTOR} does not have repository write access." >&2
    exit 1
    ;;
esac

pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"
state="$(jq --raw-output .state <<<"${pr}")"
base="$(jq --raw-output .base.ref <<<"${pr}")"
sha="$(jq --raw-output .head.sha <<<"${pr}")"
# A closed PR or a PR for another base is not a reviewable main candidate.
if [[ "${state}" != "open" || "${base}" != "main" ]]; then
  echo "PR ${PR_NUMBER} must be open and target main." >&2
  exit 1
fi

runs="$(
  gh api \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?head_sha=${sha}&event=pull_request&status=completed&per_page=100"
)"
# Bind authorization to a successful completed run for the immutable head SHA.
if ! jq --exit-status --arg sha "${sha}" \
  'any(.workflow_runs[]; .head_sha == $sha and .conclusion == "success")' \
  <<<"${runs}" >/dev/null; then
  echo "PR ${PR_NUMBER} head ${sha} has no successful completed CI run." >&2
  exit 1
fi

echo "number=${PR_NUMBER}" >>"${GITHUB_OUTPUT}"
echo "sha=${sha}" >>"${GITHUB_OUTPUT}"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Close the validation/publication race by requiring the PR to remain open,
# target main, retain the resolved head SHA, and retain successful exact-head
# CI immediately before a job receives publication authority.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_ACTOR:?GITHUB_ACTOR is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${PR_NUMBER:?PR_NUMBER is required}"
: "${PR_SHA:?PR_SHA is required}"

# The publication identity must remain bound to a protected-main dispatch.
if [[ "${GITHUB_REF}" != "refs/heads/main" ]]; then
  echo "PR publication operations must be dispatched from main." >&2
  exit 1
fi

permission="$(
  gh api "repos/${GITHUB_REPOSITORY}/collaborators/${GITHUB_ACTOR}/permission" \
    --jq .permission
)"
# Recheck writer authority in case access changed after the validation job.
case "${permission}" in
  admin | maintain | push) ;;
  *)
    echo "${GITHUB_ACTOR} does not have repository write access." >&2
    exit 1
    ;;
esac

pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"
# Stop if review state, base, or source changed after the validation job.
if [[ "$(jq --raw-output .state <<<"${pr}")" != "open" \
  || "$(jq --raw-output .base.ref <<<"${pr}")" != "main" \
  || "$(jq --raw-output .head.sha <<<"${pr}")" != "${PR_SHA}" ]]; then
  echo "PR ${PR_NUMBER} changed after validation." >&2
  exit 1
fi

# Repeat the copied-ref and push-CI proof immediately before publication.
script_dir="$(dirname -- "${BASH_SOURCE[0]}")"
bash "${script_dir}/require-tested-copied-head.sh"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Configure the checked-out repository with the current workflow-token actor.

set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"

viewer="$(
  gh api graphql \
    -f query='query { viewer { name login databaseId } }' \
    --jq '.data.viewer'
)"
login="$(jq --raw-output '.login // empty' <<<"${viewer}")"
database_id="$(jq --raw-output '.databaseId // empty' <<<"${viewer}")"
name="$(jq --raw-output '.name // empty' <<<"${viewer}")"
# GitHub's workflow identity must provide a stable login and numeric ID.
if [[ ! "${login}" =~ ^[A-Za-z0-9-]+(\[bot\])?$ \
  || ! "${database_id}" =~ ^[0-9]+$ ]]; then
  echo "GitHub did not return a valid workflow-token identity." >&2
  exit 1
fi
# Prefer the display name only when GitHub supplied one.
if [[ -z "${name}" ]]; then
  name="${login}"
fi
email="${database_id}+${login}@users.noreply.github.com"

git config --local user.name "${name}"
git config --local user.email "${email}"
# Release tags must use exactly the token-derived local identity.
if [[ "$(git config --local user.name)" != "${name}" \
  || "$(git config --local user.email)" != "${email}" ]]; then
  echo "The release Git identity did not persist locally." >&2
  exit 1
fi

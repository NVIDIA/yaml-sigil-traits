#!/usr/bin/env bash

# Validate the exact commit range proposed by a pull request. The workflow
# checks out the pull request head with full history and supplies immutable base
# and head SHAs so this script does not have to infer refs or inspect a
# synthetic merge commit.
set -euo pipefail

: "${BASE_SHA:?BASE_SHA must identify the pull request base commit}"
: "${HEAD_SHA:?HEAD_SHA must identify the pull request head commit}"

range="${BASE_SHA}..${HEAD_SHA}"

# Fail clearly if the checkout is incomplete or either event SHA is invalid.
git cat-file -e "${BASE_SHA}^{commit}"
git cat-file -e "${HEAD_SHA}^{commit}"

# Target-branch linear-history rules do not reject merge commits hidden inside
# a pull request that is later squash-merged. Inspect parent counts directly.
mapfile -t merge_commits < <(git rev-list --merges "${range}")
if ((${#merge_commits[@]} > 0)); then
  printf 'Merge commits are not allowed in pull requests:\n'
  git show --no-patch --format='  %H %s' "${merge_commits[@]}"
  exit 1
fi

# An empty range indicates that the event and checkout do not describe a
# reviewable change; do not silently report that as a successful policy check.
mapfile -t commits < <(git rev-list --reverse "${range}")
if ((${#commits[@]} == 0)); then
  echo "::error::The pull request commit range is empty."
  exit 1
fi

# Enforce the Developer Certificate of Origin on every proposed commit. Use
# Git's trailer parser rather than a loose text match, and require at least one
# Signed-off-by identity to match that commit's author or committer exactly.
invalid_signoffs=()
for commit in "${commits[@]}"; do
  author="$(git show --no-patch --format='%an <%ae>' "${commit}")"
  committer="$(git show --no-patch --format='%cn <%ce>' "${commit}")"
  valid=false

  while IFS= read -r signoff; do
    if [[ "${signoff}" == "${author}" || "${signoff}" == "${committer}" ]]; then
      valid=true
      break
    fi
  done < <(
    git show --no-patch \
      --format='%(trailers:key=Signed-off-by,valueonly)' "${commit}"
  )

  if [[ "${valid}" != "true" ]]; then
    invalid_signoffs+=("${commit}")
  fi
done

if ((${#invalid_signoffs[@]} > 0)); then
  echo "::error::Each commit needs a Signed-off-by trailer matching its author or committer."
  git show --no-patch --format='  %H %s' "${invalid_signoffs[@]}"
  exit 1
fi

printf 'Validated %d linear, signed-off pull request commit(s).\n' \
  "${#commits[@]}"

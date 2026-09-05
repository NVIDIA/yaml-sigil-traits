#!/usr/bin/env bash

# Validate the complete tracked and untracked boundary of one canonical traits
# release PR. The caller stages this script from protected main before source.
set -euo pipefail

# Accept only the exact immutable coordinates and release identifiers used by
# the protected candidate workflow.
if [[ "$#" -ne 4 ]]; then
  echo "usage: check-release-pr.sh BASE_SHA HEAD_SHA RELEASE_BRANCH VERSION" >&2
  exit 2
fi

base_sha="$1"
head_sha="$2"
release_branch="$3"
version="$4"
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?'

# Bind the exact protected base, copied head, and canonical branch/version.
if [[ ! "${base_sha}" =~ ^[0-9a-f]{40}$ \
  || ! "${head_sha}" =~ ^[0-9a-f]{40}$ \
  || ! "${version}" =~ ^${semver}$ \
  || "${release_branch}" != "release-plz-manual-${version}" ]]; then
  echo "release PR coordinates are malformed" >&2
  exit 1
fi

git cat-file -e "${base_sha}^{commit}"
git cat-file -e "${head_sha}^{commit}"

# A release PR is one exact commit directly atop the protected current base.
if [[ "$(git rev-parse HEAD)" != "${head_sha}" \
  || "$(git rev-parse refs/remotes/origin/main)" != "${base_sha}" \
  || "$(git rev-list --count "${base_sha}..${head_sha}")" != "1" \
  || "$(git rev-parse "${head_sha}^")" != "${base_sha}" ]]; then
  echo "release PR is not one commit current with protected main" >&2
  exit 1
fi

# A materialized release candidate must not carry untracked additions, even
# though `git diff` cannot report them.
mapfile -d '' worktree_entries < <(
  git status --porcelain=v1 -z --untracked-files=all
)
if ((${#worktree_entries[@]} != 0)); then
  echo "release PR materialization contains untracked or dirty paths" >&2
  exit 1
fi

# Include every tracked change class, especially deletions, and disable rename
# collapsing so an old unexpected path cannot hide behind an allowed new path.
mapfile -d '' changed_paths < <(
  git diff --name-only --no-renames --diff-filter=ACDMRTUXB -z \
    "${base_sha}" "${head_sha}"
)
if ((${#changed_paths[@]} != 2)); then
  echo "release PR must change exactly Cargo.toml and CHANGELOG.md" >&2
  exit 1
fi

seen_cargo=false
seen_changelog=false
for path in "${changed_paths[@]}"; do
  # Only the two source-release documents belong to this transaction.
  case "${path}" in
    Cargo.toml)
      seen_cargo=true
      ;;
    CHANGELOG.md)
      seen_changelog=true
      ;;
    *)
      echo "release PR changed an unexpected path: ${path}" >&2
      exit 1
      ;;
  esac
done

# Both allowed paths must remain direct regular files, not deletions, links, or
# executable files whose names happen to pass the changed-path allowlist.
if [[ "${seen_cargo}" != true || "${seen_changelog}" != true \
  || "$(git ls-tree "${head_sha}" -- Cargo.toml | cut -d ' ' -f 1-2)" != "100644 blob" \
  || "$(git ls-tree "${head_sha}" -- CHANGELOG.md | cut -d ' ' -f 1-2)" != "100644 blob" ]]; then
  echo "release PR source documents are absent or have an unsafe file type" >&2
  exit 1
fi

echo "validated exact source-only release PR boundary"

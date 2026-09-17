#!/usr/bin/env bash

# Attach an already-qualified detached source to the selected local base refs so pinned
# release-plz can resolve its merged pull request. This never updates a remote.
set -euo pipefail

# Accept exactly one lowercase commit identity selected by protected policy.
if [[ "$#" -ne 2 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: attach-release-source.sh SOURCE_SHA BASE_REF" >&2
  exit 2
fi
source_sha="$1"
base_ref="$2"
version_component='(0|[1-9][0-9]{0,8})'
# Only the previously qualified main or canonical support line may be attached.
if [[ "${base_ref}" != refs/heads/main \
  && ! "${base_ref}" =~ ^refs/heads/support/${version_component}\.${version_component}$ ]]; then
  echo "release source base is not canonical main or support/M.N" >&2
  exit 1
fi
tracking_ref="refs/remotes/origin/${base_ref#refs/heads/}"

head_sha="$(git rev-parse --verify HEAD)"
status="$(git status --porcelain=v1 --untracked-files=all)"
# Ref attachment is valid only for the exact clean qualified source tree.
if [[ "${head_sha}" != "${source_sha}" || -n "${status}" ]]; then
  echo "release source checkout differs from the qualified commit" >&2
  exit 1
fi

# These updates are strictly local Git context; no fetch, push, or credential
# operation is permitted at the Cargo publication boundary.
git update-ref "${base_ref}" "${source_sha}"
git update-ref "${tracking_ref}" "${source_sha}"
git symbolic-ref HEAD "${base_ref}"

# Read back all three bindings before release-plz receives publication authority.
if [[ "$(git rev-parse HEAD)" != "${source_sha}" \
  || "$(git rev-parse "${base_ref}")" != "${source_sha}" \
  || "$(git rev-parse "${tracking_ref}")" != "${source_sha}" \
  || "$(git symbolic-ref --quiet HEAD)" != "${base_ref}" \
  || -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "local release source refs did not retain the exact qualified source" >&2
  exit 1
fi

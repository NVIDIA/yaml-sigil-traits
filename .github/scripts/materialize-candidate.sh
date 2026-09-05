#!/usr/bin/env bash

# Materialize one bot-copied candidate with anonymous Git transport. The
# caller loads this script from protected main before any candidate path exists.
set -euo pipefail

# Keep machine and user Git configuration, credential helpers, and prompts out
# of the candidate checkout boundary.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0

# Require the fixed repository, exact copied ref, exact reviewed head, and an
# optional fixed source-spec repository as the complete input contract.
if [[ "$#" -ne 3 && "$#" -ne 5 ]]; then
  echo "usage: materialize-candidate.sh REPOSITORY HEAD_SHA COPIED_REF [GITLINK_PATH GITLINK_REPOSITORY]" >&2
  exit 2
fi

repository="$1"
head_sha="$2"
copied_ref="$3"
gitlink_path="${4:-}"
gitlink_repository="${5:-}"

# Reject values that could become options, alternate refs, or shell-visible
# control characters before passing them to Git.
if [[ ! "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ \
  || ! "${head_sha}" =~ ^[0-9a-f]{40}$ \
  || ! "${copied_ref}" =~ ^pull-request/[1-9][0-9]*$ ]]; then
  echo "candidate repository, head, or copied ref is malformed" >&2
  exit 1
fi

# The optional gitlink pair is all-or-nothing and accepts one simple path plus
# a caller-fixed public repository URL or local test fixture.
if [[ ( -n "${gitlink_path}" || -n "${gitlink_repository}" ) \
  && ( ! "${gitlink_path}" =~ ^[A-Za-z0-9_.-]+$ \
    || -z "${gitlink_repository}" \
    || "${gitlink_repository}" == -* \
    || "${gitlink_repository}" == *$'\n'* \
    || "${gitlink_repository}" == *$'\r'* ) ]]; then
  echo "candidate gitlink policy is malformed" >&2
  exit 1
fi

canonical_url="https://github.com/${repository}.git"
candidate_ref="refs/heads/${copied_ref}"
pull_number="${copied_ref#pull-request/}"
pull_ref="refs/pull/${pull_number}/head"

# Tests may provide an explicit local origin. Production leaves this unset and
# is therefore pinned to the canonical public repository URL.
if [[ "${GITHUB_ACTIONS:-}" == "true" \
  && -n "${YAML_SIGIL_MATERIALIZE_TEST_ORIGIN:-}" ]]; then
  echo "test-only candidate origin is forbidden in GitHub Actions" >&2
  exit 1
fi
origin_url="${YAML_SIGIL_MATERIALIZE_TEST_ORIGIN:-${canonical_url}}"

# Cargo searches every ancestor of the candidate workspace for
# `.cargo/config{,.toml}`. Reject either file before checkout so runner state
# outside the candidate cannot inject registries, credentials, wrappers, or
# build configuration. The candidate root is deliberately excluded here: its
# tracked configuration remains ordinary reviewed candidate input.
workspace="$(pwd -P)"
ancestor="$(dirname -- "${workspace}")"
while :; do
  if [[ -e "${ancestor}/.cargo/config" \
    || -L "${ancestor}/.cargo/config" \
    || -e "${ancestor}/.cargo/config.toml" \
    || -L "${ancestor}/.cargo/config.toml" ]]; then
    echo "Cargo configuration exists above candidate workspace: ${ancestor}/.cargo" >&2
    exit 1
  fi
  if [[ "${ancestor}" == "/" ]]; then
    break
  fi
  ancestor="$(dirname -- "${ancestor}")"
done

# Initialize only Git metadata, then fetch current main, the exact copied ref,
# and GitHub's canonical current pull-request head without tags, credentials,
# submodules, or a working tree.
if [[ ! -d .git ]]; then
  git init --quiet --initial-branch=main .
fi
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "${origin_url}"
else
  git remote add origin "${origin_url}"
fi
git -c credential.helper= fetch --no-tags --no-recurse-submodules origin \
  "+refs/heads/main:refs/remotes/origin/main" \
  "+${candidate_ref}:refs/remotes/origin/candidate" \
  "+${pull_ref}:refs/remotes/origin/pull-head"

base_sha="$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')"
copied_sha="$(git rev-parse --verify 'refs/remotes/origin/candidate^{commit}')"
pull_sha="$(git rev-parse --verify 'refs/remotes/origin/pull-head^{commit}')"

# A moved copied ref, moved canonical pull head, or candidate that is no longer
# based on exact current main needs another human authorization and cannot
# execute in this run.
if [[ "${copied_sha}" != "${head_sha}" \
  || "${pull_sha}" != "${head_sha}" \
  || ! "${base_sha}" =~ ^[0-9a-f]{40}$ ]] \
  || ! git merge-base --is-ancestor "${base_sha}" "${head_sha}"; then
  echo "candidate ref, pull head, reviewed head, or current main binding changed" >&2
  exit 1
fi

# Populate the index without materializing paths, then reject every requested
# content filter. With system/global configuration disabled, no candidate can
# make a required filter or Git LFS helper execute during checkout.
git read-tree "${head_sha}"
attribute_result="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yaml-sigil-filter-attributes-${BASHPID}"
git ls-files -z \
  | git check-attr --cached --stdin -z filter \
  > "${attribute_result}"
while IFS= read -r -d '' path \
  && IFS= read -r -d '' attribute \
  && IFS= read -r -d '' value; do
  # Only an absent or explicitly disabled filter is safe to materialize.
  if [[ "${attribute}" != "filter" \
    || ( "${value}" != "unspecified" && "${value}" != "unset" ) ]]; then
    printf 'candidate path %q requests unsupported Git filter %q\n' \
      "${path}" "${value}" >&2
    exit 1
  fi
done < "${attribute_result}"

# Disable the well-known LFS process explicitly in addition to rejecting all
# filter attributes, then perform one ordinary detached checkout.
git -c credential.helper= \
  -c filter.lfs.process= \
  -c filter.lfs.smudge= \
  -c filter.lfs.required=false \
  checkout --quiet --force --detach "${head_sha}"

# A repository without a governed gitlink is complete at this boundary.
if [[ -z "${gitlink_path}" ]]; then
  exit 0
fi

entry="$(git ls-tree "${head_sha}" -- "${gitlink_path}")"
read -r mode object_type source_sha entry_path <<< "${entry}"

# Resolve only an exact commit gitlink. Never load `.gitmodules`, local
# submodule settings, or a repository URL selected by the candidate.
if [[ "${mode}" != "160000" \
  || "${object_type}" != "commit" \
  || ! "${source_sha}" =~ ^[0-9a-f]{40}$ \
  || "${entry_path}" != "${gitlink_path}" ]]; then
  echo "candidate source gitlink is not one exact commit" >&2
  exit 1
fi

git init --quiet --initial-branch=main "${gitlink_path}"
git -C "${gitlink_path}" remote add origin "${gitlink_repository}"
git -c credential.helper= -C "${gitlink_path}" fetch \
  --no-tags --no-recurse-submodules --depth=1 origin "${source_sha}"
git -c credential.helper= \
  -c filter.lfs.process= \
  -c filter.lfs.smudge= \
  -c filter.lfs.required=false \
  -C "${gitlink_path}" checkout --quiet --force --detach "${source_sha}"

# Finish with exact source and fixed-remote readback; no post-materialization
# step receives a credential from this script.
test "$(git rev-parse HEAD)" = "${head_sha}"
test "$(git -C "${gitlink_path}" rev-parse HEAD)" = "${source_sha}"
test "$(git -C "${gitlink_path}" remote get-url origin)" = "${gitlink_repository}"

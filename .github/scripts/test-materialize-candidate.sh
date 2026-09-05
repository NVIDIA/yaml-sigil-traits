#!/usr/bin/env bash

# Exercise copied-ref materialization without network access or credentials.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
materializer="${script_dir}/materialize-candidate.sh"
fixture_root="$(mktemp -d)"

cleanup() {
  # The fixture owns this exact temporary directory and removes no other path.
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT

git_config() {
  git -C "$1" config user.name "Fixture Author"
  git -C "$1" config user.email "fixture@example.invalid"
}

commit_all() {
  git -C "$1" add --all
  git -C "$1" commit --quiet -m "$2"
}

make_spec() {
  local work="${fixture_root}/spec-work"
  local bare="${fixture_root}/spec.git"
  git init --quiet --initial-branch=main "${work}"
  git_config "${work}"
  printf '# Specification fixture\n' > "${work}/README.md"
  commit_all "${work}" "spec fixture"
  git clone --quiet --bare "${work}" "${bare}"
  printf '%s\n' "${bare}"
}

make_candidate() {
  local name="$1"
  local attributes="$2"
  local spec_repo="$3"
  local work="${fixture_root}/${name}-work"
  local bare="${fixture_root}/${name}.git"
  git init --quiet --initial-branch=main "${work}"
  git_config "${work}"
  printf '[package]\nname = "fixture"\nversion = "0.1.0"\n' \
    > "${work}/Cargo.toml"
  mkdir -p "${work}/src"
  printf 'pub fn value() -> u8 { 1 }\n' > "${work}/src/lib.rs"
  commit_all "${work}" "base fixture"
  local base
  base="$(git -C "${work}" rev-parse HEAD)"
  git -C "${work}" switch --quiet -c pull-request/7
  mkdir -p "${work}/.cargo"
  printf '[net]\noffline = true\n' > "${work}/.cargo/config.toml"
  printf '%s\n' "${attributes}" > "${work}/.gitattributes"
  printf 'candidate\n' > "${work}/candidate.txt"
  local spec_sha
  spec_sha="$(git --git-dir="${spec_repo}" rev-parse refs/heads/main)"
  printf '[submodule "source-spec"]\n\tpath = source-spec\n\turl = https://example.invalid/untrusted.git\n' \
    > "${work}/.gitmodules"
  git -C "${work}" add --all
  git -C "${work}" update-index --add --cacheinfo \
    "160000,${spec_sha},source-spec"
  git -C "${work}" commit --quiet -m "candidate fixture"
  local head
  head="$(git -C "${work}" rev-parse HEAD)"
  git clone --quiet --bare "${work}" "${bare}"
  git --git-dir="${bare}" update-ref refs/heads/main "${base}"
  git --git-dir="${bare}" update-ref refs/pull/7/head "${head}"
  printf '%s\n' "${bare}"
}

run_materializer() {
  local bare="$1"
  local spec_repo="$2"
  local destination="$3"
  local head
  head="$(git --git-dir="${bare}" rev-parse refs/heads/pull-request/7)"
  mkdir "${destination}"
  (
    cd "${destination}"
    env -u GITHUB_ACTIONS \
      RUNNER_TEMP="${fixture_root}" \
      YAML_SIGIL_MATERIALIZE_TEST_ORIGIN="${bare}" \
      "${materializer}" NVIDIA/yaml-sigil-test "${head}" pull-request/7 \
      source-spec "${spec_repo}"
  )
}

spec_repo="$(make_spec)"
plain_repo="$(make_candidate plain '# no content filters' "${spec_repo}")"

# The local-origin override is a test seam only. Prove the production Actions
# environment rejects it before unsetting that marker for the fixture cases.
actions_destination="${fixture_root}/actions-checkout"
mkdir "${actions_destination}"
if (
  cd "${actions_destination}"
  GITHUB_ACTIONS=true \
    RUNNER_TEMP="${fixture_root}" \
    YAML_SIGIL_MATERIALIZE_TEST_ORIGIN="${plain_repo}" \
    "${materializer}" NVIDIA/yaml-sigil-test \
    "$(git --git-dir="${plain_repo}" rev-parse refs/heads/pull-request/7)" \
    pull-request/7 source-spec "${spec_repo}"
); then
  echo "test origin unexpectedly accepted in GitHub Actions" >&2
  exit 1
fi

run_materializer "${plain_repo}" "${spec_repo}" "${fixture_root}/plain-checkout"
test "$(git -C "${fixture_root}/plain-checkout/source-spec" remote get-url origin)" \
  = "${spec_repo}"

# Named filters are rejected before checkout, including an otherwise optional
# driver that a later machine configuration could mark required.
filtered_repo="$(make_candidate filtered '*.txt filter=external' "${spec_repo}")"
if run_materializer "${filtered_repo}" "${spec_repo}" \
  "${fixture_root}/filtered-checkout"; then
  echo "named candidate filter unexpectedly materialized" >&2
  exit 1
fi

# Git LFS is a filter and must not smudge or execute merely because a candidate
# records an LFS attribute.
lfs_repo="$(make_candidate lfs '*.txt filter=lfs diff=lfs merge=lfs -text' "${spec_repo}")"
if run_materializer "${lfs_repo}" "${spec_repo}" \
  "${fixture_root}/lfs-checkout"; then
  echo "candidate LFS attribute unexpectedly materialized" >&2
  exit 1
fi

# Cargo configuration in any parent of the checkout would affect candidate
# commands despite an otherwise clean CARGO_HOME, so reject it before checkout.
configured_parent="${fixture_root}/configured-parent"
mkdir -p "${configured_parent}/.cargo"
printf '[build]\nrustflags = ["--cfg", "ancestor_injection"]\n' \
  > "${configured_parent}/.cargo/config.toml"
if run_materializer "${plain_repo}" "${spec_repo}" \
  "${configured_parent}/candidate-checkout"; then
  echo "ancestor Cargo configuration unexpectedly accepted" >&2
  exit 1
fi

# Exact-head authorization is invalid once the copied ref points elsewhere.
stale_destination="${fixture_root}/stale-checkout"
mkdir "${stale_destination}"
if (
  cd "${stale_destination}"
  env -u GITHUB_ACTIONS \
    RUNNER_TEMP="${fixture_root}" \
    YAML_SIGIL_MATERIALIZE_TEST_ORIGIN="${plain_repo}" \
    "${materializer}" NVIDIA/yaml-sigil-test "$(printf 'f%.0s' {1..40})" \
    pull-request/7 source-spec "${spec_repo}"
); then
  echo "stale candidate head unexpectedly materialized" >&2
  exit 1
fi

# The copied ref is insufficient when the live pull-request head has moved.
# Require GitHub's canonical pull-head ref to remain at the authorized SHA.
moved_pull_repo="$(make_candidate moved-pull '# no content filters' "${spec_repo}")"
git --git-dir="${moved_pull_repo}" update-ref refs/pull/7/head \
  "$(git --git-dir="${moved_pull_repo}" rev-parse refs/heads/main)"
if run_materializer "${moved_pull_repo}" "${spec_repo}" \
  "${fixture_root}/moved-pull-checkout"; then
  echo "moved pull-request head unexpectedly materialized" >&2
  exit 1
fi

echo "candidate materialization checks passed"

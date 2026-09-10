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
  local root_cargo_config="${4:-false}"
  local base_branch="${5:-main}"
  local work="${fixture_root}/${name}-work"
  local bare="${fixture_root}/${name}.git"
  git init --quiet --initial-branch=main "${work}"
  git_config "${work}"
  printf '[package]\nname = "fixture"\nversion = "0.1.0"\n' \
    > "${work}/Cargo.toml"
  mkdir -p "${work}/src"
  printf 'pub fn value() -> u8 { 1 }\n' > "${work}/src/lib.rs"
  if [[ "${root_cargo_config}" == "base" ]]; then
    mkdir -p "${work}/.cargo"
    printf '[alias]\nxtask = "check"\n' > "${work}/.cargo/config.toml"
  fi
  commit_all "${work}" "base fixture"
  local policy_sha
  policy_sha="$(git -C "${work}" rev-parse HEAD)"
  if [[ "${base_branch}" != "main" ]]; then
    git -C "${work}" switch --quiet -c "${base_branch}"
    printf 'coordination base\n' > "${work}/coordination.txt"
    if [[ "${root_cargo_config}" == "coordination" ]]; then
      mkdir -p "${work}/.cargo"
      printf '[alias]\nxtask = "check"\n' > "${work}/.cargo/config.toml"
    fi
    commit_all "${work}" "coordination fixture"
  fi
  local base_sha
  base_sha="$(git -C "${work}" rev-parse HEAD)"
  git -C "${work}" switch --quiet -c pull-request/7
  # A dedicated negative fixture opts into candidate-root Cargo configuration.
  if [[ "${root_cargo_config}" == "true" ]]; then
    mkdir -p "${work}/.cargo"
    printf '[build]\nrustc-wrapper = "/bin/false"\n' \
      > "${work}/.cargo/config.toml"
  fi
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
  git --git-dir="${bare}" update-ref refs/heads/main "${policy_sha}"
  git --git-dir="${bare}" update-ref "refs/heads/${base_branch}" "${base_sha}"
  git --git-dir="${bare}" update-ref refs/pull/7/head "${head}"
  printf '%s\n' "${bare}"
}

run_materializer_bound_in() {
  local bare="$1"
  local spec_repo="$2"
  local destination="$3"
  local policy_sha="$4"
  local base_ref="$5"
  local base_sha="$6"
  local head="$7"
  (
    cd "${destination}"
    env -u GITHUB_ACTIONS \
      RUNNER_TEMP="${fixture_root}" \
      YAML_SIGIL_MATERIALIZE_TEST_ORIGIN="${bare}" \
      "${materializer}" NVIDIA/yaml-sigil-rs "${head}" pull-request/7 \
      "${policy_sha}" "${base_ref}" "${base_sha}" \
      source-spec "${spec_repo}"
  )
}

run_materializer_in() {
  local bare="$1"
  local spec_repo="$2"
  local destination="$3"
  local base_ref="${4:-refs/heads/main}"
  local policy_sha
  local base_sha
  local head
  policy_sha="$(git --git-dir="${bare}" rev-parse refs/heads/main)"
  base_sha="$(git --git-dir="${bare}" rev-parse "${base_ref}")"
  head="$(git --git-dir="${bare}" rev-parse refs/heads/pull-request/7)"
  run_materializer_bound_in \
    "${bare}" "${spec_repo}" "${destination}" \
    "${policy_sha}" "${base_ref}" "${base_sha}" "${head}"
}

run_materializer() {
  local bare="$1"
  local spec_repo="$2"
  local destination="$3"
  local base_ref="${4:-refs/heads/main}"
  mkdir "${destination}"
  run_materializer_in "${bare}" "${spec_repo}" "${destination}" "${base_ref}"
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
    "${materializer}" NVIDIA/yaml-sigil-rs \
    "$(git --git-dir="${plain_repo}" rev-parse refs/heads/pull-request/7)" \
    pull-request/7 \
    "$(git --git-dir="${plain_repo}" rev-parse refs/heads/main)" \
    refs/heads/main \
    "$(git --git-dir="${plain_repo}" rev-parse refs/heads/main)" \
    source-spec "${spec_repo}"
); then
  echo "test origin unexpectedly accepted in GitHub Actions" >&2
  exit 1
fi

run_materializer "${plain_repo}" "${spec_repo}" "${fixture_root}/plain-checkout"
test "$(git -C "${fixture_root}/plain-checkout/source-spec" remote get-url origin)" \
  = "${spec_repo}"

# Protected current main supplies executable policy while an independently
# bound coordination ref supplies the contribution base.
coordination_repo="$(
  make_candidate coordination '# no content filters' "${spec_repo}" \
    false dev/0.6.0
)"
run_materializer "${coordination_repo}" "${spec_repo}" \
  "${fixture_root}/coordination-checkout" refs/heads/dev/0.6.0

# A root Cargo configuration is safe only when its path, mode, and blob are
# unchanged from protected current main.
protected_config_repo="$(make_candidate protected-config '# no content filters' "${spec_repo}" base)"
run_materializer "${protected_config_repo}" "${spec_repo}" \
  "${fixture_root}/protected-config-checkout"

# Candidate-root Cargo configuration could replace Rust tools or introduce a
# wrapper before policy evaluation. Reject it before checkout.
root_config_repo="$(make_candidate root-config '# no content filters' "${spec_repo}" true)"
if run_materializer "${root_config_repo}" "${spec_repo}" \
  "${fixture_root}/root-config-checkout"; then
  echo "candidate-root Cargo configuration was accepted" >&2
  exit 1
fi

# A coordination branch cannot replace the root Cargo policy supplied by
# protected main, even when the candidate inherits that configuration.
coordination_config_repo="$(
  make_candidate coordination-config '# no content filters' "${spec_repo}" \
    coordination dev/0.6.0
)"
if run_materializer "${coordination_config_repo}" "${spec_repo}" \
  "${fixture_root}/coordination-config-checkout" refs/heads/dev/0.6.0; then
  echo "coordination-only root Cargo configuration was accepted" >&2
  exit 1
fi

# A destination with either ordinary residue or preinitialized Git metadata is
# not a fresh materialization root.
residue_destination="${fixture_root}/residue-checkout"
mkdir "${residue_destination}"
printf 'residue\n' > "${residue_destination}/left-behind.txt"
if run_materializer_in "${plain_repo}" "${spec_repo}" \
  "${residue_destination}"; then
  echo "candidate destination residue was accepted" >&2
  exit 1
fi

git_destination="${fixture_root}/git-checkout"
git init --quiet --initial-branch=main "${git_destination}"
if run_materializer_in "${plain_repo}" "${spec_repo}" \
  "${git_destination}"; then
  echo "preinitialized candidate Git metadata was accepted" >&2
  exit 1
fi

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
if run_materializer_bound_in \
  "${plain_repo}" "${spec_repo}" "${stale_destination}" \
  "$(git --git-dir="${plain_repo}" rev-parse refs/heads/main)" \
  refs/heads/main \
  "$(git --git-dir="${plain_repo}" rev-parse refs/heads/main)" \
  "$(printf 'f%.0s' {1..40})"; then
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

# Policy and contribution bases are distinct objects. Swapping their expected
# SHAs or moving either live ref after preflight must fail closed.
swapped_destination="${fixture_root}/swapped-base-checkout"
mkdir "${swapped_destination}"
coordination_policy="$(
  git --git-dir="${coordination_repo}" rev-parse refs/heads/main
)"
coordination_base="$(
  git --git-dir="${coordination_repo}" rev-parse refs/heads/dev/0.6.0
)"
coordination_head="$(
  git --git-dir="${coordination_repo}" rev-parse refs/heads/pull-request/7
)"
if run_materializer_bound_in \
  "${coordination_repo}" "${spec_repo}" "${swapped_destination}" \
  "${coordination_base}" refs/heads/dev/0.6.0 \
  "${coordination_policy}" "${coordination_head}"; then
  echo "swapped policy and contribution base were accepted" >&2
  exit 1
fi

moved_policy_repo="$(
  make_candidate moved-policy '# no content filters' "${spec_repo}" \
    false dev/0.6.0
)"
moved_policy="$(git --git-dir="${moved_policy_repo}" rev-parse refs/heads/main)"
moved_policy_base="$(
  git --git-dir="${moved_policy_repo}" rev-parse refs/heads/dev/0.6.0
)"
moved_policy_head="$(
  git --git-dir="${moved_policy_repo}" rev-parse refs/heads/pull-request/7
)"
git --git-dir="${moved_policy_repo}" update-ref refs/heads/main \
  "${moved_policy_base}"
moved_policy_destination="${fixture_root}/moved-policy-checkout"
mkdir "${moved_policy_destination}"
if run_materializer_bound_in \
  "${moved_policy_repo}" "${spec_repo}" "${moved_policy_destination}" \
  "${moved_policy}" refs/heads/dev/0.6.0 \
  "${moved_policy_base}" "${moved_policy_head}"; then
  echo "moved protected policy ref was accepted" >&2
  exit 1
fi

moved_base_repo="$(
  make_candidate moved-base '# no content filters' "${spec_repo}" \
    false dev/0.6.0
)"
moved_base_policy="$(git --git-dir="${moved_base_repo}" rev-parse refs/heads/main)"
moved_base="$(
  git --git-dir="${moved_base_repo}" rev-parse refs/heads/dev/0.6.0
)"
moved_base_head="$(
  git --git-dir="${moved_base_repo}" rev-parse refs/heads/pull-request/7
)"
git --git-dir="${moved_base_repo}" update-ref refs/heads/dev/0.6.0 \
  "${moved_base_head}"
moved_base_destination="${fixture_root}/moved-base-checkout"
mkdir "${moved_base_destination}"
if run_materializer_bound_in \
  "${moved_base_repo}" "${spec_repo}" "${moved_base_destination}" \
  "${moved_base_policy}" refs/heads/dev/0.6.0 \
  "${moved_base}" "${moved_base_head}"; then
  echo "moved contribution base ref was accepted" >&2
  exit 1
fi

echo "candidate materialization checks passed"

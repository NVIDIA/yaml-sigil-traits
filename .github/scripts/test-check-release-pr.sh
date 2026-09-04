#!/usr/bin/env bash

# Exercise the protected release-PR path and commit boundary without network.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checker="${script_dir}/check-release-pr.sh"
fixture_root="$(mktemp -d)"

cleanup() {
  # The test owns this exact temporary directory and no other path.
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT

make_fixture() {
  local name="$1"
  local root="${fixture_root}/${name}"
  git init --quiet --initial-branch=main "${root}"
  git -C "${root}" config user.name "Fixture Author"
  git -C "${root}" config user.email "fixture@example.invalid"
  printf '[package]\nname = "fixture"\nversion = "1.2.2"\n' \
    > "${root}/Cargo.toml"
  printf '# Changelog\n' > "${root}/CHANGELOG.md"
  printf 'fixture\n' > "${root}/README.md"
  git -C "${root}" add Cargo.toml CHANGELOG.md README.md
  git -C "${root}" commit --quiet -m "base"
  git -C "${root}" update-ref refs/remotes/origin/main HEAD
  git -C "${root}" switch --quiet -c release-plz-manual-1.2.3
  printf '[package]\nname = "fixture"\nversion = "1.2.3"\n' \
    > "${root}/Cargo.toml"
  printf '# Changelog\n\n## [1.2.3]\n\n- Release.\n' \
    > "${root}/CHANGELOG.md"
  printf '%s\n' "${root}"
}

run_checker() {
  local root="$1"
  local base
  local head
  base="$(git -C "${root}" rev-parse refs/remotes/origin/main)"
  head="$(git -C "${root}" rev-parse HEAD)"
  (
    cd "${root}"
    "${checker}" "${base}" "${head}" release-plz-manual-1.2.3 1.2.3
  )
}

valid="$(make_fixture valid)"
git -C "${valid}" add Cargo.toml CHANGELOG.md
git -C "${valid}" commit --quiet -m "release"
run_checker "${valid}"

deleted="$(make_fixture deleted)"
git -C "${deleted}" add Cargo.toml CHANGELOG.md
git -C "${deleted}" rm --quiet README.md
git -C "${deleted}" commit --quiet -m "release with deletion"
# A tracked deletion must appear in the exact inventory and fail the boundary.
if run_checker "${deleted}"; then
  echo "release PR unexpectedly accepted a tracked deletion" >&2
  exit 1
fi

untracked="$(make_fixture untracked)"
git -C "${untracked}" add Cargo.toml CHANGELOG.md
git -C "${untracked}" commit --quiet -m "release"
printf 'unexpected\n' > "${untracked}/untracked.txt"
# An untracked addition is outside the reviewed source-only transaction.
if run_checker "${untracked}"; then
  echo "release PR unexpectedly accepted an untracked addition" >&2
  exit 1
fi

removed_allowed="$(make_fixture removed-allowed)"
git -C "${removed_allowed}" rm --quiet --force Cargo.toml
git -C "${removed_allowed}" add CHANGELOG.md
git -C "${removed_allowed}" commit --quiet -m "release with missing manifest"
# Even an allowlisted path cannot be deleted by a release transaction.
if run_checker "${removed_allowed}"; then
  echo "release PR unexpectedly accepted a deleted manifest" >&2
  exit 1
fi

echo "release PR boundary checks passed"

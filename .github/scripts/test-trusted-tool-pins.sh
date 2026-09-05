#!/usr/bin/env bash

# Prove the narrow trusted-tool source lint rejects floating versions.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checker="${script_dir}/check-trusted-tool-pins.sh"
fixture_root="$(mktemp -d)"

cleanup() {
  # This test owns the exact temporary fixture directory.
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT

write_fixture() {
  local audit_spec="$1"
  local toolchain="$2"
  printf '%s\n' \
    'jobs:' \
    '  trusted:' \
    '    steps:' \
    '      - uses: actions-rust-lang/setup-rust-toolchain@0123456789012345678901234567890123456789' \
    '        with:' \
    "          toolchain: ${toolchain}" \
    '      - uses: taiki-e/install-action@0123456789012345678901234567890123456789' \
    '        with:' \
    "          tool: ${audit_spec},cargo-machete@0.9.2" \
    > "${fixture_root}/ci.yml"
}

write_matrix_fixture() {
  # GitHub matrix expressions must remain literal inside this source fixture.
  # shellcheck disable=SC2016
  printf '%s\n' \
    'jobs:' \
    '  trusted:' \
    '    strategy:' \
    '      matrix:' \
    '        include:' \
    '          - toolchain: 1.98.0' \
    '          - toolchain: 1.95.0' \
    '    steps:' \
    '      - uses: actions-rust-lang/setup-rust-toolchain@0123456789012345678901234567890123456789' \
    '        with:' \
    '          toolchain: ${{ matrix.toolchain }}' \
    '      - uses: taiki-e/install-action@0123456789012345678901234567890123456789' \
    '        with:' \
    '          tool: cargo-audit@0.22.2,cargo-machete@0.9.2' \
    > "${fixture_root}/ci.yml"
}

write_fixture cargo-audit@0.22.2 1.98.0
"${checker}" "${fixture_root}/ci.yml"

write_fixture cargo-audit@0.22.2 '"1.98.0"'
"${checker}" "${fixture_root}/ci.yml"

write_matrix_fixture
"${checker}" "${fixture_root}/ci.yml"

write_fixture cargo-audit 1.98.0
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "unversioned cargo-audit unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.1 1.98.0
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "wrong cargo-audit version unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 stable
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "floating Rust stable unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 1.99.0
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "unexpected Rust version unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 nightly
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "nightly Rust unexpectedly passed source lint" >&2
  exit 1
fi

# Preserve the deliberately rejected GitHub expression as fixture data.
# shellcheck disable=SC2016
write_fixture cargo-audit@0.22.2 '${{ matrix.other }}'
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "unexpected matrix expression unexpectedly passed source lint" >&2
  exit 1
fi


write_fixture cargo-audit@0.22.2 '"stable"'
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "quoted floating Rust stable unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 "'stable'"
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "single-quoted floating Rust stable unexpectedly passed source lint" >&2
  exit 1
fi

echo "trusted tool pin checks passed"

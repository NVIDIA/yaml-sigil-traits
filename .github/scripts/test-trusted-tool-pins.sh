#!/usr/bin/env bash

# Prove the narrow trusted-tool and release-registry checks reject drift.
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
  local deny_spec="${3:-cargo-deny@0.20.2}"
  printf '%s\n' \
    'jobs:' \
    '  trusted:' \
    '    steps:' \
    '      - uses: actions-rust-lang/setup-rust-toolchain@0123456789012345678901234567890123456789' \
    '        with:' \
    "          toolchain: ${toolchain}" \
    '      - uses: taiki-e/install-action@0123456789012345678901234567890123456789' \
    '        with:' \
    "          tool: ${audit_spec},${deny_spec},cargo-machete@0.9.2" \
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
    '          tool: cargo-audit@0.22.2,cargo-deny@0.20.2,cargo-machete@0.9.2' \
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

write_fixture cargo-audit@0.22.2 1.98.0 cargo-machete@0.9.2
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "missing cargo-deny unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 1.98.0 cargo-deny
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "unversioned cargo-deny unexpectedly passed source lint" >&2
  exit 1
fi

write_fixture cargo-audit@0.22.2 1.98.0 cargo-deny@0.20.1
if "${checker}" "${fixture_root}/ci.yml"; then
  echo "wrong cargo-deny version unexpectedly passed source lint" >&2
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

expected_index="sparse+https://index.crates.io/"
expected_protocol="sparse"

write_release_fixture() {
  local index_line="${1-}"
  local protocol_line="${2-}"
  printf '%s\n' "${index_line}" "${protocol_line}" \
    > "${fixture_root}/publish.yml"
}

expect_release_fixture_rejected() {
  local label="$1"
  local index_line="${2-}"
  local protocol_line="${3-}"
  write_release_fixture "${index_line}" "${protocol_line}"
  # Every noncanonical fixture must fail the source-policy check.
  if "${checker}" "${fixture_root}/ci.yml" "${fixture_root}/publish.yml"; then
    echo "${label} unexpectedly passed release policy" >&2
    exit 1
  fi
}

write_fixture cargo-audit@0.22.2 1.98.0
write_release_fixture \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: ${expected_index}" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_protocol}"
"${checker}" "${fixture_root}/ci.yml" "${fixture_root}/publish.yml"

expect_release_fixture_rejected "missing crates.io index" "" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_protocol}"
expect_release_fixture_rejected "empty crates.io index" \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX:" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_protocol}"
expect_release_fixture_rejected "alternate crates.io index" \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: https://github.com/rust-lang/crates.io-index" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_protocol}"
expect_release_fixture_rejected "missing crates.io protocol" \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: ${expected_index}" ""
expect_release_fixture_rejected "alternate crates.io protocol" \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: ${expected_index}" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: git"

# Default invocation must inspect both fixed callees, including candidate-only
# drift, even when the trusted workflow passes. Fixtures remain source text.
mkdir -p "${fixture_root}/.github/workflows"
write_fixture cargo-audit@0.22.2 1.98.0
cp "${fixture_root}/ci.yml" "${fixture_root}/.github/workflows/ci-trusted.yml"
cp "${fixture_root}/ci.yml" "${fixture_root}/.github/workflows/ci-candidate.yml"
write_release_fixture \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: ${expected_index}" \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_protocol}"
cp "${fixture_root}/publish.yml" "${fixture_root}/.github/workflows/publish.yml"
(cd "${fixture_root}" && "${checker}")
write_fixture cargo-audit@0.22.2 stable
cp "${fixture_root}/ci.yml" "${fixture_root}/.github/workflows/ci-candidate.yml"
# A valid trusted callee cannot mask a floating candidate toolchain.
if (cd "${fixture_root}" && "${checker}"); then
  echo "candidate-only tool drift unexpectedly passed source lint" >&2
  exit 1
fi
rm "${fixture_root}/.github/workflows/ci-candidate.yml"
# Missing candidate policy cannot silently narrow the checked input set.
if (cd "${fixture_root}" && "${checker}"); then
  echo "missing candidate workflow unexpectedly passed source lint" >&2
  exit 1
fi

echo "trusted tool pin checks passed"

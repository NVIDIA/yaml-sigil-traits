#!/usr/bin/env bash

# Enforce the reviewed Rust, cargo-audit, and release registry source pins.
# This is a narrow supply-chain lint, not a workflow graph or permissions parser.
set -euo pipefail

workflow="${1:-.github/workflows/ci.yml}"
release_workflow="${2:-.github/workflows/publish.yml}"
expected_audit="cargo-audit@0.22.2"
expected_toolchain="1.98.0"
compatibility_toolchain="1.95.0"
expected_registry_index="sparse+https://index.crates.io/"
expected_registry_protocol="sparse"
# This is a literal GitHub expression admitted by the source check, not shell.
# shellcheck disable=SC2016
matrix_toolchain='${{ matrix.toolchain }}'

if [[ ! -f "${workflow}" || -L "${workflow}" ]]; then
  echo "trusted-tool workflow is missing or not a regular file" >&2
  exit 1
fi

# Registry policy must come from a regular protected workflow source.
if [[ ! -f "${release_workflow}" || -L "${release_workflow}" ]]; then
  echo "release workflow is missing or not a regular file" >&2
  exit 1
fi

# Keep install-action tool inventories on one reviewable line. Multiline tool
# scalars could hide an unversioned cargo-audit entry from this focused check.
if grep -Eq '^[[:space:]]*tool:[[:space:]]*[>|]' "${workflow}"; then
  echo "trusted tool inventories must use an inline scalar" >&2
  exit 1
fi

audit_specs=0
while IFS= read -r line; do
  [[ "${line}" == *"tool:"* ]] || continue
  value="${line#*tool:}"
  IFS=',' read -r -a tools <<< "${value}"
  for raw in "${tools[@]}"; do
    tool="${raw#"${raw%%[![:space:]]*}"}"
    tool="${tool%"${tool##*[![:space:]]}"}"
    case "${tool}" in
      cargo-audit*)
        audit_specs=$((audit_specs + 1))
        if [[ "${tool}" != "${expected_audit}" ]]; then
          echo "trusted cargo-audit install is not pinned to ${expected_audit}" >&2
          exit 1
        fi
        ;;
    esac
  done
done < "${workflow}"

if ((audit_specs == 0)); then
  echo "trusted cargo-audit install is missing" >&2
  exit 1
fi

# Floating stable is not an acceptable tool-authentication environment. The
# independent Rust 1.95.0 compatibility lane remains permitted.
exact_toolchains=0
while IFS= read -r line; do
  case "${line}" in
    *toolchain:*|*RUSTUP_TOOLCHAIN:*)
      value="${line#*:}"
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
      # Normalize one ordinary YAML quote pair without accepting expressions.
      case "${value}" in
        \"*\"|\'*\') value="${value:1:${#value}-2}" ;;
      esac
      case "${value}" in
        "${expected_toolchain}")
          exact_toolchains=$((exact_toolchains + 1))
          ;;
        "${compatibility_toolchain}"|"${matrix_toolchain}")
          ;;
        *)
          echo "trusted Rust setup is not an allowed exact toolchain" >&2
          exit 1
          ;;
      esac
      ;;
  esac
done < "${workflow}"
if ((exact_toolchains == 0)); then
  echo "trusted Rust ${expected_toolchain} setup is missing" >&2
  exit 1
fi

index_key_count="$(grep -Ec \
  '^[[:space:]]*CARGO_REGISTRIES_CRATES_IO_INDEX:' "${release_workflow}" || :)"
index_value_count="$(grep -Fxc \
  "          CARGO_REGISTRIES_CRATES_IO_INDEX: ${expected_registry_index}" \
  "${release_workflow}" || :)"
protocol_key_count="$(grep -Ec \
  '^[[:space:]]*CARGO_REGISTRIES_CRATES_IO_PROTOCOL:' "${release_workflow}" || :)"
protocol_value_count="$(grep -Fxc \
  "          CARGO_REGISTRIES_CRATES_IO_PROTOCOL: ${expected_registry_protocol}" \
  "${release_workflow}" || :)"

# Exactly one canonical sparse index prevents implicit or alternate resolution.
if ((index_key_count != 1 || index_value_count != 1)); then
  echo "release registry index is missing, duplicated, or not canonical" >&2
  exit 1
fi

# Keep Cargo's protocol aligned with the canonical sparse index scheme.
if ((protocol_key_count != 1 || protocol_value_count != 1)); then
  echo "release registry protocol is missing, duplicated, or not sparse" >&2
  exit 1
fi

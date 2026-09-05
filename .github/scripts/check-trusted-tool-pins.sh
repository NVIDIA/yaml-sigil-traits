#!/usr/bin/env bash

# Enforce only the reviewed trusted Rust and cargo-audit source pins. This is a
# narrow supply-chain lint, not a workflow graph or permissions parser.
set -euo pipefail

workflow="${1:-.github/workflows/ci.yml}"
expected_audit="cargo-audit@0.22.2"
expected_toolchain="1.98.0"
compatibility_toolchain="1.95.0"
# This is a literal GitHub expression admitted by the source check, not shell.
# shellcheck disable=SC2016
matrix_toolchain='${{ matrix.toolchain }}'

if [[ ! -f "${workflow}" || -L "${workflow}" ]]; then
  echo "trusted-tool workflow is missing or not a regular file" >&2
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

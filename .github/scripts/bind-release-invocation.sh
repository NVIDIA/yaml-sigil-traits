#!/usr/bin/env bash

# Bind dispatch strings before materializing source. Executed only from the
# separate protected-main checkout, without publication credentials. This
# helper emits bounded CLI inputs; typed Rust qualification proves Git, PR,
# inventory, version, and package state before granting publication authority.
set -euo pipefail

# Only the two compiled Rust repository families have a publication policy.
if [[ "${GITHUB_ACTIONS:-}" != true || "${GITHUB_REF:-}" != refs/heads/main ]]; then
  echo "release invocation requires main-only GitHub Actions" >&2
  exit 1
fi
# Repository selection uses GitHub's own identity, never the mutable CI flag.
case "${GITHUB_REPOSITORY:-}" in
  NVIDIA/yaml-sigil-rs|NVIDIA/yaml-sigil-traits) ;;
  *) echo "repository has no support publication policy" >&2; exit 1 ;;
esac
base="${INPUT_BASE:-refs/heads/main}"
source="${INPUT_SOURCE:-}"
version="${INPUT_VERSION:-}"
run_id="${INPUT_RUN_ID:-}"
attempt="${INPUT_ATTEMPT:-}"
component='(0|[1-9][0-9]{0,8})'
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?'
# Canonical bounded base names cannot inject command arguments or output lines.
if [[ "${base}" != refs/heads/main && ! "${base}" =~ ^refs/heads/support/${component}\.${component}$ ]]; then
  echo "release base is not canonical main or support/M.N" >&2
  exit 1
fi
# An optional operator version is checked again against the actual source.
if [[ -n "${version}" && ( ${#version} -gt 128 || ! "${version}" =~ ^${semver}$ ) ]]; then
  echo "release version is not canonical SemVer" >&2
  exit 1
fi
# Main pushes keep automatic qualification; support can enter only by dispatch.
case "${GITHUB_EVENT_NAME:-}" in
  push)
    test "${base}" = refs/heads/main
    test -z "${source}${version}${run_id}${attempt}"
    source="${GITHUB_SHA}"
    mode=auto
    ;;
  workflow_dispatch)
    mode="${DISPATCH_OPERATION:-}"
    # Recovery carries original-run audit coordinates; fresh release cannot.
    case "${mode}" in
      recover)
        [[ "${run_id}" =~ ^[1-9][0-9]*$ && "${attempt}" =~ ^[1-9][0-9]*$ ]]
        ;;
      release)
        test "${base}" != refs/heads/main
        test -n "${version}"
        test -z "${run_id}${attempt}"
        ;;
      validate)
        test -z "${run_id}${attempt}"
        ;;
      *) echo "unsupported release dispatch operation" >&2; exit 1 ;;
    esac
    # Historical support recovery names its exact immutable package version.
    if [[ "${base}" != refs/heads/main && "${mode}" == recover ]]; then
      test -n "${version}"
    fi
    ;;
  *) echo "unsupported release event" >&2; exit 1 ;;
esac
[[ "${source}" =~ ^[0-9a-f]{40}$ ]]
# Main validation retains the original exact-dispatch-source requirement.
if [[ "${base}" == refs/heads/main && "${mode}" == validate ]]; then
  test "${source}" = "${GITHUB_SHA}"
fi
# A declared support version must belong to the selected line.
if [[ "${base}" != refs/heads/main && -n "${version}" ]]; then
  [[ "${version}" == "${base#refs/heads/support/}."* ]]
fi
printf 'base_ref=%s\nsource_sha=%s\nversion=%s\nmode=%s\n' \
  "${base}" "${source}" "${version}" "${mode}" >> "${GITHUB_OUTPUT}"

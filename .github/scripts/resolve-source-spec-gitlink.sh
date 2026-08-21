#!/usr/bin/env bash

# Resolve the exact source-spec gitlink recorded by a candidate checkout. The
# caller uses the resulting commit only with the fixed NVIDIA/yaml-sigil-spec
# repository; candidate-controlled submodule configuration is never loaded.
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo 'usage: resolve-source-spec-gitlink.sh CANDIDATE_ROOT OUTPUT_FILE' >&2
  exit 2
fi

candidate_root="$1"
output_file="$2"

if [[ ! -d "${candidate_root}/.git" && ! -f "${candidate_root}/.git" ]]; then
  echo 'candidate root is not a Git checkout' >&2
  exit 1
fi

entry="$(git -C "${candidate_root}" ls-tree HEAD -- source-spec)"
read -r mode object_type source_sha path <<< "${entry}"

if [[ "${mode}" != '160000' || "${object_type}" != 'commit' || \
  "${path}" != 'source-spec' || ! "${source_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'candidate source-spec entry is not an exact commit gitlink' >&2
  exit 1
fi

printf 'sha=%s\n' "${source_sha}" >> "${output_file}"

#!/usr/bin/env bash
# Exercise candidate-controlled state only inside terminal candidate execution.
# The workflow deliberately has no later same-job policy or privileged consumer.
set -euo pipefail

: "${RUNNER_TEMP:?}"
: "${GITHUB_ENV:?}"
: "${GITHUB_PATH:?}"

# Fail if the terminal candidate process unexpectedly receives privileged state.
for variable in \
  ACTIONS_CACHE_URL \
  ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  ACTIONS_ID_TOKEN_REQUEST_URL \
  ACTIONS_RESULTS_URL \
  ACTIONS_RUNTIME_TOKEN \
  ACTIONS_RUNTIME_URL \
  APP_TOKEN \
  CARGO_REGISTRIES_CRATES_IO_TOKEN \
  GH_TOKEN \
  GITHUB_TOKEN \
  GIT_TOKEN; do
  if [[ -n "${!variable:-}" ]]; then
    printf 'candidate canary: %s is unexpectedly populated\n' "${variable}" >&2
    exit 1
  fi
done

canary_root="${RUNNER_TEMP}/candidate-state-canary"
fake_bin="${canary_root}/bin"
markers="${canary_root}/markers"
cargo_home="${canary_root}/cargo-home"
mini_crate="${canary_root}/wrapper-check"
install -d "${fake_bin}" "${markers}" "${cargo_home}" "${mini_crate}/src"

# Exercise a candidate-owned Cargo alias without altering the job's Cargo home.
printf '%s\n' \
  '[alias]' \
  'candidate-canary = "version"' > "${cargo_home}/config.toml"
cargo_bin="${CARGO_BIN:-${FIXED_CARGO:-}}"
if [[ -z "${cargo_bin}" ]]; then
  cargo_bin="$(command -v cargo)"
fi
test -x "${cargo_bin}"
CARGO_HOME="${cargo_home}" "${cargo_bin}" candidate-canary >/dev/null

# Exercise substituted audit and deny executables under a scoped candidate PATH.
for tool in cargo-audit cargo-deny; do
  tool_path="${fake_bin}/${tool}"
  # These expressions belong to the generated executable, not this shell.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\\n" "${0##*/}" >> "${CANDIDATE_CANARY_MARKERS:?}/substituted-tools"' \
    > "${tool_path}"
  chmod 0500 "${tool_path}"
done
CANDIDATE_CANARY_MARKERS="${markers}" \
  PATH="${fake_bin}:${PATH}" cargo-audit --version
CANDIDATE_CANARY_MARKERS="${markers}" \
  PATH="${fake_bin}:${PATH}" cargo-deny --version
grep -Fx 'cargo-audit' "${markers}/substituted-tools"
grep -Fx 'cargo-deny' "${markers}/substituted-tools"

# Exercise Cargo's compiler-wrapper calling convention on a dependency-free crate.
wrapper="${fake_bin}/rustc-wrapper"
# These expressions belong to the generated wrapper, not this shell.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'compiler="$1"' \
  'shift' \
  'printf "wrapper\\n" >> "${CANDIDATE_CANARY_MARKERS:?}/wrapper"' \
  'exec "${compiler}" "$@"' > "${wrapper}"
chmod 0500 "${wrapper}"
printf '%s\n' \
  '[package]' \
  'name = "candidate-wrapper-canary"' \
  'version = "0.0.0"' \
  'edition = "2021"' \
  '' \
  '[workspace]' > "${mini_crate}/Cargo.toml"
printf '%s\n' '#![allow(dead_code)]' 'pub fn canary() {}' \
  > "${mini_crate}/src/lib.rs"
rustc_bin="${FIXED_RUSTC:-}"
if [[ -z "${rustc_bin}" ]]; then
  rustc_bin="$(command -v rustc)"
fi
CANDIDATE_CANARY_MARKERS="${markers}" \
  CARGO_HOME="${cargo_home}" \
  CARGO_TARGET_DIR="${canary_root}/target" \
  RUSTC="${rustc_bin}" \
  RUSTC_WRAPPER="${wrapper}" \
  "${cargo_bin}" check --offline --quiet --manifest-path "${mini_crate}/Cargo.toml"
grep -Fx 'wrapper' "${markers}/wrapper"

# Poison only runner command files. GitHub applies these after this terminal step.
printf '%s\n' 'YAML_SIGIL_CANDIDATE_CANARY=untrusted' >> "${GITHUB_ENV}"
printf '%s\n' "${fake_bin}" >> "${GITHUB_PATH}"

printf '%s\n' 'candidate state canary completed'

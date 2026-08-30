#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Prepare immutable tools and one exact candidate, then execute the candidate
# as the terminal workload under a different operating-system identity. The
# job invoking this script must contain no repository-backed Actions and no
# later step. The candidate identity cannot reach runner command files or the
# token-bearing parent, and the parent kills every process owned by that
# identity before returning the terminal result.
set -euo pipefail

if [[ "$#" -ne 9 ]]; then
  echo 'usage: run-terminal-candidate.sh PROFILE RUNNER_OS POLICY_ROOT POLICY_SHA CANONICAL_REPOSITORY HEAD_REPOSITORY BASE_SHA HEAD_SHA COMMAND_FILE' >&2
  exit 2
fi

profile="$1"
runner_os="$2"
policy_root="$3"
policy_sha="$4"
canonical_repository="$5"
head_repository="$6"
base_sha="$7"
head_sha="$8"
command_file="$9"

runner_command_files=()
for command_name in GITHUB_ENV GITHUB_PATH GITHUB_OUTPUT GITHUB_STEP_SUMMARY; do
  command_path="${!command_name:-}"
  if [[ -z "${command_path}" || ! -f "${command_path}" ]]; then
    echo "required runner command file ${command_name} is absent" >&2
    exit 1
  fi
  runner_command_files+=("${command_path}")
done
if [[ -n "${GITHUB_STATE:-}" ]]; then
  if [[ ! -f "${GITHUB_STATE}" ]]; then
    echo 'runner state command file is absent' >&2
    exit 1
  fi
  runner_command_files+=("${GITHUB_STATE}")
fi
if [[ "${command_file}" != "${GITHUB_ENV}" ]]; then
  echo 'runner environment command file binding is inconsistent' >&2
  exit 1
fi
command_directory="$(cd "$(dirname "${command_file}")" && pwd -P)"
for command_path in "${runner_command_files[@]}"; do
  resolved_directory="$(cd "$(dirname "${command_path}")" && pwd -P)"
  if [[ "${resolved_directory}" != "${command_directory}" ]]; then
    echo 'runner command files do not share one protected directory' >&2
    exit 1
  fi
done

case "${profile}" in
  controller | protected-ci | candidate-ci) ;;
  *)
    echo 'terminal candidate profile is invalid' >&2
    exit 2
    ;;
esac

if [[ "${runner_os}" != 'Linux' ]]; then
  echo 'terminal candidate execution requires Linux' >&2
  exit 2
fi

case "${canonical_repository}" in
  NVIDIA/yaml-sigil-spec) repository_kind='spec' ;;
  NVIDIA/yaml-sigil-traits) repository_kind='traits' ;;
  NVIDIA/yaml-sigil-rs) repository_kind='rs' ;;
  *)
    echo 'terminal candidate repository is outside the fixed policy table' >&2
    exit 2
    ;;
esac

if [[ "${profile}" == 'candidate-ci' && "${repository_kind}" == 'spec' ]]; then
  echo 'supplemental candidate CI is unavailable for the specification repository' >&2
  exit 2
fi

if [[ ! "${head_repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo 'candidate repository is invalid' >&2
  exit 2
fi

if [[ ! "${policy_sha}" =~ ^[0-9a-f]{40}$ || \
  ! "${base_sha}" =~ ^[0-9a-f]{40}$ || \
  ! "${head_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'terminal candidate commit binding is invalid' >&2
  exit 2
fi

policy_root="$(cd "${policy_root}" && pwd -P)"
if [[ ! -f "${command_file}" ]]; then
  echo 'runner command file is absent' >&2
  exit 1
fi

trusted_git="$(command -v git)"
trusted_python_command="$(command -v python3)"
trusted_cargo="$(command -v cargo)"
trusted_rustup="$(command -v rustup)"
trusted_env="$(command -v env)"
trusted_git="$(realpath "${trusted_git}")"
trusted_python="$(realpath "${trusted_python_command}")"
trusted_cargo="$(realpath "${trusted_cargo}")"
trusted_rustup="$(realpath "${trusted_rustup}")"
trusted_env="$(realpath "${trusted_env}")"

if [[ "$("${trusted_git}" -C "${policy_root}" rev-parse --verify 'HEAD^{commit}')" != "${policy_sha}" ]]; then
  echo 'terminal policy checkout is not the authorized commit' >&2
  exit 1
fi

"${trusted_python}" -c \
  'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); raise SystemExit(0 if value.get("repository") == sys.argv[2] and value.get("repository_kind") == sys.argv[3] else 1)' \
  "${policy_root}/.github/protected-pr-ci.json" \
  "${canonical_repository}" "${repository_kind}"

github_token="${GITHUB_TOKEN:-}"
if [[ -z "${github_token}" ]]; then
  echo 'read-only verification token is absent' >&2
  exit 1
fi

original_path="${PATH}"

# Remove runner control, credential, preload, and provider state before any
# downloaded tool or candidate process can start. The verifier receives only
# the read-only token in its own environment later.
while IFS='=' read -r name _; do
  case "${name}" in
    ACTIONS_* | GITHUB_* | GH_* | RUNNER_* | CI | LD_* | DYLD_* | PYTHONPATH | RUSTC_WRAPPER | RUSTDOCFLAGS)
      unset "${name}"
      ;;
  esac
done < <(env)

# Resolve only the just-created trusted sandbox before forming candidate
# paths. The protected no-follow preflight receives this physical ancestor.
sandbox="$(mktemp -d)"
sandbox="$(
  cd -P -- "${sandbox}"
  pwd -P
)"
chmod 0755 "${sandbox}"
candidate_root="${sandbox}/candidate"
candidate_home="${sandbox}/candidate-home"
candidate_cache="${candidate_home}/.cache"
candidate_cargo_home="${sandbox}/candidate-cargo-home"
candidate_target="${sandbox}/candidate-target"
candidate_temp="${sandbox}/candidate-temp"
candidate_buf_cache="${sandbox}/candidate-buf-cache"
candidate_pycache="${sandbox}/candidate-pycache"
candidate_root_lockfile="${candidate_home}/Cargo.lock"
trusted_tools="${sandbox}/trusted-tools"
trusted_rustup_home="${sandbox}/trusted-rustup"
setup_cargo_home="${sandbox}/setup-cargo-home"
setup_target="${sandbox}/setup-target"
detached_pid_file="${candidate_home}/detached.pid"
protected_validator="${trusted_cargo}"
mkdir -p \
  "${candidate_home}" "${candidate_cache}" "${candidate_cargo_home}" \
  "${candidate_target}" \
  "${candidate_temp}" "${candidate_buf_cache}" "${candidate_pycache}" \
  "${trusted_tools}/bin" "${trusted_rustup_home}" "${setup_cargo_home}" \
  "${setup_target}"

# Preserve the Rustup multicall name after resolving the original executable.
# Some installations expose rustup as a symlink to rustup-init, whose resolved
# basename selects installer mode instead of toolchain management mode.
install -m 0555 "${trusted_rustup}" "${trusted_tools}/bin/rustup"
trusted_rustup="${trusted_tools}/bin/rustup"

safe_path=''
while IFS= read -r entry; do
  [[ -n "${entry}" && -d "${entry}" ]] || continue
  resolved_entry="$(cd "${entry}" && pwd -P)"
  case "${resolved_entry}" in
    "${sandbox}" | "${sandbox}"/*) continue ;;
  esac
  case ":${safe_path}:" in
    *:"${resolved_entry}":*) ;;
    *) safe_path="${safe_path:+${safe_path}:}${resolved_entry}" ;;
  esac
done < <(tr ':' '\n' <<< "${original_path}")
safe_path="${trusted_tools}/bin:$(dirname "${trusted_cargo}"):$(dirname "${trusted_python}"):${safe_path}"

export CARGO_HOME="${setup_cargo_home}"
export CARGO_TARGET_DIR="${setup_target}"
export PATH="${safe_path}"
export RUSTUP_HOME="${trusted_rustup_home}"
export RUSTUP_TOOLCHAIN='stable'
export RUSTFLAGS='-D warnings'

if [[ "${profile}" != 'controller' ]]; then
  "${trusted_rustup}" toolchain install stable --profile minimal \
    --component clippy --component rustfmt --no-self-update
  cargo +stable install --locked --root "${trusted_tools}" rumdl --version 0.2.54
  cargo +stable install --locked --root "${trusted_tools}" cargo-audit
  cargo +stable install --locked --root "${trusted_tools}" cargo-machete --version 0.9.2

  if [[ "${repository_kind}" != 'spec' ]]; then
    cargo +stable install --locked --root "${trusted_tools}" cargo-deny --version 0.20.2
  fi

  if [[ "${repository_kind}" == 'spec' ]]; then
    # The Rust installer verifies Buf's signed upstream checksum manifest
    # before staging the pinned official binaries in the trusted tool tree.
    BUF_RS_CACHE_DIR="${sandbox}/trusted-buf-cache" \
      BUF_RS_TOOLCHAIN_BIN_DIR="${trusted_tools}/bin" \
      cargo +stable install --locked --root "${trusted_tools}" \
      buf-toolchain --version 1.72.0
  fi

  if [[ "${profile}" == 'candidate-ci' ]]; then
    "${trusted_rustup}" toolchain install 1.95.0 --profile minimal --no-self-update
  fi
fi

install -m 0555 "${trusted_cargo}" "${trusted_tools}/bin/cargo"
trusted_cargo="${trusted_tools}/bin/cargo"
protected_validator="${trusted_cargo}"

# Cargo discovers component subcommands through PATH. An isolated Rustup home
# contains their toolchain binaries but does not add matching Cargo-home
# proxies, so stage only the trusted stable tools the validators invoke.
if [[ "${profile}" != 'controller' ]]; then
  for rust_proxy in cargo-clippy cargo-fmt clippy-driver rustc rustdoc rustfmt; do
    install -m 0555 "${trusted_rustup}" \
      "${trusted_tools}/bin/${rust_proxy}"
  done
fi

git_command=(
  "${trusted_git}"
  -c advice.detachedHead=false
  -c core.autocrlf=false
  -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
  -c credential.helper=
)

export GIT_TERMINAL_PROMPT=0
"${git_command[@]}" init --quiet --initial-branch=main "${candidate_root}"
"${git_command[@]}" -C "${candidate_root}" remote add origin \
  "https://github.com/${head_repository}.git"
"${git_command[@]}" -C "${candidate_root}" fetch --no-tags \
  --no-recurse-submodules --depth=1 origin "${head_sha}"
"${git_command[@]}" -C "${candidate_root}" checkout --quiet --detach FETCH_HEAD
if [[ "$("${git_command[@]}" -C "${candidate_root}" rev-parse --verify 'HEAD^{commit}')" != "${head_sha}" ]]; then
  echo 'candidate checkout did not resolve to the authorized head' >&2
  exit 1
fi

digest() {
  "${trusted_python}" -c \
    'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "$1"
}

GITHUB_TOKEN="${github_token}" "${trusted_python}" \
  "${policy_root}/.github/scripts/protected_checkout.py" verify \
  --candidate-root "${candidate_root}" \
  --git "${trusted_git}" \
  --repository "${canonical_repository}" \
  --base-sha "${base_sha}" \
  --head-sha "${head_sha}" \
  --config "${policy_root}/.github/protected-pr-ci.json" \
  --expected-verifier-sha256 "$(digest "${policy_root}/.github/scripts/protected_checkout.py")" \
  --expected-controller-sha256 "$(digest "${policy_root}/.github/scripts/protected_pr_ci.py")" \
  --expected-config-sha256 "$(digest "${policy_root}/.github/protected-pr-ci.json")"
github_token=''

if [[ "${repository_kind}" == 'traits' && "${profile}" != 'controller' ]]; then
  spec_output="${sandbox}/source-spec.out"
  "${policy_root}/.github/scripts/resolve-source-spec-gitlink.sh" \
    "${candidate_root}" "${spec_output}"
  source_spec_sha="$(sed -n 's/^sha=//p' "${spec_output}")"
  if [[ ! "${source_spec_sha}" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'protected specification gitlink resolver returned an invalid commit' >&2
    exit 1
  fi
  "${git_command[@]}" init --quiet --initial-branch=main "${candidate_root}/source-spec"
  "${git_command[@]}" -C "${candidate_root}/source-spec" remote add origin \
    'https://github.com/NVIDIA/yaml-sigil-spec.git'
  "${git_command[@]}" -C "${candidate_root}/source-spec" fetch --no-tags \
    --no-recurse-submodules --depth=1 origin "${source_spec_sha}"
  "${git_command[@]}" -C "${candidate_root}/source-spec" checkout --quiet --detach FETCH_HEAD
  if [[ "$("${git_command[@]}" -C "${candidate_root}/source-spec" rev-parse --verify 'HEAD^{commit}')" != "${source_spec_sha}" ]]; then
    echo 'specification checkout did not resolve to the authorized gitlink' >&2
    exit 1
  fi
fi

if [[ "${profile}" == 'protected-ci' ]]; then
  policy_manifest="${policy_root}/xtask/Cargo.toml"
  if [[ "${repository_kind}" == 'spec' ]]; then
    policy_manifest="${policy_root}/conformance/rebuild-rs/xtask/Cargo.toml"
  fi
  export BUF_RS_CACHE_DIR="${sandbox}/trusted-buf-cache"
  mkdir -p "${BUF_RS_CACHE_DIR}"
  cargo +stable build --locked --manifest-path "${policy_manifest}"
  protected_validator="${trusted_tools}/bin/protected-validator"
  cp "${setup_target}/debug/xtask" "${protected_validator}"
  chmod 0555 "${protected_validator}"
fi

if [[ "${repository_kind}" == 'spec' && "${profile}" == 'protected-ci' ]]; then
  "${protected_validator}" candidate-preflight \
    --candidate-root "${candidate_root}"
fi

chmod -R a+rX,go-w "${policy_root}" "${candidate_root}" \
  "${trusted_tools}" "${trusted_rustup_home}"

driver="${policy_root}/.github/scripts/terminal_candidate.py"
candidate_path="${safe_path}"

candidate_user='yscandidate'
candidate_user_created='false'

cleanup_candidate_user() {
  if [[ "${candidate_user_created}" != 'true' ]]; then
    return
  fi
  if [[ -n "${candidate_uid:-}" ]]; then
    sudo -n pkill -KILL -u "${candidate_uid}" >/dev/null 2>&1 || true
  fi
  sudo -n userdel "${candidate_user}" >/dev/null 2>&1 || true
  if id "${candidate_user}" >/dev/null 2>&1; then
    return 1
  fi
  candidate_user_created='false'
}
trap 'cleanup_candidate_user || true' EXIT

if id "${candidate_user}" >/dev/null 2>&1; then
  echo 'disposable candidate user already exists' >&2
  exit 1
fi
sudo -n useradd --system --user-group --no-create-home \
  --home-dir "${candidate_home}" --shell /usr/sbin/nologin \
  "${candidate_user}"
candidate_user_created='true'
candidate_uid="$(id -u "${candidate_user}")"
if pgrep -u "${candidate_uid}" >/dev/null 2>&1; then
  echo 'new disposable candidate identity unexpectedly owns a process' >&2
  exit 1
fi

chmod 0700 "${command_directory}"
# Only elevated setup may transfer writable roots to the disposable identity.
sudo -n chown -R "${candidate_uid}" \
  "${candidate_home}" "${candidate_cache}" "${candidate_cargo_home}" \
  "${candidate_target}" \
  "${candidate_temp}" "${candidate_buf_cache}" "${candidate_pycache}"

candidate_environment=(
  PATH="${candidate_path}" \
  HOME="${candidate_home}" \
  XDG_CACHE_HOME="${candidate_cache}" \
  LOGNAME="${candidate_user}" \
  USER="${candidate_user}" \
  TMPDIR="${candidate_temp}" \
  CARGO_HOME="${candidate_cargo_home}" \
  CARGO_TARGET_DIR="${candidate_target}" \
  RUSTUP_HOME="${trusted_rustup_home}" \
  RUSTUP_TOOLCHAIN='stable' \
  RUSTFLAGS='-D warnings' \
  BUF_CACHE_DIR="${candidate_buf_cache}" \
  BUF_RS_CACHE_DIR="${candidate_buf_cache}" \
  PYTHONPYCACHEPREFIX="${candidate_pycache}" \
  YAML_SIGIL_PROFILE="${profile}" \
  YAML_SIGIL_TERMINAL_CANDIDATE='1'
)
if [[ "${repository_kind}" != 'spec' && "${profile}" != 'controller' ]]; then
  # Current Cargo keeps its generated root lock outside the deliberately
  # read-only candidate source. The Rust validator separately preserves each
  # committed xtask lock for xtask-workspace commands.
  candidate_environment+=(
    CARGO_RESOLVER_LOCKFILE_PATH="${candidate_root_lockfile}"
  )
fi

set +e
sudo -n -u "${candidate_user}" -- "${trusted_env}" -i \
  "${candidate_environment[@]}" \
  "${trusted_python}" "${driver}" run \
  --profile "${profile}" \
  --kind "${repository_kind}" \
  --policy-root "${policy_root}" \
  --candidate-root "${candidate_root}" \
  --trusted-cargo "${trusted_cargo}" \
  --trusted-python "${trusted_python}" \
  --trusted-rustup-home "${trusted_rustup_home}" \
  --protected-validator "${protected_validator}" \
  --command-file "${command_file}" \
  --detached-pid-file "${detached_pid_file}"
candidate_status=$?
set -e

sudo -n pkill -KILL -u "${candidate_uid}" >/dev/null 2>&1 || true
for _ in {1..300}; do
  if ! pgrep -u "${candidate_uid}" >/dev/null 2>&1; then
    echo 'Terminal candidate identity is quiescent.'
    if ! cleanup_candidate_user; then
      echo 'disposable candidate identity could not be removed' >&2
      exit 1
    fi
    trap - EXIT
    exit "${candidate_status}"
  fi
  sleep 0.1
done

echo 'terminal candidate identity retained a process after cleanup' >&2
ps -U "${candidate_uid}" -o pid=,ppid=,state=,comm= >&2 || true
exit 1

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
trusted_toolchain='1.98.0'
cargo_audit_version='0.22.2'

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
trusted_python_command='/usr/bin/python3'
trusted_cargo="$(command -v cargo)"
trusted_rustup="$(command -v rustup)"
trusted_git="$(realpath "${trusted_git}")"
trusted_python="$(realpath "${trusted_python_command}")"
trusted_cargo="$(realpath "${trusted_cargo}")"
trusted_rustup="$(realpath "${trusted_rustup}")"

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
candidate_state="${sandbox}/candidate-state"
candidate_home="${candidate_state}/home"
candidate_cache="${candidate_state}/cache"
candidate_cargo_seed="${sandbox}/candidate-cargo-seed"
candidate_cargo_states="${candidate_state}/cargo-phases"
candidate_prefetch_target="${candidate_state}/prefetch-target"
candidate_temp="${candidate_state}/temp"
candidate_buf_cache="${candidate_state}/buf-cache"
candidate_pycache="${candidate_state}/pycache"
prefetch_root_lockfile="${candidate_home}/Cargo.lock"
candidate_root_lockfile="${sandbox}/candidate-root.Cargo.lock"
trusted_tools="${sandbox}/trusted-tools"
trusted_rustup_home="${sandbox}/trusted-rustup"
setup_cargo_home="${sandbox}/setup-cargo-home"
setup_target="${sandbox}/setup-target"
protected_validator="${trusted_cargo}"
mkdir -p \
  "${candidate_home}" "${candidate_cache}" "${candidate_cargo_seed}" \
  "${candidate_cargo_states}" "${candidate_prefetch_target}" \
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
export RUSTUP_TOOLCHAIN="${trusted_toolchain}"
export RUSTFLAGS='-D warnings'

if [[ "${profile}" != 'controller' ]]; then
  "${trusted_rustup}" toolchain install "${trusted_toolchain}" --profile minimal \
    --component clippy --component rustfmt --no-self-update
  rustc_version="$("${trusted_rustup}" run "${trusted_toolchain}" rustc --version)"
  cargo_version="$("${trusted_rustup}" run "${trusted_toolchain}" cargo --version)"
  case "${rustc_version}" in
    "rustc ${trusted_toolchain} ("*) ;;
    *)
      echo 'installed rustc version differs from protected policy' >&2
      exit 1
      ;;
  esac
  case "${cargo_version}" in
    "cargo ${trusted_toolchain} ("*) ;;
    *)
      echo 'installed Cargo version differs from protected policy' >&2
      exit 1
      ;;
  esac
  cargo +"${trusted_toolchain}" install --locked --root "${trusted_tools}" rumdl --version 0.2.54
  cargo +"${trusted_toolchain}" install --locked --root "${trusted_tools}" \
    cargo-audit --version "${cargo_audit_version}"
  cargo +"${trusted_toolchain}" install --locked --root "${trusted_tools}" cargo-machete --version 0.9.2
  if [[ "$("${trusted_tools}/bin/cargo-audit" --version)" != \
    "cargo-audit ${cargo_audit_version}" ]]; then
    echo 'installed cargo-audit version differs from protected policy' >&2
    exit 1
  fi

  if [[ "${repository_kind}" != 'spec' ]]; then
    cargo +"${trusted_toolchain}" install --locked --root "${trusted_tools}" cargo-deny --version 0.20.2
  fi

  if [[ "${repository_kind}" == 'spec' ]]; then
    # The Rust installer verifies Buf's signed upstream checksum manifest
    # before staging the pinned official binaries in the trusted tool tree.
    BUF_RS_CACHE_DIR="${sandbox}/trusted-buf-cache" \
      BUF_RS_TOOLCHAIN_BIN_DIR="${trusted_tools}/bin" \
      cargo +"${trusted_toolchain}" install --locked --root "${trusted_tools}" \
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
# proxies, so stage only the pinned trusted tools the validators invoke.
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

# Reject executable Cargo configuration that has not already been adopted in
# protected policy before Cargo reads any candidate-controlled configuration.
"${trusted_python}" "${policy_root}/.github/scripts/terminal_candidate.py" \
  cargo-config-preflight \
  --kind "${repository_kind}" \
  --policy-root "${policy_root}" \
  --candidate-root "${candidate_root}"

if [[ "${profile}" == 'protected-ci' ]]; then
  policy_manifest="${policy_root}/xtask/Cargo.toml"
  if [[ "${repository_kind}" == 'spec' ]]; then
    policy_manifest="${policy_root}/conformance/rebuild-rs/xtask/Cargo.toml"
  fi
  export BUF_RS_CACHE_DIR="${sandbox}/trusted-buf-cache"
  mkdir -p "${BUF_RS_CACHE_DIR}"
  cargo +"${trusted_toolchain}" build --locked --manifest-path "${policy_manifest}"
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

candidate_user='yscandidate'
candidate_user_created='false'
candidate_container="yaml-sigil-candidate-${head_sha}-$$"
fetch_container="${candidate_container}-fetch"
candidate_image="yaml-sigil-candidate:${head_sha}-${profile}-$$"
candidate_image_created='false'
trusted_docker=''

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

cleanup_candidate_container() {
  local failed='false'
  if [[ -z "${trusted_docker}" ]]; then
    return
  fi
  for container in "${candidate_container}" "${fetch_container}"; do
    if "${trusted_docker}" container inspect "${container}" >/dev/null 2>&1; then
      "${trusted_docker}" container rm --force "${container}" >/dev/null 2>&1 || failed='true'
    fi
  done
  if [[ "${candidate_image_created}" == 'true' ]]; then
    "${trusted_docker}" image rm --force "${candidate_image}" >/dev/null 2>&1 || failed='true'
    if "${trusted_docker}" image inspect "${candidate_image}" >/dev/null 2>&1; then
      failed='true'
    else
      candidate_image_created='false'
    fi
  fi
  [[ "${failed}" == 'false' ]]
}

cleanup_all() {
  local failed='false'
  cleanup_candidate_container || failed='true'
  cleanup_candidate_user || failed='true'
  [[ "${failed}" == 'false' ]]
}
trap 'cleanup_all || true' EXIT

if id "${candidate_user}" >/dev/null 2>&1; then
  echo 'disposable candidate user already exists' >&2
  exit 1
fi
sudo -n useradd --system --user-group --no-create-home \
  --home-dir "${candidate_home}" --shell /usr/sbin/nologin \
  "${candidate_user}"
candidate_user_created='true'
candidate_uid="$(id -u "${candidate_user}")"
candidate_gid="$(id -g "${candidate_user}")"
if pgrep -u "${candidate_uid}" >/dev/null 2>&1; then
  echo 'new disposable candidate identity unexpectedly owns a process' >&2
  exit 1
fi

chmod 0700 "${command_directory}"
# Only elevated setup may transfer writable roots to the disposable identity.
sudo -n chown -R "${candidate_uid}" \
  "${candidate_state}" "${candidate_cargo_seed}"

# Resolve the running agent from its executable rather than assuming a hosted
# image directory. This probe prints metadata and accessibility only; it never
# reads registration or credential contents.
mapfile -t runner_worker_pids < <(pgrep -x Runner.Worker)
if [[ "${#runner_worker_pids[@]}" -ne 1 ]]; then
  echo 'cannot uniquely identify the Actions runner worker' >&2
  exit 1
fi
runner_worker_executable="$(readlink -f "/proc/${runner_worker_pids[0]}/exe")"
case "${runner_worker_executable}" in
  */bin/Runner.Worker) ;;
  *)
    echo 'Actions runner worker executable has an unexpected layout' >&2
    exit 1
    ;;
esac
runner_agent_root="$(dirname "$(dirname "${runner_worker_executable}")")"
runner_state_entries=0
for entry in .runner .credentials .credentials_rsaparams; do
  runner_state_path="${runner_agent_root}/${entry}"
  if [[ ! -e "${runner_state_path}" && ! -L "${runner_state_path}" ]]; then
    continue
  fi
  runner_state_metadata="$(stat -Lc 'type=%F mode=%a owner=%u group=%g size=%s' -- "${runner_state_path}")"
  if sudo -n -u "${candidate_user}" -- test -r "${runner_state_path}"; then
    runner_state_readable='true'
  else
    runner_state_readable='false'
  fi
  echo "Runner control-plane probe ${entry}: ${runner_state_metadata} candidate-readable=${runner_state_readable}"
  runner_state_entries=$((runner_state_entries + 1))
done
if [[ "${runner_state_entries}" -eq 0 ]]; then
  echo 'Actions runner control-plane files were not found for metadata probing' >&2
  exit 1
fi

trusted_docker="$(realpath "$(command -v docker)")"
trusted_tar="$(realpath "$(command -v tar)")"
"${trusted_docker}" version --format '{{.Client.Version}} {{.Server.Version}}' >/dev/null
empty_rootfs="${sandbox}/empty-rootfs.tar"
"${trusted_tar}" --format=posix --create --file="${empty_rootfs}" --files-from=/dev/null
"${trusted_docker}" image import "${empty_rootfs}" "${candidate_image}" >/dev/null
candidate_image_created='true'
"${trusted_docker}" image inspect "${candidate_image}" >/dev/null

container_system_mounts=(
  --mount 'type=bind,src=/usr,dst=/usr,readonly'
  --mount 'type=bind,src=/bin,dst=/bin,readonly'
  --mount 'type=bind,src=/lib,dst=/lib,readonly'
  --mount 'type=bind,src=/lib64,dst=/lib64,readonly'
  --mount 'type=bind,src=/etc/ssl/certs,dst=/etc/ssl/certs,readonly'
)
container_security=(
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges=true
  --pids-limit 512
  --user "${candidate_uid}:${candidate_gid}"
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=1073741824'
)
container_inputs=(
  --mount "type=bind,src=${policy_root},dst=/policy,readonly"
  --mount "type=bind,src=${candidate_root},dst=/candidate,readonly"
  --mount "type=bind,src=${trusted_tools},dst=/trusted-tools,readonly"
  --mount "type=bind,src=${trusted_rustup_home},dst=/trusted-rustup,readonly"
  --mount "type=bind,src=${candidate_state},dst=/state"
)
container_environment=(
  --env 'PATH=/trusted-tools/bin:/usr/bin:/bin'
  --env 'HOME=/state/home'
  --env 'XDG_CACHE_HOME=/state/cache'
  --env "LOGNAME=${candidate_user}"
  --env "USER=${candidate_user}"
  --env 'TMPDIR=/state/temp'
  --env 'RUSTUP_HOME=/trusted-rustup'
  --env "RUSTUP_TOOLCHAIN=${trusted_toolchain}"
  --env 'RUSTFLAGS=-D warnings'
  --env 'BUF_CACHE_DIR=/state/buf-cache'
  --env 'BUF_RS_CACHE_DIR=/state/buf-cache'
  --env 'PYTHONPYCACHEPREFIX=/state/pycache'
)

# Dependency acquisition runs without credentials inside the same filesystem
# and PID boundary later used for validation. No candidate program is built or
# executed, and the resulting source cache becomes read-only before use.
if [[ "${profile}" != 'controller' ]]; then
  "${trusted_docker}" run --name "${fetch_container}" --rm --network bridge \
    "${container_security[@]}" "${container_system_mounts[@]}" \
    "${container_inputs[@]}" \
    --mount "type=bind,src=${candidate_cargo_seed},dst=/cargo-seed" \
    "${container_environment[@]}" \
    --env 'CARGO_HOME=/cargo-seed' \
    --env 'CARGO_TARGET_DIR=/state/prefetch-target' \
    --env 'CARGO_RESOLVER_LOCKFILE_PATH=/state/home/Cargo.lock' \
    "${candidate_image}" \
    /trusted-tools/bin/cargo "+${trusted_toolchain}" fetch \
    --manifest-path /candidate/Cargo.toml
  "${trusted_docker}" run --name "${fetch_container}" --rm --network bridge \
    "${container_security[@]}" "${container_system_mounts[@]}" \
    "${container_inputs[@]}" \
    --mount "type=bind,src=${candidate_cargo_seed},dst=/cargo-seed" \
    "${container_environment[@]}" \
    --env 'CARGO_HOME=/cargo-seed' \
    --env 'CARGO_TARGET_DIR=/state/prefetch-target' \
    "${candidate_image}" \
    /trusted-tools/bin/cargo "+${trusted_toolchain}" fetch --locked \
    --manifest-path /candidate/xtask/Cargo.toml
  "${trusted_docker}" run --name "${fetch_container}" --rm --network bridge \
    "${container_security[@]}" "${container_system_mounts[@]}" \
    "${container_inputs[@]}" \
    --mount "type=bind,src=${candidate_cargo_seed},dst=/cargo-seed" \
    "${container_environment[@]}" \
    --env 'CARGO_HOME=/cargo-seed' \
    "${candidate_image}" \
    /usr/bin/git -c core.hooksPath=/dev/null -c credential.helper= clone \
    --depth=1 --no-tags https://github.com/RustSec/advisory-db.git \
    /cargo-seed/advisory-db
  if [[ ! -f "${prefetch_root_lockfile}" ]]; then
    echo 'Cargo prefetch did not produce the external root lockfile' >&2
    exit 1
  fi
  install -m 0444 "${prefetch_root_lockfile}" "${candidate_root_lockfile}"
fi
chmod -R a+rX,go-w "${candidate_cargo_seed}"

# The terminal validation container has no runner home, host PID namespace,
# Docker socket, credentials, or outbound network. Authenticated source and
# pinned tools are read-only; every writable Cargo/target phase is disposable.
validation_environment=(
  "${container_environment[@]}"
  --env 'CARGO_HOME=/state/initial-cargo-home'
  --env 'CARGO_TARGET_DIR=/state/initial-target'
  --env 'CARGO_NET_OFFLINE=true'
  --env 'YAML_SIGIL_CARGO_SEED=/cargo-seed'
  --env 'YAML_SIGIL_CARGO_STATE_ROOT=/state/cargo-phases'
  --env 'YAML_SIGIL_CARGO_AUDIT=/trusted-tools/bin/cargo-audit'
  --env "YAML_SIGIL_PROFILE=${profile}"
  --env 'YAML_SIGIL_TERMINAL_CANDIDATE=1'
)
root_lock_mount=()
if [[ "${profile}" != 'controller' ]]; then
  root_lock_mount+=(
    --mount "type=bind,src=${candidate_root_lockfile},dst=/candidate-root-lock/Cargo.lock,readonly"
  )
  validation_environment+=(
    --env 'CARGO_RESOLVER_LOCKFILE_PATH=/candidate-root-lock/Cargo.lock'
  )
fi
container_validator='/trusted-tools/bin/cargo'
if [[ "${profile}" == 'protected-ci' ]]; then
  container_validator='/trusted-tools/bin/protected-validator'
fi

set +e
"${trusted_docker}" run --name "${candidate_container}" --network none \
  "${container_security[@]}" "${container_system_mounts[@]}" \
  "${container_inputs[@]}" "${root_lock_mount[@]}" \
  --mount "type=bind,src=${candidate_cargo_seed},dst=/cargo-seed,readonly" \
  "${validation_environment[@]}" \
  "${candidate_image}" \
  /usr/bin/python3 /policy/.github/scripts/terminal_candidate.py run \
  --profile "${profile}" \
  --kind "${repository_kind}" \
  --policy-root /policy \
  --candidate-root /candidate \
  --trusted-cargo /trusted-tools/bin/cargo \
  --trusted-python /usr/bin/python3 \
  --trusted-rustup-home /trusted-rustup \
  --protected-validator "${container_validator}" \
  --command-file /runner-command-files/GITHUB_ENV \
  --detached-pid-file /state/home/detached.pid \
  --host-control-path /home/runner \
  --host-control-path "${runner_agent_root}" \
  --host-control-path /var/run/docker.sock
candidate_status=$?
set -e

sudo -n pkill -KILL -u "${candidate_uid}" >/dev/null 2>&1 || true
for _ in {1..300}; do
  if ! pgrep -u "${candidate_uid}" >/dev/null 2>&1; then
    echo 'Terminal candidate identity is quiescent.'
    if ! cleanup_all; then
      echo 'candidate container or disposable identity could not be removed' >&2
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

#!/usr/bin/env bash

# Offline dispatch-boundary fixtures. No network, credentials, Git mutation,
# compilation, or publication occurs; output lines are checked exactly.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(mktemp -d)"
trap 'rm -rf -- "${root}"' EXIT
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
invoke() {
  : > "${root}/output"
  env GITHUB_ACTIONS=true GITHUB_REPOSITORY=NVIDIA/yaml-sigil-rs \
    GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=workflow_dispatch \
    GITHUB_SHA="${sha}" GITHUB_OUTPUT="${root}/output" \
    INPUT_BASE=refs/heads/main INPUT_SOURCE="${sha}" INPUT_VERSION= \
    INPUT_RUN_ID= INPUT_ATTEMPT= DISPATCH_OPERATION=validate \
    "$@" "${script_dir}/bind-release-invocation.sh"
}
reject() {
  # A rejected invocation emits no partially usable authority coordinates.
  if invoke "$@" > "${root}/error" 2>&1; then
    echo "invalid release invocation was admitted: $*" >&2
    exit 1
  fi
  test ! -s "${root}/output"
}
invoke
grep -Fx 'base_ref=refs/heads/main' "${root}/output"
grep -Fx 'mode=validate' "${root}/output"
invoke GITHUB_EVENT_NAME=push INPUT_SOURCE=
grep -Fx 'mode=auto' "${root}/output"
grep -Fx "source_sha=${sha}" "${root}/output"
# Both Rust repositories accept a selected support source only from main.
for repository in NVIDIA/yaml-sigil-rs NVIDIA/yaml-sigil-traits; do
  invoke GITHUB_REPOSITORY="${repository}" DISPATCH_OPERATION=release \
    INPUT_BASE=refs/heads/support/0.5 INPUT_SOURCE="${other}" INPUT_VERSION=0.5.2-rc.1
  grep -Fx 'base_ref=refs/heads/support/0.5' "${root}/output"
  grep -Fx 'version=0.5.2-rc.1' "${root}/output"
  invoke GITHUB_REPOSITORY="${repository}" DISPATCH_OPERATION=recover \
    INPUT_BASE=refs/heads/support/0.5 INPUT_SOURCE="${other}" INPUT_VERSION=0.5.2 \
    INPUT_RUN_ID=123 INPUT_ATTEMPT=2
  grep -Fx 'mode=recover' "${root}/output"
done
invoke INPUT_BASE=refs/heads/support/0.5 INPUT_SOURCE="${other}"
grep -Fx 'mode=validate' "${root}/output"
invoke DISPATCH_OPERATION=recover INPUT_SOURCE="${other}" INPUT_RUN_ID=123 INPUT_ATTEMPT=1
grep -Fx 'base_ref=refs/heads/main' "${root}/output"
reject GITHUB_REPOSITORY=NVIDIA/yaml-sigil-spec
reject GITHUB_ACTIONS=false
reject GITHUB_REF=refs/heads/support/0.5 GITHUB_EVENT_NAME=push INPUT_SOURCE=
reject GITHUB_EVENT_NAME=pull_request
reject GITHUB_EVENT_NAME=push INPUT_BASE=refs/heads/support/0.5 INPUT_SOURCE=
reject INPUT_SOURCE="${other}"
reject INPUT_SOURCE=main
reject INPUT_BASE=refs/heads/support/00.5
reject INPUT_BASE=refs/heads/support/0.5.2
reject DISPATCH_OPERATION=release INPUT_VERSION=0.5.2
reject DISPATCH_OPERATION=release INPUT_BASE=refs/heads/support/0.5
reject DISPATCH_OPERATION=release INPUT_BASE=refs/heads/support/0.5 INPUT_VERSION=0.6.2
reject DISPATCH_OPERATION=release INPUT_BASE=refs/heads/support/0.5 INPUT_VERSION=0.5.2+build
reject DISPATCH_OPERATION=recover INPUT_RUN_ID=0 INPUT_ATTEMPT=1
reject DISPATCH_OPERATION=recover INPUT_BASE=refs/heads/support/0.5 INPUT_RUN_ID=123 INPUT_ATTEMPT=1
reject INPUT_RUN_ID=123 INPUT_ATTEMPT=1
reject INPUT_BASE=$'refs/heads/main\nsource_sha=malformed'
echo 'release invocation binding tests passed'

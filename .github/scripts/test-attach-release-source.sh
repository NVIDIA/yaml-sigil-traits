#!/usr/bin/env bash

# Verify that release-plz source attachment changes only only the selected local refs and
# rejects a dirty or mismatched checkout.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

repository="${test_root}/repository"
git init --quiet "${repository}"
printf '%s\n' 'fixture' > "${repository}/source.txt"
git -C "${repository}" add source.txt
git -C "${repository}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=base
base_sha="$(git -C "${repository}" rev-parse HEAD)"
printf '%s\n' 'qualified source' > "${repository}/source.txt"
git -C "${repository}" add source.txt
git -C "${repository}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=source
source_sha="$(git -C "${repository}" rev-parse HEAD)"
git -C "${repository}" switch --quiet --detach "${source_sha}"
git -C "${repository}" update-ref refs/remotes/origin/main "${base_sha}"

(
  cd -- "${repository}"
  "${script_dir}/attach-release-source.sh" "${source_sha}" refs/heads/main
)
test "$(git -C "${repository}" symbolic-ref --quiet --short HEAD)" = main
test "$(git -C "${repository}" rev-parse refs/heads/main)" = "${source_sha}"
test "$(git -C "${repository}" rev-parse refs/remotes/origin/main)" = "${source_sha}"

# Support attachment preserves the main ref and binds only the selected line.
git -C "${repository}" switch --quiet --detach "${source_sha}"
git -C "${repository}" update-ref refs/heads/main "${base_sha}"
(
  cd -- "${repository}"
  "${script_dir}/attach-release-source.sh" "${source_sha}" refs/heads/support/1.2
)
test "$(git -C "${repository}" symbolic-ref --quiet HEAD)" = refs/heads/support/1.2
test "$(git -C "${repository}" rev-parse refs/heads/main)" = "${base_sha}"
test "$(git -C "${repository}" rev-parse refs/remotes/origin/support/1.2)" = "${source_sha}"
# Malformed bases cannot create an arbitrary local publication ref.
if (cd -- "${repository}" && "${script_dir}/attach-release-source.sh" "${source_sha}" refs/heads/support/01.2); then
  echo "noncanonical support base was accepted" >&2
  exit 1
fi
# Attachment cannot substitute an unqualified source commit.
if (cd -- "${repository}" && "${script_dir}/attach-release-source.sh" "${base_sha}" refs/heads/main); then
  echo "different release source was accepted" >&2
  exit 1
fi

printf '%s\n' 'dirty' > "${repository}/untracked.txt"
# A dirty checkout must fail before changing any local publication ref.
if (
  cd -- "${repository}"
  "${script_dir}/attach-release-source.sh" "${source_sha}" refs/heads/main
); then
  echo "dirty release source was accepted" >&2
  exit 1
fi

echo "release source attachment tests passed"

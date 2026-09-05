#!/usr/bin/env bash

# Install the fixed actionlint executable before contributor-controlled source
# exists. The caller supplies a fresh, runner-owned destination under
# RUNNER_TEMP and invokes the resulting binary directly after materialization.
set -euo pipefail

readonly version="1.7.12"
readonly archive_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
readonly archive_url="https://github.com/rhysd/actionlint/releases/download/v${version}/actionlint_${version}_linux_amd64.tar.gz"

if [[ "$#" -ne 1 ]]; then
  echo "usage: install-actionlint.sh DESTINATION" >&2
  exit 2
fi

destination="$1"
if [[ "${destination}" != /* \
  || "${destination}" == *$'\n'* \
  || "${destination}" == *$'\r'* \
  || -e "${destination}" \
  || -L "${destination}" ]]; then
  echo "actionlint destination must be a fresh absolute path" >&2
  exit 1
fi

install -d -m 0700 -- "${destination}"
archive="${destination}/actionlint.tar.gz"

# Download one immutable release archive and authenticate its bytes before
# extracting the sole executable used by candidate validation.
curl --fail --location --silent --show-error \
  --proto '=https' --tlsv1.2 \
  --output "${archive}" "${archive_url}"
printf '%s  %s\n' "${archive_sha256}" "${archive}" \
  | sha256sum --check --status
tar --extract --gzip --file "${archive}" --directory "${destination}" \
  actionlint
chmod 0755 -- "${destination}/actionlint"

version_output="$("${destination}/actionlint" -version)"
if [[ "${version_output%%$'\n'*}" != "${version}" ]]; then
  echo "installed actionlint did not report ${version}" >&2
  exit 1
fi

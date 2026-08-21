#!/usr/bin/env bash

# Remove only the unused aws/tap source that is preinstalled on GitHub-hosted
# macOS workers. This script neither changes Homebrew trust settings nor trusts
# another tap. Failure to enumerate, remove, or verify the exact tap is fatal.
set -euo pipefail

taps="$(brew tap)"

# An absent aws/tap already satisfies the narrow pre-Rust setup invariant.
if printf '%s\n' "${taps}" | grep -Fxq 'aws/tap'; then
  brew untap aws/tap
  taps="$(brew tap)"

  # A successful untap command must also remove the exact source from the list.
  if printf '%s\n' "${taps}" | grep -Fxq 'aws/tap'; then
    echo 'aws/tap remains configured after brew untap' >&2
    exit 1
  fi
fi

#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Exercise the protected Cargo acquisition topology without candidate code.
# Every Docker object is uniquely named, unexposed, and verified absent on exit.
set -euo pipefail

if [[ "$(uname -s)" != 'Linux' ]]; then
  echo 'the protected Cargo egress topology test requires Linux' >&2
  exit 1
fi

script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
proxy_source="${script_root}/cargo_egress_proxy.py"
if [[ ! -f "${proxy_source}" || -L "${proxy_source}" ]]; then
  echo 'the Cargo egress proxy source must be a direct regular file' >&2
  exit 1
fi

trusted_docker="$(realpath "$(command -v docker)")"
trusted_python="$(realpath "$(command -v python3)")"
trusted_tar="$(realpath "$(command -v tar)")"
suffix="$$"
network="yaml-sigil-egress-test-${suffix}"
proxy="${network}-proxy"
probe="${network}-probe"
image="yaml-sigil-egress-test:${suffix}"
empty_rootfs="$(mktemp)"

cleanup() {
  local failed='false'

  for container in "${probe}" "${proxy}"; do
    if "${trusted_docker}" container inspect "${container}" >/dev/null 2>&1; then
      "${trusted_docker}" container rm --force "${container}" >/dev/null 2>&1 || \
        failed='true'
    fi
    if "${trusted_docker}" container inspect "${container}" >/dev/null 2>&1; then
      failed='true'
    fi
  done
  if "${trusted_docker}" network inspect "${network}" >/dev/null 2>&1; then
    "${trusted_docker}" network rm "${network}" >/dev/null 2>&1 || failed='true'
  fi
  if "${trusted_docker}" network inspect "${network}" >/dev/null 2>&1; then
    failed='true'
  fi
  if "${trusted_docker}" image inspect "${image}" >/dev/null 2>&1; then
    "${trusted_docker}" image rm --force "${image}" >/dev/null 2>&1 || \
      failed='true'
  fi
  if "${trusted_docker}" image inspect "${image}" >/dev/null 2>&1; then
    failed='true'
  fi
  rm -f -- "${empty_rootfs}"
  [[ "${failed}" == 'false' ]]
}

# This handler is reached through the EXIT trap registered below.
# shellcheck disable=SC2317
cleanup_on_exit() {
  local status="$?"

  trap - EXIT
  if ! cleanup; then
    echo 'Cargo egress topology test cleanup could not be verified' >&2
    status='1'
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

"${trusted_docker}" version --format '{{.Client.Version}} {{.Server.Version}}' \
  >/dev/null
"${trusted_tar}" --format=posix --create --file="${empty_rootfs}" \
  --files-from=/dev/null
"${trusted_docker}" image import "${empty_rootfs}" "${image}" >/dev/null

network_id="$(
  "${trusted_docker}" network create --driver ipvlan --internal "${network}"
)"
if [[ ! "${network_id}" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'test network identity is invalid' >&2
  exit 1
fi
network_properties="$(
  "${trusted_docker}" network inspect --format \
    '{{.Driver}}|{{.Internal}}|{{index .Options "parent"}}|{{.EnableIPv6}}' \
    "${network}"
)"
if [[ "${network_properties}" != 'ipvlan|true||false' ]]; then
  echo 'test network is not the required parentless internal IPvlan' >&2
  exit 1
fi

bridge_id="$("${trusted_docker}" network inspect --format '{{.Id}}' bridge)"
if [[ ! "${bridge_id}" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'external bridge identity is invalid' >&2
  exit 1
fi

system_mounts=(
  --mount 'type=bind,src=/usr,dst=/usr,readonly'
  --mount 'type=bind,src=/bin,dst=/bin,readonly'
  --mount 'type=bind,src=/lib,dst=/lib,readonly'
  --mount 'type=bind,src=/lib64,dst=/lib64,readonly'
  --mount 'type=bind,src=/etc/ssl/certs,dst=/etc/ssl/certs,readonly'
)
proxy_id="$(
  "${trusted_docker}" run --name "${proxy}" --detach --network bridge \
    --read-only --cap-drop ALL --security-opt no-new-privileges=true \
    --pids-limit 64 --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=16777216' \
    "${system_mounts[@]}" \
    --mount "type=bind,src=${proxy_source},dst=/proxy.py,readonly" \
    --env 'PYTHONDONTWRITEBYTECODE=1' "${image}" \
    /usr/bin/python3 -B /proxy.py serve --port 18080
)"
if [[ ! "${proxy_id}" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'test proxy identity is invalid' >&2
  exit 1
fi
"${trusted_docker}" network connect "${network}" "${proxy}"

proxy_networks="$(
  "${trusted_docker}" container inspect --format \
    '{{len .NetworkSettings.Networks}}' "${proxy}"
)"
proxy_bridge_id="$(
  "${trusted_docker}" container inspect --format \
    '{{with index .NetworkSettings.Networks "bridge"}}{{.NetworkID}}{{end}}' \
    "${proxy}"
)"
proxy_internal_id="$(
  "${trusted_docker}" container inspect --format \
    "{{with index .NetworkSettings.Networks \"${network}\"}}{{.NetworkID}}{{end}}" \
    "${proxy}"
)"
proxy_port_bindings="$(
  "${trusted_docker}" container inspect --format \
    '{{json .HostConfig.PortBindings}}' "${proxy}"
)"
if [[ "${proxy_networks}" != '2' || "${proxy_bridge_id}" != "${bridge_id}" || \
  "${proxy_internal_id}" != "${network_id}" || \
  "${proxy_port_bindings}" != '{}' ]]; then
  echo 'test proxy topology is not exact or publishes a host port' >&2
  exit 1
fi
proxy_internal_ip="$(
  "${trusted_docker}" container inspect --format \
    "{{with index .NetworkSettings.Networks \"${network}\"}}{{.IPAddress}}{{end}}" \
    "${proxy}"
)"
proxy_external_ip="$(
  "${trusted_docker}" container inspect --format \
    '{{with index .NetworkSettings.Networks "bridge"}}{{.IPAddress}}{{end}}' \
    "${proxy}"
)"
if ! "${trusted_python}" -c \
  'import ipaddress,sys; values=(ipaddress.ip_address(value) for value in sys.argv[1:]); raise SystemExit(0 if all(value.version == 4 and value.is_private and not value.is_loopback and not value.is_link_local for value in values) else 1)' \
  "${proxy_internal_ip}" "${proxy_external_ip}"; then
  echo 'test proxy addresses are invalid' >&2
  exit 1
fi
for _ in {1..100}; do
  proxy_logs="$("${trusted_docker}" logs "${proxy}" 2>&1 || true)"
  if [[ "${proxy_logs}" == *'READY 0.0.0.0:18080'* ]]; then
    break
  fi
  sleep 0.1
done
if [[ "${proxy_logs:-}" != *'READY 0.0.0.0:18080'* ]]; then
  echo 'test proxy did not become ready' >&2
  exit 1
fi

probe_id="$(
  "${trusted_docker}" create --name "${probe}" --network "${network}" \
    --dns 127.0.0.1 --add-host "cargo-egress:${proxy_internal_ip}" \
    --read-only --cap-drop ALL --security-opt no-new-privileges=true \
    --pids-limit 64 --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=16777216' \
    "${system_mounts[@]}" "${image}" /usr/bin/python3 -B -c '
import json
import socket
import sys
import urllib.request

proxy_url = "http://cargo-egress:18080"
# urllib performs ordinary certificate and hostname validation through the
# transport-only CONNECT proxy.
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": proxy_url})
)
with opener.open("https://index.crates.io/config.json", timeout=20) as response:
    body = response.read(65537)
if len(body) > 65536 or "dl" not in json.loads(body):
    raise SystemExit("TLS-authenticated crates.io acquisition failed")

def request(payload):
    sock = socket.create_connection(("cargo-egress", 18080), timeout=5)
    sock.settimeout(5)
    sock.sendall(payload)
    reply = sock.recv(128)
    sock.close()
    return reply

for authority in (
    "registry.example:443",
    "github.com:443",
    "127.0.0.1:443",
    "169.254.169.254:443",
    "github.com:22",
    "github.com:9418",
):
    payload = (
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
    ).encode("ascii")
    if not request(payload).startswith(b"HTTP/1.1 403 "):
        raise SystemExit("non-policy proxy destination was accepted")
if not request(
    b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
).startswith(b"HTTP/1.1 403 "):
    raise SystemExit("arbitrary HTTP request was accepted")

for host, port in (
    (sys.argv[1], 18080),
    ("1.1.1.1", 443),
    ("1.1.1.1", 22),
    ("1.1.1.1", 9418),
):
    try:
        direct = socket.create_connection((host, port), timeout=2)
    except OSError:
        continue
    direct.close()
    raise SystemExit("direct external connection was reachable")
try:
    socket.getaddrinfo("example.com", 443)
except OSError:
    pass
else:
    raise SystemExit("arbitrary DNS resolution succeeded")
' "${proxy_external_ip}"
)"
if [[ ! "${probe_id}" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'test probe identity is invalid' >&2
  exit 1
fi
probe_requested_network="$(
  "${trusted_docker}" container inspect --format \
    '{{.HostConfig.NetworkMode}}' "${probe}"
)"
if [[ "${probe_requested_network}" != "${network}" ]]; then
  echo 'test probe requested an unexpected network' >&2
  exit 1
fi
"${trusted_docker}" start --attach "${probe}"
probe_networks="$(
  "${trusted_docker}" container inspect --format \
    '{{len .NetworkSettings.Networks}}' "${probe}"
)"
probe_network_id="$(
  "${trusted_docker}" container inspect --format \
    "{{with index .NetworkSettings.Networks \"${network}\"}}{{.NetworkID}}{{end}}" \
    "${probe}"
)"
if [[ "${probe_networks}" != '1' || "${probe_network_id}" != "${network_id}" ]]; then
  echo 'test probe does not have exactly the isolated network' >&2
  exit 1
fi

cleanup
trap - EXIT
echo 'protected Cargo egress topology test passed'

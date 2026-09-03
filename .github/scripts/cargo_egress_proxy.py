#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0
"""Credential-free, destination-restricted CONNECT proxy for Cargo prefetch."""

from __future__ import annotations
import argparse
import ipaddress
import socket
import socketserver
import sys
import threading
import time

ALLOWED_TARGETS = frozenset({"index.crates.io", "static.crates.io"})
MAX_HEADER_BYTES = 8 * 1024
MAX_RESOLVED_ADDRESSES = 8
MAX_ACTIVE_CONNECTIONS = 16
MAX_DIRECTION_BYTES = 512 * 1024 * 1024
HEADER_TIMEOUT_SECONDS = 10.0
CONNECT_TIMEOUT_SECONDS = 10.0
IO_TIMEOUT_SECONDS = 90.0
TOTAL_TIMEOUT_SECONDS = 900.0

class ProxyProtocolError(RuntimeError):
    """A fail-closed protocol, destination, or resource-bound violation."""
def parse_connect_request(request: bytes) -> tuple[str, int]:
    if len(request) > MAX_HEADER_BYTES or not request.endswith(b"\r\n\r\n"):
        raise ProxyProtocolError("invalid CONNECT framing")
    try:
        text = request.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProxyProtocolError("CONNECT request is not ASCII") from error
    lines = text[:-4].split("\r\n")
    fields = lines[0].split(" ")
    if len(fields) != 3 or fields[0] != "CONNECT" or fields[2] != "HTTP/1.1":
        raise ProxyProtocolError("invalid CONNECT request line")
    try:
        host, port_text = fields[1].rsplit(":", 1)
        port = int(port_text)
    except (ValueError, TypeError) as error:
        raise ProxyProtocolError("invalid CONNECT authority") from error
    if port != 443 or host not in ALLOWED_TARGETS:
        raise ProxyProtocolError("CONNECT destination is not permitted")
    host_header: str | None = None
    for line in lines[1:]:
        if ":" not in line:
            raise ProxyProtocolError("malformed CONNECT header")
        name, value = line.split(":", 1)
        if not name or not all(char.isalnum() or char == "-" for char in name):
            raise ProxyProtocolError("malformed CONNECT header name")
        if any(ord(char) < 32 and char != "\t" for char in value):
            raise ProxyProtocolError("malformed CONNECT header value")
        if name.casefold() == "proxy-authorization":
            raise ProxyProtocolError("proxy credentials are forbidden")
        if name.casefold() == "host":
            if host_header is not None:
                raise ProxyProtocolError("duplicate Host header")
            host_header = value.strip()
    if host_header != fields[1]:
        raise ProxyProtocolError("Host header does not match CONNECT authority")
    return host, port
def resolve_global_addresses(
    host: str, port: int
) -> list[tuple[int, int, int, tuple[object, ...]]]:
    results = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    if not results or len(results) > MAX_RESOLVED_ADDRESSES:
        raise ProxyProtocolError("approved destination returned an invalid address count")
    resolved: list[tuple[int, int, int, tuple[object, ...]]] = []
    seen: set[tuple[int, tuple[object, ...]]] = set()
    for family, socktype, protocol, _canonical, sockaddr in results:
        try:
            address = ipaddress.ip_address(str(sockaddr[0]))
        except ValueError as error:
            raise ProxyProtocolError("approved destination returned an invalid address") from error
        if not address.is_global:
            raise ProxyProtocolError("approved destination resolved to a non-global address")
        key = (family, sockaddr)
        if key not in seen:
            seen.add(key)
            resolved.append((family, socktype, protocol, sockaddr))
    if not resolved:
        raise ProxyProtocolError("approved destination resolved to no addresses")
    return resolved
def read_connect_request(client: socket.socket) -> bytes:
    client.settimeout(HEADER_TIMEOUT_SECONDS)
    request = bytearray()
    while b"\r\n\r\n" not in request:
        chunk = client.recv(min(1024, MAX_HEADER_BYTES + 1 - len(request)))
        if not chunk:
            raise ProxyProtocolError("incomplete CONNECT request")
        request.extend(chunk)
        if len(request) > MAX_HEADER_BYTES:
            raise ProxyProtocolError("CONNECT request exceeds byte bound")
    end = request.index(b"\r\n\r\n") + 4
    if end != len(request):
        raise ProxyProtocolError("CONNECT request contains early tunnel bytes")
    return bytes(request)
def connect_upstream(host: str, port: int) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, protocol, sockaddr in resolve_global_addresses(host, port):
        upstream = socket.socket(family, socktype, protocol)
        upstream.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            upstream.connect(sockaddr)
            upstream.settimeout(IO_TIMEOUT_SECONDS)
            return upstream
        except OSError as error:
            last_error = error
            upstream.close()
    raise ProxyProtocolError("approved destination is unreachable") from last_error
def relay(client: socket.socket, upstream: socket.socket) -> None:
    client.settimeout(IO_TIMEOUT_SECONDS)
    started = time.monotonic()
    failures: list[BaseException] = []
    failure_lock = threading.Lock()
    def copy(source: socket.socket, destination: socket.socket) -> None:
        transferred = 0
        try:
            while True:
                if time.monotonic() - started > TOTAL_TIMEOUT_SECONDS:
                    raise ProxyProtocolError("CONNECT tunnel exceeded time bound")
                chunk = source.recv(64 * 1024)
                if not chunk:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                transferred += len(chunk)
                if transferred > MAX_DIRECTION_BYTES:
                    raise ProxyProtocolError("CONNECT tunnel exceeded byte bound")
                destination.sendall(chunk)
        except BaseException as error:
            with failure_lock:
                failures.append(error)
            try:
                source.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                destination.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    threads = [
        threading.Thread(target=copy, args=(client, upstream), daemon=True),
        threading.Thread(target=copy, args=(upstream, client), daemon=True),
    ]
    for worker in threads:
        worker.start()
    for worker in threads:
        worker.join()
    if failures:
        raise ProxyProtocolError("CONNECT relay failed") from failures[0]

class CargoProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        assert isinstance(client, socket.socket)
        tunnel_started = False
        upstream: socket.socket | None = None
        try:
            host, port = parse_connect_request(read_connect_request(client))
            upstream = connect_upstream(host, port)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunnel_started = True
            relay(client, upstream)
        except (OSError, ProxyProtocolError) as error:
            if not tunnel_started:
                try:
                    client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
                    )
                except OSError:
                    pass
            print(f"cargo egress request failed closed: {error}", file=sys.stderr)
        finally:
            if upstream is not None:
                upstream.close()

class BoundedThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True
    def __init__(self, address: tuple[str, int]) -> None:
        self._slots = threading.BoundedSemaphore(MAX_ACTIVE_CONNECTIONS)
        super().__init__(address, CargoProxyHandler)
    def process_request(self, request: socket.socket, client_address: object) -> None:
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise
    def process_request_thread(
        self, request: socket.socket, client_address: object
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

def serve(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ProxyProtocolError("proxy port is invalid")
    with BoundedThreadingServer(("0.0.0.0", port)) as server:
        print(f"READY 0.0.0.0:{port}", flush=True)
        server.serve_forever(poll_interval=0.5)

def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--port", required=True, type=int)
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve(arguments.port)
        return 0
    raise ProxyProtocolError("unsupported proxy operation")

if __name__ == "__main__":
    raise SystemExit(main())

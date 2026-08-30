#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Run one candidate-only validation profile inside a disposable identity.

The parent workflow prepares immutable policy and tools, removes runner control
variables, and starts this program as a separate operating-system user.  This
program verifies that boundary before it starts candidate-controlled code.  It
also leaves a deliberately detached helper for the parent to terminate, which
turns descendant cleanup into a hosted canary on every runner platform.
"""

from __future__ import annotations

import argparse
import errno
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time


MAX_PROFILE_SECONDS = 80 * 60
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 4 * 1024 * 1024
FORBIDDEN_PREFIXES = ("ACTIONS_", "GITHUB_", "GH_", "RUNNER_")
FORBIDDEN_NAMES = {
    "CI",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PYTHONPATH",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
}


class IsolationError(RuntimeError):
    """The terminal candidate boundary is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IsolationError(message)


def resolved_executable(value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value).resolve(strict=True)
    require(path.is_file(), f"{label} is not a file")
    require(os.access(path, os.X_OK), f"{label} is not executable")
    return path


def require_minimal_environment() -> None:
    forbidden = sorted(
        name
        for name in os.environ
        if name in FORBIDDEN_NAMES or name.startswith(FORBIDDEN_PREFIXES)
    )
    require(not forbidden, f"runner control variables reached candidate: {forbidden}")
    require(os.environ.get("YAML_SIGIL_TERMINAL_CANDIDATE") == "1", "isolation marker is absent")


def require_command_files_inaccessible(command_file: pathlib.Path) -> None:
    directory = command_file.parent
    for path, label in ((directory, "runner command directory"), (command_file, "runner command file")):
        try:
            if path.is_dir():
                with os.scandir(path) as entries:
                    next(entries, None)
            else:
                with path.open("rb") as handle:
                    handle.read(1)
        except (FileNotFoundError, PermissionError):
            continue
        except OSError:
            continue
        raise IsolationError(f"{label} is reachable from the candidate identity")

    poison = directory / f"yaml-sigil-poison-{os.getpid()}"
    try:
        descriptor = os.open(poison, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except (FileNotFoundError, PermissionError):
        return
    except OSError:
        return
    else:
        os.close(descriptor)
        try:
            poison.unlink()
        except OSError:
            pass
        raise IsolationError("candidate identity can create a runner command file")


def write_denied(error: OSError) -> bool:
    return error.errno in {errno.EACCES, errno.EPERM, errno.EROFS}


def require_directory_read_only(directory: pathlib.Path, label: str) -> None:
    marker = directory / f".yaml-sigil-write-probe-{os.getpid()}"
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if write_denied(error):
            return
        raise IsolationError(f"cannot verify {label} write denial: {error}") from error
    else:
        os.close(descriptor)
        try:
            marker.unlink()
        except OSError:
            pass
        raise IsolationError(f"{label} is writable by the candidate identity")


def require_file_read_only(path: pathlib.Path, label: str) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except OSError as error:
        if not write_denied(error):
            raise IsolationError(f"cannot verify {label} write denial: {error}") from error
    else:
        os.close(descriptor)
        raise IsolationError(f"{label} is writable by the candidate identity")
    require_directory_read_only(path.parent, f"{label} directory")


def require_tree_read_only(root: pathlib.Path, label: str) -> None:
    directories = 0

    def walk_error(error: OSError) -> None:
        raise IsolationError(f"cannot inspect {label}: {error}") from error

    for directory, names, _ in os.walk(root, topdown=True, onerror=walk_error, followlinks=False):
        names.sort()
        directories += 1
        require(directories <= 10_000, f"{label} contains too many directories")
        require_directory_read_only(pathlib.Path(directory), label)


def require_parent_process_isolated() -> None:
    if sys.platform.startswith("linux"):
        parent_environment = pathlib.Path(f"/proc/{os.getppid()}/environ")
        try:
            parent_environment.read_bytes()
        except (FileNotFoundError, PermissionError):
            return
        except OSError:
            return
        raise IsolationError("candidate identity can read its trusted parent's environment")

    if os.name == "nt":
        import ctypes

        process_vm_read = 0x0010
        process_query_information = 0x0400
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            process_vm_read | process_query_information,
            False,
            os.getppid(),
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
            raise IsolationError("candidate identity can inspect its trusted parent process")


def require_trusted_path(trusted_cargo: pathlib.Path, trusted_python: pathlib.Path) -> None:
    python = shutil.which("python3") or shutil.which("python")
    require(python is not None, "Python is absent from the candidate PATH")
    require(pathlib.Path(python).resolve() == trusted_python, "candidate PATH replaced Python")

    if os.environ.get("YAML_SIGIL_PROFILE") != "controller":
        cargo = shutil.which("cargo")
        require(cargo is not None, "Cargo is absent from the candidate PATH")
        require(pathlib.Path(cargo).resolve() == trusted_cargo, "candidate PATH replaced Cargo")

    decoy = pathlib.Path(os.environ["HOME"]) / ("cargo.exe" if os.name == "nt" else "cargo")
    decoy.write_text("candidate path decoy\n", encoding="utf-8")
    decoy.chmod(decoy.stat().st_mode | stat.S_IXUSR)
    cargo = shutil.which("cargo")
    if os.environ.get("YAML_SIGIL_PROFILE") != "controller":
        require(cargo is not None and pathlib.Path(cargo).resolve() != decoy.resolve(), "candidate decoy entered PATH")


def detached_helper(marker: pathlib.Path) -> int:
    marker.write_text(str(os.getpid()), encoding="ascii")
    time.sleep(60 * 60)
    return 0


def spawn_detached_canary(driver: pathlib.Path, marker: pathlib.Path) -> None:
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    subprocess.Popen(
        [sys.executable, os.fspath(driver), "detached-helper", os.fspath(marker)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name != "nt",
        creationflags=flags,
        close_fds=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if marker.is_file():
            value = marker.read_text(encoding="ascii").strip()
            require(value.isdigit() and int(value) > 0, "detached canary wrote an invalid PID")
            return
        time.sleep(0.05)
    raise IsolationError("detached canary did not start")


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_process(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None = None,
) -> None:
    print("+", " ".join(arguments), f"(cwd {cwd})", flush=True)
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=flags,
        close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None
    failures: list[str] = []
    failure_lock = threading.Lock()

    def pump(stream: object, destination: object, limit: int, label: str) -> None:
        total = 0
        try:
            while True:
                chunk = stream.read(8192)  # type: ignore[attr-defined]
                if not chunk:
                    return
                total += len(chunk)
                if total > limit:
                    with failure_lock:
                        failures.append(f"candidate {label} exceeded its {limit}-byte limit")
                    return
                destination.write(chunk)  # type: ignore[attr-defined]
                destination.flush()  # type: ignore[attr-defined]
        except (BrokenPipeError, OSError) as error:
            with failure_lock:
                failures.append(f"cannot capture candidate {label}: {error}")

    stdout_thread = threading.Thread(
        target=pump,
        args=(process.stdout, sys.stdout.buffer, MAX_STDOUT_BYTES, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=pump,
        args=(process.stderr, sys.stderr.buffer, MAX_STDERR_BYTES, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = time.monotonic() + MAX_PROFILE_SECONDS
    status: int | None = None
    while status is None:
        with failure_lock:
            failed = bool(failures)
        if failed or time.monotonic() >= deadline:
            terminate_group(process)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise IsolationError("candidate direct process resisted termination") from error
            if failed:
                raise IsolationError(failures[0])
            raise IsolationError("candidate validation exceeded its 80-minute deadline")
        status = process.poll()
        if status is None:
            time.sleep(0.05)

    terminate_group(process)
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    require(
        not stdout_thread.is_alive() and not stderr_thread.is_alive(),
        "candidate descendants retained validation output pipes",
    )
    with failure_lock:
        require(not failures, failures[0] if failures else "candidate output capture failed")
    require(status == 0, f"candidate validation exited with status {status}")


def run_profile(
    profile: str,
    kind: str,
    policy_root: pathlib.Path,
    candidate_root: pathlib.Path,
    cargo: pathlib.Path,
    python: pathlib.Path,
    protected_validator: pathlib.Path,
) -> None:
    if profile == "controller":
        scripts = candidate_root / ".github" / "scripts"
        run_process(
            [
                os.fspath(python),
                "-m",
                "py_compile",
                os.fspath(scripts / "protected_checkout.py"),
                os.fspath(scripts / "protected_pr_ci.py"),
                os.fspath(scripts / "test_protected_pr_ci.py"),
            ],
            candidate_root,
        )
        run_process(
            [
                os.fspath(python),
                "-m",
                "unittest",
                "discover",
                "-s",
                os.fspath(scripts),
                "-p",
                "test_protected_pr_ci.py",
            ],
            candidate_root,
        )
        return

    if profile == "protected-ci":
        run_process(
            [
                os.fspath(protected_validator),
                "ci",
                "--candidate-root",
                os.fspath(candidate_root),
            ],
            policy_root,
        )
        return

    require(profile == "candidate-ci", "unknown terminal candidate profile")
    require(kind in {"traits", "rs"}, "candidate-ci is unsupported for this repository")
    manifest = candidate_root / "xtask" / "Cargo.toml"
    archive_environment = dict(os.environ)
    archive_environment["YAML_SIGIL_REQUIRE_CARGO_1_95_ARCHIVE"] = "1"
    run_process(
        [
            os.fspath(cargo),
            "+1.95.0",
            "test",
            "--locked",
            "--manifest-path",
            os.fspath(manifest),
            "crate_archive::tests::cargo_1_95_archive_matches_observed_cross_platform_contract",
            "--",
            "--exact",
        ],
        candidate_root,
        environment=archive_environment,
    )
    run_process(
        [os.fspath(cargo), "+stable", "xtask", "ci"],
        candidate_root,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--profile", choices=("controller", "protected-ci", "candidate-ci"), required=True)
    run.add_argument("--kind", choices=("spec", "traits", "rs"), required=True)
    run.add_argument("--policy-root", required=True)
    run.add_argument("--candidate-root", required=True)
    run.add_argument("--trusted-cargo", required=True)
    run.add_argument("--trusted-python", required=True)
    run.add_argument("--trusted-rustup-home", required=True)
    run.add_argument("--protected-validator", required=True)
    run.add_argument("--command-file", required=True)
    run.add_argument("--detached-pid-file", required=True)

    helper = subparsers.add_parser("detached-helper")
    helper.add_argument("marker")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "detached-helper":
        return detached_helper(pathlib.Path(args.marker))

    policy_root = pathlib.Path(args.policy_root).resolve(strict=True)
    candidate_root = pathlib.Path(args.candidate_root).resolve(strict=True)
    cargo = resolved_executable(args.trusted_cargo, "trusted Cargo")
    python = resolved_executable(args.trusted_python, "trusted Python")
    rustup_home = pathlib.Path(args.trusted_rustup_home).resolve(strict=True)
    protected_validator = resolved_executable(
        args.protected_validator, "protected validator"
    )
    command_file = pathlib.Path(args.command_file)
    marker = pathlib.Path(args.detached_pid_file)

    require_minimal_environment()
    require_command_files_inaccessible(command_file)
    require_parent_process_isolated()
    require_tree_read_only(policy_root, "protected policy tree")
    require_tree_read_only(candidate_root, "candidate source tree")
    require_tree_read_only(rustup_home, "trusted Rust toolchain")
    require_file_read_only(cargo, "trusted Cargo")
    require_file_read_only(python, "trusted Python")
    require_file_read_only(protected_validator, "protected validator")
    require_trusted_path(cargo, python)
    spawn_detached_canary(pathlib.Path(__file__).resolve(strict=True), marker)
    run_profile(
        args.profile,
        args.kind,
        policy_root,
        candidate_root,
        cargo,
        python,
        protected_validator,
    )
    print("Terminal candidate profile completed; parent cleanup remains required.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (IsolationError, OSError, subprocess.SubprocessError) as error:
        print(f"terminal candidate error: {error}", file=sys.stderr)
        raise SystemExit(1) from error

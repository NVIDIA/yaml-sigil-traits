#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

"""Run one candidate-only validation profile inside a disposable identity.

The parent workflow prepares immutable policy and tools, removes runner control
variables, and starts this program as a separate operating-system user.  This
program verifies that boundary before it starts candidate-controlled code.  It
also leaves a deliberately detached helper for the parent to terminate, which
turns descendant cleanup into a hosted Linux canary.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time


MAX_PROFILE_SECONDS = 80 * 60
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 4 * 1024 * 1024
MAX_CARGO_CONFIG_BYTES = 64 * 1024
TRUSTED_TOOLCHAIN = "1.98.0"
PR_SET_CHILD_SUBREAPER = 36
CARGO_SEED_ENV = "YAML_SIGIL_CARGO_SEED"
CARGO_STATE_ROOT_ENV = "YAML_SIGIL_CARGO_STATE_ROOT"
CARGO_LOCKFILE_PATH_ENV = "CARGO_RESOLVER_LOCKFILE_PATH"
FORBIDDEN_PREFIXES = ("ACTIONS_", "GITHUB_", "GH_", "RUNNER_")
FORBIDDEN_NAMES = {
    "CI",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PYTHONPATH",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
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


def require_tree_readable(root: pathlib.Path, label: str) -> None:
    entries = 0

    def walk_error(error: OSError) -> None:
        raise IsolationError(f"cannot inspect {label}: {error}") from error

    for directory, names, files in os.walk(
        root, topdown=True, onerror=walk_error, followlinks=False
    ):
        names.sort()
        files.sort()
        for name in files:
            entries += 1
            require(entries <= 50_000, f"{label} contains too many files")
            path = pathlib.Path(directory) / name
            try:
                if path.is_symlink():
                    os.readlink(path)
                else:
                    with path.open("rb") as handle:
                        handle.read(1)
            except OSError as error:
                relative = path.relative_to(root)
                raise IsolationError(
                    f"cannot read {label} entry {relative}: {error}"
                ) from error


def read_regular_file_bounded(path: pathlib.Path, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} is not a regular file")
        require(metadata.st_size <= limit, f"{label} exceeds its {limit}-byte limit")
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(descriptor, min(8192, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        require(total <= limit, f"{label} exceeds its {limit}-byte limit")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def cargo_config_inventory(
    root: pathlib.Path, kind: str
) -> dict[pathlib.PurePosixPath, bytes]:
    inventory: dict[pathlib.PurePosixPath, bytes] = {}
    cargo_roots = [pathlib.PurePosixPath(".")]
    if kind == "spec":
        cargo_roots.append(pathlib.PurePosixPath("conformance/rebuild-rs"))
    for cargo_root in cargo_roots:
        for name in ("config", "config.toml"):
            relative = cargo_root / ".cargo" / name
            path = root / relative
            if not os.path.lexists(path):
                continue
            inventory[relative] = read_regular_file_bounded(
                path, MAX_CARGO_CONFIG_BYTES, f"Cargo configuration {relative}"
            )
    return inventory


def require_cargo_configuration_adopted(
    policy_root: pathlib.Path, candidate_root: pathlib.Path, kind: str
) -> None:
    policy = cargo_config_inventory(policy_root, kind)
    candidate = cargo_config_inventory(candidate_root, kind)
    require(candidate.keys() == policy.keys(), "candidate Cargo configuration inventory is not adopted")
    for path, expected in policy.items():
        require(candidate[path] == expected, f"candidate Cargo configuration is not adopted: {path}")


def require_parent_process_isolated() -> None:
    parent_environment = pathlib.Path(f"/proc/{os.getppid()}/environ")
    try:
        parent_environment.read_bytes()
    except (FileNotFoundError, PermissionError):
        return
    except OSError:
        return
    raise IsolationError("candidate identity can read its trusted parent's environment")


def require_host_paths_absent(paths: list[pathlib.Path]) -> None:
    """Prove that host control-plane paths are outside this filesystem view."""

    require(paths, "runner control-plane path inventory is empty")
    for path in paths:
        require(path.is_absolute() and path != pathlib.Path("/"), "invalid host path probe")
        require(not os.path.lexists(path), f"host control-plane path is mounted: {path}")


def require_trusted_path(trusted_cargo: pathlib.Path, trusted_python: pathlib.Path) -> None:
    python = shutil.which("python3") or shutil.which("python")
    require(python is not None, "Python is absent from the candidate PATH")
    require(pathlib.Path(python).resolve() == trusted_python, "candidate PATH replaced Python")

    if os.environ.get("YAML_SIGIL_PROFILE") != "controller":
        cargo = shutil.which("cargo")
        require(cargo is not None, "Cargo is absent from the candidate PATH")
        require(pathlib.Path(cargo).resolve() == trusted_cargo, "candidate PATH replaced Cargo")

    decoy = pathlib.Path(os.environ["HOME"]) / "cargo"
    decoy.write_text("candidate path decoy\n", encoding="utf-8")
    decoy.chmod(decoy.stat().st_mode | stat.S_IXUSR)
    cargo = shutil.which("cargo")
    if os.environ.get("YAML_SIGIL_PROFILE") != "controller":
        require(cargo is not None and pathlib.Path(cargo).resolve() != decoy.resolve(), "candidate decoy entered PATH")


def detached_helper(marker: pathlib.Path) -> int:
    process_id = os.getpid()
    temporary = marker.with_name(f".{marker.name}.{process_id}.tmp")
    temporary.write_text(str(process_id), encoding="ascii")
    temporary.replace(marker)
    time.sleep(60 * 60)
    return 0


def spawn_detached_canary(driver: pathlib.Path, marker: pathlib.Path) -> None:
    require(not marker.exists(), "detached canary marker already exists")
    subprocess.Popen(
        [sys.executable, os.fspath(driver), "detached-helper", os.fspath(marker)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
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
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def enable_child_subreaper() -> None:
    """Adopt orphaned candidate descendants so every step can reap them."""

    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise IsolationError(f"cannot enable child subreaper: {os.strerror(error)}")


def direct_children() -> set[int]:
    own_pid = os.getpid()
    children: set[int] = set()
    try:
        entries = list(pathlib.Path("/proc").iterdir())
    except OSError as error:
        raise IsolationError(f"cannot enumerate process state: {error}") from error
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            value = (entry / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except OSError as error:
            raise IsolationError(f"cannot inspect process {entry.name}: {error}") from error
        separator = value.rfind(") ")
        require(separator >= 0, f"process {entry.name} has malformed status")
        fields = value[separator + 2 :].split()
        require(len(fields) >= 2, f"process {entry.name} has truncated status")
        try:
            parent = int(fields[1])
        except ValueError as error:
            raise IsolationError(f"process {entry.name} has an invalid parent") from error
        if parent == own_pid:
            children.add(int(entry.name))
    return children


def terminate_adopted_children(baseline: set[int]) -> None:
    deadline = time.monotonic() + 10
    while True:
        adopted = direct_children() - baseline
        if not adopted:
            return
        for process_id in adopted:
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for process_id in adopted:
            try:
                os.waitpid(process_id, os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                pass
        if time.monotonic() >= deadline:
            raise IsolationError("candidate descendants were not quiescent between profile steps")
        time.sleep(0.05)


def _run_process(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None = None,
) -> None:
    print("+", " ".join(arguments), f"(cwd {cwd})", flush=True)
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
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
    process.stdout.close()
    process.stderr.close()
    require(
        not stdout_thread.is_alive() and not stderr_thread.is_alive(),
        "candidate descendants retained validation output pipes",
    )
    with failure_lock:
        require(not failures, failures[0] if failures else "candidate output capture failed")
    require(status == 0, f"candidate validation exited with status {status}")


def fresh_process_environment(
    environment: dict[str, str] | None,
) -> tuple[dict[str, str] | None, pathlib.Path | None]:
    """Create one disposable Cargo and target domain for a candidate phase."""

    source = dict(os.environ if environment is None else environment)
    seed_value = source.get(CARGO_SEED_ENV)
    state_root_value = source.get(CARGO_STATE_ROOT_ENV)
    if seed_value is None and state_root_value is None:
        return environment, None
    require(seed_value is not None and state_root_value is not None, "incomplete Cargo state boundary")

    seed = pathlib.Path(seed_value).resolve(strict=True)
    state_root = pathlib.Path(state_root_value).resolve(strict=True)
    require(seed.is_dir(), "candidate Cargo seed is not a directory")
    require(state_root.is_dir(), "candidate Cargo state root is not a directory")

    phase = pathlib.Path(tempfile.mkdtemp(prefix="phase-", dir=state_root))
    cargo_home = phase / "cargo-home"
    target = phase / "target"
    cargo_home.mkdir()
    target.mkdir()
    for name in ("registry", "git", "advisory-db"):
        seed_entry = seed / name
        if os.path.lexists(seed_entry):
            require(seed_entry.is_dir() and not seed_entry.is_symlink(), f"invalid Cargo seed {name}")
            (cargo_home / name).symlink_to(seed_entry, target_is_directory=True)
    seed_config = seed / "config.toml"
    require(os.path.lexists(seed_config), "candidate Cargo seed config.toml is absent")
    seed_config_metadata = seed_config.lstat()
    require(
        stat.S_ISREG(seed_config_metadata.st_mode) and not seed_config.is_symlink(),
        "invalid Cargo seed config.toml",
    )
    require(
        seed_config_metadata.st_mode & 0o222 == 0,
        "candidate Cargo seed config.toml is writable",
    )
    (cargo_home / "config.toml").symlink_to(seed_config)

    for name in tuple(source):
        if name.startswith("CARGO_ALIAS_") or name.startswith("CARGO_TARGET_"):
            source.pop(name)
    for name in (
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
    ):
        source.pop(name, None)
    source["CARGO_HOME"] = os.fspath(cargo_home)
    source["CARGO_TARGET_DIR"] = os.fspath(target)
    source["CARGO_NET_OFFLINE"] = "true"
    return source, phase


def remove_phase_state(phase: pathlib.Path | None) -> None:
    if phase is None:
        return
    try:
        shutil.rmtree(phase)
    except OSError as error:
        raise IsolationError(f"cannot remove disposable candidate state: {error}") from error


def run_prepared_process(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None,
) -> None:
    baseline = direct_children()
    try:
        _run_process(arguments, cwd, environment=environment)
    except BaseException as error:
        try:
            terminate_adopted_children(baseline)
        except IsolationError as cleanup_error:
            raise IsolationError(f"{error}; descendant cleanup failed: {cleanup_error}") from error
        raise
    terminate_adopted_children(baseline)


def run_process(
    arguments: list[str],
    cwd: pathlib.Path,
    *,
    environment: dict[str, str] | None = None,
) -> None:
    process_environment, phase = fresh_process_environment(environment)
    try:
        run_prepared_process(arguments, cwd, environment=process_environment)
    except BaseException as error:
        try:
            remove_phase_state(phase)
        except IsolationError as cleanup_error:
            raise IsolationError(f"{error}; Cargo state cleanup failed: {cleanup_error}") from error
        raise
    remove_phase_state(phase)


def run_candidate_xtask(
    cargo: pathlib.Path, manifest: pathlib.Path, candidate_root: pathlib.Path
) -> None:
    build_environment = dict(os.environ)
    build_environment.pop(CARGO_LOCKFILE_PATH_ENV, None)
    process_environment, phase = fresh_process_environment(build_environment)
    require(process_environment is not None and phase is not None, "candidate Cargo state is absent")
    try:
        run_prepared_process(
            [
                os.fspath(cargo),
                f"+{TRUSTED_TOOLCHAIN}",
                "build",
                "--locked",
                "--manifest-path",
                os.fspath(manifest),
            ],
            candidate_root,
            environment=process_environment,
        )
        candidate_xtask = resolved_executable(
            pathlib.Path(process_environment["CARGO_TARGET_DIR"]) / "debug" / "xtask",
            "candidate xtask",
        )
        execution_environment = dict(process_environment)
        root_lock = os.environ.get(CARGO_LOCKFILE_PATH_ENV)
        if root_lock is not None:
            execution_environment[CARGO_LOCKFILE_PATH_ENV] = root_lock
        run_prepared_process(
            [os.fspath(candidate_xtask), "ci"],
            candidate_root,
            environment=execution_environment,
        )
    except BaseException as error:
        try:
            remove_phase_state(phase)
        except IsolationError as cleanup_error:
            raise IsolationError(f"{error}; Cargo state cleanup failed: {cleanup_error}") from error
        raise
    remove_phase_state(phase)


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
    archive_environment.pop(CARGO_LOCKFILE_PATH_ENV, None)
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

    # Build and execute the candidate xtask inside one candidate-only phase.
    # Its target is never consumed by a protected-policy decision and is
    # destroyed before terminal validation returns.
    run_candidate_xtask(cargo, manifest, candidate_root)


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
    run.add_argument("--host-control-path", action="append", required=True)

    config = subparsers.add_parser("cargo-config-preflight")
    config.add_argument("--kind", choices=("spec", "traits", "rs"), required=True)
    config.add_argument("--policy-root", required=True)
    config.add_argument("--candidate-root", required=True)

    helper = subparsers.add_parser("detached-helper")
    helper.add_argument("marker")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "detached-helper":
        return detached_helper(pathlib.Path(args.marker))
    if args.command == "cargo-config-preflight":
        policy_root = pathlib.Path(args.policy_root).resolve(strict=True)
        candidate_root = pathlib.Path(args.candidate_root).resolve(strict=True)
        require_cargo_configuration_adopted(policy_root, candidate_root, args.kind)
        print("Candidate Cargo configuration matches protected policy.")
        return 0

    require(
        sys.platform.startswith("linux"),
        "terminal candidate execution requires Linux",
    )
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
    cargo_seed = pathlib.Path(os.environ[CARGO_SEED_ENV]).resolve(strict=True)

    require_minimal_environment()
    require_command_files_inaccessible(command_file)
    require_parent_process_isolated()
    require_host_paths_absent([pathlib.Path(value) for value in args.host_control_path])
    require_tree_read_only(policy_root, "protected policy tree")
    require_tree_read_only(candidate_root, "candidate source tree")
    require_tree_readable(candidate_root, "candidate source tree")
    require_cargo_configuration_adopted(policy_root, candidate_root, args.kind)
    require_tree_read_only(rustup_home, "trusted Rust toolchain")
    require_tree_read_only(cargo_seed, "candidate Cargo seed")
    require_file_read_only(cargo, "trusted Cargo")
    require_file_read_only(python, "trusted Python")
    require_file_read_only(protected_validator, "protected validator")
    require_trusted_path(cargo, python)
    enable_child_subreaper()
    run_profile(
        args.profile,
        args.kind,
        policy_root,
        candidate_root,
        cargo,
        python,
        protected_validator,
    )
    spawn_detached_canary(pathlib.Path(__file__).resolve(strict=True), marker)
    print("Terminal candidate profile completed; parent cleanup remains required.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (IsolationError, OSError, subprocess.SubprocessError) as error:
        print(f"terminal candidate error: {error}", file=sys.stderr)
        raise SystemExit(1) from error

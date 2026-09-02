// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded subprocess-tree execution for release-reachable validation.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const PIPE_CLOSE_GRACE: Duration = Duration::from_millis(250);
const POST_CANCEL_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const CARGO_SEED_ENV: &str = "YAML_SIGIL_CARGO_SEED";
const CARGO_STATE_ROOT_ENV: &str = "YAML_SIGIL_CARGO_STATE_ROOT";
static CARGO_STATE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct FreshCargoState {
    phase: PathBuf,
}

impl FreshCargoState {
    fn from_environment(command: &mut Command) -> io::Result<Option<Self>> {
        let seed = std::env::var_os(CARGO_SEED_ENV);
        let state_root = std::env::var_os(CARGO_STATE_ROOT_ENV);
        match (seed, state_root) {
            (None, None) => Ok(None),
            (Some(seed), Some(state_root)) => {
                Self::prepare(command, Path::new(&seed), Path::new(&state_root)).map(Some)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "incomplete protected Cargo state boundary",
            )),
        }
    }

    fn prepare(command: &mut Command, seed: &Path, state_root: &Path) -> io::Result<Self> {
        let seed = seed.canonicalize()?;
        let state_root = state_root.canonicalize()?;
        if !seed.is_dir() || !state_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected Cargo seed and state root must be directories",
            ));
        }

        let sequence = CARGO_STATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let phase = state_root.join(format!("rust-phase-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&phase)?;
        let cargo_home = phase.join("cargo-home");
        let target = phase.join("target");
        std::fs::create_dir(&cargo_home)?;
        std::fs::create_dir(&target)?;

        link_seed_entries(&seed, &cargo_home)?;

        let mut inherited = std::env::vars_os()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        inherited.extend(command.get_envs().map(|(name, _)| name.to_os_string()));
        for name in inherited {
            let text = name.to_string_lossy();
            if text.starts_with("CARGO_ALIAS_") || text.starts_with("CARGO_TARGET_") {
                command.env_remove(name);
            }
        }
        for name in [
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
        ] {
            command.env_remove(name);
        }
        command
            .env("CARGO_HOME", cargo_home)
            .env("CARGO_TARGET_DIR", target)
            .env("CARGO_NET_OFFLINE", "true");
        Ok(Self { phase })
    }

    fn cleanup(self) -> io::Result<()> {
        std::fs::remove_dir_all(&self.phase).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "remove disposable Cargo state {}: {error}",
                    self.phase.display()
                ),
            )
        })
    }
}

#[cfg(unix)]
fn link_seed_entries(seed: &Path, cargo_home: &Path) -> io::Result<()> {
    for name in ["registry", "git", "advisory-db"] {
        let entry = seed.join(name);
        if entry.try_exists()? {
            let metadata = std::fs::symlink_metadata(&entry)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("protected Cargo seed {name} is not a direct directory"),
                ));
            }
            std::os::unix::fs::symlink(&entry, cargo_home.join(name))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn link_seed_entries(_seed: &Path, _cargo_home: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "protected Cargo state isolation is Linux-only",
    ))
}

fn finish_with_fresh_state<T>(
    result: io::Result<T>,
    state: Option<FreshCargoState>,
) -> io::Result<T> {
    let cleanup = match state {
        Some(state) => state.cleanup(),
        None => Ok(()),
    };
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; Cargo state cleanup failed: {cleanup_error}"),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputLimits {
    pub(crate) stdout: usize,
    pub(crate) stderr: usize,
}

pub(crate) const VALIDATION_OUTPUT_LIMITS: OutputLimits = OutputLimits {
    stdout: 4 * 1024 * 1024,
    stderr: 64 * 1024,
};

pub(crate) type Output = std::process::Output;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    fn limit(self, limits: OutputLimits) -> usize {
        match self {
            Self::Stdout => limits.stdout,
            Self::Stderr => limits.stderr,
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Debug)]
struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[cfg(any(windows, test))]
fn read_bounded_pipe(mut reader: impl Read, limit: usize) -> io::Result<BoundedPipe> {
    let sentinel = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output limit"))?;
    let mut bytes = Vec::with_capacity(sentinel.min(8 * 1024));
    reader
        .by_ref()
        .take(sentinel as u64)
        .read_to_end(&mut bytes)?;
    Ok(BoundedPipe {
        exceeded: bytes.len() > limit,
        bytes,
    })
}

fn validate_limits(limits: OutputLimits, input: Option<&[u8]>) -> io::Result<()> {
    limits
        .stdout
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid stdout limit"))?;
    limits
        .stderr
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid stderr limit"))?;
    if input.is_some_and(|bytes| bytes.len() > MAX_INPUT_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("subprocess stdin exceeded its {MAX_INPUT_BYTES}-byte limit"),
        ));
    }
    Ok(())
}

fn status_poll(
    result: io::Result<Option<ExitStatus>>,
    program: &str,
) -> io::Result<Option<ExitStatus>> {
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("poll {program} subprocess status: {error}"),
        )
    })
}

pub(crate) fn require_within_limit(bytes: &[u8], limit: usize, label: &str) -> io::Result<()> {
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} exceeded its {limit}-byte limit"),
        ));
    }
    Ok(())
}

/// Capture both output streams while containing descendants and retaining no
/// more than each configured limit plus one sentinel byte.
pub(crate) fn output(command: &mut Command, limits: OutputLimits) -> io::Result<Output> {
    validate_limits(limits, None)?;
    let state = FreshCargoState::from_environment(command)?;
    finish_with_fresh_state(platform::output(command, limits, None), state)
}

/// Write bounded input and capture both bounded output streams under the same
/// process-tree containment contract as output.
pub(crate) fn output_with_input(
    command: &mut Command,
    input: &[u8],
    limits: OutputLimits,
) -> io::Result<Output> {
    validate_limits(limits, Some(input))?;
    let state = FreshCargoState::from_environment(command)?;
    finish_with_fresh_state(platform::output(command, limits, Some(input)), state)
}

#[cfg(unix)]
mod platform {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdin, Stdio};
    #[cfg(target_os = "linux")]
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::thread;
    use std::time::Instant;

    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    #[cfg(target_os = "linux")]
    use rustix::process::getpgid;
    #[cfg(not(target_os = "linux"))]
    use rustix::process::test_kill_process_group;
    use rustix::process::{Pid, Signal, kill_process_group, setpgid};
    #[cfg(target_os = "linux")]
    use rustix::process::{WaitOptions, kill_process, set_child_subreaper, waitpid};

    #[cfg(target_os = "linux")]
    static SUBREAPER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[cfg(target_os = "linux")]
    struct SubreaperScope {
        baseline: BTreeSet<i32>,
        caller_group: Pid,
        was_enabled: bool,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(target_os = "linux")]
    impl SubreaperScope {
        fn enter() -> io::Result<Self> {
            let lock = SUBREAPER_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| io::Error::other("bounded-process subreaper lock was poisoned"))?;
            let was_enabled = rustix::process::child_subreaper()?.is_some();
            if !was_enabled {
                set_child_subreaper(Pid::from_raw(1))?;
            }
            Ok(Self {
                baseline: direct_children()?,
                caller_group: getpgid(None)?,
                was_enabled,
                _lock: lock,
            })
        }

        fn terminate_and_reap(&self) -> io::Result<()> {
            let deadline = Instant::now() + POST_CANCEL_TIMEOUT;
            loop {
                let adopted = direct_children()?
                    .difference(&self.baseline)
                    .copied()
                    // The test harness and a future concurrent caller may
                    // have unrelated direct children in the caller's process
                    // group. Descendants launched by this module begin in a
                    // dedicated group; a setsid escape necessarily has a
                    // different group too. Leave unrelated children alone.
                    .filter(|raw| {
                        Pid::from_raw(*raw).is_some_and(|pid| {
                            getpgid(Some(pid)).is_ok_and(|group| group != self.caller_group)
                        })
                    })
                    .collect::<Vec<_>>();
                if adopted.is_empty() {
                    return Ok(());
                }
                for raw in &adopted {
                    if let Some(pid) = Pid::from_raw(*raw) {
                        let _ = kill_process(pid, Signal::KILL);
                    }
                }
                for raw in adopted {
                    if let Some(pid) = Pid::from_raw(raw) {
                        match waitpid(Some(pid), WaitOptions::NOHANG) {
                            Ok(_) | Err(rustix::io::Errno::CHILD) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "subprocess descendants were not quiescent after direct-child exit",
                    ));
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for SubreaperScope {
        fn drop(&mut self) {
            if !self.was_enabled {
                let _ = set_child_subreaper(None);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn direct_children() -> io::Result<BTreeSet<i32>> {
        let own_pid = i32::try_from(std::process::id())
            .map_err(|_| io::Error::other("current process ID is out of range"))?;
        let mut children = BTreeSet::new();
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            let stat = match std::fs::read_to_string(entry.path().join("stat")) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let (_, fields) = stat.rsplit_once(") ").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "malformed /proc process stat")
            })?;
            let parent = fields
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated /proc process stat")
                })?
                .parse::<i32>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid /proc parent process ID",
                    )
                })?;
            if parent == own_pid {
                children.insert(pid);
            }
        }
        Ok(children)
    }

    struct Capture<R> {
        reader: Option<R>,
        bytes: Vec<u8>,
        limit: usize,
        stream: Stream,
    }

    impl<R: Read> Capture<R> {
        fn new(reader: R, stream: Stream, limit: usize) -> io::Result<Self> {
            let sentinel = limit.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid output limit")
            })?;
            Ok(Self {
                reader: Some(reader),
                bytes: Vec::with_capacity(sentinel.min(8 * 1024)),
                limit,
                stream,
            })
        }

        fn complete(&self) -> bool {
            self.reader.is_none()
        }

        fn exceeded(&self) -> bool {
            self.bytes.len() > self.limit
        }

        fn drain(&mut self) -> io::Result<bool> {
            let Some(reader) = self.reader.as_mut() else {
                return Ok(false);
            };
            let sentinel = self.limit + 1;
            if self.bytes.len() >= sentinel {
                return Ok(false);
            }

            let mut progressed = false;
            loop {
                let remaining = sentinel - self.bytes.len();
                let mut buffer = [0_u8; 8192];
                let wanted = remaining.min(buffer.len());
                match reader.read(&mut buffer[..wanted]) {
                    Ok(0) => {
                        self.reader = None;
                        return Ok(true);
                    }
                    Ok(count) => {
                        self.bytes.extend_from_slice(&buffer[..count]);
                        progressed = true;
                        if self.bytes.len() >= sentinel {
                            return Ok(true);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(progressed);
                    }
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("read {}: {error}", self.stream.label()),
                        ));
                    }
                }
            }
        }
    }

    trait CaptureState {
        fn has_exceeded(&self) -> bool;
        fn stream(&self) -> Stream;
    }

    impl<R: Read> CaptureState for Capture<R> {
        fn has_exceeded(&self) -> bool {
            self.exceeded()
        }

        fn stream(&self) -> Stream {
            self.stream
        }
    }

    fn set_nonblocking(handle: &impl AsFd) -> io::Result<()> {
        let flags = fcntl_getfl(handle)?;
        fcntl_setfl(handle, flags | OFlags::NONBLOCK)?;
        Ok(())
    }

    fn prepare(command: &mut Command) {
        // SAFETY: the post-fork hook performs only the async-signal-safe
        // setpgid system call and returns its operating-system error.
        unsafe {
            command.pre_exec(|| {
                setpgid(None, None).map_err(io::Error::from)?;
                Ok(())
            });
        }
    }

    fn terminate_tree(child: &mut Child, group: Pid) {
        let _ = kill_process_group(group, Signal::KILL);
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
    }

    #[cfg(target_os = "linux")]
    fn terminate_remaining_group(group: Pid) -> io::Result<()> {
        let _ = kill_process_group(group, Signal::KILL);
        // Group members become direct children of the active subreaper. The
        // enclosing scope reaps them before this operation can return; polling
        // the group here would wait forever on those unreaped zombies.
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn terminate_remaining_group(group: Pid) -> io::Result<()> {
        let _ = kill_process_group(group, Signal::KILL);
        let deadline = Instant::now() + POST_CANCEL_TIMEOUT;
        while test_kill_process_group(group).is_ok() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "subprocess process group was not quiescent after direct-child exit",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    fn reap_until(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "direct child did not exit before the post-cancellation deadline",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn write_input(
        writer: &mut Option<ChildStdin>,
        input: &[u8],
        offset: &mut usize,
    ) -> io::Result<bool> {
        let Some(stdin) = writer.as_mut() else {
            return Ok(false);
        };
        let mut progressed = false;
        while *offset < input.len() {
            match stdin.write(&input[*offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "subprocess stdin stopped accepting input",
                    ));
                }
                Ok(count) => {
                    *offset += count;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(progressed),
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                    *writer = None;
                    return Ok(true);
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("write subprocess stdin: {error}"),
                    ));
                }
            }
        }
        *writer = None;
        Ok(true)
    }

    fn cleanup_error(primary: io::Error, cleanup: io::Result<ExitStatus>) -> io::Error {
        match cleanup {
            Ok(_) => primary,
            Err(error) => io::Error::other(format!("{primary}; cleanup failed: {error}")),
        }
    }

    pub(super) fn output(
        command: &mut Command,
        limits: OutputLimits,
        input: Option<&[u8]>,
    ) -> io::Result<Output> {
        output_with_status_poll(command, limits, input, |child| child.try_wait())
    }

    pub(super) fn output_with_status_poll(
        command: &mut Command,
        limits: OutputLimits,
        input: Option<&[u8]>,
        mut poll: impl FnMut(&mut Child) -> io::Result<Option<ExitStatus>>,
    ) -> io::Result<Output> {
        #[cfg(target_os = "linux")]
        let scope = SubreaperScope::enter()?;
        let result = output_inner(command, limits, input, &mut poll);
        #[cfg(target_os = "linux")]
        let cleanup = scope.terminate_and_reap();
        #[cfg(not(target_os = "linux"))]
        let cleanup: io::Result<()> = Ok(());
        match (result, cleanup) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}; descendant cleanup failed: {cleanup}"
            ))),
        }
    }

    fn output_inner(
        command: &mut Command,
        limits: OutputLimits,
        input: Option<&[u8]>,
        poll: &mut impl FnMut(&mut Child) -> io::Result<Option<ExitStatus>>,
    ) -> io::Result<Output> {
        let program = command.get_program().to_string_lossy().into_owned();
        prepare(command);
        command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;
        let group = Pid::from_child(&child);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other(format!("{program} stdout was not captured")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other(format!("{program} stderr was not captured")))?;
        let mut stdin = if input.is_some() {
            Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other(format!("{program} stdin was not captured")))?,
            )
        } else {
            None
        };

        let setup = (|| -> io::Result<()> {
            set_nonblocking(&stdout)?;
            set_nonblocking(&stderr)?;
            if let Some(handle) = stdin.as_ref() {
                set_nonblocking(handle)?;
            }
            Ok(())
        })();
        if let Err(error) = setup {
            terminate_tree(&mut child, group);
            drop(stdout);
            drop(stderr);
            drop(stdin);
            return Err(cleanup_error(
                error,
                reap_until(&mut child, Instant::now() + POST_CANCEL_TIMEOUT),
            ));
        }

        let mut stdout = Capture::new(stdout, Stream::Stdout, limits.stdout)?;
        let mut stderr = Capture::new(stderr, Stream::Stderr, limits.stderr)?;
        let input = input.unwrap_or_default();
        let mut input_offset = 0_usize;
        if input.is_empty() {
            stdin = None;
        }

        let mut status = None;
        let mut direct_exit = None;
        let mut failure = None;

        loop {
            let mut progressed = false;
            match stdout.drain() {
                Ok(value) => progressed |= value,
                Err(error) => failure = Some(error),
            }
            if failure.is_none() {
                match stderr.drain() {
                    Ok(value) => progressed |= value,
                    Err(error) => failure = Some(error),
                }
            }
            if failure.is_none() {
                match write_input(&mut stdin, input, &mut input_offset) {
                    Ok(value) => progressed |= value,
                    Err(error) => failure = Some(error),
                }
            }

            for capture in [&stdout as &dyn CaptureState, &stderr as &dyn CaptureState] {
                if failure.is_none() && capture.has_exceeded() {
                    failure = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{program} {} exceeded its {}-byte limit",
                            capture.stream().label(),
                            capture.stream().limit(limits)
                        ),
                    ));
                }
            }
            if failure.is_some() {
                break;
            }

            if status.is_none() {
                match status_poll(poll(&mut child), &program) {
                    Ok(Some(reaped)) => {
                        status = Some(reaped);
                        direct_exit = Some(Instant::now());
                        progressed = true;
                    }
                    Ok(None) => {}
                    // Route polling errors through process-tree termination and
                    // bounded reaping instead of returning past cleanup.
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }

            if status.is_some() && stdout.complete() && stderr.complete() {
                break;
            }
            if direct_exit.is_some_and(|started| started.elapsed() >= PIPE_CLOSE_GRACE) {
                failure = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{program} descendants retained output pipes after the direct child exited"
                    ),
                ));
                break;
            }
            if !progressed {
                thread::sleep(POLL_INTERVAL);
            }
        }

        if let Some(error) = failure {
            terminate_tree(&mut child, group);
            drop(stdout);
            drop(stderr);
            drop(stdin);
            let cleanup = match status {
                Some(reaped) => Ok(reaped),
                None => reap_until(&mut child, Instant::now() + POST_CANCEL_TIMEOUT),
            };
            return Err(cleanup_error(error, cleanup));
        }

        terminate_remaining_group(group)?;
        Ok(Output {
            status: status.ok_or_else(|| io::Error::other("direct child was not reaped"))?,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }
}

#[cfg(windows)]
mod platform {
    use super::*;

    use std::io::Write;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio};
    use std::ptr::null;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::IO::CancelSynchronousIo;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    enum WorkerMessage {
        Capture(Stream, io::Result<BoundedPipe>),
        Input(io::Result<()>),
    }

    struct Job {
        handle: OwnedHandle,
    }

    impl Job {
        fn create() -> io::Result<Self> {
            let raw = unsafe { CreateJobObjectW(null(), null()) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
            let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if information.BasicLimitInformation.LimitFlags
                & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
                != 0
            {
                return Err(io::Error::other(
                    "bounded job object unexpectedly permits process breakaway",
                ));
            }
            let configured = unsafe {
                SetInformationJobObject(
                    handle.as_raw_handle() as HANDLE,
                    JobObjectExtendedLimitInformation,
                    (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle })
        }

        fn assign(&self, child: &Child) -> io::Result<()> {
            let assigned = unsafe {
                AssignProcessToJobObject(
                    self.handle.as_raw_handle() as HANDLE,
                    child.as_raw_handle() as HANDLE,
                )
            };
            if assigned == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn terminate(&self) -> io::Result<()> {
            let terminated =
                unsafe { TerminateJobObject(self.handle.as_raw_handle() as HANDLE, 1) };
            if terminated == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    fn resume_primary_thread(child: &Child) -> io::Result<()> {
        let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if raw_snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot as RawHandle) };
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };
        let mut available =
            unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        while available != 0 {
            if entry.th32OwnerProcessID == child.id() {
                let raw_thread =
                    unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if raw_thread.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread as RawHandle) };
                let previous = unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) };
                if previous == u32::MAX {
                    return Err(io::Error::last_os_error());
                }
                if previous != 1 {
                    return Err(io::Error::other(format!(
                        "suspended child thread had unsupported suspend count {previous}"
                    )));
                }
                return Ok(());
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            available = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        }
        Err(io::Error::other(
            "could not locate the suspended child primary thread",
        ))
    }

    fn spawn_reader(
        reader: impl Read + Send + 'static,
        stream: Stream,
        limit: usize,
        sender: Sender<WorkerMessage>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let _ = sender.send(WorkerMessage::Capture(
                stream,
                read_bounded_pipe(reader, limit),
            ));
        })
    }

    fn spawn_writer(
        mut writer: ChildStdin,
        input: Vec<u8>,
        sender: Sender<WorkerMessage>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let result = writer.write_all(&input).and_then(|()| writer.flush());
            let _ = sender.send(WorkerMessage::Input(result));
        })
    }

    fn cancel_worker(worker: &JoinHandle<()>) {
        // ERROR_NOT_FOUND is benign when the worker is between synchronous
        // calls or has already finished, so cancellation is best-effort here.
        let _ = unsafe { CancelSynchronousIo(worker.as_raw_handle() as HANDLE) };
    }

    fn join_worker(worker: Option<JoinHandle<()>>, label: &str) -> io::Result<()> {
        if let Some(worker) = worker {
            worker
                .join()
                .map_err(|_| io::Error::other(format!("{label} worker thread panicked")))?;
        }
        Ok(())
    }

    fn reap_until(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "direct child did not exit before the post-cancellation deadline",
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    struct Captures {
        stdout: Option<Vec<u8>>,
        stderr: Option<Vec<u8>>,
        stdout_finished: bool,
        stderr_finished: bool,
        input_finished: bool,
    }

    impl Captures {
        fn finished(&self, input_expected: bool) -> bool {
            self.stdout_finished && self.stderr_finished && (!input_expected || self.input_finished)
        }

        fn record(
            &mut self,
            message: WorkerMessage,
            limits: OutputLimits,
            program: &str,
        ) -> Option<io::Error> {
            match message {
                WorkerMessage::Capture(stream, Ok(capture)) => {
                    let exceeded = capture.exceeded;
                    match stream {
                        Stream::Stdout => {
                            self.stdout_finished = true;
                            self.stdout = Some(capture.bytes);
                        }
                        Stream::Stderr => {
                            self.stderr_finished = true;
                            self.stderr = Some(capture.bytes);
                        }
                    }
                    if exceeded {
                        Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{program} {} exceeded its {}-byte limit",
                                stream.label(),
                                stream.limit(limits)
                            ),
                        ))
                    } else {
                        None
                    }
                }
                WorkerMessage::Capture(stream, Err(error)) => {
                    match stream {
                        Stream::Stdout => self.stdout_finished = true,
                        Stream::Stderr => self.stderr_finished = true,
                    }
                    Some(io::Error::new(
                        error.kind(),
                        format!("read {}: {error}", stream.label()),
                    ))
                }
                WorkerMessage::Input(Ok(())) => {
                    self.input_finished = true;
                    None
                }
                WorkerMessage::Input(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                    self.input_finished = true;
                    None
                }
                WorkerMessage::Input(Err(error)) => {
                    self.input_finished = true;
                    Some(io::Error::new(
                        error.kind(),
                        format!("write subprocess stdin: {error}"),
                    ))
                }
            }
        }
    }

    fn receive_until(
        receiver: &Receiver<WorkerMessage>,
        captures: &mut Captures,
        limits: OutputLimits,
        program: &str,
        input_expected: bool,
        deadline: Instant,
    ) {
        while !captures.finished(input_expected) && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining.min(POLL_INTERVAL)) {
                Ok(message) => {
                    let _ = captures.record(message, limits, program);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn cleanup_error(
        primary: io::Error,
        cleanup: io::Result<ExitStatus>,
        workers_finished: bool,
        join: io::Result<()>,
    ) -> io::Error {
        let mut details = vec![primary.to_string()];
        if let Err(error) = cleanup {
            details.push(format!("cleanup failed: {error}"));
        }
        if !workers_finished {
            details.push("I/O workers did not cancel before the hard deadline".to_string());
        }
        if let Err(error) = join {
            details.push(format!("worker cleanup failed: {error}"));
        }
        io::Error::other(details.join("; "))
    }

    pub(super) fn output(
        command: &mut Command,
        limits: OutputLimits,
        input: Option<&[u8]>,
    ) -> io::Result<Output> {
        output_with_status_poll(command, limits, input, |child| child.try_wait())
    }

    pub(super) fn output_with_status_poll(
        command: &mut Command,
        limits: OutputLimits,
        input: Option<&[u8]>,
        mut poll: impl FnMut(&mut Child) -> io::Result<Option<ExitStatus>>,
    ) -> io::Result<Output> {
        let program = command.get_program().to_string_lossy().into_owned();
        let job = Job::create()?;
        command
            .creation_flags(CREATE_SUSPENDED)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn()?;
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let cleanup = child.wait();
            return Err(match cleanup {
                Ok(_) => error,
                Err(cleanup) => io::Error::other(format!("{error}; cleanup failed: {cleanup}")),
            });
        }

        let stdout: ChildStdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other(format!("{program} stdout was not captured")))?;
        let stderr: ChildStderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other(format!("{program} stderr was not captured")))?;
        let stdin: Option<ChildStdin> = if input.is_some() {
            Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other(format!("{program} stdin was not captured")))?,
            )
        } else {
            None
        };

        let (sender, receiver) = mpsc::channel();
        let mut stdout_worker = Some(spawn_reader(
            stdout,
            Stream::Stdout,
            limits.stdout,
            sender.clone(),
        ));
        let mut stderr_worker = Some(spawn_reader(
            stderr,
            Stream::Stderr,
            limits.stderr,
            sender.clone(),
        ));
        let mut stdin_worker = stdin
            .map(|writer| spawn_writer(writer, input.unwrap_or_default().to_vec(), sender.clone()));
        drop(sender);

        if let Err(error) = resume_primary_thread(&child) {
            let _ = job.terminate();
            if let Some(worker) = stdout_worker.as_ref() {
                cancel_worker(worker);
            }
            if let Some(worker) = stderr_worker.as_ref() {
                cancel_worker(worker);
            }
            if let Some(worker) = stdin_worker.as_ref() {
                cancel_worker(worker);
            }
            drop(job);
            let _ = child.kill();
            let cleanup = reap_until(&mut child, Instant::now() + POST_CANCEL_TIMEOUT);
            return Err(cleanup_error(error, cleanup, false, Ok(())));
        }

        let input_expected = stdin_worker.is_some();
        let mut captures = Captures {
            stdout: None,
            stderr: None,
            stdout_finished: false,
            stderr_finished: false,
            input_finished: !input_expected,
        };
        let mut status = None;
        let mut direct_exit = None;
        let mut failure = None;

        loop {
            match receiver.recv_timeout(POLL_INTERVAL) {
                Ok(message) => {
                    if let Some(error) = captures.record(message, limits, &program)
                        && failure.is_none()
                    {
                        failure = Some(error);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    if !captures.finished(input_expected) && failure.is_none() {
                        failure = Some(io::Error::other(
                            "subprocess I/O workers stopped before reporting",
                        ));
                    }
                }
            }

            if status.is_none() {
                match status_poll(poll(&mut child), &program) {
                    Ok(Some(reaped)) => {
                        status = Some(reaped);
                        direct_exit = Some(Instant::now());
                    }
                    Ok(None) => {}
                    // Route polling errors through job termination and bounded
                    // reaping instead of returning past cleanup.
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            if failure.is_some() {
                break;
            }
            if status.is_some() && captures.finished(input_expected) {
                break;
            }
            if direct_exit.is_some_and(|started| started.elapsed() >= PIPE_CLOSE_GRACE) {
                failure = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{program} descendants retained output pipes after the direct child exited"
                    ),
                ));
                break;
            }
        }

        if let Some(error) = failure {
            let _ = job.terminate();
            if !captures.stdout_finished
                && let Some(worker) = stdout_worker.as_ref()
            {
                cancel_worker(worker);
            }
            if !captures.stderr_finished
                && let Some(worker) = stderr_worker.as_ref()
            {
                cancel_worker(worker);
            }
            if input_expected
                && !captures.input_finished
                && let Some(worker) = stdin_worker.as_ref()
            {
                cancel_worker(worker);
            }
            drop(job);
            if status.is_none() {
                let _ = child.kill();
            }
            let deadline = Instant::now() + POST_CANCEL_TIMEOUT;
            let cleanup = match status {
                Some(reaped) => Ok(reaped),
                None => reap_until(&mut child, deadline),
            };
            receive_until(
                &receiver,
                &mut captures,
                limits,
                &program,
                input_expected,
                deadline,
            );

            let mut join_result = Ok(());
            if captures.stdout_finished
                && let Err(error) = join_worker(stdout_worker.take(), "stdout")
            {
                join_result = Err(error);
            }
            if captures.stderr_finished
                && let Err(error) = join_worker(stderr_worker.take(), "stderr")
                && join_result.is_ok()
            {
                join_result = Err(error);
            }
            if captures.input_finished
                && let Err(error) = join_worker(stdin_worker.take(), "stdin")
                && join_result.is_ok()
            {
                join_result = Err(error);
            }
            return Err(cleanup_error(
                error,
                cleanup,
                captures.finished(input_expected),
                join_result,
            ));
        }

        drop(job);
        join_worker(stdout_worker.take(), "stdout")?;
        join_worker(stderr_worker.take(), "stderr")?;
        join_worker(stdin_worker.take(), "stdin")?;

        Ok(Output {
            status: status.ok_or_else(|| io::Error::other("direct child was not reaped"))?,
            stdout: captures
                .stdout
                .ok_or_else(|| io::Error::other("stdout worker returned no bytes"))?,
            stderr: captures
                .stderr
                .ok_or_else(|| io::Error::other("stderr worker returned no bytes"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::process::Stdio;
    use std::thread;
    use std::time::Instant;

    fn test_command(name: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--ignored", "--exact", name, "--nocapture", "--quiet"]);
        command
    }

    fn wait_for_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(value) = fs::read_to_string(path)
                && let Ok(pid) = value.trim().parse()
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild did not record its process ID"
            );
            thread::sleep(POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        rustix::process::Pid::from_raw(pid as i32)
            .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
    }

    #[cfg(windows)]
    fn process_exists(pid: u32) -> bool {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

        use windows_sys::Win32::Foundation::{HANDLE, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return false;
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut code = 0_u32;
        let query_succeeded =
            unsafe { GetExitCodeProcess(handle.as_raw_handle() as HANDLE, &mut code) != 0 };
        query_succeeded && code == STILL_ACTIVE as u32
    }

    fn wait_for_exit(pid: u32) {
        let deadline = Instant::now() + POST_CANCEL_TIMEOUT;
        while process_exists(pid) && Instant::now() < deadline {
            thread::sleep(POLL_INTERVAL);
        }
        assert!(!process_exists(pid), "contained grandchild {pid} survived");
    }

    #[test]
    fn bounded_pipe_reads_only_limit_plus_sentinel() {
        let mut exact = Cursor::new(vec![b'x'; 8]);
        let exact_capture = read_bounded_pipe(&mut exact, 8).unwrap();
        assert!(!exact_capture.exceeded);
        assert_eq!(exact_capture.bytes.len(), 8);
        assert_eq!(exact.position(), 8);

        let mut oversized = Cursor::new(vec![b'x'; 32]);
        let oversized_capture = read_bounded_pipe(&mut oversized, 8).unwrap();
        assert!(oversized_capture.exceeded);
        assert_eq!(oversized_capture.bytes.len(), 9);
        assert_eq!(oversized.position(), 9);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_state_discards_alias_wrapper_and_target_poison() {
        let seed = tempfile::tempdir().unwrap();
        for name in ["registry", "git", "advisory-db"] {
            fs::create_dir(seed.path().join(name)).unwrap();
        }
        let root = tempfile::tempdir().unwrap();
        let limits = OutputLimits {
            stdout: 4096,
            stderr: 4096,
        };

        let mut first = Command::new("/bin/sh");
        first
            .arg("-c")
            .arg("mkdir -p \"$CARGO_HOME/bin\"; printf poison > \"$CARGO_HOME/config.toml\"; printf poison > \"$CARGO_HOME/bin/cargo-audit\"; printf poison > \"$CARGO_TARGET_DIR/forged\"")
            .env("RUSTC_WRAPPER", "/candidate/wrapper")
            .env("CARGO_ALIAS_AUDIT", "version");
        let first_state = FreshCargoState::prepare(&mut first, seed.path(), root.path()).unwrap();
        assert!(
            platform::output(&mut first, limits, None)
                .unwrap()
                .status
                .success()
        );
        first_state.cleanup().unwrap();

        let marker = root.path().join("clean");
        let mut second = Command::new("/bin/sh");
        second.arg("-c").arg(format!(
            "test ! -e \"$CARGO_HOME/config.toml\" && test ! -e \"$CARGO_HOME/bin/cargo-audit\" && test ! -e \"$CARGO_TARGET_DIR/forged\" && test -z \"${{RUSTC_WRAPPER-}}\" && test -z \"${{CARGO_ALIAS_AUDIT-}}\" && printf clean > {}",
            marker.display()
        ));
        let second_state = FreshCargoState::prepare(&mut second, seed.path(), root.path()).unwrap();
        assert!(
            platform::output(&mut second, limits, None)
                .unwrap()
                .status
                .success()
        );
        second_state.cleanup().unwrap();
        assert_eq!(fs::read(marker).unwrap(), b"clean");
    }

    #[test]
    fn status_poll_failure_terminates_and_reaps_the_process_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let parent_pid_file = temporary.path().join("parent.pid");
        let descendant_pid_file = temporary.path().join("descendant.pid");
        let mut command = test_command("bounded_process::tests::spawn_poll_failure_tree");
        command.env("YAML_SIGIL_TEST_PARENT_PID_FILE", &parent_pid_file);
        command.env("YAML_SIGIL_TEST_PID_FILE", &descendant_pid_file);
        let observed_parent = parent_pid_file.clone();
        let observed_descendant = descendant_pid_file.clone();
        let started = Instant::now();

        let error = platform::output_with_status_poll(
            &mut command,
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
            None,
            |child| {
                if observed_parent.is_file() && observed_descendant.is_file() {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "synthetic status-poll failure",
                    ))
                } else {
                    child.try_wait()
                }
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("synthetic status-poll failure"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "status-poll failure did not terminate the process tree promptly"
        );
        wait_for_exit(wait_for_pid(&parent_pid_file));
        wait_for_exit(wait_for_pid(&descendant_pid_file));
    }

    #[test]
    fn output_kills_a_pipe_inheriting_grandchild_after_overflow() {
        let temporary = tempfile::tempdir().unwrap();
        let pid_file = temporary.path().join("grandchild.pid");
        let mut command = test_command("bounded_process::tests::spawn_oversized_grandchild");
        command.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        let started = Instant::now();
        let error = output(
            &mut command,
            OutputLimits {
                stdout: 512,
                stderr: 512,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("exceeded its 512-byte limit"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "overflowing process tree was not terminated promptly"
        );
        wait_for_exit(wait_for_pid(&pid_file));
    }

    #[cfg(unix)]
    #[test]
    fn nominal_success_terminates_a_same_group_detached_descendant() {
        let temporary = tempfile::tempdir().unwrap();
        let pid_file = temporary.path().join("success-descendant.pid");
        let mut command = test_command("bounded_process::tests::spawn_success_descendant");
        command.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        let output = output(
            &mut command,
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
        )
        .unwrap();
        assert!(output.status.success());
        wait_for_exit(wait_for_pid(&pid_file));
    }

    #[test]
    fn bounded_input_is_delivered_without_changing_output_limits() {
        let temporary = tempfile::tempdir().unwrap();
        let output_file = temporary.path().join("stdin.bin");
        let mut command = test_command("bounded_process::tests::echo_stdin_child");
        command.env("YAML_SIGIL_TEST_INPUT_FILE", &output_file);
        let result = output_with_input(
            &mut command,
            b"bounded input",
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
        )
        .unwrap();
        assert!(result.status.success());
        assert_eq!(fs::read(output_file).unwrap(), b"bounded input");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nominal_success_terminates_a_silent_session_escapee() {
        let temporary = tempfile::tempdir().unwrap();
        let pid_file = temporary.path().join("escapee.pid");
        let mut command = test_command("bounded_process::tests::spawn_session_escapee");
        command.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        let started = Instant::now();
        let result = output(
            &mut command,
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
        )
        .unwrap();

        assert!(result.status.success());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "escaped descendant held the validator open"
        );

        wait_for_exit(wait_for_pid(&pid_file));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn nominal_success_returns_before_a_silent_session_escapee_and_test_cleans_up() {
        let temporary = tempfile::tempdir().unwrap();
        let pid_file = temporary.path().join("escapee.pid");
        let mut command = test_command("bounded_process::tests::spawn_session_escapee");
        command.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        let started = Instant::now();
        let result = output(
            &mut command,
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
        );
        let elapsed = started.elapsed();

        // Non-Linux Unix has no subreaper guarantee here. Record that the
        // new-session descendant survived process-group cleanup, then kill it
        // explicitly before making assertions so a failed test leaves no
        // background process behind.
        let pid = wait_for_pid(&pid_file);
        let survived_group_cleanup = process_exists(pid);
        if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        wait_for_exit(pid);

        let result = result.unwrap();
        assert!(result.status.success());
        assert!(
            elapsed < Duration::from_secs(5),
            "escaped descendant held the validator open"
        );
        assert!(
            survived_group_cleanup,
            "new-session descendant unexpectedly exited before explicit test cleanup"
        );
    }

    #[cfg(windows)]
    #[test]
    fn child_cannot_break_away_from_the_job() {
        let mut command = test_command("bounded_process::tests::attempt_job_breakaway");
        let result = output(
            &mut command,
            OutputLimits {
                stdout: 4096,
                stderr: 4096,
            },
        )
        .unwrap();
        assert!(result.status.success());
        assert!(
            result
                .stdout
                .windows(b"breakaway-rejected\n".len())
                .any(|window| window == b"breakaway-rejected\n")
        );
        assert!(
            !result
                .stdout
                .windows(b"breakaway-allowed\n".len())
                .any(|window| window == b"breakaway-allowed\n")
        );
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn spawn_oversized_grandchild() {
        let mut child = test_command("bounded_process::tests::oversized_grandchild");
        child.env(
            "YAML_SIGIL_TEST_PID_FILE",
            std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap(),
        );
        let _ = child.status();
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn spawn_poll_failure_tree() {
        fs::write(
            std::env::var_os("YAML_SIGIL_TEST_PARENT_PID_FILE").unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        let mut child = test_command("bounded_process::tests::poll_failure_descendant");
        child.env(
            "YAML_SIGIL_TEST_PID_FILE",
            std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap(),
        );
        let _ = child.status();
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn poll_failure_descendant() {
        fs::write(
            std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn oversized_grandchild() {
        let pid_file = PathBuf::from(std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap());
        fs::write(pid_file, std::process::id().to_string()).unwrap();
        let bytes = vec![b'x'; 1024];
        std::io::stdout().write_all(&bytes).unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stderr().write_all(&bytes).unwrap();
        std::io::stderr().flush().unwrap();
        thread::sleep(Duration::from_secs(30));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    // This helper deliberately leaves its child in the inherited process
    // group so a successful direct child cannot leave background work alive.
    #[allow(clippy::zombie_processes)]
    fn spawn_success_descendant() {
        let pid_file = PathBuf::from(std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap());
        let mut child = test_command("bounded_process::tests::sleeping_success_descendant");
        child.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        child.stdin(Stdio::null());
        child.stdout(Stdio::null());
        child.stderr(Stdio::null());
        child.spawn().unwrap();
        // Do not let the direct child exit before its descendant has joined
        // the process group and recorded the identity checked by the parent.
        wait_for_pid(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn sleeping_success_descendant() {
        let pid_file = PathBuf::from(std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap());
        fs::write(pid_file, std::process::id().to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn echo_stdin_child() {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).unwrap();
        fs::write(
            std::env::var_os("YAML_SIGIL_TEST_INPUT_FILE").unwrap(),
            bytes,
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    // This helper deliberately orphans a new-session child so each platform
    // regression can exercise its documented descendant boundary.
    #[allow(clippy::zombie_processes)]
    fn spawn_session_escapee() {
        use std::os::unix::process::CommandExt;

        let pid_file = PathBuf::from(std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap());
        let mut child = test_command("bounded_process::tests::sleeping_escapee");
        child.env("YAML_SIGIL_TEST_PID_FILE", &pid_file);
        // SAFETY: the post-fork hook performs only the async-signal-safe
        // setsid system call and returns its operating-system error.
        unsafe {
            child.pre_exec(|| {
                rustix::process::setsid().map_err(io::Error::from)?;
                Ok(())
            });
        }
        child.stdin(Stdio::null());
        child.stdout(Stdio::null());
        child.stderr(Stdio::null());
        child.spawn().unwrap();
        wait_for_pid(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn sleeping_escapee() {
        let pid_file = PathBuf::from(std::env::var_os("YAML_SIGIL_TEST_PID_FILE").unwrap());
        fs::write(pid_file, std::process::id().to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn attempt_job_breakaway() {
        use std::os::windows::process::CommandExt;

        use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;

        let mut child = test_command("bounded_process::tests::sleep_child");
        child.creation_flags(CREATE_BREAKAWAY_FROM_JOB);
        match child.spawn() {
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                println!("breakaway-allowed");
            }
            Err(_) => println!("breakaway-rejected"),
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "spawned explicitly by the bounded-process regression"]
    fn sleep_child() {
        thread::sleep(Duration::from_secs(30));
    }
}

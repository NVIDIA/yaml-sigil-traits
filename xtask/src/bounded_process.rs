// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded subprocess output capture for candidate-controlled validation.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputLimits {
    pub(crate) stdout: usize,
    pub(crate) stderr: usize,
}

pub(crate) const VALIDATION_OUTPUT_LIMITS: OutputLimits = OutputLimits {
    stdout: 4 * 1024 * 1024,
    stderr: 64 * 1024,
};

#[derive(Debug)]
pub(crate) struct Output {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
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

#[derive(Debug)]
struct BoundedPipe {
    bytes: Vec<u8>,
    exceeded: bool,
}

type ReaderMessage = (Stream, io::Result<BoundedPipe>);

fn read_bounded_pipe(reader: impl Read, limit: usize) -> io::Result<BoundedPipe> {
    let sentinel = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output limit"))?;
    let mut bytes = Vec::with_capacity(sentinel.min(8 * 1024));
    reader.take(sentinel as u64).read_to_end(&mut bytes)?;
    Ok(BoundedPipe {
        exceeded: bytes.len() > limit,
        bytes,
    })
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    stream: Stream,
    limit: usize,
    sender: Sender<ReaderMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = sender.send((stream, read_bounded_pipe(reader, limit)));
    })
}

fn kill_and_reap(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    if let Err(kill_error) = child.kill() {
        return match child.try_wait()? {
            Some(status) => Ok(status),
            None => Err(kill_error),
        };
    }
    child.wait()
}

fn join_reader(reader: JoinHandle<()>, stream: Stream) -> io::Result<()> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("{} reader thread panicked", stream.label())))
}

fn record_failure(failure: &mut Option<io::Error>, error: io::Error) {
    if failure.is_none() {
        *failure = Some(error);
    }
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

/// Capture both output streams without retaining more than each limit plus one
/// sentinel byte. An overflow or reader failure terminates and reaps the child
/// before both reader threads are joined.
pub(crate) fn output(command: &mut Command, limits: OutputLimits) -> io::Result<Output> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other(format!("{program} stdout was not captured")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other(format!("{program} stderr was not captured")))?;

    let (sender, receiver) = mpsc::channel();
    let stdout_reader = spawn_reader(stdout, Stream::Stdout, limits.stdout, sender.clone());
    let stderr_reader = spawn_reader(stderr, Stream::Stderr, limits.stderr, sender.clone());
    drop(sender);

    let mut stdout = None;
    let mut stderr = None;
    let mut status = None;
    let mut failure = None;

    for _ in 0..2 {
        let (stream, capture) = match receiver.recv() {
            Ok(message) => message,
            Err(error) => {
                record_failure(
                    &mut failure,
                    io::Error::other(format!("output reader stopped before reporting: {error}")),
                );
                if status.is_none() {
                    match kill_and_reap(&mut child) {
                        Ok(reaped) => status = Some(reaped),
                        Err(error) => record_failure(&mut failure, error),
                    }
                }
                break;
            }
        };

        match capture {
            Ok(capture) => {
                if capture.exceeded {
                    record_failure(
                        &mut failure,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{program} {} exceeded its {}-byte limit",
                                stream.label(),
                                stream.limit(limits)
                            ),
                        ),
                    );
                    if status.is_none() {
                        match kill_and_reap(&mut child) {
                            Ok(reaped) => status = Some(reaped),
                            Err(error) => record_failure(&mut failure, error),
                        }
                    }
                }
                match stream {
                    Stream::Stdout => stdout = Some(capture.bytes),
                    Stream::Stderr => stderr = Some(capture.bytes),
                }
            }
            Err(error) => {
                record_failure(
                    &mut failure,
                    io::Error::new(error.kind(), format!("read {}: {error}", stream.label())),
                );
                if status.is_none() {
                    match kill_and_reap(&mut child) {
                        Ok(reaped) => status = Some(reaped),
                        Err(error) => record_failure(&mut failure, error),
                    }
                }
            }
        }
    }

    if status.is_none() {
        match child.wait() {
            Ok(reaped) => status = Some(reaped),
            Err(error) => record_failure(&mut failure, error),
        }
    }
    if let Err(error) = join_reader(stdout_reader, Stream::Stdout) {
        record_failure(&mut failure, error);
    }
    if let Err(error) = join_reader(stderr_reader, Stream::Stderr) {
        record_failure(&mut failure, error);
    }
    if let Some(error) = failure {
        return Err(error);
    }

    Ok(Output {
        status: status.ok_or_else(|| io::Error::other("child was not reaped"))?,
        stdout: stdout.ok_or_else(|| io::Error::other("stdout reader returned no bytes"))?,
        stderr: stderr.ok_or_else(|| io::Error::other("stderr reader returned no bytes"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Cursor, Write};
    use std::time::{Duration, Instant};

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

    #[test]
    fn output_kills_and_reaps_a_child_that_keeps_running_after_overflow() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "bounded_process::tests::oversized_stderr_then_sleep_child",
            "--nocapture",
        ]);
        let started = Instant::now();
        let error = output(
            &mut command,
            OutputLimits {
                stdout: 64 * 1024,
                stderr: 8,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("stderr exceeded its 8-byte limit"));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "overflowing child was not terminated promptly"
        );
    }

    #[test]
    #[ignore = "spawned explicitly by the bounded-process lifecycle regression"]
    fn oversized_stderr_then_sleep_child() {
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(b"123456789").unwrap();
        stderr.flush().unwrap();
        drop(stderr);
        std::thread::sleep(Duration::from_secs(30));
    }
}

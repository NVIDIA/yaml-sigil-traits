// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local coverage for the public crate's unit and integration tests.

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
use std::io;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

use clap::{Args, ValueEnum};

use crate::features::FeatureArgs;
use crate::process::{CommandSpec, Probe};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CoverageEngine {
    #[default]
    LlvmCov,
    Tarpaulin,
}

#[derive(Args, Debug, Default)]
pub(crate) struct CoverageOptions {
    /// Coverage report generator.
    #[arg(long, value_enum, default_value_t = CoverageEngine::LlvmCov)]
    pub(crate) engine: CoverageEngine,
    #[command(flatten)]
    pub(crate) features: FeatureArgs,
}

#[derive(Args, Debug)]
pub(crate) struct CoverageArgs {
    #[command(flatten)]
    pub(crate) options: CoverageOptions,
    /// Open the HTML report after generating it successfully.
    #[arg(long)]
    pub(crate) open: bool,
}

impl CoverageEngine {
    fn index(self) -> &'static str {
        match self {
            Self::LlvmCov => "target/coverage/llvm-cov/html/index.html",
            Self::Tarpaulin => "target/coverage/tarpaulin/tarpaulin-report.html",
        }
    }

    fn probe(self) -> Probe {
        match self {
            Self::LlvmCov => Probe::cargo_tool(
                "cargo-llvm-cov",
                "llvm-cov",
                "cargo install --locked cargo-llvm-cov\nrustup component add llvm-tools-preview",
            ),
            Self::Tarpaulin => Probe::cargo_tool(
                "cargo-tarpaulin",
                "tarpaulin",
                "cargo install --locked cargo-tarpaulin",
            ),
        }
    }
}

fn commands(options: &CoverageOptions) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    let mut test = match options.engine {
        CoverageEngine::LlvmCov => {
            commands.push(
                CommandSpec::cargo(&["llvm-cov", "clean", "--workspace"])
                    .env("CARGO_LLVM_COV_SETUP", "no"),
            );
            CommandSpec::cargo(&[
                "llvm-cov",
                "test",
                "--package",
                "yaml-sigil-traits",
                "--lib",
                "--tests",
                "--html",
                "--output-dir",
                "target/coverage/llvm-cov",
            ])
            .env("CARGO_LLVM_COV_SETUP", "no")
        }
        CoverageEngine::Tarpaulin => CommandSpec::cargo(&[
            "tarpaulin",
            "--package",
            "yaml-sigil-traits",
            "--lib",
            "--tests",
            "--target-dir",
            "target/coverage/tarpaulin/build",
            "--exclude-files",
            "xtask/*",
            "--out",
            "Html",
            "--output-dir",
            "target/coverage/tarpaulin",
        ]),
    };
    test.args.extend(options.features.cargo_args());
    commands.push(test);
    commands
}

pub(crate) fn run(root: &Path, options: &CoverageOptions, open: bool) -> io::Result<()> {
    options.engine.probe().require(root)?;
    let report = root.join(options.engine.index());
    generate_report(
        &report,
        open,
        || {
            for command in commands(options) {
                command.run(root)?;
            }
            Ok(())
        },
        || open_in_browser(&report),
    )
}

fn generate_report(
    path: &Path,
    open: bool,
    generate: impl FnOnce() -> io::Result<()>,
    view: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("remove previous report {}: {error}", path.display()),
            ));
        }
    }
    generate()?;
    if !path.is_file() {
        return Err(io::Error::other(format!(
            "coverage completed without the expected report {}",
            path.display()
        )));
    }
    eprintln!("Wrote {}", path.display());
    if open {
        view()?;
    }
    Ok(())
}

fn open_in_browser(path: &Path) -> io::Result<()> {
    open_canonical_path(&path.canonicalize()?)
}

#[cfg(target_os = "linux")]
fn open_canonical_path(path: &Path) -> io::Result<()> {
    let mut command = Command::new("xdg-open");
    command.arg(path);
    open_with_command(command, path)
}

#[cfg(target_os = "macos")]
fn open_canonical_path(path: &Path) -> io::Result<()> {
    let mut command = Command::new("open");
    command.arg(path);
    open_with_command(command, path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_with_command(mut command: Command, path: &Path) -> io::Result<()> {
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::other(format!(
            "browser opener failed with {status}; open {} manually",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!(
                "No browser opener is available; open {} manually.",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "launch browser opener: {error}; open {} manually",
                path.display()
            ),
        )),
    }
}

#[cfg(target_os = "windows")]
fn open_canonical_path(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: this guard follows a successful CoInitializeEx call and
            // stays on the same thread until it is dropped.
            unsafe { CoUninitialize() };
        }
    }

    // SAFETY: the reserved pointer is null. The apartment belongs to this
    // CLI thread for the duration of the shell operation.
    let com_result = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if com_result < 0 {
        return Err(io::Error::other(format!(
            "Windows could not initialize the browser shell apartment (HRESULT 0x{:08X}); open {} manually",
            com_result as u32,
            path.display()
        )));
    }
    let _com_apartment = ComApartment;
    let operation = windows_wide_argument(OsStr::new("open"))?;
    let shell_path = windows_shell_path_argument(path.as_os_str())?;
    // SAFETY: both buffers remain NUL-terminated during the call. Other
    // pointers are permitted null optional parameters. The path is data.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            shell_path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOW,
        )
    };
    if result as usize as isize <= 32 {
        return Err(io::Error::other(format!(
            "Windows could not open the browser path (code {}); open {} manually",
            result as usize,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_wide_argument(value: &OsStr) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows browser argument contains a NUL code unit",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(target_os = "windows")]
fn windows_shell_path_argument(value: &OsStr) -> io::Result<Vec<u16>> {
    const BACKSLASH: u16 = b'\\' as u16;
    const VERBATIM_PREFIX: &[u16] = &[BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];
    const VERBATIM_UNC_PREFIX: &[u16] = &[
        BACKSLASH,
        BACKSLASH,
        b'?' as u16,
        BACKSLASH,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        BACKSLASH,
    ];

    let encoded = windows_wide_argument(value)?;
    let encoded = &encoded[..encoded.len() - 1];
    let mut shell_path = if let Some(rest) = encoded.strip_prefix(VERBATIM_UNC_PREFIX) {
        let mut path = vec![BACKSLASH, BACKSLASH];
        path.extend_from_slice(rest);
        path
    } else if let Some(rest) = encoded.strip_prefix(VERBATIM_PREFIX) {
        // Canonical drive paths use this prefix. Reject other verbatim
        // namespaces because the Windows shell may not interpret them as paths.
        if rest.len() < 3 || rest[1] != b':' as u16 || rest[2] != BACKSLASH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "canonical Windows browser path is not a drive or UNC path",
            ));
        }
        rest.to_vec()
    } else {
        encoded.to_vec()
    };
    shell_path.push(0);
    Ok(shell_path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_canonical_path(path: &Path) -> io::Result<()> {
    eprintln!(
        "No browser opener is configured for this OS; open {} manually.",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_keeps_product_scope_and_feature_selection() {
        for engine in [CoverageEngine::LlvmCov, CoverageEngine::Tarpaulin] {
            let options = CoverageOptions {
                engine,
                features: FeatureArgs {
                    no_default_features: true,
                    features: vec!["product-feature".into()],
                    ..FeatureArgs::default()
                },
            };
            let commands = commands(&options);
            let test = commands.last().unwrap();
            assert!(
                test.args
                    .windows(2)
                    .any(|args| args == ["--package", "yaml-sigil-traits"])
            );
            assert!(test.args.contains(&"--lib".into()));
            assert!(test.args.contains(&"--tests".into()));
            assert!(test.args.contains(&"--no-default-features".into()));
            assert!(test.args.contains(&"product-feature".into()));
            assert!(!test.args.contains(&"--all-features".into()));
            assert!(!test.args.contains(&"--locked".into()));
            if engine == CoverageEngine::LlvmCov {
                assert_eq!(commands[0].args, ["llvm-cov", "clean", "--workspace"]);
                assert!(commands.iter().all(|command| {
                    command
                        .env
                        .contains(&("CARGO_LLVM_COV_SETUP".into(), "no".into()))
                }));
            } else {
                assert!(
                    test.args
                        .windows(2)
                        .any(|args| args == ["--target-dir", "target/coverage/tarpaulin/build"])
                );
                assert!(
                    test.args
                        .windows(2)
                        .any(|args| args == ["--exclude-files", "xtask/*"])
                );
            }
        }
        assert_ne!(
            CoverageEngine::LlvmCov.index(),
            CoverageEngine::Tarpaulin.index()
        );
        assert!(
            commands(&CoverageOptions::default())
                .last()
                .unwrap()
                .args
                .contains(&"--all-features".into())
        );
    }

    #[test]
    fn reports_open_only_after_successful_fresh_generation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("report.html");
        std::fs::write(&path, b"stale").unwrap();
        generate_report(
            &path,
            true,
            || {
                assert!(!path.exists());
                std::fs::write(&path, b"fresh")
            },
            || {
                assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
                Ok(())
            },
        )
        .unwrap();
        let error = generate_report(
            &path,
            true,
            || Err(io::Error::other("test failed")),
            || panic!("must not open after failure"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("test failed"));
        assert!(!path.exists());
        assert!(
            generate_report(
                &path,
                true,
                || Ok(()),
                || panic!("must not open without a report")
            )
            .is_err()
        );
        generate_report(
            &path,
            false,
            || std::fs::write(&path, b"fresh"),
            || panic!("must not open without --open"),
        )
        .unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn browser_paths_preserve_metacharacters_and_reject_nuls() {
        use std::os::windows::ffi::OsStringExt as _;

        for (canonical, expected) in [
            (
                r"C:\workspace & ^ (group)% name\index.html",
                r"C:\workspace & ^ (group)% name\index.html",
            ),
            (
                r"\\?\C:\workspace & ^ (group)% name\index.html",
                r"C:\workspace & ^ (group)% name\index.html",
            ),
            (
                r"\\?\UNC\server\share & ^ (group)% name\index.html",
                r"\\server\share & ^ (group)% name\index.html",
            ),
        ] {
            let encoded = windows_shell_path_argument(OsStr::new(canonical)).unwrap();
            assert_eq!(encoded.last(), Some(&0));
            assert_eq!(
                std::ffi::OsString::from_wide(&encoded[..encoded.len() - 1]),
                OsStr::new(expected)
            );
        }
        let embedded_nul =
            std::ffi::OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0]);
        assert!(windows_shell_path_argument(&embedded_nul).is_err());
        assert!(windows_shell_path_argument(OsStr::new(r"\\?\Volume{test}\index.html")).is_err());
    }
}

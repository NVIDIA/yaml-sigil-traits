// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Atomic, root-anchored, no-follow reads for release-reachable manifests.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};

pub(crate) const MANIFEST_LIMIT: usize = 1024 * 1024;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn relative_components(path: &Path) -> io::Result<Vec<OsString>> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(invalid_input(
            "safe file path must be a nonempty relative path",
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(invalid_input(
                "safe file path may not contain prefixes, roots, or traversal",
            ));
        };
        let text = value
            .to_str()
            .ok_or_else(|| invalid_input("safe file path must be valid UTF-8"))?;
        if text.contains(':') || text.contains('\0') {
            return Err(invalid_input(
                "safe file path may not contain alternate data streams or NUL",
            ));
        }
        components.push(value.to_owned());
    }
    if components.is_empty() {
        return Err(invalid_input("safe file path has no normal components"));
    }
    Ok(components)
}

fn read_bounded(mut file: File, limit: usize, label: &Path) -> io::Result<Vec<u8>> {
    let sentinel = limit
        .checked_add(1)
        .ok_or_else(|| invalid_input("safe file limit is invalid"))?;
    let mut bytes = Vec::with_capacity(sentinel.min(8 * 1024));
    file.by_ref()
        .take(sentinel as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds its {limit}-byte limit", label.display()),
        ));
    }
    Ok(bytes)
}

fn read_utf8_bounded(file: File, limit: usize, label: &Path) -> io::Result<String> {
    String::from_utf8(read_bounded(file, limit, label)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8: {error}", label.display()),
        )
    })
}

pub(crate) struct TrustedRoot {
    platform: platform::Root,
}

impl TrustedRoot {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            platform: platform::Root::open(path)?,
        })
    }

    pub(crate) fn read_utf8(&self, path: &Path, limit: usize) -> io::Result<String> {
        let components = relative_components(path)?;
        let file = self.platform.open_file(&components)?;
        read_utf8_bounded(file, limit, path)
    }

    pub(crate) fn read_manifest(&self, path: &Path) -> io::Result<String> {
        self.read_utf8(path, MANIFEST_LIMIT)
    }
}

pub(crate) fn read_manifest(root: &Path, path: &Path) -> io::Result<String> {
    TrustedRoot::open(root)?.read_manifest(path)
}

#[cfg(unix)]
mod platform {
    use super::*;

    use rustix::fd::OwnedFd;
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};

    pub(super) struct Root {
        directory: OwnedFd,
    }

    fn require_type(descriptor: &OwnedFd, directory: bool) -> io::Result<()> {
        let metadata = fstat(descriptor)?;
        let file_type = FileType::from_raw_mode(metadata.st_mode);
        if (directory && !file_type.is_dir()) || (!directory && !file_type.is_file()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                if directory {
                    "safe path component is not a directory"
                } else {
                    "safe final path is not a regular file"
                },
            ));
        }
        Ok(())
    }

    impl Root {
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            let directory = open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            require_type(&directory, true)?;
            Ok(Self { directory })
        }

        pub(super) fn open_file(&self, components: &[OsString]) -> io::Result<File> {
            let mut traversed: Option<OwnedFd> = None;
            for component in &components[..components.len() - 1] {
                let parent = traversed.as_ref().unwrap_or(&self.directory);
                let next = openat(
                    parent,
                    component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                require_type(&next, true)?;
                traversed = Some(next);
            }
            let parent = traversed.as_ref().unwrap_or(&self.directory);
            let file = openat(
                parent,
                &components[components.len() - 1],
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            require_type(&file, false)?;
            Ok(File::from(file))
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;

    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::ptr::{null, null_mut};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FILE_TYPE_DISK, FileAttributeTagInfo, FileStandardInfo, GetFileInformationByHandleEx,
        GetFileType, OPEN_EXISTING, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    pub(super) struct Root {
        directory: OwnedHandle,
    }

    fn raw_handle(handle: &OwnedHandle) -> HANDLE {
        handle.as_raw_handle() as HANDLE
    }

    fn require_handle_type(handle: &OwnedHandle, directory: bool) -> io::Result<()> {
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let attribute_ok = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if attribute_ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "safe path component is a reparse point",
            ));
        }
        if unsafe { GetFileType(raw_handle(handle)) } != FILE_TYPE_DISK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "safe path handle is not a disk file",
            ));
        }
        let mut standard = FILE_STANDARD_INFO::default();
        let standard_ok = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if standard_ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if standard.Directory != directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                if directory {
                    "safe path component is not a directory"
                } else {
                    "safe final path is not a regular file"
                },
            ));
        }
        Ok(())
    }

    fn nt_open_relative(
        parent: &OwnedHandle,
        component: &OsString,
        directory: bool,
    ) -> io::Result<OwnedHandle> {
        let mut name: Vec<u16> = component.encode_wide().collect();
        let byte_length = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| invalid_input("safe Windows path component is too long"))?;
        let mut unicode = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: name.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: raw_handle(parent),
            ObjectName: &mut unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut opened: HANDLE = null_mut();
        let desired =
            FILE_READ_ATTRIBUTES | SYNCHRONIZE | if directory { 0 } else { FILE_READ_DATA };
        let options = FILE_OPEN_REPARSE_POINT
            | FILE_SYNCHRONOUS_IO_NONALERT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        let status = unsafe {
            NtCreateFile(
                &mut opened,
                desired,
                &attributes,
                &mut status_block,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                options,
                null(),
                0,
            )
        };
        if status < 0 || opened.is_null() || opened == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(format!(
                "NtCreateFile failed with NTSTATUS {status:#x}",
            )));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(opened as RawHandle) };
        require_handle_type(&handle, directory)?;
        Ok(handle)
    }

    impl Root {
        pub(super) fn open(path: &Path) -> io::Result<Self> {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let opened = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if opened == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let directory = unsafe { OwnedHandle::from_raw_handle(opened as RawHandle) };
            require_handle_type(&directory, true)?;
            Ok(Self { directory })
        }

        pub(super) fn open_file(&self, components: &[OsString]) -> io::Result<File> {
            let mut traversed: Option<OwnedHandle> = None;
            for component in &components[..components.len() - 1] {
                let parent = traversed.as_ref().unwrap_or(&self.directory);
                traversed = Some(nt_open_relative(parent, component, true)?);
            }
            let parent = traversed.as_ref().unwrap_or(&self.directory);
            let file = nt_open_relative(parent, &components[components.len() - 1], false)?;
            Ok(File::from(file))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn exact_limit_limit_plus_one_and_utf8_are_bounded() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("exact.toml"), vec![b'x'; 8]).unwrap();
        fs::write(temporary.path().join("large.toml"), vec![b'x'; 9]).unwrap();
        fs::write(temporary.path().join("invalid.toml"), [0xff]).unwrap();
        let root = TrustedRoot::open(temporary.path()).unwrap();

        assert_eq!(root.read_utf8(Path::new("exact.toml"), 8).unwrap().len(), 8);
        assert_eq!(
            root.read_utf8(Path::new("large.toml"), 8)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            root.read_utf8(Path::new("invalid.toml"), 8)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn directories_absolute_paths_traversal_and_streams_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir(temporary.path().join("directory")).unwrap();
        fs::write(temporary.path().join("Cargo.toml"), b"[package]\n").unwrap();
        let root = TrustedRoot::open(temporary.path()).unwrap();

        assert!(root.read_manifest(Path::new("directory")).is_err());
        assert!(root.read_manifest(Path::new("../Cargo.toml")).is_err());
        assert!(
            root.read_manifest(&temporary.path().join("Cargo.toml"))
                .is_err()
        );
        assert!(root.read_manifest(Path::new("Cargo.toml:stream")).is_err());
        assert_eq!(
            fs::read(temporary.path().join("Cargo.toml")).unwrap(),
            b"[package]\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlinks_intermediate_symlinks_and_devices_are_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("real.toml"), b"[package]\n").unwrap();
        symlink("real.toml", temporary.path().join("link.toml")).unwrap();
        fs::create_dir(temporary.path().join("real-directory")).unwrap();
        fs::write(
            temporary.path().join("real-directory").join("Cargo.toml"),
            b"[package]\n",
        )
        .unwrap();
        symlink("real-directory", temporary.path().join("linked-directory")).unwrap();
        let root = TrustedRoot::open(temporary.path()).unwrap();

        assert!(root.read_manifest(Path::new("link.toml")).is_err());
        assert!(
            root.read_manifest(Path::new("linked-directory/Cargo.toml"))
                .is_err()
        );
        assert!(
            TrustedRoot::open(Path::new("/dev"))
                .unwrap()
                .read_manifest(Path::new("null"))
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_and_intermediate_reparse_points_are_rejected() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("real.toml"), b"[package]\n").unwrap();
        symlink_file("real.toml", temporary.path().join("link.toml")).unwrap();
        fs::create_dir(temporary.path().join("real-directory")).unwrap();
        fs::write(
            temporary.path().join("real-directory").join("Cargo.toml"),
            b"[package]\n",
        )
        .unwrap();
        symlink_dir("real-directory", temporary.path().join("linked-directory")).unwrap();
        let root = TrustedRoot::open(temporary.path()).unwrap();

        assert!(root.read_manifest(Path::new("link.toml")).is_err());
        assert!(
            root.read_manifest(Path::new("linked-directory/Cargo.toml"))
                .is_err()
        );
    }
}

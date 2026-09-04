// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded crates.io reads and exact Cargo source-archive inspection.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use flate2::bufread::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::bounded_process::{self, OutputLimits};
use crate::release_policy::PackagePolicy;

pub(crate) const MAX_CRATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_TOTAL_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CRATE_FILES: usize = 10_000;
const MAX_CRATE_UNPACKED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CRATE_DECOMPRESSED_BYTES: u64 = 160 * 1024 * 1024;
const TAR_BLOCK_BYTES: usize = 512;
const READ_ATTEMPTS: usize = 3;
pub(crate) const CARGO_ARCHIVE_MTIME: u64 = 1_153_704_088;
const CARGO_ARCHIVE_MODES: &[u32] = &[0o644, 0o755];
const GNU_NUL_ZERO: [u8; 8] = [0; 8];
const GNU_OCTAL_ZERO: [u8; 8] = *b"0000000\0";
const GNU_UID_RANGE: std::ops::Range<usize> = 108..116;
const GNU_GID_RANGE: std::ops::Range<usize> = 116..124;
const GNU_TYPEFLAG_OFFSET: usize = 156;
const GNU_DEVICE_MAJOR_RANGE: std::ops::Range<usize> = 329..337;
const GNU_DEVICE_MINOR_RANGE: std::ops::Range<usize> = 337..345;
const USER_AGENT: &str = "yaml-sigil-release-workflow/1.0";
type RequiredArchive = (String, Vec<u8>, BTreeMap<String, ArchiveFile>);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct RegistryVersion {
    pub(crate) num: String,
    pub(crate) yanked: bool,
    pub(crate) checksum: String,
}

pub(crate) trait Registry {
    fn exact_version(
        &mut self,
        package: &str,
        version: &str,
    ) -> Result<Option<RegistryVersion>, String>;
    fn download(&mut self, package: &str, version: &str) -> Result<Vec<u8>, String>;
}

pub(crate) struct CratesIo {
    total_response_bytes: usize,
}

impl CratesIo {
    pub(crate) fn new() -> Self {
        Self {
            total_response_bytes: 0,
        }
    }

    fn account_response(&mut self, bytes: usize) -> Result<(), String> {
        self.total_response_bytes = self
            .total_response_bytes
            .checked_add(bytes)
            .ok_or_else(|| "aggregate registry response size overflowed".to_string())?;
        if self.total_response_bytes > MAX_TOTAL_RESPONSE_BYTES {
            return Err("aggregate registry response bytes exceeded 32 MiB".to_string());
        }
        Ok(())
    }

    fn request_json(&mut self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("https://crates.io/api/v1{path}");
        let mut last = None;
        for attempt in 1..=READ_ATTEMPTS {
            let mut command = Command::new("curl");
            command.args([
                "--disable",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "30",
                "--write-out",
                "\n%{http_code}",
                "--user-agent",
                USER_AGENT,
                &url,
            ]);
            let output = bounded_process::output(
                &mut command,
                OutputLimits {
                    stdout: MAX_JSON_BYTES,
                    stderr: MAX_ERROR_BYTES,
                },
            )
            .map_err(|error| format!("run crates.io request: {error}"))?;
            self.account_response(output.stdout.len())?;
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if attempt < READ_ATTEMPTS && transient_detail(&detail) {
                    last = Some("crates.io read failed transiently".to_string());
                    thread::sleep(Duration::from_secs(attempt as u64));
                    continue;
                }
                return Err(format!("crates.io read failed: {detail}"));
            }
            let split = output
                .stdout
                .iter()
                .rposition(|byte| *byte == b'\n')
                .ok_or_else(|| "crates.io response lacked an HTTP status".to_string())?;
            let body = output.stdout[..split].to_vec();
            let status = std::str::from_utf8(&output.stdout[split + 1..])
                .map_err(|_| "crates.io returned a non-UTF-8 status".to_string())?;
            match status {
                "200" => return Ok(Some(body)),
                "404" => return Ok(None),
                "429" | "500" | "502" | "503" | "504" if attempt < READ_ATTEMPTS => {
                    last = Some(format!("crates.io returned transient HTTP {status}"));
                    thread::sleep(Duration::from_secs(attempt as u64));
                }
                _ => return Err(format!("crates.io returned HTTP {status}")),
            }
        }
        Err(last.unwrap_or_else(|| "crates.io read failed".to_string()))
    }
}

impl Registry for CratesIo {
    fn exact_version(
        &mut self,
        package: &str,
        version: &str,
    ) -> Result<Option<RegistryVersion>, String> {
        validate_component(package, "crate name")?;
        validate_component(version, "crate version")?;
        let Some(body) = self.request_json(&format!("/crates/{package}/{version}"))? else {
            return Ok(None);
        };
        let response: RegistryResponse = serde_json::from_slice(&body)
            .map_err(|error| format!("crates.io returned invalid exact-version JSON: {error}"))?;
        Ok(Some(response.version))
    }

    fn download(&mut self, package: &str, version: &str) -> Result<Vec<u8>, String> {
        validate_component(package, "crate name")?;
        validate_component(version, "crate version")?;
        let url = format!("https://crates.io/api/v1/crates/{package}/{version}/download");
        let mut last = None;
        for attempt in 1..=READ_ATTEMPTS {
            let mut command = Command::new("curl");
            command.args([
                "--disable",
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "60",
                "--max-filesize",
                &MAX_CRATE_BYTES.to_string(),
                "--user-agent",
                USER_AGENT,
                &url,
            ]);
            let output = bounded_process::output(
                &mut command,
                OutputLimits {
                    stdout: MAX_CRATE_BYTES,
                    stderr: MAX_ERROR_BYTES,
                },
            )
            .map_err(|error| format!("run crates.io archive download: {error}"))?;
            self.account_response(output.stdout.len())?;
            if output.status.success() {
                return Ok(output.stdout);
            }
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if attempt < READ_ATTEMPTS && transient_detail(&detail) {
                last = Some("crates.io archive download failed transiently".to_string());
                thread::sleep(Duration::from_secs(attempt as u64));
                continue;
            }
            return Err(format!("crates.io archive download failed: {detail}"));
        }
        Err(last.unwrap_or_else(|| "crates.io archive download failed".to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct RegistryResponse {
    version: RegistryVersion,
}

fn validate_component(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(format!("{label} is invalid"))
    } else {
        Ok(())
    }
}

fn transient_detail(detail: &str) -> bool {
    [
        "timed out",
        "Timeout",
        "Could not resolve host",
        "Failed to connect",
        "Connection reset",
        "HTTP 429",
        "HTTP 502",
        "HTTP 503",
        "HTTP 504",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
}

pub(crate) fn require_archive(
    registry: &mut impl Registry,
    policy: &PackagePolicy,
    version: &str,
    commit: &str,
) -> Result<RequiredArchive, String> {
    let record = registry
        .exact_version(policy.package, version)?
        .ok_or_else(|| format!("crates.io lacks {} {version}", policy.package))?;
    if record.num != version || record.yanked || !is_checksum(&record.checksum) {
        return Err(format!(
            "crates.io does not expose {} {version} as one exact non-yanked archive",
            policy.package
        ));
    }
    let archive = registry.download(policy.package, version)?;
    let actual = format!("{:x}", Sha256::digest(&archive));
    if actual != record.checksum {
        return Err(format!(
            "crates.io archive checksum differs for {} {version}",
            policy.package
        ));
    }
    let files = inspect_archive_entries(&archive, policy, version, commit)?;
    Ok((record.checksum, archive, files))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveFile {
    pub(crate) body: Vec<u8>,
    metadata: ArchiveMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveMetadata {
    header_sha256: String,
    entry_type: u8,
    mode: u32,
    uid: Vec<u8>,
    gid: Vec<u8>,
    mtime: u64,
    username: Vec<u8>,
    groupname: Vec<u8>,
    device_major: Vec<u8>,
    device_minor: Vec<u8>,
}

#[cfg(test)]
pub(crate) fn inspect_archive(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
    commit: &str,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    inspect_archive_with_limit(
        archive,
        policy,
        version,
        commit,
        MAX_CRATE_DECOMPRESSED_BYTES,
    )
}

pub(crate) fn inspect_archive_entries(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
    commit: &str,
) -> Result<BTreeMap<String, ArchiveFile>, String> {
    inspect_archive_entries_with_limit(
        archive,
        policy,
        version,
        Some(commit),
        MAX_CRATE_DECOMPRESSED_BYTES,
    )
}

#[cfg(test)]
pub(crate) fn archive_inventory_sha256(files: &BTreeMap<String, ArchiveFile>) -> String {
    let mut digest = Sha256::new();
    inventory_value(&mut digest, b"yaml-sigil-crate-inventory-v1");
    for (path, file) in files {
        inventory_value(&mut digest, path.as_bytes());
        inventory_value(
            &mut digest,
            format!("header-sha256={}", file.metadata.header_sha256).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("entry-type={}", file.metadata.entry_type).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("mode={}", file.metadata.mode).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("uid={}", hex(&file.metadata.uid)).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("gid={}", hex(&file.metadata.gid)).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("mtime={}", file.metadata.mtime).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("username={}", hex(&file.metadata.username)).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("groupname={}", hex(&file.metadata.groupname)).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("device-major={}", hex(&file.metadata.device_major)).as_bytes(),
        );
        inventory_value(
            &mut digest,
            format!("device-minor={}", hex(&file.metadata.device_minor)).as_bytes(),
        );
        inventory_value(&mut digest, format!("size={}", file.body.len()).as_bytes());
        inventory_value(
            &mut digest,
            format!("sha256={:x}", Sha256::digest(&file.body)).as_bytes(),
        );
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
fn inventory_value(digest: &mut Sha256, value: &[u8]) {
    digest.update(value);
    digest.update([0]);
}

#[cfg(test)]
fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn archive_vcs_commit(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
) -> Result<String, String> {
    let files = inspect_archive_entries_with_limit(
        archive,
        policy,
        version,
        None,
        MAX_CRATE_DECOMPRESSED_BYTES,
    )?;
    Ok(parse_vcs_info(&files, policy)?.git.sha1)
}

#[cfg(test)]
fn inspect_archive_with_limit(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
    commit: &str,
    decompressed_limit: u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    inspect_archive_entries_with_limit(archive, policy, version, Some(commit), decompressed_limit)
        .map(|entries| {
            entries
                .into_iter()
                .map(|(path, file)| (path, file.body))
                .collect()
        })
}

fn inspect_archive_entries_with_limit(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
    commit: Option<&str>,
    decompressed_limit: u64,
) -> Result<BTreeMap<String, ArchiveFile>, String> {
    if archive.is_empty() || archive.len() > MAX_CRATE_BYTES {
        return Err(format!(
            "{} source archive is empty or oversized",
            policy.package
        ));
    }
    let prefix = format!("{}-{version}", policy.package);
    let decompressed = decompress_single_gzip(archive, policy.package, decompressed_limit)?;
    validate_tar_termination(&decompressed, policy.package)?;
    let mut package = tar::Archive::new(Cursor::new(&decompressed));
    (|| {
        let entries = package
            .entries()
            .map_err(|error| format!("{} source archive is invalid: {error}", policy.package))?
            .raw(true);
        let mut files = BTreeMap::new();
        let mut count = 0usize;
        let mut total = 0u64;
        for entry in entries {
            let mut entry = entry.map_err(|error| {
                format!(
                    "{} source archive entry is invalid: {error}",
                    policy.package
                )
            })?;
            count += 1;
            if count > MAX_CRATE_FILES {
                return Err(format!(
                    "{} source archive contains too many entries",
                    policy.package
                ));
            }
            let size = entry.header().size().map_err(|error| {
                format!(
                    "{} source archive has an invalid entry size: {error}",
                    policy.package
                )
            })?;
            total = total
                .checked_add(size)
                .ok_or_else(|| format!("{} source archive size overflowed", policy.package))?;
            if total > MAX_CRATE_UNPACKED_BYTES {
                return Err(format!(
                    "{} source archive expands beyond its limit",
                    policy.package
                ));
            }
            let raw_path = entry.path_bytes();
            let path = std::str::from_utf8(&raw_path)
                .map_err(|_| format!("{} source archive has a non-UTF-8 path", policy.package))?
                .to_string();
            validate_raw_header_path(entry.header(), &path, policy.package)?;
            validate_archive_path(&path, &prefix, policy.package)?;
            let metadata = cargo_archive_metadata(entry.header(), policy.package)?;
            let relative = path
                .strip_prefix(&format!("{prefix}/"))
                .ok_or_else(|| format!("{} source archive path lacks its root", policy.package))?;
            let mut body = Vec::with_capacity(size.min(MAX_CRATE_BYTES as u64) as usize);
            entry
                .by_ref()
                .take(size + 1)
                .read_to_end(&mut body)
                .map_err(|error| {
                    format!(
                        "{} source archive entry is unreadable: {error}",
                        policy.package
                    )
                })?;
            if body.len() as u64 != size
                || files
                    .insert(relative.to_string(), ArchiveFile { body, metadata })
                    .is_some()
            {
                return Err(format!(
                    "{} source archive contains a duplicate or truncated file",
                    policy.package
                ));
            }
        }
        if count == 0 {
            return Err(format!("{} source archive is empty", policy.package));
        }
        let vcs = parse_vcs_info(&files, policy)?;
        if commit.is_some_and(|expected| vcs.git.sha1 != expected) {
            return Err(format!(
                "{} source archive is not bound to the exact clean release commit",
                policy.package
            ));
        }
        Ok(files)
    })()
}

fn decompress_single_gzip(
    archive: &[u8],
    package: &str,
    decompressed_limit: u64,
) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(Cursor::new(archive));
    let mut decompressed = Vec::new();
    decoder
        .by_ref()
        .take(decompressed_limit + 1)
        .read_to_end(&mut decompressed)
        .map_err(|error| format!("{package} source archive gzip stream is invalid: {error}"))?;
    if decompressed.len() as u64 > decompressed_limit {
        return Err(format!("{package} source archive expands beyond its limit"));
    }
    let consumed = decoder.into_inner().position();
    if consumed != archive.len() as u64 {
        return Err(format!(
            "{package} source archive contains another gzip member or trailing bytes"
        ));
    }
    Ok(decompressed)
}

fn validate_tar_termination(tar: &[u8], package: &str) -> Result<(), String> {
    if tar.len() < TAR_BLOCK_BYTES * 2 || !tar.len().is_multiple_of(TAR_BLOCK_BYTES) {
        return Err(format!(
            "{package} source archive has a noncanonical tar length"
        ));
    }
    let mut offset = 0usize;
    while offset < tar.len() {
        let header = &tar[offset..offset + TAR_BLOCK_BYTES];
        if header.iter().all(|byte| *byte == 0) {
            let second = tar
                .get(offset + TAR_BLOCK_BYTES..offset + TAR_BLOCK_BYTES * 2)
                .ok_or_else(|| {
                    format!("{package} source archive lacks its canonical tar terminator")
                })?;
            if !second.iter().all(|byte| *byte == 0)
                || tar[offset + TAR_BLOCK_BYTES * 2..]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(format!(
                    "{package} source archive contains records after its tar terminator"
                ));
            }
            return Ok(());
        }
        let header = tar::Header::from_byte_slice(header);
        let size = header.entry_size().map_err(|error| {
            format!("{package} source archive has an invalid physical entry size: {error}")
        })?;
        let padded = size
            .checked_add((TAR_BLOCK_BYTES - 1) as u64)
            .map(|value| value / TAR_BLOCK_BYTES as u64 * TAR_BLOCK_BYTES as u64)
            .ok_or_else(|| format!("{package} source archive physical size overflowed"))?;
        let next = (offset as u64)
            .checked_add(TAR_BLOCK_BYTES as u64)
            .and_then(|value| value.checked_add(padded))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("{package} source archive physical size overflowed"))?;
        if next > tar.len() {
            return Err(format!(
                "{package} source archive contains a truncated physical entry"
            ));
        }
        offset = next;
    }
    Err(format!(
        "{package} source archive lacks its canonical tar terminator"
    ))
}

fn cargo_archive_metadata(header: &tar::Header, package: &str) -> Result<ArchiveMetadata, String> {
    if header.as_gnu().is_none() {
        return Err(format!(
            "{package} source archive entry does not use Cargo's GNU header format"
        ));
    }
    // The GNU tar header stores the raw type flag at byte 156. Cargo 1.95
    // emits the canonical ASCII `0` regular-file spelling, not the NUL alias.
    let entry_type = header.as_bytes()[GNU_TYPEFLAG_OFFSET];
    if entry_type != tar::EntryType::file().as_byte() {
        return Err(format!(
            "{package} source archive contains a noncanonical entry type"
        ));
    }
    let mode = header
        .mode()
        .map_err(|error| format!("{package} source archive has an invalid mode: {error}"))?;
    if !CARGO_ARCHIVE_MODES.contains(&mode) {
        return Err(format!(
            "{package} source archive contains a noncanonical or unsafe mode"
        ));
    }
    // Cargo 1.95 emits NUL zeroes for generated entries and octal zeroes for
    // entries copied from disk. Preserve the raw form so reproduction catches
    // a representation change even though both decode to numeric zero.
    let uid = header.as_bytes()[GNU_UID_RANGE].to_vec();
    let gid = header.as_bytes()[GNU_GID_RANGE].to_vec();
    if !cargo_zero_field(&uid) || !cargo_zero_field(&gid) {
        return Err(format!(
            "{package} source archive contains noncanonical ownership: UID {uid:?}, GID {gid:?}"
        ));
    }
    let mtime = header
        .mtime()
        .map_err(|error| format!("{package} source archive has an invalid mtime: {error}"))?;
    if mtime != CARGO_ARCHIVE_MTIME {
        return Err(format!(
            "{package} source archive contains a noncanonical mtime"
        ));
    }
    let username = header
        .username_bytes()
        .ok_or_else(|| format!("{package} source archive omits Cargo's owner representation"))?;
    let groupname = header
        .groupname_bytes()
        .ok_or_else(|| format!("{package} source archive omits Cargo's group representation"))?;
    if !username.is_empty() || !groupname.is_empty() {
        return Err(format!(
            "{package} source archive contains noncanonical owner or group names"
        ));
    }
    if header
        .link_name_bytes()
        .is_some_and(|name| !name.is_empty())
    {
        return Err(format!(
            "{package} source archive regular entry contains a link target"
        ));
    }
    let device_major = header.as_bytes()[GNU_DEVICE_MAJOR_RANGE].to_vec();
    let device_minor = header.as_bytes()[GNU_DEVICE_MINOR_RANGE].to_vec();
    if !cargo_zero_field(&device_major) || !cargo_zero_field(&device_minor) {
        return Err(format!(
            "{package} source archive contains noncanonical device metadata"
        ));
    }
    Ok(ArchiveMetadata {
        header_sha256: format!("{:x}", Sha256::digest(header.as_bytes())),
        entry_type,
        mode,
        uid,
        gid,
        mtime,
        username: username.to_vec(),
        groupname: groupname.to_vec(),
        device_major,
        device_minor,
    })
}

fn validate_raw_header_path(header: &tar::Header, path: &str, package: &str) -> Result<(), String> {
    let name = &header.as_bytes()[..100];
    let length = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    if &name[..length] != path.as_bytes() || name[length..].iter().any(|byte| *byte != 0) {
        return Err(format!(
            "{package} source archive contains a noncanonical raw path"
        ));
    }
    Ok(())
}

fn cargo_zero_field(field: &[u8]) -> bool {
    field == GNU_NUL_ZERO || field == GNU_OCTAL_ZERO
}

fn validate_archive_path(path: &str, prefix: &str, package: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\0', '\r', '\n', '\\'])
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        || (path != prefix && !path.starts_with(&format!("{prefix}/")))
    {
        Err(format!("{package} source archive contains an unsafe path"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VcsInfo {
    git: VcsGit,
    path_in_vcs: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VcsGit {
    sha1: String,
    #[serde(default)]
    dirty: bool,
}

fn parse_vcs_info(
    files: &BTreeMap<String, ArchiveFile>,
    policy: &PackagePolicy,
) -> Result<VcsInfo, String> {
    let body = &files
        .get(".cargo_vcs_info.json")
        .ok_or_else(|| {
            format!(
                "{} source archive lacks .cargo_vcs_info.json",
                policy.package
            )
        })?
        .body;
    let vcs: VcsInfo = serde_json::from_slice(body).map_err(|error| {
        format!(
            "{} source archive has invalid VCS metadata: {error}",
            policy.package
        )
    })?;
    if vcs.git.sha1.len() != 40
        || !vcs
            .git
            .sha1
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || vcs.git.dirty
        || vcs.path_in_vcs != policy.path_in_vcs
    {
        return Err(format!(
            "{} source archive contains invalid VCS identity",
            policy.package
        ));
    }
    Ok(vcs)
}

pub(crate) fn is_checksum(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn require_clean_source(root: &Path, commit: &str) -> Result<(), String> {
    let mut head_command = Command::new("git");
    head_command.current_dir(root).args(["rev-parse", "HEAD"]);
    let head = bounded_process::output(
        &mut head_command,
        OutputLimits {
            stdout: MAX_ERROR_BYTES,
            stderr: MAX_ERROR_BYTES,
        },
    )
    .map_err(|error| format!("read release source commit: {error}"))?;
    if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != commit {
        return Err("release source is not at the expected commit".to_string());
    }
    let mut status_command = Command::new("git");
    status_command
        .current_dir(root)
        .args(["status", "--porcelain"]);
    let status = bounded_process::output(
        &mut status_command,
        OutputLimits {
            stdout: MAX_JSON_BYTES,
            stderr: MAX_ERROR_BYTES,
        },
    )
    .map_err(|error| format!("read release source status: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("release source is not a clean checkout".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    #[derive(Clone, Copy)]
    struct TestMetadata {
        gnu: bool,
        entry_type: u8,
        mode: u32,
        uid: [u8; 8],
        gid: [u8; 8],
        mtime: u64,
        username: &'static str,
        groupname: &'static str,
        device_major: [u8; 8],
        device_minor: [u8; 8],
    }

    impl Default for TestMetadata {
        fn default() -> Self {
            Self {
                gnu: true,
                entry_type: tar::EntryType::file().as_byte(),
                mode: 0o644,
                uid: [0; 8],
                gid: [0; 8],
                mtime: CARGO_ARCHIVE_MTIME,
                username: "",
                groupname: "",
                device_major: [0; 8],
                device_minor: [0; 8],
            }
        }
    }

    fn append_test_file(
        builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
        path: &str,
        body: &[u8],
        metadata: TestMetadata,
    ) {
        let mut header = if metadata.gnu {
            tar::Header::new_gnu()
        } else {
            tar::Header::new_ustar()
        };
        header.set_entry_type(tar::EntryType::new(metadata.entry_type));
        header.as_mut_bytes()[GNU_TYPEFLAG_OFFSET] = metadata.entry_type;
        header.set_mode(metadata.mode);
        header.set_mtime(metadata.mtime);
        header.set_username(metadata.username).unwrap();
        header.set_groupname(metadata.groupname).unwrap();
        header.as_mut_bytes()[GNU_UID_RANGE].copy_from_slice(&metadata.uid);
        header.as_mut_bytes()[GNU_GID_RANGE].copy_from_slice(&metadata.gid);
        header.as_mut_bytes()[GNU_DEVICE_MAJOR_RANGE].copy_from_slice(&metadata.device_major);
        header.as_mut_bytes()[GNU_DEVICE_MINOR_RANGE].copy_from_slice(&metadata.device_minor);
        header.set_size(body.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, body).unwrap();
    }

    fn archive_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, body) in files {
            append_test_file(&mut builder, path, body, TestMetadata::default());
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn archive_with_metadata(path: &str, body: &[u8], metadata: TestMetadata) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append_test_file(&mut builder, path, body, metadata);
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn archive(path: &str, vcs: &[u8]) -> Vec<u8> {
        archive_with_files(&[(path, vcs)])
    }

    fn recompress(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    struct FixtureDirectory(std::path::PathBuf);

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn run_fixture_command(command: &mut Command, label: &str) -> Vec<u8> {
        let output = bounded_process::output(command, bounded_process::VALIDATION_OUTPUT_LIMITS)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    fn cargo_1_95_archive_matches_observed_cross_platform_contract() {
        if std::env::var_os("YAML_SIGIL_REQUIRE_CARGO_1_95_ARCHIVE").is_none() {
            return;
        }

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let version =
            run_fixture_command(Command::new(&cargo).arg("--version"), "read Cargo version");
        let version = String::from_utf8(version).expect("Cargo version is UTF-8");
        assert!(
            version.starts_with("cargo 1.95.0 "),
            "archive contract must be observed with exact Cargo 1.95.0, got {version:?}"
        );

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "yaml-sigil-cargo-archive-contract-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("src")).expect("create fixture source directory");
        let _fixture = FixtureDirectory(root.clone());
        std::fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname = \"cargo-archive-contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\ndescription = \"Cargo 1.95 archive contract fixture\"\n",
        )
        .expect("write fixture manifest");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, b"pub fn fixture() -> bool { true }\n")
            .expect("write fixture source");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&source)
                .expect("read fixture source permissions")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&source, permissions).expect("make fixture source executable");
        }

        run_fixture_command(
            Command::new("git")
                .current_dir(&root)
                .args(["init", "--quiet"]),
            "initialize fixture repository",
        );
        run_fixture_command(
            Command::new("git")
                .current_dir(&root)
                .args(["config", "core.autocrlf", "false"]),
            "configure fixture line endings",
        );
        run_fixture_command(
            Command::new("git").current_dir(&root).args([
                "config",
                "user.name",
                "Cargo archive fixture",
            ]),
            "configure fixture author name",
        );
        run_fixture_command(
            Command::new("git").current_dir(&root).args([
                "config",
                "user.email",
                "fixture@example.invalid",
            ]),
            "configure fixture author email",
        );
        run_fixture_command(
            Command::new("git")
                .current_dir(&root)
                .args(["add", "Cargo.toml", "src/lib.rs"]),
            "stage fixture source",
        );
        run_fixture_command(
            Command::new("git").current_dir(&root).args([
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "fixture",
            ]),
            "commit fixture source",
        );
        let commit = run_fixture_command(
            Command::new("git")
                .current_dir(&root)
                .args(["rev-parse", "HEAD"]),
            "read fixture commit",
        );
        let commit = String::from_utf8(commit)
            .expect("fixture commit is UTF-8")
            .trim()
            .to_string();

        run_fixture_command(
            Command::new(&cargo).current_dir(&root).args([
                "package",
                "--no-verify",
                "--offline",
                "--target-dir",
                "target",
            ]),
            "package Cargo archive fixture",
        );
        let archive = std::fs::read(root.join("target/package/cargo-archive-contract-0.1.0.crate"))
            .expect("read packaged fixture");
        let policy = PackagePolicy {
            package: "cargo-archive-contract",
            tag_prefix: "v",
            changelog: "CHANGELOG.md",
            path_in_vcs: "",
        };
        let entries = inspect_archive_entries(&archive, &policy, "0.1.0", &commit)
            .expect("Cargo 1.95 fixture follows the encoded archive contract");

        assert_eq!(entries["Cargo.toml"].metadata.mode, 0o644);
        assert_eq!(entries["Cargo.toml.orig"].metadata.mode, 0o644);
        assert_eq!(entries["Cargo.lock"].metadata.mode, 0o644);
        assert_eq!(entries[".cargo_vcs_info.json"].metadata.mode, 0o644);
        for generated in [".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml"] {
            assert_eq!(entries[generated].metadata.uid, GNU_NUL_ZERO);
            assert_eq!(entries[generated].metadata.gid, GNU_NUL_ZERO);
            assert_eq!(entries[generated].metadata.device_major, GNU_NUL_ZERO);
            assert_eq!(entries[generated].metadata.device_minor, GNU_NUL_ZERO);
        }
        for copied in ["Cargo.toml.orig", "src/lib.rs"] {
            assert_eq!(entries[copied].metadata.uid, GNU_OCTAL_ZERO);
            assert_eq!(entries[copied].metadata.gid, GNU_OCTAL_ZERO);
            assert_eq!(entries[copied].metadata.device_major, GNU_OCTAL_ZERO);
            assert_eq!(entries[copied].metadata.device_minor, GNU_OCTAL_ZERO);
        }
        #[cfg(unix)]
        assert_eq!(entries["src/lib.rs"].metadata.mode, 0o755);
        #[cfg(windows)]
        assert_eq!(entries["src/lib.rs"].metadata.mode, 0o644);
    }

    #[test]
    fn archive_requires_exact_vcs_commit_and_path() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let root = format!("{}-0.4.0", package.package);
        let bytes = archive(&format!("{root}/.cargo_vcs_info.json"), vcs.as_bytes());
        let files = inspect_archive(&bytes, package, "0.4.0", &commit).unwrap();
        assert!(files.contains_key(".cargo_vcs_info.json"));
        assert!(inspect_archive(&bytes, package, "0.4.0", &"b".repeat(40),).is_err());
    }

    #[test]
    fn archive_path_policy_rejects_traversal_and_wrong_roots() {
        let package = crate::release_policy::TRAITS_POLICY.packages[0].package;
        let root = format!("{package}-0.4.0");
        assert!(validate_archive_path(&format!("{root}/../escape"), &root, package).is_err());
        assert!(validate_archive_path("other-0.4.0/Cargo.toml", &root, package).is_err());
        assert!(validate_archive_path(&format!("{root}/trailing/"), &root, package).is_err());
        assert!(validate_archive_path(&format!("{root}//alias"), &root, package).is_err());
    }

    #[test]
    fn cargo_metadata_contract_rejects_each_independent_drift() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let path = format!("{}-0.4.0/.cargo_vcs_info.json", package.package);

        let mut cases = Vec::new();
        cases.push((
            "header format",
            TestMetadata {
                gnu: false,
                ..TestMetadata::default()
            },
        ));
        cases.push((
            "entry type",
            TestMetadata {
                entry_type: b'\0',
                ..TestMetadata::default()
            },
        ));
        cases.push((
            "mode",
            TestMetadata {
                mode: 0o600,
                ..TestMetadata::default()
            },
        ));
        let mut metadata = TestMetadata::default();
        metadata.uid[0] = b'1';
        cases.push(("uid", metadata));
        let mut metadata = TestMetadata::default();
        metadata.gid[0] = b'1';
        cases.push(("gid", metadata));
        let mut metadata = TestMetadata::default();
        metadata.mtime += 1;
        cases.push(("mtime", metadata));
        cases.push((
            "username",
            TestMetadata {
                username: "root",
                ..TestMetadata::default()
            },
        ));
        cases.push((
            "groupname",
            TestMetadata {
                groupname: "root",
                ..TestMetadata::default()
            },
        ));
        let mut metadata = TestMetadata::default();
        metadata.device_major[0] = b'1';
        cases.push(("device major", metadata));
        let mut metadata = TestMetadata::default();
        metadata.device_minor[0] = b'1';
        cases.push(("device minor", metadata));

        for (label, metadata) in cases {
            let bytes = archive_with_metadata(&path, vcs.as_bytes(), metadata);
            assert!(
                inspect_archive(&bytes, package, "0.4.0", &commit).is_err(),
                "accepted drift in {label}"
            );
        }
    }

    #[test]
    fn cargo_regular_modes_are_exact_and_metadata_affects_equality() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let path = format!("{}-0.4.0/.cargo_vcs_info.json", package.package);
        let regular = archive_with_metadata(&path, vcs.as_bytes(), TestMetadata::default());
        let executable = archive_with_metadata(
            &path,
            vcs.as_bytes(),
            TestMetadata {
                mode: 0o755,
                ..TestMetadata::default()
            },
        );

        let regular = inspect_archive_entries(&regular, package, "0.4.0", &commit).unwrap();
        let executable = inspect_archive_entries(&executable, package, "0.4.0", &commit).unwrap();
        assert_ne!(regular, executable);
        assert_eq!(
            regular[".cargo_vcs_info.json"].body,
            executable[".cargo_vcs_info.json"].body
        );
    }

    #[test]
    fn cargo_zero_representations_are_exact_and_affect_equality() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let path = format!("{}-0.4.0/.cargo_vcs_info.json", package.package);
        let nul = archive_with_metadata(&path, vcs.as_bytes(), TestMetadata::default());
        let octal = archive_with_metadata(
            &path,
            vcs.as_bytes(),
            TestMetadata {
                uid: GNU_OCTAL_ZERO,
                gid: GNU_OCTAL_ZERO,
                device_major: GNU_OCTAL_ZERO,
                device_minor: GNU_OCTAL_ZERO,
                ..TestMetadata::default()
            },
        );

        let nul = inspect_archive_entries(&nul, package, "0.4.0", &commit).unwrap();
        let octal = inspect_archive_entries(&octal, package, "0.4.0", &commit).unwrap();
        assert_ne!(nul, octal);
    }

    #[test]
    fn special_archive_entry_types_are_rejected() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let path = format!("{}-0.4.0/.cargo_vcs_info.json", package.package);
        for entry_type in *b"1234567xgLKSV" {
            let bytes = archive_with_metadata(
                &path,
                vcs.as_bytes(),
                TestMetadata {
                    entry_type,
                    ..TestMetadata::default()
                },
            );
            assert!(inspect_archive(&bytes, package, "0.4.0", &commit).is_err());
        }
    }

    #[test]
    fn second_gzip_member_and_trailing_bytes_are_rejected() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let root = format!("{}-0.4.0", package.package);
        let archive = archive(&format!("{root}/.cargo_vcs_info.json"), vcs.as_bytes());

        let mut second_member = archive.clone();
        second_member.extend_from_slice(&archive);
        assert!(inspect_archive(&second_member, package, "0.4.0", &commit).is_err());

        let mut trailing = archive;
        trailing.extend_from_slice(b"trailing");
        assert!(inspect_archive(&trailing, package, "0.4.0", &commit).is_err());
    }

    #[test]
    fn post_terminator_tar_record_is_rejected() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let root = format!("{}-0.4.0", package.package);
        let archive = archive(&format!("{root}/.cargo_vcs_info.json"), vcs.as_bytes());
        let mut tar = decompress_single_gzip(&archive, package.package, 1024 * 1024).unwrap();
        let mut record = [0u8; TAR_BLOCK_BYTES];
        record[0] = b'x';
        tar.extend_from_slice(&record);
        let altered = recompress(&tar);

        assert!(inspect_archive(&altered, package, "0.4.0", &commit).is_err());
    }

    #[test]
    fn inventory_encoding_matches_the_cross_language_vector() {
        let files = BTreeMap::from([(
            "file".to_string(),
            ArchiveFile {
                body: b"body".to_vec(),
                metadata: ArchiveMetadata {
                    header_sha256: "a".repeat(64),
                    entry_type: b'0',
                    mode: 0o644,
                    uid: GNU_OCTAL_ZERO.to_vec(),
                    gid: GNU_OCTAL_ZERO.to_vec(),
                    mtime: CARGO_ARCHIVE_MTIME,
                    username: Vec::new(),
                    groupname: Vec::new(),
                    device_major: GNU_OCTAL_ZERO.to_vec(),
                    device_minor: GNU_OCTAL_ZERO.to_vec(),
                },
            },
        )]);
        assert_eq!(
            archive_inventory_sha256(&files),
            "3c31e83038d128e6babaf8adcbcda975c18db383b6999a097d7a30c3f3a87a0d"
        );
    }

    #[test]
    fn compressed_archive_expansion_within_stream_limit_is_accepted() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let root = format!("{}-0.4.0", package.package);
        let vcs_path = format!("{root}/.cargo_vcs_info.json");
        let payload_path = format!("{root}/compressible.bin");
        let payload = vec![b'a'; 64 * 1024];
        let bytes = archive_with_files(&[
            (vcs_path.as_str(), vcs.as_bytes()),
            (payload_path.as_str(), payload.as_slice()),
        ]);

        assert!(bytes.len() < payload.len());
        let files =
            inspect_archive_with_limit(&bytes, package, "0.4.0", &commit, 80 * 1024).unwrap();
        assert_eq!(files["compressible.bin"], payload);
    }

    #[test]
    fn oversized_hidden_gnu_metadata_exceeds_stream_limit() {
        let package = &crate::release_policy::TRAITS_POLICY.packages[0];
        let commit = "a".repeat(40);
        let vcs = format!("{{\"git\":{{\"sha1\":\"{commit}\"}},\"path_in_vcs\":\"\"}}");
        let root = format!("{}-0.4.0", package.package);
        let vcs_path = format!("{root}/.cargo_vcs_info.json");
        let long_path = format!("{root}/{}", "a".repeat(8 * 1024));
        let bytes = archive_with_files(&[
            (vcs_path.as_str(), vcs.as_bytes()),
            (long_path.as_str(), &[]),
        ]);

        assert!(bytes.len() < 2 * 1024);
        let error =
            inspect_archive_with_limit(&bytes, package, "0.4.0", &commit, 2 * 1024).unwrap_err();
        assert!(error.contains("expands beyond its limit"));
    }

    #[test]
    fn checksum_validation_is_lowercase_and_exact() {
        assert!(is_checksum(&"a".repeat(64)));
        assert!(!is_checksum(&"A".repeat(64)));
    }
}

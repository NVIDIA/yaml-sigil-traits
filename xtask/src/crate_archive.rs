// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded crates.io reads and exact Cargo source-archive inspection.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::release_policy::PackagePolicy;

pub(crate) const MAX_CRATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_CRATE_FILES: usize = 10_000;
const MAX_CRATE_UNPACKED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CRATE_DECOMPRESSED_BYTES: u64 = 160 * 1024 * 1024;
const READ_ATTEMPTS: usize = 3;
const USER_AGENT: &str = "yaml-sigil-release-workflow/1.0";

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

pub(crate) struct CratesIo;

impl CratesIo {
    pub(crate) fn new() -> Self {
        Self
    }

    fn request_json(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("https://crates.io/api/v1{path}");
        let mut last = None;
        for attempt in 1..=READ_ATTEMPTS {
            let output = Command::new("curl")
                .args([
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
                ])
                .output()
                .map_err(|error| format!("run crates.io request: {error}"))?;
            if output.stdout.len() > MAX_JSON_BYTES || output.stderr.len() > MAX_ERROR_BYTES {
                return Err("crates.io response exceeded its bound".to_string());
            }
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
            let output = Command::new("curl")
                .args([
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
                ])
                .output()
                .map_err(|error| format!("run crates.io archive download: {error}"))?;
            if output.stdout.len() > MAX_CRATE_BYTES || output.stderr.len() > MAX_ERROR_BYTES {
                return Err("crates.io archive response exceeded its bound".to_string());
            }
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
) -> Result<(String, BTreeMap<String, Vec<u8>>), String> {
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
    let files = inspect_archive(&archive, policy, version, commit)?;
    Ok((record.checksum, files))
}

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

fn inspect_archive_with_limit(
    archive: &[u8],
    policy: &PackagePolicy,
    version: &str,
    commit: &str,
    decompressed_limit: u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    if archive.is_empty() || archive.len() > MAX_CRATE_BYTES {
        return Err(format!(
            "{} source archive is empty or oversized",
            policy.package
        ));
    }
    let prefix = format!("{}-{version}", policy.package);
    let decoder = GzDecoder::new(Cursor::new(archive));
    let stream_limit = decompressed_limit + 1;
    let mut package = tar::Archive::new(decoder.take(stream_limit));
    let inspection = (|| {
        let entries = package
            .entries()
            .map_err(|error| format!("{} source archive is invalid: {error}", policy.package))?;
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
            let raw_path = std::str::from_utf8(&raw_path)
                .map_err(|_| format!("{} source archive has a non-UTF-8 path", policy.package))?
                .to_string();
            let directory = entry.header().entry_type().is_dir();
            let path = raw_path.strip_suffix('/').unwrap_or(&raw_path);
            validate_archive_path(path, &prefix, policy.package)?;
            if directory {
                continue;
            }
            if !entry.header().entry_type().is_file() {
                return Err(format!(
                    "{} source archive contains a non-file entry",
                    policy.package
                ));
            }
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
            if body.len() as u64 != size || files.insert(relative.to_string(), body).is_some() {
                return Err(format!(
                    "{} source archive contains a duplicate or truncated file",
                    policy.package
                ));
            }
        }
        if count == 0 {
            return Err(format!("{} source archive is empty", policy.package));
        }
        require_vcs_info(&files, policy, commit)?;
        Ok(files)
    })();

    let mut stream = package.into_inner();
    let drain = std::io::copy(&mut stream, &mut std::io::sink());
    if stream_limit - stream.limit() > decompressed_limit {
        return Err(format!(
            "{} source archive expands beyond its limit",
            policy.package
        ));
    }
    drain.map_err(|error| {
        format!(
            "{} source archive decompressed stream is unreadable: {error}",
            policy.package
        )
    })?;
    inspection
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

fn require_vcs_info(
    files: &BTreeMap<String, Vec<u8>>,
    policy: &PackagePolicy,
    commit: &str,
) -> Result<(), String> {
    let body = files.get(".cargo_vcs_info.json").ok_or_else(|| {
        format!(
            "{} source archive lacks .cargo_vcs_info.json",
            policy.package
        )
    })?;
    let vcs: VcsInfo = serde_json::from_slice(body).map_err(|error| {
        format!(
            "{} source archive has invalid VCS metadata: {error}",
            policy.package
        )
    })?;
    if vcs.git.sha1 != commit || vcs.git.dirty || vcs.path_in_vcs != policy.path_in_vcs {
        return Err(format!(
            "{} source archive is not bound to the exact clean release commit",
            policy.package
        ));
    }
    Ok(())
}

pub(crate) fn is_checksum(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn require_clean_source(root: &Path, commit: &str) -> Result<(), String> {
    let head = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("read release source commit: {error}"))?;
    if head.stdout.len() > MAX_ERROR_BYTES
        || head.stderr.len() > MAX_ERROR_BYTES
        || !head.status.success()
        || String::from_utf8_lossy(&head.stdout).trim() != commit
    {
        return Err("release source is not at the expected commit".to_string());
    }
    let status = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|error| format!("read release source status: {error}"))?;
    if status.stdout.len() > MAX_JSON_BYTES
        || status.stderr.len() > MAX_ERROR_BYTES
        || !status.status.success()
        || !status.stdout.is_empty()
    {
        return Err("release source is not a clean checkout".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn archive_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(body.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, *body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn archive(path: &str, vcs: &[u8]) -> Vec<u8> {
        archive_with_files(&[(path, vcs)])
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

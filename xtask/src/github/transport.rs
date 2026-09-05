// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Injected, bounded transport around the GitHub CLI.

use std::process::Command;
use std::thread;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::bounded_process::{self, OutputLimits};

pub(crate) const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_ERROR_BYTES: usize = 64 * 1024;
const READ_ATTEMPTS: usize = 3;
pub(crate) const GITHUB_API_VERSION: &str = "2026-03-10";
const GITHUB_JSON_MEDIA_TYPE: &str = "application/vnd.github+json";

pub(crate) trait Transport {
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String>;
    fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String>;
    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, _payload: &P) -> Result<T, String> {
        Err("unexpected GitHub GraphQL read".to_string())
    }
    fn mutate<T: DeserializeOwned, P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<T, String>;
}

pub(crate) struct GhCli;

impl GhCli {
    pub(crate) fn new() -> Result<Self, String> {
        let mut command = Command::new("gh");
        command.args(["--version"]);
        let output = bounded_process::output(
            &mut command,
            OutputLimits {
                stdout: MAX_ERROR_BYTES,
                stderr: MAX_ERROR_BYTES,
            },
        )
        .map_err(|error| format!("run gh: {error}"))?;
        if !output.status.success() {
            return Err("gh is unavailable".to_string());
        }
        Ok(Self)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        payload: Option<&[u8]>,
        read: bool,
    ) -> Result<Vec<u8>, RequestError> {
        if !matches!(method, "GET" | "POST") || path.is_empty() || path.contains(['\0', '\r', '\n'])
        {
            return Err(RequestError::Permanent(
                "invalid GitHub request".to_string(),
            ));
        }
        let attempts = if read { READ_ATTEMPTS } else { 1 };
        let mut last = None;
        for attempt in 1..=attempts {
            let mut command = Command::new("gh");
            command.args([
                "api",
                "--method",
                method,
                "--header",
                &format!("Accept: {GITHUB_JSON_MEDIA_TYPE}"),
                "--header",
                &format!("X-GitHub-Api-Version: {GITHUB_API_VERSION}"),
                path,
            ]);
            if payload.is_some() {
                command.args(["--input", "-"]);
            }
            let limits = OutputLimits {
                stdout: MAX_RESPONSE_BYTES,
                stderr: MAX_ERROR_BYTES,
            };
            let output = match payload {
                Some(body) => bounded_process::output_with_input(&mut command, body, limits),
                None => bounded_process::output(&mut command, limits),
            }
            .map_err(|error| RequestError::Permanent(format!("run gh api: {error}")))?;
            if output.status.success() {
                return Ok(output.stdout);
            }
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let error = if is_not_found(&detail) {
                RequestError::NotFound
            } else if read && is_transient(&detail) {
                RequestError::Transient(redacted_error(method, path, &detail))
            } else {
                RequestError::Permanent(redacted_error(method, path, &detail))
            };
            if !matches!(error, RequestError::Transient(_)) || attempt == attempts {
                return Err(error);
            }
            last = Some(error);
            thread::sleep(Duration::from_secs(attempt as u64));
        }
        Err(last.unwrap_or_else(|| RequestError::Permanent("GitHub request failed".to_string())))
    }

    fn decode<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<T, String> {
        serde_json::from_slice(body)
            .map_err(|error| format!("{method} {path} returned invalid JSON: {error}"))
    }
}

impl Transport for GhCli {
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
        let body = self
            .request("GET", path, None, true)
            .map_err(RequestError::message)?;
        self.decode("GET", path, &body)
    }

    fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String> {
        match self.request("GET", path, None, true) {
            Ok(body) => self.decode("GET", path, &body).map(Some),
            Err(RequestError::NotFound) => Ok(None),
            Err(error) => Err(error.message()),
        }
    }

    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("serialize GitHub GraphQL request: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("GitHub GraphQL request exceeded its bound".to_string());
        }
        let response = self
            .request("POST", "graphql", Some(&body), true)
            .map_err(RequestError::message)?;
        self.decode("POST", "graphql", &response)
    }

    fn mutate<T: DeserializeOwned, P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<T, String> {
        if method != "POST" {
            return Err("GitHub mutation method is unsupported".to_string());
        }
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("serialize GitHub request: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("GitHub request exceeded its bound".to_string());
        }
        let response = self
            .request(method, path, Some(&body), false)
            .map_err(RequestError::message)?;
        self.decode(method, path, &response)
    }
}

#[derive(Debug)]
enum RequestError {
    NotFound,
    Transient(String),
    Permanent(String),
}

impl RequestError {
    fn message(self) -> String {
        match self {
            Self::NotFound => "GitHub object was not found".to_string(),
            Self::Transient(message) | Self::Permanent(message) => message,
        }
    }
}

fn redacted_error(method: &str, path: &str, detail: &str) -> String {
    let detail = detail.lines().next().unwrap_or("request failed");
    let detail: String = detail.chars().take(512).collect();
    format!("{method} {path} failed: {detail}")
}

fn is_not_found(detail: &str) -> bool {
    detail.contains("HTTP 404") || detail.contains("(HTTP 404)")
}

fn is_transient(detail: &str) -> bool {
    [
        "HTTP 429",
        "HTTP 502",
        "HTTP 503",
        "HTTP 504",
        "timeout",
        "timed out",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
}

pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_values_are_percent_encoded() {
        assert_eq!(percent_encode("owner:release/plz"), "owner%3Arelease%2Fplz");
    }

    #[test]
    fn retry_classification_is_narrow() {
        assert!(is_transient("gh: unavailable (HTTP 503)"));
        assert!(!is_transient("gh: forbidden (HTTP 403)"));
        assert!(is_not_found("gh: Not Found (HTTP 404)"));
    }
}

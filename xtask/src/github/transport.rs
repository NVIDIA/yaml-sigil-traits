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
const MAX_PAGES: usize = 20;
const PAGE_SIZE: usize = 100;
const READ_ATTEMPTS: usize = 3;
const GITHUB_API_VERSION: &str = "2026-03-10";
const GITHUB_JSON_MEDIA_TYPE: &str = "application/vnd.github+json";

pub(crate) trait Transport {
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String>;
    fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String>;
    fn paginate<T: DeserializeOwned>(&mut self, path: &str) -> Result<Vec<T>, String>;
    fn mutate<T: DeserializeOwned, P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<T, String>;
    fn mutate_empty<P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<(), String>;
    fn delete(&mut self, path: &str) -> Result<(), String>;
    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String>;
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
        if !matches!(method, "GET" | "POST" | "PATCH" | "DELETE")
            || path.is_empty()
            || path.contains(['\0', '\r', '\n'])
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

    fn paginate<T: DeserializeOwned>(&mut self, path: &str) -> Result<Vec<T>, String> {
        collect_pages(|page| {
            let separator = if path.contains('?') { '&' } else { '?' };
            let page_path = format!("{path}{separator}per_page={PAGE_SIZE}&page={page}");
            let body = self
                .request("GET", &page_path, None, true)
                .map_err(RequestError::message)?;
            self.decode("GET", &page_path, &body)
        })
    }

    fn mutate<T: DeserializeOwned, P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<T, String> {
        if !matches!(method, "POST" | "PATCH") {
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

    fn mutate_empty<P: Serialize>(
        &mut self,
        method: &str,
        path: &str,
        payload: &P,
    ) -> Result<(), String> {
        if method != "POST" {
            return Err("GitHub no-content mutation method is unsupported".to_string());
        }
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("serialize GitHub request: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("GitHub request exceeded its bound".to_string());
        }
        let response = self
            .request(method, path, Some(&body), false)
            .map_err(RequestError::message)?;
        if !response.is_empty() {
            return Err(format!("{method} {path} unexpectedly returned a body"));
        }
        Ok(())
    }

    fn delete(&mut self, path: &str) -> Result<(), String> {
        self.request("DELETE", path, None, false)
            .map(|_| ())
            .map_err(RequestError::message)
    }

    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("serialize GraphQL request: {error}"))?;
        let response = self
            .request("POST", "graphql", Some(&body), false)
            .map_err(RequestError::message)?;
        self.decode("POST", "graphql", &response)
    }
}

fn collect_pages<T>(
    mut fetch: impl FnMut(usize) -> Result<Vec<T>, String>,
) -> Result<Vec<T>, String> {
    let mut values = Vec::new();
    for page in 1..=MAX_PAGES {
        let page_values = fetch(page)?;
        if page_values.len() > PAGE_SIZE {
            return Err("GitHub returned an oversized page".to_string());
        }
        let complete = page_values.len() < PAGE_SIZE;
        values.extend(page_values);
        if complete {
            return Ok(values);
        }
    }
    Err("GitHub pagination exceeded its bound".to_string())
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

    #[test]
    fn fake_pagination_is_complete_and_bounded() {
        let mut pages = vec![vec![1_u8; PAGE_SIZE], vec![2_u8]].into_iter();
        let values = collect_pages(|_| Ok(pages.next().expect("expected fake page"))).unwrap();
        assert_eq!(values.len(), PAGE_SIZE + 1);
        assert_eq!(values[PAGE_SIZE], 2);

        assert!(collect_pages::<u8>(|_| Ok(vec![0; PAGE_SIZE + 1])).is_err());
        assert!(collect_pages::<u8>(|_| Ok(vec![0; PAGE_SIZE])).is_err());
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::VecDeque;

    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    use super::Transport;

    #[derive(Debug)]
    pub(crate) struct Expected {
        operation: String,
        path: String,
        payload: Option<Value>,
        result: Result<Option<Value>, String>,
    }

    impl Expected {
        pub(crate) fn json(operation: &str, path: &str, value: Value) -> Self {
            Self {
                operation: operation.to_string(),
                path: path.to_string(),
                payload: None,
                result: Ok(Some(value)),
            }
        }

        pub(crate) fn mutation(
            operation: &str,
            path: &str,
            payload: Value,
            result: Result<Value, &str>,
        ) -> Self {
            Self {
                operation: operation.to_string(),
                path: path.to_string(),
                payload: Some(payload),
                result: result.map(Some).map_err(str::to_string),
            }
        }

        pub(crate) fn missing(path: &str) -> Self {
            Self {
                operation: "OPTIONAL".to_string(),
                path: path.to_string(),
                payload: None,
                result: Ok(None),
            }
        }

        pub(crate) fn optional(path: &str, value: Value) -> Self {
            Self {
                operation: "OPTIONAL".to_string(),
                path: path.to_string(),
                payload: None,
                result: Ok(Some(value)),
            }
        }
    }

    pub(crate) struct FakeTransport {
        expected: VecDeque<Expected>,
    }

    impl FakeTransport {
        pub(crate) fn new(expected: impl IntoIterator<Item = Expected>) -> Self {
            Self {
                expected: expected.into_iter().collect(),
            }
        }

        pub(crate) fn finish(self) {
            assert!(
                self.expected.is_empty(),
                "unused fake GitHub calls: {:?}",
                self.expected
            );
        }

        fn call(
            &mut self,
            operation: &str,
            path: &str,
            payload: Option<Value>,
        ) -> Result<Option<Value>, String> {
            let expected = self
                .expected
                .pop_front()
                .ok_or_else(|| format!("unexpected {operation} {path}"))?;
            if expected.operation != operation
                || expected.path != path
                || expected.payload != payload
            {
                return Err(format!(
                    "expected {} {} {:?}; got {operation} {path} {:?}",
                    expected.operation, expected.path, expected.payload, payload
                ));
            }
            expected.result
        }

        fn decode<T: DeserializeOwned>(
            value: Option<Value>,
            operation: &str,
            path: &str,
        ) -> Result<T, String> {
            let value = value.ok_or_else(|| format!("{operation} {path} unexpectedly missing"))?;
            serde_json::from_value(value)
                .map_err(|error| format!("decode fake {operation} {path}: {error}"))
        }
    }

    impl Transport for FakeTransport {
        fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            let value = self.call("GET", path, None)?;
            Self::decode(value, "GET", path)
        }

        fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String> {
            self.call("OPTIONAL", path, None)?
                .map(|value| {
                    serde_json::from_value(value)
                        .map_err(|error| format!("decode fake OPTIONAL {path}: {error}"))
                })
                .transpose()
        }

        fn paginate<T: DeserializeOwned>(&mut self, path: &str) -> Result<Vec<T>, String> {
            let value = self.call("PAGINATE", path, None)?;
            Self::decode(value, "PAGINATE", path)
        }

        fn mutate<T: DeserializeOwned, P: Serialize>(
            &mut self,
            method: &str,
            path: &str,
            payload: &P,
        ) -> Result<T, String> {
            let payload = serde_json::to_value(payload)
                .map_err(|error| format!("serialize fake mutation: {error}"))?;
            let value = self.call(method, path, Some(payload))?;
            Self::decode(value, method, path)
        }

        fn mutate_empty<P: Serialize>(
            &mut self,
            method: &str,
            path: &str,
            payload: &P,
        ) -> Result<(), String> {
            let payload = serde_json::to_value(payload)
                .map_err(|error| format!("serialize fake mutation: {error}"))?;
            self.call(method, path, Some(payload)).map(|_| ())
        }

        fn delete(&mut self, path: &str) -> Result<(), String> {
            self.call("DELETE", path, None).map(|_| ())
        }

        fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String> {
            let payload = serde_json::to_value(payload)
                .map_err(|error| format!("serialize fake GraphQL mutation: {error}"))?;
            let value = self.call("GRAPHQL", "graphql", Some(payload))?;
            Self::decode(value, "GRAPHQL", "graphql")
        }
    }
}

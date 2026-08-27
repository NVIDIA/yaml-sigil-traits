// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Configure a token-derived repository-local Git identity.

use std::env;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::github::models::Signature;
use crate::github::transport::Transport;
use crate::github::{git_line, git_output, repository_policy_for_root, workflow_repository};

pub(super) fn configure_command(
    root: &Path,
    repository: Option<&str>,
    github: &mut impl Transport,
) -> Result<(), String> {
    match env::var_os("GITHUB_ACTIONS") {
        None => {
            let repository = local_repository_argument(repository)?;
            repository_policy_for_root(root, repository)?;
        }
        Some(value) if value == "true" => {
            if repository.is_some() {
                return Err(
                    "hosted git-identity configure does not accept repository arguments"
                        .to_string(),
                );
            }
            workflow_repository(root)?;
        }
        Some(_) => return Err("GITHUB_ACTIONS has an unexpected value".to_string()),
    }
    configure(root, github)
}

fn local_repository_argument(repository: Option<&str>) -> Result<&str, String> {
    repository
        .filter(|repository| !repository.is_empty())
        .ok_or_else(|| "local git-identity configure requires --repository".to_string())
}

fn configure(root: &Path, github: &mut impl Transport) -> Result<(), String> {
    let identity = token_signature(github)?;
    git_output(root, &["config", "--local", "user.name", &identity.name])?;
    git_output(root, &["config", "--local", "user.email", &identity.email])?;
    if git_line(root, &["config", "--local", "user.name"])? != identity.name
        || git_line(root, &["config", "--local", "user.email"])? != identity.email
    {
        return Err("the release Git identity did not persist locally".to_string());
    }
    eprintln!("github: configured the token-derived local Git identity");
    Ok(())
}

pub(super) fn token_signature(github: &mut impl Transport) -> Result<Signature, String> {
    let response: ViewerResponse = github.graphql(&json!({
        "query": "query { viewer { name login databaseId } }",
    }))?;
    if response.errors.is_some() {
        return Err("GitHub returned errors for the workflow-token identity".to_string());
    }
    let viewer = response
        .data
        .and_then(|data| data.viewer)
        .ok_or_else(|| "GitHub returned no workflow-token identity".to_string())?;
    if !valid_login(&viewer.login) || viewer.id == 0 {
        return Err("GitHub did not return a valid workflow-token identity".to_string());
    }
    let name = viewer
        .name
        .as_deref()
        .filter(|name| valid_name(name))
        .unwrap_or(&viewer.login)
        .to_string();
    let email = format!("{}+{}@users.noreply.github.com", viewer.id, viewer.login);
    Ok(Signature { name, email })
}

#[derive(Debug, Deserialize)]
struct ViewerResponse {
    #[serde(default)]
    data: Option<ViewerData>,
    #[serde(default)]
    errors: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ViewerData {
    #[serde(default)]
    viewer: Option<Viewer>,
}

#[derive(Debug, Deserialize)]
struct Viewer {
    login: String,
    #[serde(rename = "databaseId")]
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

fn valid_login(value: &str) -> bool {
    let base = value.strip_suffix("[bot]").unwrap_or(value);
    !base.is_empty()
        && base.len() <= 100
        && base
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.contains(['\0', '\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::consts::{RUST_REPOSITORY, TRAITS_REPOSITORY};
    use crate::github::{APP_ID, APP_LOGIN};

    #[test]
    fn workflow_logins_and_names_are_bounded() {
        assert!(valid_login("github-actions[bot]"));
        assert!(valid_login("release-bot"));
        assert!(!valid_login("bad/name"));
        assert!(valid_name("GitHub Actions"));
        assert!(!valid_name("bad\nname"));
    }

    #[test]
    fn local_identity_requires_one_explicit_repository() {
        assert!(local_repository_argument(None).is_err());
        assert_eq!(
            local_repository_argument(Some(TRAITS_REPOSITORY)).unwrap(),
            TRAITS_REPOSITORY
        );
        assert_eq!(
            local_repository_argument(Some(RUST_REPOSITORY)).unwrap(),
            RUST_REPOSITORY
        );
        assert!(local_repository_argument(Some("")).is_err());
    }

    #[test]
    fn viewer_identity_uses_the_graphql_database_id() {
        let response: ViewerResponse = serde_json::from_value(json!({
            "data": {
                "viewer": {
                    "login": APP_LOGIN,
                    "databaseId": APP_ID,
                    "name": null,
                }
            }
        }))
        .unwrap();
        let viewer = response.data.unwrap().viewer.unwrap();
        assert_eq!(viewer.login, APP_LOGIN);
        assert_eq!(viewer.id, APP_ID);
        assert!(viewer.name.is_none());
    }
}

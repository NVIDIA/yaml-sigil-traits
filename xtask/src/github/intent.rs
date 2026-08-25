// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Resolve one exact App-owned release proposal and explicit release intent.

use std::path::Path;

use crate::github::models::PullRequest;
use crate::github::transport::{Transport, percent_encode};
use crate::github::{
    APP_ID, APP_LOGIN, RELEASE_BRANCH, append_outputs, env_bool, env_required, workflow_repository,
};

pub(super) fn resolve(root: &Path, github: &mut impl Transport) -> Result<(), String> {
    let repository = workflow_repository(root)?.full_name.to_string();
    let manual = env_bool("MANUAL_DISPATCH")?;
    let requested_mode = env_required("REQUESTED_MODE")?;
    let requested_bump = env_required("REQUESTED_BUMP")?;
    if !matches!(requested_mode.as_str(), "next-candidate" | "promote-stable") {
        return Err("REQUESTED_MODE must be next-candidate or promote-stable".to_string());
    }
    if !matches!(requested_bump.as_str(), "patch" | "minor" | "major") {
        return Err("REQUESTED_BUMP must be patch, minor, or major".to_string());
    }

    let owner = repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .ok_or_else(|| "repository lacks an owner".to_string())?;
    let head = percent_encode(&format!("{owner}:{RELEASE_BRANCH}"));
    let pulls: Vec<PullRequest> =
        github.paginate(&format!("repos/{repository}/pulls?state=open&head={head}"))?;
    if pulls.len() > 1 || pulls.iter().any(|pull| !exact_app_pull(pull, &repository)) {
        return Err(
            "the existing release proposal lookup is ambiguous or unauthorized".to_string(),
        );
    }

    let mut proceed = true;
    let mode = requested_mode;
    let mut bump = requested_bump;
    if !manual {
        if mode != "next-candidate" || bump != "patch" {
            return Err(
                "background release proposals must use next-candidate patch mode".to_string(),
            );
        }
        if pulls.len() == 1 {
            proceed = false;
            eprintln!(
                "github: an exact App-owned proposal already exists; no background update is needed"
            );
        }
    } else if mode == "promote-stable" {
        bump = "patch".to_string();
    }

    append_outputs(&[
        ("proceed", if proceed { "true" } else { "false" }),
        ("mode", &mode),
        ("bump", &bump),
    ])
}

fn exact_app_pull(pull: &PullRequest, repository: &str) -> bool {
    pull.state == "open"
        && pull.user.login == APP_LOGIN
        && pull.user.id == APP_ID
        && pull.head.branch == RELEASE_BRANCH
        && pull.head.repo.full_name == repository
        && pull.base.branch == "main"
        && pull.base.repo.full_name == repository
        && pull.number > 0
        && !pull.node_id.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::consts::TRAITS_REPOSITORY;
    use crate::github::models::{PullRef, Repository, User};

    fn pull() -> PullRequest {
        PullRequest {
            number: 28,
            state: "open".to_string(),
            user: User {
                login: APP_LOGIN.to_string(),
                id: APP_ID,
                name: None,
            },
            head: PullRef {
                branch: RELEASE_BRANCH.to_string(),
                sha: "a".repeat(40),
                repo: Repository {
                    full_name: TRAITS_REPOSITORY.to_string(),
                },
            },
            base: PullRef {
                branch: "main".to_string(),
                sha: "b".repeat(40),
                repo: Repository {
                    full_name: TRAITS_REPOSITORY.to_string(),
                },
            },
            commits: 1,
            node_id: "PR_node".to_string(),
            draft: true,
            title: String::new(),
            body: None,
            merged_at: None,
            merge_commit_sha: None,
            merged_by: None,
        }
    }

    #[test]
    fn app_pull_is_bound_to_immutable_identity_and_repository() {
        let mut value = pull();
        assert!(exact_app_pull(&value, TRAITS_REPOSITORY));
        value.user.id += 1;
        assert!(!exact_app_pull(&value, TRAITS_REPOSITORY));
    }
}

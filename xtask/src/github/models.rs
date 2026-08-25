// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Minimal typed GitHub response models used by release automation.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct User {
    pub(crate) login: String,
    pub(crate) id: u64,
    #[serde(default)]
    pub(crate) name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Repository {
    pub(crate) full_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct PullRef {
    #[serde(rename = "ref")]
    pub(crate) branch: String,
    pub(crate) sha: String,
    pub(crate) repo: Repository,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct PullRequest {
    pub(crate) number: u64,
    pub(crate) state: String,
    pub(crate) user: User,
    pub(crate) head: PullRef,
    pub(crate) base: PullRef,
    #[serde(default)]
    pub(crate) commits: u64,
    pub(crate) node_id: String,
    pub(crate) draft: bool,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) body: Option<String>,
    #[serde(default)]
    pub(crate) merged_at: Option<String>,
    #[serde(default)]
    pub(crate) merge_commit_sha: Option<String>,
    #[serde(default)]
    pub(crate) merged_by: Option<User>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct GitObject {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct GitRef {
    #[serde(rename = "ref")]
    pub(crate) name: String,
    pub(crate) object: GitObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Signature {
    pub(crate) name: String,
    pub(crate) email: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Verification {
    pub(crate) verified: bool,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct TreeIdentity {
    pub(crate) sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Parent {
    pub(crate) sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct RawCommit {
    pub(crate) author: Signature,
    pub(crate) committer: Signature,
    pub(crate) message: String,
    pub(crate) verification: Verification,
    pub(crate) tree: TreeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct RepositoryCommit {
    pub(crate) sha: String,
    pub(crate) author: Option<User>,
    pub(crate) committer: Option<User>,
    pub(crate) commit: RawCommit,
    pub(crate) parents: Vec<Parent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct CreatedCommit {
    pub(crate) sha: String,
    pub(crate) author: Signature,
    pub(crate) committer: Signature,
    pub(crate) message: String,
    pub(crate) verification: Verification,
    pub(crate) tree: TreeIdentity,
    pub(crate) parents: Vec<Parent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct CommitSummary {
    pub(crate) sha: String,
    #[serde(default)]
    pub(crate) author: Option<User>,
    #[serde(default)]
    pub(crate) committer: Option<User>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Compare {
    pub(crate) ahead_by: u64,
    pub(crate) commits: Vec<CommitSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct TreeEntry {
    pub(crate) path: String,
    pub(crate) mode: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Tree {
    pub(crate) sha: String,
    pub(crate) truncated: bool,
    pub(crate) tree: Vec<TreeEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Permission {
    pub(crate) permission: String,
    pub(crate) user: User,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::consts::TRAITS_REPOSITORY;
    use serde_json::json;

    #[test]
    fn pull_list_shape_does_not_require_detail_only_fields() {
        let value = json!({
            "number": 28,
            "state": "open",
            "user": {"login": "release-bot", "id": 1},
            "head": {
                "ref": "release-plz-next",
                "sha": "a".repeat(40),
                "repo": {"full_name": TRAITS_REPOSITORY}
            },
            "base": {
                "ref": "main",
                "sha": "b".repeat(40),
                "repo": {"full_name": TRAITS_REPOSITORY}
            },
            "node_id": "PR_node",
            "draft": true
        });
        let pull: PullRequest = serde_json::from_value(value).unwrap();
        assert_eq!(pull.commits, 0);
        assert!(pull.merged_by.is_none());
    }
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Authorize publication from immutable commits and exact Git trees.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use semver::Version;
use toml_edit::DocumentMut;

use crate::github::consts::{RepositoryKind, repository_policy};
use crate::github::models::{
    CommitSummary, Permission, PullRequest, RepositoryCommit, Tree, TreeEntry, User,
};
use crate::github::release_pr::require_repository_app_commit;
use crate::github::transport::{Transport, percent_encode};
use crate::github::{
    APP_EMAIL, APP_ID, APP_LOGIN, RELEASE_BRANCH, WEB_FLOW_EMAIL, WEB_FLOW_ID, WEB_FLOW_LOGIN,
    WEB_FLOW_NAME, git_line, is_sha, repository_policy_for_root, require_captured_ancestry,
};
use crate::safe_file;

const MAX_MANUAL_COMMITS: usize = 100;
const WRITER_PERMISSIONS: &[&str] = &["admin", "maintain", "write"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MainRequirement {
    Exact,
    Ancestry,
}

pub(super) fn authorize_command(
    root: &Path,
    repository: &str,
    commit: &str,
    baseline_version: &str,
    baseline_commit: &str,
    github: &mut impl Transport,
) -> Result<(), String> {
    let authorization = authorize_source(
        github,
        repository,
        commit,
        root,
        baseline_version,
        baseline_commit,
        MainRequirement::Ancestry,
    )?;
    eprintln!(
        "github: authorized exact merged release proposal PR #{}",
        authorization.pull_request
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SourceAuthorization {
    pub(super) pull_request: u64,
    pub(super) proposal_commit: String,
    pub(super) base_commit: String,
    pub(super) owner_id: u64,
    pub(super) merger_id: u64,
}

pub(super) fn authorize_source(
    github: &mut impl Transport,
    repository: &str,
    commit: &str,
    root: &Path,
    baseline_version: &str,
    baseline_commit: &str,
    main_requirement: MainRequirement,
) -> Result<SourceAuthorization, String> {
    if !is_sha(commit) || !is_sha(baseline_commit) {
        return Err("repository or release commit is unsupported".to_string());
    }
    repository_policy_for_root(root, repository)?;
    let baseline = release_version(baseline_version)?;
    if git_line(root, &["rev-parse", "HEAD"])? != commit {
        return Err("checkout does not identify the release commit".to_string());
    }
    require_main_position(github, repository, commit, main_requirement)?;
    let current = manifest_release_version(root, repository)?;
    let stable_promotion = is_stable_promotion(&baseline, &current);
    let manual_branch = format!("release-plz-manual-{current}");

    let associated: Vec<PullRequest> =
        github.paginate(&format!("repos/{repository}/commits/{commit}/pulls"))?;
    let mut matches = Vec::new();
    for pull in associated {
        if exact_merged_association(&pull, repository, commit, &manual_branch) {
            matches.push(pull);
        }
    }
    if matches.len() != 1 {
        return Err("release commit lacks one exact merged proposal".to_string());
    }
    let association = matches.pop().expect("one association");
    let number = association.number;
    let pull: PullRequest = github.get(&format!("repos/{repository}/pulls/{number}"))?;
    require_unchanged_pull(&pull, &association, repository, commit)?;

    let merger = pull
        .merged_by
        .as_ref()
        .ok_or_else(|| "release pull request has no exact merger".to_string())?;
    require_writer(github, repository, merger, "release merger")?;
    let app_proposal = pull.head.branch == RELEASE_BRANCH
        && pull.user.login == APP_LOGIN
        && pull.user.id == APP_ID;
    let manual_proposal = pull.head.branch == manual_branch && pull.user.login != APP_LOGIN;
    if !app_proposal && !manual_proposal {
        return Err("release pull request ownership is invalid".to_string());
    }
    if manual_proposal {
        require_writer(github, repository, &pull.user, "release owner")?;
    }

    let summaries: Vec<CommitSummary> =
        github.paginate(&format!("repos/{repository}/pulls/{number}/commits"))?;
    if summaries.is_empty()
        || summaries.len() > MAX_MANUAL_COMMITS
        || summaries.len() != pull.commits as usize
        || (app_proposal && summaries.len() != 1)
    {
        return Err("release pull request has an invalid commit inventory".to_string());
    }
    if summaries.last().map(|summary| summary.sha.as_str()) != Some(&pull.head.sha) {
        return Err("release pull request head changed during authorization".to_string());
    }
    let base_sha = pull.base.sha.as_str();
    if !is_sha(base_sha) {
        return Err("release pull request base is invalid".to_string());
    }
    if stable_promotion && base_sha != baseline_commit {
        return Err("stable promotion base does not match the exact tagged RC commit".to_string());
    }

    let commits = fetch_commit_sequence(github, repository, &summaries)?;
    require_linear_sequence(&commits, base_sha)?;
    let proposal = commits.last().expect("nonempty commit sequence");
    if app_proposal {
        let bot = app_bot();
        require_repository_app_commit(proposal, &bot, Some(base_sha))?;
    } else {
        for proposal_commit in &commits {
            require_manual_commit(proposal_commit, &pull.user)?;
        }
    }

    let integrated: RepositoryCommit =
        github.get(&format!("repos/{repository}/commits/{commit}"))?;
    require_integrated_commit(&integrated, proposal, base_sha, &pull.user, app_proposal)?;
    let base: RepositoryCommit = github.get(&format!("repos/{repository}/commits/{base_sha}"))?;
    if base.sha != base_sha || !is_sha(&base.commit.tree.sha) {
        return Err("release base commit response is mismatched".to_string());
    }
    require_exact_tree_diff(
        github,
        repository,
        &base.commit.tree.sha,
        &proposal.commit.tree.sha,
    )?;

    // Re-read the mutable authorities immediately before granting publication.
    require_main_position(github, repository, commit, main_requirement)?;
    let final_pull: PullRequest = github.get(&format!("repos/{repository}/pulls/{number}"))?;
    require_unchanged_pull(&final_pull, &association, repository, commit)?;
    let final_merger = final_pull
        .merged_by
        .as_ref()
        .ok_or_else(|| "release pull request lost its merger".to_string())?;
    require_current_release_writers(
        github,
        repository,
        final_merger,
        manual_proposal.then_some(&final_pull.user),
    )?;
    Ok(SourceAuthorization {
        pull_request: number,
        proposal_commit: proposal.sha.clone(),
        base_commit: base_sha.to_string(),
        owner_id: pull.user.id,
        merger_id: final_merger.id,
    })
}

fn release_version(value: &str) -> Result<Version, String> {
    let version = Version::parse(value)
        .map_err(|error| format!("unsupported release version {value}: {error}"))?;
    if !version.build.is_empty() {
        return Err("release versions cannot contain build metadata".to_string());
    }
    if !version.pre.is_empty() {
        let Some(number) = version.pre.as_str().strip_prefix("rc.") else {
            return Err("release prereleases must use rc.N".to_string());
        };
        if number.parse::<u64>().ok().is_none_or(|number| number == 0) || number.starts_with('0') {
            return Err("release prereleases must use positive canonical rc.N".to_string());
        }
    }
    Ok(version)
}

fn manifest_release_version(root: &Path, repository: &str) -> Result<Version, String> {
    let body = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .map_err(|error| format!("read release manifest: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse release manifest: {error}"))?;
    let policy = repository_policy(repository)
        .ok_or_else(|| "release repository is unsupported".to_string())?;
    let value = if policy.kind == RepositoryKind::Traits {
        document
            .get("package")
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str)
    } else {
        document
            .get("workspace")
            .and_then(|item| item.get("package"))
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str)
    }
    .ok_or_else(|| "release source has no exact manifest version".to_string())?;
    release_version(value)
}

fn is_stable_promotion(baseline: &Version, current: &Version) -> bool {
    !baseline.pre.is_empty()
        && current.pre.is_empty()
        && baseline.major == current.major
        && baseline.minor == current.minor
        && baseline.patch == current.patch
}

fn exact_merged_association(
    pull: &PullRequest,
    repository: &str,
    commit: &str,
    manual_branch: &str,
) -> bool {
    let app = pull.head.branch == RELEASE_BRANCH
        && pull.user.login == APP_LOGIN
        && pull.user.id == APP_ID;
    let manual = pull.head.branch == manual_branch && pull.user.login != APP_LOGIN;
    pull.number > 0
        && pull.state == "closed"
        && pull
            .merged_at
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        && integrated_commit_matches(pull, commit)
        && (app || manual)
        && pull.head.repo.full_name == repository
        && pull.base.repo.full_name == repository
        && pull.base.branch == "main"
}

fn integrated_commit_matches(pull: &PullRequest, commit: &str) -> bool {
    match pull.merge_commit_sha.as_deref() {
        Some(merge_commit) => merge_commit == commit,
        None => pull.head.sha == commit,
    }
}

fn require_unchanged_pull(
    detailed: &PullRequest,
    associated: &PullRequest,
    repository: &str,
    commit: &str,
) -> Result<(), String> {
    if detailed.number != associated.number
        || detailed.state != "closed"
        || detailed.merged_at != associated.merged_at
        || !integrated_commit_matches(detailed, commit)
        || detailed.user != associated.user
        || detailed.head != associated.head
        || detailed.base != associated.base
        || detailed.head.repo.full_name != repository
        || detailed.base.repo.full_name != repository
        || detailed.base.branch != "main"
        || detailed.commits == 0
        || detailed.commits as usize > MAX_MANUAL_COMMITS
    {
        return Err("release pull request changed during authorization".to_string());
    }
    Ok(())
}

fn require_writer(
    github: &mut impl Transport,
    repository: &str,
    user: &User,
    label: &str,
) -> Result<(), String> {
    if user.login.is_empty() || user.id == 0 {
        return Err(format!("{label} has no immutable identity"));
    }
    let permission: Permission = github.get(&format!(
        "repos/{repository}/collaborators/{}/permission",
        percent_encode(&user.login)
    ))?;
    if !WRITER_PERMISSIONS.contains(&permission.permission.as_str())
        || permission.user.login != user.login
        || permission.user.id != user.id
    {
        return Err(format!("{label} lacks current write authority"));
    }
    Ok(())
}

fn require_current_release_writers(
    github: &mut impl Transport,
    repository: &str,
    merger: &User,
    manual_owner: Option<&User>,
) -> Result<(), String> {
    require_writer(github, repository, merger, "release merger")?;
    if let Some(owner) = manual_owner {
        require_writer(github, repository, owner, "release owner")?;
    }
    Ok(())
}

fn fetch_commit_sequence(
    github: &mut impl Transport,
    repository: &str,
    summaries: &[CommitSummary],
) -> Result<Vec<RepositoryCommit>, String> {
    let mut values = Vec::with_capacity(summaries.len());
    for summary in summaries {
        if !is_sha(&summary.sha) {
            return Err("release proposal commit summary is invalid".to_string());
        }
        let commit: RepositoryCommit =
            github.get(&format!("repos/{repository}/commits/{}", summary.sha))?;
        if commit.sha != summary.sha {
            return Err("release proposal commit response is mismatched".to_string());
        }
        values.push(commit);
    }
    Ok(values)
}

fn require_linear_sequence(commits: &[RepositoryCommit], base: &str) -> Result<(), String> {
    let mut expected_parent = base;
    for commit in commits {
        if commit.parents.len() != 1 || commit.parents[0].sha != expected_parent {
            return Err("release proposal commits are not one linear sequence".to_string());
        }
        expected_parent = &commit.sha;
    }
    Ok(())
}

fn app_bot() -> crate::github::release_pr::Bot {
    crate::github::release_pr::Bot {
        login: APP_LOGIN.to_string(),
        id: APP_ID,
        email: APP_EMAIL.to_string(),
    }
}

fn require_manual_commit(commit: &RepositoryCommit, owner: &User) -> Result<(), String> {
    let author = commit.author.as_ref();
    let committer = commit.committer.as_ref();
    let identity = format!(
        "{} <{}>",
        commit.commit.author.name, commit.commit.author.email
    );
    let expected_dco = format!("Signed-off-by: {identity}");
    if !is_sha(&commit.sha)
        || author.is_none_or(|user| user.login != owner.login || user.id != owner.id)
        || committer.is_none_or(|user| user.login != owner.login || user.id != owner.id)
        || commit.commit.author != commit.commit.committer
        || commit.commit.author.name.is_empty()
        || commit.commit.author.email.is_empty()
        || !commit.commit.verification.verified
        || commit.commit.verification.reason != "valid"
        || dco_lines(&commit.commit.message) != [expected_dco.as_str()]
        || !is_sha(&commit.commit.tree.sha)
    {
        return Err("manual release proposal commit identity is invalid".to_string());
    }
    Ok(())
}

fn require_integrated_commit(
    integrated: &RepositoryCommit,
    proposal: &RepositoryCommit,
    base: &str,
    owner: &User,
    app_proposal: bool,
) -> Result<(), String> {
    if integrated.commit.tree.sha != proposal.commit.tree.sha
        || !integrated.commit.verification.verified
        || integrated.commit.verification.reason != "valid"
    {
        return Err("current main integration is invalid".to_string());
    }
    if integrated.sha == proposal.sha {
        if integrated != proposal {
            return Err("fast-forward integration changed the proposal commit".to_string());
        }
        return Ok(());
    }
    if integrated.parents.len() != 1 || integrated.parents[0].sha != base {
        return Err("squash integration does not retain the exact proposal base".to_string());
    }
    let author = integrated.author.as_ref();
    let committer = integrated.committer.as_ref();
    let expected_author = if app_proposal {
        APP_LOGIN
    } else {
        owner.login.as_str()
    };
    let expected_author_id = if app_proposal { APP_ID } else { owner.id };
    let expected_email = if app_proposal {
        APP_EMAIL.to_string()
    } else {
        proposal.commit.author.email.clone()
    };
    let expected_name = if app_proposal {
        APP_LOGIN.to_string()
    } else {
        proposal.commit.author.name.clone()
    };
    let expected_dco = format!("Signed-off-by: {expected_name} <{expected_email}>");
    if author.is_none_or(|user| user.login != expected_author || user.id != expected_author_id)
        || committer.is_none_or(|user| user.login != WEB_FLOW_LOGIN || user.id != WEB_FLOW_ID)
        || integrated.commit.author.name != expected_name
        || integrated.commit.author.email != expected_email
        || integrated.commit.committer.name != WEB_FLOW_NAME
        || integrated.commit.committer.email != WEB_FLOW_EMAIL
        || dco_lines(&integrated.commit.message) != [expected_dco.as_str()]
    {
        return Err("current main squash integration identity is invalid".to_string());
    }
    Ok(())
}

fn dco_lines(message: &str) -> Vec<&str> {
    message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .collect()
}

fn require_exact_tree_diff(
    github: &mut impl Transport,
    repository: &str,
    base_tree: &str,
    proposal_tree: &str,
) -> Result<(), String> {
    if !is_sha(base_tree) || !is_sha(proposal_tree) || base_tree == proposal_tree {
        return Err("release proposal tree identities are invalid".to_string());
    }
    let base: Tree = github.get(&format!(
        "repos/{repository}/git/trees/{base_tree}?recursive=1"
    ))?;
    let proposal: Tree = github.get(&format!(
        "repos/{repository}/git/trees/{proposal_tree}?recursive=1"
    ))?;
    let base = normalized_tree(base, base_tree)?;
    let proposal = normalized_tree(proposal, proposal_tree)?;
    let paths: BTreeSet<_> = base.keys().chain(proposal.keys()).cloned().collect();
    let mut changed = BTreeSet::new();
    for path in paths {
        let old = base.get(&path);
        let new = proposal.get(&path);
        if old == new {
            continue;
        }
        let (Some(old), Some(new)) = (old, new) else {
            return Err("release proposal added or removed a path".to_string());
        };
        if old.kind != "blob"
            || new.kind != "blob"
            || old.mode != new.mode
            || old.mode != "100644"
            || !allowed_tree_path(repository, &path)
        {
            return Err(format!(
                "release proposal exceeds its generated-file allowlist at {path}"
            ));
        }
        changed.insert(path);
    }
    if changed.is_empty() {
        return Err("release proposal has no exact tree change".to_string());
    }
    Ok(())
}

fn normalized_tree(tree: Tree, expected: &str) -> Result<BTreeMap<String, TreeEntry>, String> {
    if tree.sha != expected || tree.truncated || tree.tree.len() > 100_000 {
        return Err("GitHub returned an incomplete immutable tree".to_string());
    }
    let mut entries = BTreeMap::new();
    for entry in tree.tree {
        if entry.path.is_empty()
            || entry.path.starts_with('/')
            || entry.path.ends_with('/')
            || entry.path.contains(['\0', '\r', '\n', '\\'])
            || entry
                .path
                .split('/')
                .any(|component| matches!(component, "" | "." | ".."))
            || !is_sha(&entry.sha)
            || entries.insert(entry.path.clone(), entry).is_some()
        {
            return Err("GitHub returned an invalid immutable tree entry".to_string());
        }
    }
    Ok(entries)
}

fn allowed_tree_path(repository: &str, path: &str) -> bool {
    repository_policy(repository).is_some_and(|policy| policy.generated_paths.contains(&path))
}

fn require_main_position(
    github: &mut impl Transport,
    repository: &str,
    commit: &str,
    requirement: MainRequirement,
) -> Result<(), String> {
    match requirement {
        MainRequirement::Exact => require_main(github, repository, commit),
        MainRequirement::Ancestry => require_captured_ancestry(github, repository, commit),
    }
}

fn require_main(github: &mut impl Transport, repository: &str, commit: &str) -> Result<(), String> {
    let value: crate::github::models::GitRef =
        github.get(&format!("repos/{repository}/git/ref/heads/main"))?;
    if value.name != "refs/heads/main"
        || value.object.kind != "commit"
        || value.object.sha != commit
    {
        return Err("protected main changed during source authorization".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::consts::TRAITS_REPOSITORY;
    use crate::github::models::TreeIdentity;
    use crate::github::transport::fake::{Expected, FakeTransport};
    use serde_json::{Value, json};

    fn entry(path: &str, sha: char) -> TreeEntry {
        TreeEntry {
            path: path.to_string(),
            mode: "100644".to_string(),
            kind: "blob".to_string(),
            sha: sha.to_string().repeat(40),
        }
    }

    fn user(login: &str, id: u64) -> User {
        User {
            login: login.to_string(),
            id,
            name: None,
        }
    }

    fn permission(user: &User, value: &str) -> Value {
        json!({
            "permission": value,
            "user": {"login": user.login, "id": user.id},
        })
    }

    #[test]
    fn release_versions_accept_only_stable_or_canonical_rc() {
        assert!(release_version("0.4.0").is_ok());
        assert!(release_version("0.4.0-rc.2").is_ok());
        assert!(release_version("0.4.0-beta.1").is_err());
        assert!(release_version("0.4.0+local").is_err());
    }

    #[test]
    fn immutable_tree_normalization_rejects_truncation_and_duplicates() {
        let tree = Tree {
            sha: "a".repeat(40),
            truncated: false,
            tree: vec![entry("Cargo.toml", 'b')],
        };
        assert!(normalized_tree(tree, &"a".repeat(40)).is_ok());
        let duplicate = Tree {
            sha: "a".repeat(40),
            truncated: false,
            tree: vec![entry("Cargo.toml", 'b'), entry("Cargo.toml", 'c')],
        };
        assert!(normalized_tree(duplicate, &"a".repeat(40)).is_err());
    }

    #[test]
    fn stable_promotion_requires_the_exact_rc_core() {
        let rc = release_version("0.4.0-rc.2").unwrap();
        assert!(is_stable_promotion(&rc, &release_version("0.4.0").unwrap()));
        assert!(!is_stable_promotion(
            &rc,
            &release_version("0.4.1").unwrap()
        ));
    }

    #[test]
    fn tree_identity_type_remains_minimal() {
        let identity = TreeIdentity {
            sha: "d".repeat(40),
        };
        assert!(is_sha(&identity.sha));
    }

    #[test]
    fn merged_association_accepts_only_exact_merge_or_rebase_identity() {
        let commit = "a".repeat(40);
        let other = "b".repeat(40);
        let pull = |merge_commit_sha: Option<&str>, head: &str| {
            serde_json::from_value::<PullRequest>(json!({
                "number": 1,
                "state": "closed",
                "user": {"login": "owner", "id": 1},
                "head": {
                    "ref": "release-plz-manual-0.4.0-rc.2",
                    "sha": head,
                    "repo": {"full_name": TRAITS_REPOSITORY},
                },
                "base": {
                    "ref": "main",
                    "sha": other,
                    "repo": {"full_name": TRAITS_REPOSITORY},
                },
                "node_id": "PR_1",
                "draft": false,
                "merged_at": "2026-08-27T21:48:16Z",
                "merge_commit_sha": merge_commit_sha,
            }))
            .unwrap()
        };

        assert!(integrated_commit_matches(
            &pull(Some(&commit), &other),
            &commit
        ));
        assert!(integrated_commit_matches(&pull(None, &commit), &commit));
        assert!(!integrated_commit_matches(&pull(None, &other), &commit));
        assert!(!integrated_commit_matches(
            &pull(Some(&other), &commit),
            &commit
        ));
    }

    #[test]
    fn exact_main_requirement_rejects_an_ancestor() {
        let commit = "a".repeat(40);
        let mut github = FakeTransport::new([Expected::json(
            "GET",
            &format!("repos/{TRAITS_REPOSITORY}/git/ref/heads/main"),
            json!({
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": "b".repeat(40)},
            }),
        )]);
        assert_eq!(
            require_main_position(
                &mut github,
                TRAITS_REPOSITORY,
                &commit,
                MainRequirement::Exact,
            )
            .unwrap_err(),
            "protected main changed during source authorization"
        );
        github.finish();
    }

    fn tree_value(sha: char, entries: Vec<TreeEntry>) -> Value {
        json!({
            "sha": sha.to_string().repeat(40),
            "truncated": false,
            "tree": entries.into_iter().map(|entry| {
                json!({
                    "path": entry.path,
                    "mode": entry.mode,
                    "type": entry.kind,
                    "sha": entry.sha,
                })
            }).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn immutable_tree_diff_accepts_only_existing_allowlisted_blobs() {
        let base = "a".repeat(40);
        let proposal = "b".repeat(40);
        let mut github = FakeTransport::new([
            Expected::json(
                "GET",
                &format!("repos/{TRAITS_REPOSITORY}/git/trees/{base}?recursive=1"),
                tree_value('a', vec![entry("Cargo.toml", 'c'), entry("README.md", 'd')]),
            ),
            Expected::json(
                "GET",
                &format!("repos/{TRAITS_REPOSITORY}/git/trees/{proposal}?recursive=1"),
                tree_value('b', vec![entry("Cargo.toml", 'e'), entry("README.md", 'd')]),
            ),
        ]);
        assert!(require_exact_tree_diff(&mut github, TRAITS_REPOSITORY, &base, &proposal,).is_ok());
        github.finish();
    }

    #[test]
    fn immutable_tree_diff_rejects_added_or_non_blob_paths() {
        let base = "a".repeat(40);
        let proposal = "b".repeat(40);
        let path = |sha: &str| format!("repos/{TRAITS_REPOSITORY}/git/trees/{sha}?recursive=1");
        let mut added = FakeTransport::new([
            Expected::json(
                "GET",
                &path(&base),
                tree_value('a', vec![entry("Cargo.toml", 'c')]),
            ),
            Expected::json(
                "GET",
                &path(&proposal),
                tree_value('b', vec![entry("Cargo.toml", 'd'), entry("extra.txt", 'e')]),
            ),
        ]);
        assert!(require_exact_tree_diff(&mut added, TRAITS_REPOSITORY, &base, &proposal).is_err());
        added.finish();

        let mut link = entry("Cargo.toml", 'd');
        link.mode = "120000".to_string();
        let mut linked = FakeTransport::new([
            Expected::json(
                "GET",
                &path(&base),
                tree_value('a', vec![entry("Cargo.toml", 'c')]),
            ),
            Expected::json("GET", &path(&proposal), tree_value('b', vec![link])),
        ]);
        assert!(require_exact_tree_diff(&mut linked, TRAITS_REPOSITORY, &base, &proposal).is_err());
        linked.finish();
    }

    #[test]
    fn final_manual_authorization_rechecks_merger_and_owner() {
        let merger = user("release-merger", 41);
        let owner = user("release-owner", 42);
        let path = |user: &User| {
            format!(
                "repos/{TRAITS_REPOSITORY}/collaborators/{}/permission",
                percent_encode(&user.login)
            )
        };
        let mut github = FakeTransport::new([
            Expected::json("GET", &path(&merger), permission(&merger, "maintain")),
            Expected::json("GET", &path(&owner), permission(&owner, "write")),
        ]);

        require_current_release_writers(&mut github, TRAITS_REPOSITORY, &merger, Some(&owner))
            .unwrap();
        github.finish();
    }

    #[test]
    fn final_manual_authorization_rejects_owner_permission_loss() {
        let merger = user("release-merger", 41);
        let owner = user("release-owner", 42);
        let path = |user: &User| {
            format!(
                "repos/{TRAITS_REPOSITORY}/collaborators/{}/permission",
                percent_encode(&user.login)
            )
        };
        let mut github = FakeTransport::new([
            Expected::json("GET", &path(&merger), permission(&merger, "admin")),
            Expected::json("GET", &path(&owner), permission(&owner, "read")),
        ]);

        let error =
            require_current_release_writers(&mut github, TRAITS_REPOSITORY, &merger, Some(&owner))
                .unwrap_err();

        assert_eq!(error, "release owner lacks current write authority");
        github.finish();
    }
}

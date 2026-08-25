// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Create and finalize exact GitHub-signed release proposal commits.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::github::consts::{
    RELEASE_AUTHORIZATION_SENTENCE, RELEASE_TITLE_PREFIX, RepositoryKind, RepositoryPolicy,
    repository_policy,
};
use crate::github::models::{Compare, CreatedCommit, GitRef, PullRequest, RepositoryCommit, User};
use crate::github::transport::{Transport, percent_encode};
use crate::github::{
    APP_EMAIL, APP_ID, APP_LOGIN, APP_SLUG, MAX_FILE_BYTES, RELEASE_BRANCH, ReleasePrPhase,
    WEB_FLOW_EMAIL, WEB_FLOW_ID, WEB_FLOW_LOGIN, WEB_FLOW_NAME, append_outputs, command_output,
    env_bool, env_required, git_line, git_output, is_positive_integer, is_sha, output_detail,
    validate_ref_component, workflow_repository,
};

const MAX_CHANGED_FILES: usize = 16;
const MAX_TOTAL_CONTENT_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn apply(
    root: &Path,
    phase: ReleasePrPhase,
    github: &mut impl Transport,
) -> Result<(), String> {
    if env::var_os("GH_TOKEN").is_none() {
        return Err("GH_TOKEN must contain the GitHub App installation token".to_string());
    }
    let context = Context::from_environment(root)?;
    let bot = require_bot(github)?;
    match phase {
        ReleasePrPhase::Update => update(root, &context, &bot, github),
        ReleasePrPhase::Finalize => finalize(root, &context, &bot, github),
    }
}

#[derive(Debug)]
struct Context {
    repository: String,
    main: String,
    title: String,
    body: String,
    draft: bool,
    hold_draft: bool,
}

impl Context {
    fn from_environment(root: &Path) -> Result<Self, String> {
        let policy = workflow_repository(root)?;
        let repository = policy.full_name.to_string();
        let main = env_required("GITHUB_SHA")?;
        let app_slug = env_required("APP_SLUG")?;
        let branch = env_required("RELEASE_BRANCH")?;
        let target = env_required("RELEASE_TARGET")?;
        let substantive = env_bool("RELEASE_SUBSTANTIVE")?;
        let hold_draft = env_bool("RELEASE_HOLD_DRAFT")?;
        if !is_sha(&main) || app_slug != APP_SLUG || branch != RELEASE_BRANCH {
            return Err(
                "release repository, main, App, or branch identity is unexpected".to_string(),
            );
        }
        validate_ref_component(&branch, "release branch")?;
        parse_release_target(&target)?;
        if manifest_version(root, policy.kind)? != target {
            return Err("RELEASE_TARGET disagrees with the exact release manifest".to_string());
        }
        let (title, body) = release_pull_text(policy, &target);
        Ok(Self {
            repository,
            main,
            title,
            body,
            draft: !substantive,
            hold_draft,
        })
    }
}

fn parse_release_target(value: &str) -> Result<Version, String> {
    let version = Version::parse(value)
        .map_err(|error| format!("RELEASE_TARGET is not a supported version: {error}"))?;
    if version.to_string() != value || !version.build.is_empty() {
        return Err("RELEASE_TARGET is not a canonical release version".to_string());
    }
    if !version.pre.is_empty() {
        let number = version
            .pre
            .as_str()
            .strip_prefix("rc.")
            .ok_or_else(|| "RELEASE_TARGET prerelease must use rc.N".to_string())?;
        if number.starts_with('0') || number.parse::<u64>().ok().is_none_or(|value| value == 0) {
            return Err("RELEASE_TARGET prerelease must use positive canonical rc.N".to_string());
        }
    }
    Ok(version)
}

fn manifest_version(root: &Path, kind: RepositoryKind) -> Result<String, String> {
    let path = root.join("Cargo.toml");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("read release manifest metadata: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("release manifest is missing, indirect, or oversized".to_string());
    }
    let body =
        fs::read_to_string(&path).map_err(|error| format!("read release manifest: {error}"))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse release manifest: {error}"))?;
    let value = match kind {
        RepositoryKind::Traits => document
            .get("package")
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
        RepositoryKind::RustWorkspace => document
            .get("workspace")
            .and_then(|item| item.get("package"))
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
    }
    .ok_or_else(|| "release manifest has no exact release version".to_string())?;
    parse_release_target(value)?;
    Ok(value.to_string())
}

fn release_pull_text(policy: &RepositoryPolicy, target: &str) -> (String, String) {
    let title = format!("{RELEASE_TITLE_PREFIX} {} {target}", policy.title_subject);
    let body = format!(
        "This automated proposal prepares {} at `{target}`.\n\n\
         {RELEASE_AUTHORIZATION_SENTENCE}\n\
         {}\n",
        policy.release_subject, policy.release_object_sentence
    );
    (title, body)
}

#[derive(Clone, Debug)]
pub(super) struct Bot {
    pub(super) login: String,
    pub(super) id: u64,
    pub(super) email: String,
}

fn require_bot(github: &mut impl Transport) -> Result<Bot, String> {
    let user: User = github.get(&format!("users/{}", percent_encode(APP_LOGIN)))?;
    if user.login != APP_LOGIN || user.id != APP_ID {
        return Err("GitHub did not return the expected release App bot identity".to_string());
    }
    Ok(Bot {
        login: user.login,
        id: user.id,
        email: APP_EMAIL.to_string(),
    })
}

fn update(
    root: &Path,
    context: &Context,
    bot: &Bot,
    github: &mut impl Transport,
) -> Result<(), String> {
    let run_id = env_required("GITHUB_RUN_ID")?;
    let run_attempt = env_required("GITHUB_RUN_ATTEMPT")?;
    if !is_positive_integer(&run_id) || !is_positive_integer(&run_attempt) {
        return Err("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be positive integers".to_string());
    }
    if git_line(root, &["rev-parse", "HEAD"])? != context.main {
        return Err("the release diff is not based on the triggering main commit".to_string());
    }
    require_ref(github, &context.repository, "main", &context.main)?;
    let changes = generated_changes(root, &context.repository)?;
    let target = inspect_target(github, &context.repository, bot)?;
    let mut pull = inspect_open_pull(github, &context.repository, target.as_ref(), bot)?;
    let effective_draft = context.hold_draft || context.draft;
    if context.hold_draft && pull.as_ref().is_some_and(|value| !value.draft) {
        let number = pull.as_ref().expect("present pull").number;
        let node = pull.as_ref().expect("present pull").node_id.clone();
        transition_review_state(github, &context.repository, number, &node, true)?;
        let held = get_pull(github, &context.repository, number)?;
        require_owned_pull(&held, context, bot, target.as_ref(), true)?;
        pull = Some(held);
    }

    let staging = format!("automation/release-staging-{run_id}-{run_attempt}");
    validate_ref_component(&staging, "staging branch")?;
    create_ref_exact(github, &context.repository, &staging, &context.main)?;

    let operation = finish_update(
        root,
        context,
        bot,
        github,
        &changes,
        target.as_ref(),
        pull.as_ref(),
        effective_draft,
        &staging,
    );
    let cleanup = delete_ref_exact(github, &context.repository, &staging);
    match (operation, cleanup) {
        (Ok(result), Ok(())) => {
            append_outputs(&[
                ("commit_sha", &result.commit),
                ("pr_number", &result.pull.to_string()),
            ])?;
            eprintln!(
                "github: created or updated PR #{} at Verified commit {}",
                result.pull, result.commit
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}; temporary staging cleanup also failed: {cleanup_error}"
        )),
    }
}

struct UpdateResult {
    commit: String,
    pull: u64,
}

#[allow(clippy::too_many_arguments)]
fn finish_update(
    root: &Path,
    context: &Context,
    bot: &Bot,
    github: &mut impl Transport,
    changes: &[GeneratedChange],
    target: Option<&GitRef>,
    pull: Option<&PullRequest>,
    effective_draft: bool,
    staging: &str,
) -> Result<UpdateResult, String> {
    let base_tree = git_line(root, &["rev-parse", &format!("{}^{{tree}}", context.main)])?;
    if !is_sha(&base_tree) {
        return Err("the triggering main commit lacks one exact tree".to_string());
    }
    let entries: Vec<Value> = changes
        .iter()
        .map(|change| {
            json!({
                "path": change.path,
                "mode": change.mode,
                "type": "blob",
                "content": change.content,
            })
        })
        .collect();
    let tree: TreeCreated = github.mutate(
        "POST",
        &format!("repos/{}/git/trees", context.repository),
        &json!({"base_tree": base_tree, "tree": entries}),
    )?;
    if !is_sha(&tree.sha) {
        return Err("GitHub did not return an exact generated tree".to_string());
    }

    let dco = format!("Signed-off-by: {} <{}>", bot.login, bot.email);
    let message = format!("{}\n\n{dco}", context.title);
    let commit: CreatedCommit = github.mutate(
        "POST",
        &format!("repos/{}/git/commits", context.repository),
        &json!({"message": message, "tree": tree.sha, "parents": [context.main]}),
    )?;
    require_created_app_commit(&commit, bot, &context.main, &tree.sha, &dco)?;
    require_ref(github, &context.repository, "main", &context.main)?;
    update_ref_exact(github, &context.repository, staging, &commit.sha)?;
    let visible: RepositoryCommit = github.get(&format!(
        "repos/{}/commits/{}",
        context.repository, commit.sha
    ))?;
    require_repository_app_commit(&visible, bot, Some(&context.main))?;

    fetch_staging(root, staging, &commit.sha)?;
    require_ref(github, &context.repository, "main", &context.main)?;
    if context.hold_draft
        && let Some(existing) = pull
    {
        let current = get_pull(github, &context.repository, existing.number)?;
        require_owned_pull(&current, context, bot, target, true)?;
    }
    push_with_lease(
        root,
        &context.repository,
        RELEASE_BRANCH,
        &commit.sha,
        target.map(|value| value.object.sha.as_str()).unwrap_or(""),
    )?;
    require_ref(github, &context.repository, RELEASE_BRANCH, &commit.sha)?;

    let number = mutate_pull(github, context, bot, pull, &commit.sha, effective_draft)?;
    let final_pull = get_pull(github, &context.repository, number)?;
    require_final_pull(&final_pull, context, bot, &commit.sha, effective_draft)?;
    require_ref(github, &context.repository, "main", &context.main)?;
    Ok(UpdateResult {
        commit: commit.sha,
        pull: number,
    })
}

fn finalize(
    root: &Path,
    context: &Context,
    bot: &Bot,
    github: &mut impl Transport,
) -> Result<(), String> {
    let commit = env_required("RELEASE_COMMIT")?;
    let number_text = env_required("RELEASE_PR_NUMBER")?;
    if !is_sha(&commit) || !is_positive_integer(&number_text) {
        return Err("finalization requires an exact commit and pull-request number".to_string());
    }
    let number = number_text
        .parse::<u64>()
        .map_err(|_| "release pull-request number is invalid".to_string())?;
    if git_line(root, &["rev-parse", "HEAD"])? != commit {
        return Err("finalization is not running at the validated App commit".to_string());
    }
    require_ref(github, &context.repository, "main", &context.main)?;
    require_ref(github, &context.repository, RELEASE_BRANCH, &commit)?;
    let release_commit: RepositoryCommit =
        github.get(&format!("repos/{}/commits/{commit}", context.repository))?;
    require_repository_app_commit(&release_commit, bot, Some(&context.main))?;
    let held = get_pull(github, &context.repository, number)?;
    require_final_pull(&held, context, bot, &commit, true)?;
    if !context.draft {
        transition_review_state(github, &context.repository, number, &held.node_id, false)?;
    }
    let final_pull = get_pull(github, &context.repository, number)?;
    require_final_pull(&final_pull, context, bot, &commit, context.draft)?;
    require_ref(github, &context.repository, "main", &context.main)?;
    require_ref(github, &context.repository, RELEASE_BRANCH, &commit)?;
    append_outputs(&[("commit_sha", &commit), ("pr_number", &number_text)])?;
    eprintln!("github: finalized PR #{number} at validated commit {commit}");
    Ok(())
}

#[derive(Debug)]
struct GeneratedChange {
    path: String,
    mode: String,
    content: String,
}

fn generated_changes(root: &Path, repository: &str) -> Result<Vec<GeneratedChange>, String> {
    let checked = command_output(root, "git", &["diff", "--check"])?;
    if !checked.status.success() {
        return Err(format!(
            "generated diff failed git diff --check: {}",
            output_detail(&checked)
        ));
    }
    let staged = command_output(root, "git", &["diff", "--cached", "--quiet"])?;
    if !staged.status.success() {
        return Err("release automation may not consume staged changes".to_string());
    }
    if !git_output(root, &["ls-files", "--others", "--exclude-standard"])?.is_empty() {
        return Err("release automation may only modify tracked files".to_string());
    }
    if !git_output(root, &["diff", "--summary"])?.is_empty() {
        return Err("release automation may not change file modes or path identity".to_string());
    }
    let inventory = git_output(root, &["diff", "--name-status", "--no-renames"])?;
    let mut changes = Vec::new();
    let mut total = 0usize;
    for line in inventory.lines() {
        let (status, path) = line
            .split_once('\t')
            .ok_or_else(|| "git returned an invalid release diff inventory".to_string())?;
        if status != "M" || !allowed_generated_path(repository, path) {
            return Err(format!("release automation may not commit {status} {path}"));
        }
        if changes
            .iter()
            .any(|change: &GeneratedChange| change.path == path)
        {
            return Err("release diff contains a duplicate path".to_string());
        }
        let metadata = fs::metadata(root.join(path))
            .map_err(|error| format!("read generated path {path}: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Err(format!("generated path {path} is missing or oversized"));
        }
        total = total
            .checked_add(metadata.len() as usize)
            .ok_or_else(|| "generated content size overflowed".to_string())?;
        if total > MAX_TOTAL_CONTENT_BYTES {
            return Err("generated release content exceeded its total bound".to_string());
        }
        let content = fs::read_to_string(root.join(path))
            .map_err(|error| format!("generated path {path} is not UTF-8: {error}"))?;
        if content.contains('\0') {
            return Err(format!("generated path {path} contains NUL"));
        }
        let index = git_line(root, &["ls-files", "-s", "--", path])?;
        let (prefix, indexed_path) = index
            .split_once('\t')
            .ok_or_else(|| format!("git returned invalid index state for {path}"))?;
        let mut fields = prefix.split_ascii_whitespace();
        let mode = fields.next().unwrap_or_default();
        let blob = fields.next().unwrap_or_default();
        let stage = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || indexed_path != path
            || mode != "100644"
            || !is_sha(blob)
            || stage != "0"
        {
            return Err(format!("generated path {path} has unsupported index state"));
        }
        changes.push(GeneratedChange {
            path: path.to_string(),
            mode: mode.to_string(),
            content,
        });
    }
    if changes.is_empty() || changes.len() > MAX_CHANGED_FILES {
        return Err("release proposal has an empty or oversized file inventory".to_string());
    }
    Ok(changes)
}

fn allowed_generated_path(repository: &str, path: &str) -> bool {
    repository_policy(repository).is_some_and(|policy| policy.generated_paths.contains(&path))
}

fn inspect_target(
    github: &mut impl Transport,
    repository: &str,
    bot: &Bot,
) -> Result<Option<GitRef>, String> {
    let refs: Vec<GitRef> = github.get(&format!(
        "repos/{repository}/git/matching-refs/heads/{}",
        percent_encode(RELEASE_BRANCH)
    ))?;
    if refs.len() > 1 {
        return Err("GitHub returned ambiguous release branch state".to_string());
    }
    let Some(target) = refs.into_iter().next() else {
        return Ok(None);
    };
    require_exact_ref(&target, RELEASE_BRANCH, &target.object.sha)?;
    let compare: Compare = github.get(&format!(
        "repos/{repository}/compare/main...{}",
        percent_encode(RELEASE_BRANCH)
    ))?;
    if compare.ahead_by > 1
        || compare.ahead_by as usize != compare.commits.len()
        || compare.commits.iter().any(|commit| {
            commit
                .author
                .as_ref()
                .is_none_or(|user| user.login != bot.login || user.id != bot.id)
                || commit
                    .committer
                    .as_ref()
                    .is_none_or(|user| user.login != WEB_FLOW_LOGIN || user.id != WEB_FLOW_ID)
        })
    {
        return Err(format!(
            "{RELEASE_BRANCH} contains a non-App commit and will not be overwritten"
        ));
    }
    if compare.ahead_by == 1 {
        let commit: RepositoryCommit =
            github.get(&format!("repos/{repository}/commits/{}", target.object.sha))?;
        require_repository_app_commit(&commit, bot, None)?;
    }
    Ok(Some(target))
}

fn inspect_open_pull(
    github: &mut impl Transport,
    repository: &str,
    target: Option<&GitRef>,
    bot: &Bot,
) -> Result<Option<PullRequest>, String> {
    let owner = repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .ok_or_else(|| "repository lacks an owner".to_string())?;
    let head = percent_encode(&format!("{owner}:{RELEASE_BRANCH}"));
    let pulls: Vec<PullRequest> =
        github.paginate(&format!("repos/{repository}/pulls?state=open&head={head}"))?;
    if pulls.len() > 1 {
        return Err("multiple open release pull requests use the durable branch".to_string());
    }
    let Some(listed) = pulls.into_iter().next() else {
        return Ok(None);
    };
    let Some(target) = target else {
        return Err("the release pull request exists without its owned ref".to_string());
    };
    require_listed_pull_identity(&listed, repository, bot, &target.object.sha)?;
    let pull = get_pull(github, repository, listed.number)?;
    if listed.number != pull.number
        || listed.state != pull.state
        || listed.user != pull.user
        || listed.head != pull.head
        || listed.base != pull.base
        || listed.node_id != pull.node_id
        || listed.draft != pull.draft
    {
        return Err("the release pull request changed during lookup".to_string());
    }
    require_owned_pull_identity(&pull, repository, bot, &target.object.sha)?;
    Ok(Some(pull))
}

fn mutate_pull(
    github: &mut impl Transport,
    context: &Context,
    bot: &Bot,
    existing: Option<&PullRequest>,
    commit: &str,
    draft: bool,
) -> Result<u64, String> {
    let number = if let Some(existing) = existing {
        let mutation: Result<PullRequest, String> = github.mutate(
            "PATCH",
            &format!("repos/{}/pulls/{}", context.repository, existing.number),
            &json!({"title": context.title, "body": context.body}),
        );
        let reread = get_pull(github, &context.repository, existing.number)?;
        if mutation.is_err()
            && (reread.title != context.title || reread.body.as_deref() != Some(&context.body))
        {
            return Err(mutation.expect_err("checked mutation error"));
        }
        existing.number
    } else {
        let mutation: Result<PullRequest, String> = github.mutate(
            "POST",
            &format!("repos/{}/pulls", context.repository),
            &json!({
                "title": context.title,
                "head": RELEASE_BRANCH,
                "base": "main",
                "body": context.body,
                "draft": draft,
            }),
        );
        match mutation {
            Ok(pull) if pull.number > 0 => pull.number,
            Ok(_) => {
                return Err("GitHub created a pull request without an exact number".to_string());
            }
            Err(error) => {
                let discovered =
                    inspect_open_pull_after_mutation(github, &context.repository, bot, commit)?;
                discovered.ok_or(error)?.number
            }
        }
    };
    let current = get_pull(github, &context.repository, number)?;
    if current.draft != draft {
        transition_review_state(github, &context.repository, number, &current.node_id, draft)?;
    }
    Ok(number)
}

fn inspect_open_pull_after_mutation(
    github: &mut impl Transport,
    repository: &str,
    bot: &Bot,
    commit: &str,
) -> Result<Option<PullRequest>, String> {
    let owner = repository
        .split_once('/')
        .map(|item| item.0)
        .unwrap_or_default();
    let head = percent_encode(&format!("{owner}:{RELEASE_BRANCH}"));
    let pulls: Vec<PullRequest> =
        github.paginate(&format!("repos/{repository}/pulls?state=open&head={head}"))?;
    if pulls.len() > 1 {
        return Err("pull-request mutation produced ambiguous state".to_string());
    }
    let Some(listed) = pulls.into_iter().next() else {
        return Ok(None);
    };
    require_listed_pull_identity(&listed, repository, bot, commit)?;
    let pull = get_pull(github, repository, listed.number)?;
    if listed.number != pull.number
        || listed.state != pull.state
        || listed.user != pull.user
        || listed.head != pull.head
        || listed.base != pull.base
        || listed.node_id != pull.node_id
        || listed.draft != pull.draft
    {
        return Err("the created release pull request changed during lookup".to_string());
    }
    require_owned_pull_identity(&pull, repository, bot, commit)?;
    Ok(Some(pull))
}

fn get_pull(
    github: &mut impl Transport,
    repository: &str,
    number: u64,
) -> Result<PullRequest, String> {
    github.get(&format!("repos/{repository}/pulls/{number}"))
}

fn require_owned_pull(
    pull: &PullRequest,
    context: &Context,
    bot: &Bot,
    target: Option<&GitRef>,
    draft: bool,
) -> Result<(), String> {
    let target = target.ok_or_else(|| "release pull request lacks its owned ref".to_string())?;
    require_owned_pull_identity(pull, &context.repository, bot, &target.object.sha)?;
    if pull.draft != draft {
        return Err("release pull request has an unexpected review state".to_string());
    }
    Ok(())
}

fn require_owned_pull_identity(
    pull: &PullRequest,
    repository: &str,
    bot: &Bot,
    commit: &str,
) -> Result<(), String> {
    if pull.number == 0
        || pull.state != "open"
        || pull.user.login != bot.login
        || pull.user.id != bot.id
        || pull.head.repo.full_name != repository
        || pull.head.branch != RELEASE_BRANCH
        || pull.head.sha != commit
        || pull.base.repo.full_name != repository
        || pull.base.branch != "main"
        || pull.commits != 1
        || pull.node_id.is_empty()
    {
        return Err("the release pull request has unexpected ownership or refs".to_string());
    }
    Ok(())
}

fn require_listed_pull_identity(
    pull: &PullRequest,
    repository: &str,
    bot: &Bot,
    commit: &str,
) -> Result<(), String> {
    if pull.number == 0
        || pull.state != "open"
        || pull.user.login != bot.login
        || pull.user.id != bot.id
        || pull.head.repo.full_name != repository
        || pull.head.branch != RELEASE_BRANCH
        || pull.head.sha != commit
        || pull.base.repo.full_name != repository
        || pull.base.branch != "main"
        || pull.node_id.is_empty()
    {
        return Err("the listed release pull request has unexpected ownership or refs".to_string());
    }
    Ok(())
}

fn require_final_pull(
    pull: &PullRequest,
    context: &Context,
    bot: &Bot,
    commit: &str,
    draft: bool,
) -> Result<(), String> {
    require_owned_pull_identity(pull, &context.repository, bot, commit)?;
    if pull.base.sha != context.main
        || pull.title != context.title
        || pull.body.as_deref() != Some(&context.body)
        || pull.draft != draft
    {
        return Err("GitHub returned an unexpected release pull-request state".to_string());
    }
    Ok(())
}

fn require_ref(
    github: &mut impl Transport,
    repository: &str,
    branch: &str,
    expected: &str,
) -> Result<GitRef, String> {
    let value: GitRef = github.get(&format!(
        "repos/{repository}/git/ref/heads/{}",
        percent_encode(branch)
    ))?;
    require_exact_ref(&value, branch, expected)?;
    Ok(value)
}

fn require_exact_ref(value: &GitRef, branch: &str, expected: &str) -> Result<(), String> {
    if value.name != format!("refs/heads/{branch}")
        || value.object.kind != "commit"
        || value.object.sha != expected
        || !is_sha(&value.object.sha)
    {
        return Err(format!("GitHub returned unexpected {branch} ref state"));
    }
    Ok(())
}

fn create_ref_exact(
    github: &mut impl Transport,
    repository: &str,
    branch: &str,
    sha: &str,
) -> Result<(), String> {
    let mutation: Result<GitRef, String> = github.mutate(
        "POST",
        &format!("repos/{repository}/git/refs"),
        &json!({"ref": format!("refs/heads/{branch}"), "sha": sha}),
    );
    match mutation {
        Ok(value) => require_exact_ref(&value, branch, sha),
        Err(error) => require_ref(github, repository, branch, sha)
            .map(|_| ())
            .map_err(|_| error),
    }
}

fn update_ref_exact(
    github: &mut impl Transport,
    repository: &str,
    branch: &str,
    sha: &str,
) -> Result<(), String> {
    let mutation: Result<GitRef, String> = github.mutate(
        "PATCH",
        &format!(
            "repos/{repository}/git/refs/heads/{}",
            percent_encode(branch)
        ),
        &json!({"sha": sha, "force": false}),
    );
    match mutation {
        Ok(value) => require_exact_ref(&value, branch, sha),
        Err(error) => require_ref(github, repository, branch, sha)
            .map(|_| ())
            .map_err(|_| error),
    }
}

fn delete_ref_exact(
    github: &mut impl Transport,
    repository: &str,
    branch: &str,
) -> Result<(), String> {
    let path = format!(
        "repos/{repository}/git/refs/heads/{}",
        percent_encode(branch)
    );
    let mutation = github.delete(&path);
    let refs: Vec<GitRef> = github.get(&format!(
        "repos/{repository}/git/matching-refs/heads/{}",
        percent_encode(branch)
    ))?;
    if refs
        .iter()
        .any(|value| value.name == format!("refs/heads/{branch}"))
    {
        return Err(mutation
            .err()
            .unwrap_or_else(|| "GitHub still reports the staging branch".to_string()));
    }
    Ok(())
}

fn fetch_staging(root: &Path, branch: &str, commit: &str) -> Result<(), String> {
    let remote_ref = format!("refs/remotes/origin/{branch}");
    let refspec = format!("refs/heads/{branch}:{remote_ref}");
    let output = command_output(
        root,
        "git",
        &["fetch", "--no-tags", "--force", "origin", &refspec],
    )?;
    if !output.status.success() {
        return Err(format!(
            "Git did not fetch the exact staged App commit: {}",
            output_detail(&output)
        ));
    }
    if git_line(
        root,
        &["rev-parse", "--verify", &format!("{remote_ref}^{{commit}}")],
    )? != commit
    {
        return Err(
            "the fetched staging ref does not identify the verified App commit".to_string(),
        );
    }
    Ok(())
}

fn push_with_lease(
    root: &Path,
    repository: &str,
    branch: &str,
    commit: &str,
    expected_old: &str,
) -> Result<(), String> {
    let helper =
        "!f() { printf \"%s\\n\" \"username=x-access-token\" \"password=${GH_TOKEN}\"; }; f";
    let lease = format!("--force-with-lease=refs/heads/{branch}:{expected_old}");
    let url = format!("https://github.com/{repository}.git");
    let refspec = format!("{commit}:refs/heads/{branch}");
    let output = Command::new("git")
        .current_dir(root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "credential.helper=",
            "-c",
            &format!("credential.helper={helper}"),
            "push",
            "--porcelain",
            &lease,
            &url,
            &refspec,
        ])
        .output()
        .map_err(|error| format!("run atomic release branch push: {error}"))?;
    if output.stdout.len() > crate::github::transport::MAX_RESPONSE_BYTES
        || output.stderr.len() > crate::github::transport::MAX_ERROR_BYTES
    {
        return Err("Git push output exceeded its bound".to_string());
    }
    if !output.status.success() {
        return Err(format!(
            "the App-owned release branch changed before its atomic update: {}",
            output_detail(&output)
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TreeCreated {
    sha: String,
}

fn require_created_app_commit(
    commit: &CreatedCommit,
    bot: &Bot,
    parent: &str,
    tree: &str,
    dco: &str,
) -> Result<(), String> {
    if !is_sha(&commit.sha)
        || commit.author.name != bot.login
        || commit.author.email != bot.email
        || commit.committer.name != WEB_FLOW_NAME
        || commit.committer.email != WEB_FLOW_EMAIL
        || !commit.verification.verified
        || commit.verification.reason != "valid"
        || dco_lines(&commit.message) != [dco]
        || commit.tree.sha != tree
        || commit.parents.len() != 1
        || commit.parents[0].sha != parent
    {
        return Err("GitHub did not report the generated App commit as valid".to_string());
    }
    Ok(())
}

pub(super) fn require_repository_app_commit(
    commit: &RepositoryCommit,
    bot: &Bot,
    parent: Option<&str>,
) -> Result<(), String> {
    let author = commit.author.as_ref();
    let committer = commit.committer.as_ref();
    let expected_dco = format!("Signed-off-by: {} <{}>", bot.login, bot.email);
    if !is_sha(&commit.sha)
        || author.is_none_or(|user| user.login != bot.login || user.id != bot.id)
        || committer.is_none_or(|user| user.login != WEB_FLOW_LOGIN || user.id != WEB_FLOW_ID)
        || commit.commit.author.name != bot.login
        || commit.commit.author.email != bot.email
        || commit.commit.committer.name != WEB_FLOW_NAME
        || commit.commit.committer.email != WEB_FLOW_EMAIL
        || !commit.commit.verification.verified
        || commit.commit.verification.reason != "valid"
        || dco_lines(&commit.commit.message) != [expected_dco.as_str()]
        || commit.parents.len() != 1
        || parent.is_some_and(|expected| commit.parents[0].sha != expected)
        || !is_sha(&commit.commit.tree.sha)
    {
        return Err("GitHub did not resolve the exact valid App commit".to_string());
    }
    Ok(())
}

fn dco_lines(message: &str) -> Vec<&str> {
    message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .collect()
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    #[serde(default)]
    data: Option<TransitionData>,
    #[serde(default)]
    errors: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct TransitionData {
    #[serde(rename = "markPullRequestReadyForReview")]
    ready: Option<TransitionPayload>,
    #[serde(rename = "convertPullRequestToDraft")]
    draft: Option<TransitionPayload>,
}

#[derive(Debug, Deserialize)]
struct TransitionPayload {
    #[serde(rename = "pullRequest")]
    pull_request: TransitionPull,
}

#[derive(Debug, Deserialize)]
struct TransitionPull {
    number: u64,
    #[serde(rename = "isDraft")]
    is_draft: bool,
}

fn transition_review_state(
    github: &mut impl Transport,
    repository: &str,
    number: u64,
    node: &str,
    draft: bool,
) -> Result<(), String> {
    if number == 0 || node.is_empty() || node.len() > 256 || node.contains(['\0', '\r', '\n']) {
        return Err("pull-request transition identity is invalid".to_string());
    }
    let query = if draft {
        "mutation($id: ID!) { convertPullRequestToDraft(input: {pullRequestId: $id}) { pullRequest { number isDraft } } }"
    } else {
        "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { number isDraft } } }"
    };
    let response: Result<GraphqlResponse, String> = github.graphql(&json!({
        "query": query,
        "variables": {"id": node},
    }));
    match response {
        Ok(value) => {
            if value.errors.is_some() {
                return require_transition_reread(github, repository, number, draft);
            }
            let transition = value.data.as_ref().and_then(|data| {
                if draft {
                    data.draft.as_ref()
                } else {
                    data.ready.as_ref()
                }
            });
            if transition.is_none_or(|payload| {
                payload.pull_request.number != number || payload.pull_request.is_draft != draft
            }) {
                return Err("GitHub returned an unexpected review-state transition".to_string());
            }
        }
        Err(error) => {
            return require_transition_reread(github, repository, number, draft).map_err(|_| error);
        }
    }
    require_transition_reread(github, repository, number, draft)
}

fn require_transition_reread(
    github: &mut impl Transport,
    repository: &str,
    number: u64,
    draft: bool,
) -> Result<(), String> {
    let pull = get_pull(github, repository, number)?;
    if pull.number == number && pull.draft == draft {
        Ok(())
    } else {
        Err("GitHub did not retain the requested review state".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::consts::{RUST_POLICY, TRAITS_POLICY, TRAITS_REPOSITORY};
    use crate::github::models::{Parent, RawCommit, Signature, TreeIdentity, Verification};
    use crate::github::transport::fake::{Expected, FakeTransport};
    use crate::release_policy::TRAITS_POLICY as TRAITS_RELEASE_POLICY;
    use serde_json::json;

    fn bot() -> Bot {
        Bot {
            login: APP_LOGIN.to_string(),
            id: APP_ID,
            email: APP_EMAIL.to_string(),
        }
    }

    fn app_commit() -> RepositoryCommit {
        RepositoryCommit {
            sha: "a".repeat(40),
            author: Some(User {
                login: APP_LOGIN.to_string(),
                id: APP_ID,
                name: None,
            }),
            committer: Some(User {
                login: WEB_FLOW_LOGIN.to_string(),
                id: WEB_FLOW_ID,
                name: None,
            }),
            commit: RawCommit {
                author: Signature {
                    name: APP_LOGIN.to_string(),
                    email: APP_EMAIL.to_string(),
                },
                committer: Signature {
                    name: WEB_FLOW_NAME.to_string(),
                    email: WEB_FLOW_EMAIL.to_string(),
                },
                message: format!(
                    "chore(release): prepare\n\nSigned-off-by: {APP_LOGIN} <{APP_EMAIL}>"
                ),
                verification: Verification {
                    verified: true,
                    reason: "valid".to_string(),
                },
                tree: TreeIdentity {
                    sha: "b".repeat(40),
                },
            },
            parents: vec![Parent {
                sha: "c".repeat(40),
            }],
        }
    }

    #[test]
    fn app_commit_requires_signature_dco_and_immutable_identities() {
        let mut commit = app_commit();
        assert!(require_repository_app_commit(&commit, &bot(), Some(&"c".repeat(40))).is_ok());
        commit.commit.verification.verified = false;
        assert!(require_repository_app_commit(&commit, &bot(), None).is_err());
    }

    #[test]
    fn generated_paths_are_repository_scoped() {
        assert!(allowed_generated_path(
            crate::github::consts::TRAITS_REPOSITORY,
            "Cargo.toml"
        ));
        assert!(!allowed_generated_path(
            crate::github::consts::TRAITS_REPOSITORY,
            ".github/workflows/publish.yml"
        ));
    }

    #[test]
    fn release_targets_are_canonical_stable_or_rc_versions() {
        assert!(parse_release_target("1.2.3").is_ok());
        assert!(parse_release_target("1.2.3-rc.1").is_ok());
        assert!(parse_release_target("1.2.3-alpha.1").is_err());
        assert!(parse_release_target("1.2.3-rc.0").is_err());
        assert!(parse_release_target("1.2.3+build").is_err());
    }

    #[test]
    fn repository_policy_owns_release_pull_presentation() {
        let (traits_title, traits_body) = release_pull_text(&TRAITS_POLICY, "1.2.3-rc.1");
        assert_eq!(
            traits_title,
            format!(
                "{RELEASE_TITLE_PREFIX} {} {}",
                TRAITS_POLICY.title_subject, "1.2.3-rc.1"
            )
        );
        assert!(traits_body.contains(TRAITS_POLICY.release_subject));
        assert!(traits_body.contains(RELEASE_AUTHORIZATION_SENTENCE));
        assert!(traits_body.contains(TRAITS_POLICY.release_object_sentence));

        let (rust_title, rust_body) = release_pull_text(&RUST_POLICY, "1.2.3");
        assert_eq!(
            rust_title,
            format!(
                "{RELEASE_TITLE_PREFIX} {} {}",
                RUST_POLICY.title_subject, "1.2.3"
            )
        );
        assert!(rust_body.contains(RUST_POLICY.release_subject));
        assert!(rust_body.contains(RUST_POLICY.release_object_sentence));
    }

    #[test]
    fn manifest_version_uses_the_repository_family_location() {
        let traits = tempfile::tempdir().unwrap();
        fs::write(
            traits.path().join("Cargo.toml"),
            format!(
                "[package]\nname = {:?}\nversion = \"1.2.3-rc.1\"\n",
                TRAITS_RELEASE_POLICY.packages[0].package
            ),
        )
        .unwrap();
        assert_eq!(
            manifest_version(traits.path(), RepositoryKind::Traits).unwrap(),
            "1.2.3-rc.1"
        );

        let rust = tempfile::tempdir().unwrap();
        fs::write(
            rust.path().join("Cargo.toml"),
            "[workspace.package]\nversion = \"1.2.3\"\n",
        )
        .unwrap();
        assert_eq!(
            manifest_version(rust.path(), RepositoryKind::RustWorkspace).unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn uncertain_ref_creation_requires_an_exact_reread() {
        let branch = "automation/release-staging-1-1";
        let sha = "a".repeat(40);
        let payload = json!({"ref": format!("refs/heads/{branch}"), "sha": sha});
        let ref_path = format!(
            "repos/{TRAITS_REPOSITORY}/git/ref/heads/{}",
            percent_encode(branch)
        );
        let exact_ref = json!({
            "ref": format!("refs/heads/{branch}"),
            "object": {"type": "commit", "sha": sha},
        });
        let mut github = FakeTransport::new([
            Expected::mutation(
                "POST",
                &format!("repos/{TRAITS_REPOSITORY}/git/refs"),
                payload,
                Err("connection lost"),
            ),
            Expected::json("GET", &ref_path, exact_ref),
        ]);
        assert!(create_ref_exact(&mut github, TRAITS_REPOSITORY, branch, &sha).is_ok());
        github.finish();
    }
}

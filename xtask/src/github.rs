// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Typed GitHub qualification and source-only release finalization.

mod transport;

use std::collections::BTreeSet;
use std::env;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::crate_archive::{CratesIo, Registry, archive_vcs_commit, is_checksum, require_archive};
use crate::release;
use crate::release_policy::TRAITS_PACKAGE;
use crate::safe_file;
use transport::{GhCli, Transport, percent_encode};

const REPOSITORY: &str = "NVIDIA/yaml-sigil-traits";
const RELEASE_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const RELEASE_WORKFLOW_ID: u64 = 337_393_638;
const RELEASE_BRANCH_PREFIX: &str = "release-plz-manual-";
const APP_SLUG: &str = "nvidia-yamlsigil-release-pr";
const APP_LOGIN: &str = "nvidia-yamlsigil-release-pr[bot]";
const APP_ID: u64 = 318_780_254;
const APP_EMAIL: &str = "318780254+nvidia-yamlsigil-release-pr[bot]@users.noreply.github.com";
const RELEASE_SIGNER_LOGIN: &str = "ddurst-nvidia";
const RELEASE_SIGNER_ID: u64 = 267_424_412;
const RELEASE_AUTHOR_NAME: &str = "ddurst";
const RELEASE_AUTHOR_EMAIL: &str = "267424412+ddurst-nvidia@users.noreply.github.com";
const DCO_TRAILER: &str =
    "Signed-off-by: ddurst <267424412+ddurst-nvidia@users.noreply.github.com>";
const RELEASE_PATHS: &[&str] = &["CHANGELOG.md", "Cargo.toml"];
const RELEASE_SIGNATURE_QUERY: &str = r#"
query($owner:String!,$name:String!,$number:Int!){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      commits(first:2){
        totalCount
        nodes{
          commit{
            oid
            signature{
              __typename
              email
              isValid
              state
              wasSignedByGitHub
              signer{databaseId login __typename}
            }
          }
        }
        pageInfo{hasNextPage}
      }
    }
  }
}
"#;

#[derive(Args)]
pub(crate) struct GithubArgs {
    #[command(subcommand)]
    command: GithubCommand,
}

#[derive(Subcommand)]
enum GithubCommand {
    /// Operate on one source-only release.
    Release(GithubReleaseArgs),
}

#[derive(Args)]
struct GithubReleaseArgs {
    #[command(subcommand)]
    command: GithubReleaseCommand,
}

#[derive(Subcommand)]
enum GithubReleaseCommand {
    /// Qualify a main push, validation dispatch, or same-source recovery.
    Qualify {
        #[arg(long, value_enum)]
        mode: QualificationMode,
        #[arg(long, value_name = "SHA")]
        source: String,
        #[arg(long)]
        original_run_id: Option<u64>,
        #[arg(long)]
        original_run_attempt: Option<u64>,
    },
    /// Reconcile the deterministic tag and immutable zero-asset Release.
    Finalize {
        #[arg(long, value_name = "SHA")]
        source: String,
        #[arg(long)]
        version: Version,
        #[arg(long, value_enum)]
        phase: FinalizationPhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum QualificationMode {
    Push,
    Validate,
    Recover,
    Publish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FinalizationPhase {
    Await,
    Reconcile,
}

pub(crate) fn run(root: &Path, args: GithubArgs) -> Result<(), String> {
    let GithubCommand::Release(args) = args.command;
    match args.command {
        GithubReleaseCommand::Qualify {
            mode,
            source,
            original_run_id,
            original_run_attempt,
        } => {
            let context = Context::from_env(root, &source)?;
            require_api_token()?;
            let mut github = GhCli::new()?;
            let mut registry = CratesIo::new();
            let result = qualify(
                root,
                &mut github,
                &mut registry,
                &context,
                mode,
                original_run_id,
                original_run_attempt,
            )?;
            result.write_outputs()
        }
        GithubReleaseCommand::Finalize {
            source,
            version,
            phase,
        } => {
            let context = Context::from_env(root, &source)?;
            let mut registry = CratesIo::new();
            match phase {
                FinalizationPhase::Await => {
                    await_publication(root, &mut registry, &context, &version)
                }
                FinalizationPhase::Reconcile => {
                    require_api_token()?;
                    let observed_slug = env::var("APP_SLUG")
                        .map_err(|_| "APP_SLUG is required for finalization".to_string())?;
                    let mut github = GhCli::new()?;
                    finalize(
                        root,
                        &mut github,
                        &mut registry,
                        &context,
                        &version,
                        &observed_slug,
                    )
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Context {
    source: String,
    event: String,
    sha: String,
}

impl Context {
    fn from_env(root: &Path, source: &str) -> Result<Self, String> {
        require_sha(source, "release source")?;
        if env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return Err("GitHub release commands run only in GitHub Actions".to_string());
        }
        if env::var("GITHUB_REPOSITORY").as_deref() != Ok(REPOSITORY) {
            return Err("GITHUB_REPOSITORY does not match compiled policy".to_string());
        }
        let event = env::var("GITHUB_EVENT_NAME")
            .map_err(|_| "GITHUB_EVENT_NAME is required".to_string())?;
        let sha = env::var("GITHUB_SHA").map_err(|_| "GITHUB_SHA is required".to_string())?;
        require_sha(&sha, "workflow SHA")?;
        crate::crate_archive::require_clean_source(root, source)?;
        Ok(Self {
            source: source.to_string(),
            event,
            sha,
        })
    }
}

fn require_api_token() -> Result<(), String> {
    if env::var_os("GH_TOKEN").is_some_and(|value| !value.is_empty()) {
        Ok(())
    } else {
        Err("GH_TOKEN is required and must be supplied through the environment".to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Qualification {
    qualified: bool,
    source: String,
    version: Option<String>,
    registry_state: &'static str,
    validation_only: bool,
}

impl Qualification {
    fn ordinary(source: &str) -> Self {
        Self {
            qualified: false,
            source: source.to_string(),
            version: None,
            registry_state: "not-applicable",
            validation_only: false,
        }
    }

    fn validation(source: &str) -> Self {
        Self {
            qualified: false,
            source: source.to_string(),
            version: None,
            registry_state: "not-applicable",
            validation_only: true,
        }
    }

    fn write_outputs(&self) -> Result<(), String> {
        let path =
            env::var_os("GITHUB_OUTPUT").ok_or_else(|| "GITHUB_OUTPUT is required".to_string())?;
        let mut output = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| format!("open GITHUB_OUTPUT: {error}"))?;
        for (name, value) in [
            ("qualified", self.qualified.to_string()),
            ("source", self.source.clone()),
            ("version", self.version.clone().unwrap_or_default()),
            ("registry_state", self.registry_state.to_string()),
            ("validation_only", self.validation_only.to_string()),
        ] {
            if value.contains(['\r', '\n']) {
                return Err("release output contains a line break".to_string());
            }
            writeln!(output, "{name}={value}")
                .map_err(|error| format!("write GITHUB_OUTPUT: {error}"))?;
        }
        Ok(())
    }
}

fn qualify(
    root: &Path,
    github: &mut impl Transport,
    registry: &mut impl Registry,
    context: &Context,
    mode: QualificationMode,
    original_run_id: Option<u64>,
    original_run_attempt: Option<u64>,
) -> Result<Qualification, String> {
    release::check_manifest(root)?;
    require_live_policy_main(github, &context.sha)?;
    match mode {
        QualificationMode::Validate => {
            if context.event != "workflow_dispatch"
                || context.sha != context.source
                || original_run_id.is_some()
                || original_run_attempt.is_some()
            {
                return Err(
                    "validation requires one unbound exact-source workflow dispatch".to_string(),
                );
            }
            return Ok(Qualification::validation(&context.source));
        }
        QualificationMode::Push => {
            if context.event != "push"
                || context.sha != context.source
                || original_run_id.is_some()
                || original_run_attempt.is_some()
            {
                return Err("fresh qualification requires the exact push source".to_string());
            }
        }
        QualificationMode::Recover => {
            if context.event != "workflow_dispatch" {
                return Err("recovery requires workflow_dispatch".to_string());
            }
            let run_id = original_run_id
                .filter(|value| *value > 0)
                .ok_or_else(|| "recovery requires original_run_id".to_string())?;
            let attempt = original_run_attempt
                .filter(|value| *value > 0)
                .ok_or_else(|| "recovery requires original_run_attempt".to_string())?;
            validate_original_run(github, &context.source, run_id, attempt)?;
            require_ancestor_of_policy(github, &context.source, &context.sha)?;
        }
        QualificationMode::Publish => {
            if context.event != "push"
                || original_run_id.is_some()
                || original_run_attempt.is_some()
            {
                return Err("post-approval publication requalification is malformed".to_string());
            }
            require_live_policy_main(github, &context.source)?;
        }
    }

    let pulls: Vec<PullRequest> = github.get(&format!(
        "repos/{REPOSITORY}/commits/{}/pulls?per_page=100&page=1",
        context.source
    ))?;
    let Some(release_pr) = select_merged_pull_request(&pulls, &context.source)? else {
        if mode == QualificationMode::Push {
            return Ok(Qualification::ordinary(&context.source));
        }
        return Err("recovery source is not a canonical release PR merge".to_string());
    };
    if !release_pr.head.reference.starts_with(RELEASE_BRANCH_PREFIX) {
        if mode == QualificationMode::Push {
            return Ok(Qualification::ordinary(&context.source));
        }
        return Err("recovery source did not use a manual release branch".to_string());
    }

    let branch_version = release_pr
        .head
        .reference
        .strip_prefix(RELEASE_BRANCH_PREFIX)
        .expect("prefix checked");
    let version = Version::parse(branch_version)
        .map_err(|error| format!("release branch version is invalid: {error}"))?;
    if !version.build.is_empty() || release::manifest_version(root)? != version {
        return Err("release branch and manifest versions differ".to_string());
    }

    let source_commit: Commit =
        github.get(&format!("repos/{REPOSITORY}/commits/{}", context.source))?;
    validate_commit(&source_commit, &context.source, true)?;
    let head_commit: Commit = github.get(&format!(
        "repos/{REPOSITORY}/commits/{}",
        release_pr.head.sha
    ))?;
    validate_release_head(&source_commit, &head_commit, release_pr)?;
    let head_signature =
        read_release_head_signature(github, release_pr.number, &release_pr.head.sha)?;
    validate_release_head_signature(&head_commit, &head_signature)?;

    let registry_state = match registry
        .exact_version(TRAITS_PACKAGE.package, &version.to_string())?
    {
        None => "absent",
        Some(record) => {
            if record.num != version.to_string() || record.yanked || !is_checksum(&record.checksum)
            {
                return Err("crates.io returned a conflicting release record".to_string());
            }
            require_archive(
                registry,
                &TRAITS_PACKAGE,
                &version.to_string(),
                &context.source,
            )?;
            "published"
        }
    };
    if mode == QualificationMode::Publish && registry_state != "absent" {
        return Err("release appeared on crates.io during environment approval".to_string());
    }

    Ok(Qualification {
        qualified: true,
        source: context.source.clone(),
        version: Some(version.to_string()),
        registry_state,
        validation_only: false,
    })
}

fn validate_original_run(
    github: &mut impl Transport,
    source: &str,
    run_id: u64,
    attempt: u64,
) -> Result<(), String> {
    let workflow: Workflow = github.get(&format!(
        "repos/{REPOSITORY}/actions/workflows/{RELEASE_WORKFLOW_ID}"
    ))?;
    let run: WorkflowRun = github.get(&format!(
        "repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    ))?;
    let current_run: WorkflowRun =
        github.get(&format!("repos/{REPOSITORY}/actions/runs/{run_id}"))?;
    let artifacts: ArtifactInventory = github.get(&format!(
        "repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=1"
    ))?;
    validate_original_run_payload(
        &workflow,
        &run,
        &current_run,
        &artifacts,
        source,
        run_id,
        attempt,
    )
}

fn validate_original_run_payload(
    workflow: &Workflow,
    run: &WorkflowRun,
    current_run: &WorkflowRun,
    artifacts: &ArtifactInventory,
    source: &str,
    run_id: u64,
    attempt: u64,
) -> Result<(), String> {
    if workflow.id != RELEASE_WORKFLOW_ID
        || workflow.path != RELEASE_WORKFLOW_PATH
        || workflow.state != "active"
    {
        return Err("replacement publication workflow identity differs".to_string());
    }
    if !original_run_matches(workflow, run, source, run_id, attempt)
        || !original_run_matches(workflow, current_run, source, run_id, attempt)
        || run.status != current_run.status
        || run.conclusion != current_run.conclusion
    {
        return Err("original publication run does not bind the recovery source".to_string());
    }
    if artifacts.total_count != 0 || !artifacts.artifacts.is_empty() {
        return Err("original publication run retained an artifact".to_string());
    }
    Ok(())
}

fn original_run_matches(
    workflow: &Workflow,
    run: &WorkflowRun,
    source: &str,
    run_id: u64,
    attempt: u64,
) -> bool {
    run.id == run_id
        && run.run_attempt == attempt
        && run.workflow_id == workflow.id
        && run.path == RELEASE_WORKFLOW_PATH
        && run.event == "push"
        && run.status == "completed"
        && matches!(
            run.conclusion.as_deref(),
            Some("success" | "failure" | "cancelled" | "timed_out" | "action_required")
        )
        && run.head_branch.as_deref() == Some("main")
        && run.head_sha == source
        && run.repository.full_name == REPOSITORY
}

fn select_merged_pull_request<'a>(
    pulls: &'a [PullRequest],
    source: &str,
) -> Result<Option<&'a PullRequest>, String> {
    if pulls.len() >= 100 {
        return Err("commit association inventory is incomplete or oversized".to_string());
    }
    let matches: Vec<_> = pulls
        .iter()
        .filter(|pull| {
            pull.number > 0
                && pull.state == "closed"
                && pull.merged_at.is_some()
                && pull.merge_commit_sha.as_deref() == Some(source)
                && pull.base.reference == "main"
                && pull.base.repository().full_name == REPOSITORY
        })
        .collect();
    if matches.len() > 1 {
        return Err("release source has ambiguous pull request associations".to_string());
    }
    Ok(matches.into_iter().next())
}

fn validate_release_head(source: &Commit, head: &Commit, pull: &PullRequest) -> Result<(), String> {
    if pull.head.repository().full_name != REPOSITORY
        || head.sha != pull.head.sha
        || source.parents.len() != 1
        || head.parents.len() != 1
        || head.parents[0].sha != pull.base.sha
        || source.parents[0].sha != pull.base.sha
        || source.commit.tree.sha != head.commit.tree.sha
    {
        return Err("release PR is not one current commit with the exact merged tree".to_string());
    }
    validate_commit(head, &pull.head.sha, true)
}

fn read_release_head_signature(
    github: &mut impl Transport,
    pull_number: u64,
    expected_oid: &str,
) -> Result<VerifiedSignature, String> {
    if pull_number == 0 {
        return Err("release pull request number is invalid".to_string());
    }
    require_sha(expected_oid, "release pull request head")?;
    let payload = json!({
        "query": RELEASE_SIGNATURE_QUERY,
        "variables": {
            "owner": "NVIDIA",
            "name": "yaml-sigil-traits",
            "number": pull_number,
        },
    });
    let response: SignatureEnvelope = github.graphql(&payload)?;
    if response.errors.is_some() {
        return Err("release signature query returned errors".to_string());
    }
    let repository = response
        .data
        .repository
        .ok_or_else(|| "release signature repository is missing".to_string())?;
    let pull = repository
        .pull_request
        .ok_or_else(|| "release signature pull request is missing".to_string())?;
    let commits = pull.commits;
    if commits.total_count != 1
        || commits.nodes.len() != 1
        || commits.page_info.has_next_page
        || commits.nodes[0].commit.oid != expected_oid
    {
        return Err("release signature inventory is incomplete or changed".to_string());
    }
    commits
        .nodes
        .into_iter()
        .next()
        .and_then(|node| node.commit.signature)
        .ok_or_else(|| "release pull request head signer is missing".to_string())
}

fn validate_release_head_signature(
    commit: &Commit,
    signature: &VerifiedSignature,
) -> Result<(), String> {
    if !matches!(
        signature.kind.as_str(),
        "GpgSignature" | "SshSignature" | "SmimeSignature"
    ) || !signature.is_valid
        || signature.state != "VALID"
        || signature.was_signed_by_github
    {
        return Err("release pull request head is not directly GitHub Verified".to_string());
    }
    let signer = signature
        .signer
        .as_ref()
        .ok_or_else(|| "release pull request head signer is missing".to_string())?;
    if signer.database_id != Some(RELEASE_SIGNER_ID)
        || signer.login != RELEASE_SIGNER_LOGIN
        || signer.kind != "User"
    {
        return Err("release pull request head signer identity differs".to_string());
    }
    let expected_account = |value: Option<&User>, label: &str| -> Result<(), String> {
        let account = value.ok_or_else(|| format!("release {label} account is missing"))?;
        if account.id != RELEASE_SIGNER_ID
            || account.login != RELEASE_SIGNER_LOGIN
            || account.kind != "User"
        {
            return Err(format!(
                "release {label} does not match the verified signer"
            ));
        }
        Ok(())
    };
    expected_account(commit.author.as_ref(), "author")?;
    expected_account(commit.committer.as_ref(), "committer")?;

    let signature_email = signature
        .email
        .as_deref()
        .ok_or_else(|| "release signature email is missing".to_string())?;
    if commit.commit.author.name != RELEASE_AUTHOR_NAME
        || commit.commit.author.email != RELEASE_AUTHOR_EMAIL
        || commit.commit.author.email != signature_email
        || commit.commit.committer.email != signature_email
    {
        return Err("release signature email or raw author identity differs".to_string());
    }
    let author_dco = format!(
        "Signed-off-by: {} <{}>",
        commit.commit.author.name, commit.commit.author.email
    );
    if author_dco != DCO_TRAILER || !commit.commit.message.lines().any(|line| line == author_dco) {
        return Err("release commit lacks the exact raw-author DCO sign-off".to_string());
    }
    Ok(())
}

fn validate_commit(
    commit: &Commit,
    expected_sha: &str,
    require_release_paths: bool,
) -> Result<(), String> {
    if commit.sha != expected_sha
        || commit.parents.len() != 1
        || !is_sha(&commit.commit.tree.sha)
        || !commit.commit.verification.verified
        || commit.commit.verification.reason != "valid"
        || !commit
            .commit
            .message
            .lines()
            .any(|line| line == DCO_TRAILER)
    {
        return Err("release commit signature, parent, or DCO binding differs".to_string());
    }
    if require_release_paths {
        if commit.files.len() != RELEASE_PATHS.len()
            || commit.files.iter().any(|file| {
                file.status != "modified" || file.previous_filename.as_deref().is_some()
            })
        {
            return Err("release commit file status differs from exact modifications".to_string());
        }
        let actual: BTreeSet<_> = commit
            .files
            .iter()
            .map(|file| file.filename.as_str())
            .collect();
        let expected: BTreeSet<_> = RELEASE_PATHS.iter().copied().collect();
        if actual != expected {
            return Err("release commit changed files outside the release transaction".to_string());
        }
    }
    Ok(())
}

fn validate_source_version(root: &Path, version: &Version) -> Result<(), String> {
    if version.build.is_empty() && release::manifest_version(root)? == *version {
        Ok(())
    } else {
        Err("finalizer version differs from exact source".to_string())
    }
}

fn verify_published_source(
    registry: &mut impl Registry,
    context: &Context,
    version: &Version,
) -> Result<(), String> {
    let (_, archive, _) = require_archive(
        registry,
        &TRAITS_PACKAGE,
        &version.to_string(),
        &context.source,
    )?;
    if archive_vcs_commit(&archive, &TRAITS_PACKAGE, &version.to_string())? != context.source {
        return Err("published archive VCS source differs".to_string());
    }
    Ok(())
}

fn await_publication(
    root: &Path,
    registry: &mut impl Registry,
    context: &Context,
    version: &Version,
) -> Result<(), String> {
    validate_source_version(root, version)?;
    wait_for_registry(registry, &version.to_string())?;
    verify_published_source(registry, context, version)
}

fn finalize(
    root: &Path,
    github: &mut impl Transport,
    registry: &mut impl Registry,
    context: &Context,
    version: &Version,
    observed_slug: &str,
) -> Result<(), String> {
    validate_source_version(root, version)?;
    // The App-authorized phase must still be executing the protected policy
    // that started this workflow, even when the release source is historical.
    require_live_policy_main(github, &context.sha)?;
    require_ancestor_of_policy(github, &context.source, &context.sha)?;
    // Recheck the exact registry archive immediately in the App-authorized
    // phase; the preceding credential-free phase owns the bounded wait.
    verify_published_source(registry, context, version)?;
    verify_app_scope(github, observed_slug)?;

    let commit: Commit = github.get(&format!("repos/{REPOSITORY}/commits/{}", context.source))?;
    validate_commit(&commit, &context.source, true)?;
    let body = release_body(root, version)?;
    let spec = ReleaseSpec {
        version: version.clone(),
        tag: TRAITS_PACKAGE.tag(&version.to_string()),
        body,
        source: context.source.clone(),
        tagger_date: commit.commit.committer.date.clone(),
    };

    // Close the read/mutation gap: current protected policy and the retained
    // source lineage must still be exact immediately before the first write.
    require_ancestor_of_policy(github, &context.source, &context.sha)?;
    require_live_policy_main(github, &context.sha)?;
    let tag_object_sha = reconcile_tag(github, &spec, &context.sha)?;
    reconcile_release(github, &spec, &tag_object_sha, &context.sha)?;
    eprintln!(
        "github: finalized immutable zero-asset {} at {}",
        spec.tag, spec.source
    );
    Ok(())
}

fn wait_for_registry(registry: &mut impl Registry, version: &str) -> Result<(), String> {
    const ATTEMPTS: usize = 60;
    for attempt in 1..=ATTEMPTS {
        if registry
            .exact_version(TRAITS_PACKAGE.package, version)?
            .is_some()
        {
            return Ok(());
        }
        if attempt == ATTEMPTS {
            return Err(format!(
                "crates.io did not expose {} {version} within ten minutes",
                TRAITS_PACKAGE.package
            ));
        }
        thread::sleep(Duration::from_secs(10));
    }
    unreachable!("bounded registry wait always returns")
}

fn verify_app_scope(github: &mut impl Transport, observed_slug: &str) -> Result<(), String> {
    if observed_slug != APP_SLUG {
        return Err("finalizer App slug differs from compiled policy".to_string());
    }
    let installation: InstallationRepositories =
        github.get("installation/repositories?per_page=100")?;
    validate_app_scope_payload(&installation)
}

fn validate_app_scope_payload(installation: &InstallationRepositories) -> Result<(), String> {
    let names: Vec<_> = installation
        .repositories
        .iter()
        .map(|repository| repository.full_name.as_str())
        .collect();
    if installation.total_count != 1 || names != [REPOSITORY] {
        return Err("finalizer token is not scoped to exactly this repository".to_string());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseSpec {
    version: Version,
    tag: String,
    body: String,
    source: String,
    tagger_date: String,
}

impl ReleaseSpec {
    fn tag_message(&self) -> String {
        format!("Release {} {}", TRAITS_PACKAGE.package, self.version)
    }
}

fn reconcile_tag(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    policy_sha: &str,
) -> Result<String, String> {
    if let Some(object_sha) = inspect_tag(github, spec)? {
        return Ok(object_sha);
    }
    require_ancestor_of_policy(github, &spec.source, policy_sha)?;
    require_live_policy_main(github, policy_sha)?;
    let object: AnnotatedTag = github.mutate(
        "POST",
        &format!("repos/{REPOSITORY}/git/tags"),
        &json!({
            "tag": spec.tag,
            "message": spec.tag_message(),
            "object": spec.source,
            "type": "commit",
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": spec.tagger_date,
            },
        }),
    )?;
    validate_tag_object(&object, spec)?;
    // The annotated object is not reachable until its ref exists. Rebind
    // current policy once more so a move between the two POSTs cannot expose
    // a tag authorized by stale policy.
    require_ancestor_of_policy(github, &spec.source, policy_sha)?;
    require_live_policy_main(github, policy_sha)?;
    let mutation: Result<GitRef, String> = github.mutate(
        "POST",
        &format!("repos/{REPOSITORY}/git/refs"),
        &json!({"ref": format!("refs/tags/{}", spec.tag), "sha": object.sha}),
    );
    if let Err(error) = mutation {
        let retained = inspect_tag(github, spec)?;
        if retained.as_deref() != Some(object.sha.as_str()) {
            return Err(error);
        }
    }
    if inspect_tag(github, spec)?.as_deref() != Some(object.sha.as_str()) {
        return Err("GitHub did not retain the exact annotated tag".to_string());
    }
    Ok(object.sha)
}

fn inspect_tag(github: &mut impl Transport, spec: &ReleaseSpec) -> Result<Option<String>, String> {
    let path = format!(
        "repos/{REPOSITORY}/git/ref/tags/{}",
        percent_encode(&spec.tag)
    );
    let Some(reference): Option<GitRef> = github.get_optional(&path)? else {
        return Ok(None);
    };
    if reference.name != format!("refs/tags/{}", spec.tag)
        || reference.object.kind != "tag"
        || !is_sha(&reference.object.sha)
    {
        return Err("release tag ref is not one annotated tag".to_string());
    }
    let object: AnnotatedTag = github.get(&format!(
        "repos/{REPOSITORY}/git/tags/{}",
        reference.object.sha
    ))?;
    validate_tag_object(&object, spec)?;
    if object.sha != reference.object.sha {
        return Err("annotated tag object readback differs".to_string());
    }
    Ok(Some(reference.object.sha))
}

fn require_exact_tag_object(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    expected_object_sha: &str,
) -> Result<(), String> {
    require_sha(expected_object_sha, "annotated tag object")?;
    match inspect_tag(github, spec)? {
        Some(observed) if observed == expected_object_sha => Ok(()),
        Some(_) => Err("annotated tag ref changed to another object".to_string()),
        None => Err("the exact annotated tag is missing".to_string()),
    }
}

fn validate_tag_object(object: &AnnotatedTag, spec: &ReleaseSpec) -> Result<(), String> {
    if !is_sha(&object.sha)
        || object.tag != spec.tag
        || object.message != spec.tag_message()
        || object.object.kind != "commit"
        || object.object.sha != spec.source
        || object.tagger.name != APP_LOGIN
        || object.tagger.email != APP_EMAIL
        || object.tagger.date != spec.tagger_date
    {
        return Err("annotated tag conflicts with deterministic release policy".to_string());
    }
    Ok(())
}

fn reconcile_release(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    tag_object_sha: &str,
    policy_sha: &str,
) -> Result<(), String> {
    if inspect_release(github, spec)? {
        require_exact_tag_object(github, spec, tag_object_sha)?;
        return Ok(());
    }
    require_ancestor_of_policy(github, &spec.source, policy_sha)?;
    require_live_policy_main(github, policy_sha)?;
    require_exact_tag_object(github, spec, tag_object_sha)?;
    let mutation: Result<GitHubRelease, String> = github.mutate(
        "POST",
        &format!("repos/{REPOSITORY}/releases"),
        &json!({
            "tag_name": spec.tag,
            "target_commitish": spec.source,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": !spec.version.pre.is_empty(),
            "generate_release_notes": false,
        }),
    );
    match mutation {
        Ok(release) => validate_release(&release, spec)?,
        Err(_error) if inspect_release(github, spec)? => {}
        Err(error) => return Err(error),
    }
    if !inspect_release(github, spec)? {
        return Err("GitHub did not retain the immutable zero-asset Release".to_string());
    }
    require_exact_tag_object(github, spec, tag_object_sha)?;
    Ok(())
}

fn inspect_release(github: &mut impl Transport, spec: &ReleaseSpec) -> Result<bool, String> {
    let path = format!(
        "repos/{REPOSITORY}/releases/tags/{}",
        percent_encode(&spec.tag)
    );
    let Some(release): Option<GitHubRelease> = github.get_optional(&path)? else {
        return Ok(false);
    };
    validate_release(&release, spec)?;
    Ok(true)
}

fn validate_release(release: &GitHubRelease, spec: &ReleaseSpec) -> Result<(), String> {
    if release.id == 0
        || release.tag_name != spec.tag
        || release.target_commitish != spec.source
        || release.name != spec.tag
        || release.body != spec.body
        || release.draft
        || release.prerelease != !spec.version.pre.is_empty()
        || !release.immutable
        || release.author.login != APP_LOGIN
        || release.author.id != APP_ID
        || release.author.kind != "Bot"
        || !release.assets.is_empty()
    {
        return Err("GitHub Release is not exact, immutable, and zero-asset".to_string());
    }
    Ok(())
}

fn release_body(root: &Path, version: &Version) -> Result<String, String> {
    let changelog = safe_file::read_manifest(root, Path::new(TRAITS_PACKAGE.changelog))
        .map_err(|error| format!("read changelog: {error}"))?;
    let heading = format!("## [{version}]");
    let mut inside = false;
    let mut lines = Vec::new();
    for line in changelog.lines() {
        if is_changelog_heading(line, &heading) {
            if inside {
                return Err("release changelog heading is duplicated".to_string());
            }
            inside = true;
            continue;
        }
        if inside && line.starts_with("## ") {
            break;
        }
        if inside {
            lines.push(line);
        }
    }
    if !inside {
        return Err("release changelog heading is missing".to_string());
    }
    let body = lines.join("\n").trim().to_string();
    if body.is_empty() {
        return Err("release changelog section is empty".to_string());
    }
    Ok(format!("{body}\n"))
}

fn is_changelog_heading(line: &str, heading: &str) -> bool {
    line.strip_prefix(heading).is_some_and(|suffix| {
        suffix.is_empty() || suffix.starts_with('(') || suffix.starts_with(" - ")
    })
}

fn require_live_policy_main(github: &mut impl Transport, policy_sha: &str) -> Result<(), String> {
    let reference: GitRef = github.get(&format!("repos/{REPOSITORY}/git/ref/heads/main"))?;
    if reference.name != "refs/heads/main"
        || reference.object.kind != "commit"
        || reference.object.sha != policy_sha
    {
        return Err("protected main differs from the staged policy SHA".to_string());
    }
    Ok(())
}

fn require_ancestor_of_policy(
    github: &mut impl Transport,
    source: &str,
    policy_sha: &str,
) -> Result<(), String> {
    let comparison: Comparison = github.get(&format!(
        "repos/{REPOSITORY}/compare/{source}...{policy_sha}?per_page=1&page=1"
    ))?;
    let status_is_exact = if source == policy_sha {
        comparison.status == "identical"
    } else {
        comparison.status == "ahead"
    };
    if !status_is_exact
        || comparison.base_commit.sha != source
        || comparison.merge_base_commit.sha != source
    {
        return Err("release source is not on the protected current-main lineage".to_string());
    }
    Ok(())
}

fn require_sha(value: &str, label: &str) -> Result<(), String> {
    if is_sha(value) {
        Ok(())
    } else {
        Err(format!("{label} must be a lowercase 40-character SHA"))
    }
}

fn is_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone, Debug, Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PullSide {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
    repo: Repository,
}

impl PullSide {
    fn repository(&self) -> &Repository {
        &self.repo
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PullRequest {
    number: u64,
    state: String,
    merged_at: Option<String>,
    merge_commit_sha: Option<String>,
    base: PullSide,
    head: PullSide,
}

#[derive(Clone, Debug, Deserialize)]
struct Commit {
    sha: String,
    author: Option<User>,
    committer: Option<User>,
    commit: CommitBody,
    parents: Vec<GitObject>,
    files: Vec<CommitFile>,
}

#[derive(Clone, Debug, Deserialize)]
struct CommitBody {
    message: String,
    author: GitSignature,
    committer: GitSignature,
    tree: GitObject,
    verification: Verification,
}

#[derive(Clone, Debug, Deserialize)]
struct Verification {
    verified: bool,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureEnvelope {
    data: SignatureData,
    #[serde(default)]
    errors: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureData {
    repository: Option<SignatureRepository>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureRepository {
    #[serde(rename = "pullRequest")]
    pull_request: Option<SignaturePullRequest>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignaturePullRequest {
    commits: SignatureCommitConnection,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureCommitConnection {
    #[serde(rename = "totalCount")]
    total_count: usize,
    nodes: Vec<SignatureNode>,
    #[serde(rename = "pageInfo")]
    page_info: SignaturePageInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct SignaturePageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureNode {
    commit: SignatureCommit,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureCommit {
    oid: String,
    signature: Option<VerifiedSignature>,
}

#[derive(Clone, Debug, Deserialize)]
struct VerifiedSignature {
    #[serde(rename = "__typename")]
    kind: String,
    email: Option<String>,
    #[serde(rename = "isValid")]
    is_valid: bool,
    state: String,
    #[serde(rename = "wasSignedByGitHub")]
    was_signed_by_github: bool,
    signer: Option<SignatureSigner>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignatureSigner {
    #[serde(rename = "databaseId")]
    database_id: Option<u64>,
    login: String,
    #[serde(rename = "__typename")]
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CommitFile {
    filename: String,
    status: String,
    #[serde(default)]
    previous_filename: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Comparison {
    status: String,
    base_commit: GitObject,
    merge_base_commit: GitObject,
}

#[derive(Clone, Debug, Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GitRef {
    #[serde(rename = "ref")]
    name: String,
    object: GitObject,
}

#[derive(Clone, Debug, Deserialize)]
struct Workflow {
    id: u64,
    path: String,
    state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct WorkflowRun {
    id: u64,
    run_attempt: u64,
    workflow_id: u64,
    path: String,
    event: String,
    status: String,
    conclusion: Option<String>,
    head_branch: Option<String>,
    head_sha: String,
    repository: Repository,
}

#[derive(Clone, Debug, Deserialize)]
struct ArtifactInventory {
    total_count: usize,
    artifacts: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct InstallationRepositories {
    total_count: usize,
    repositories: Vec<Repository>,
}

#[derive(Clone, Debug, Deserialize)]
struct User {
    login: String,
    id: u64,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AnnotatedTag {
    sha: String,
    tag: String,
    message: String,
    object: GitObject,
    tagger: GitSignature,
}

#[derive(Clone, Debug, Deserialize)]
struct GitSignature {
    name: String,
    email: String,
    date: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubRelease {
    id: u64,
    tag_name: String,
    target_commitish: String,
    name: String,
    body: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    author: User,
    assets: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    struct FakeGithub {
        responses: BTreeMap<String, Value>,
    }

    impl Transport for FakeGithub {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            let value = self
                .responses
                .get(path)
                .cloned()
                .ok_or_else(|| format!("unexpected GitHub read: {path}"))?;
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            self.responses
                .get(path)
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| error.to_string())
        }

        fn graphql<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            payload: &P,
        ) -> Result<T, String> {
            let request = serde_json::to_value(payload).map_err(|error| error.to_string())?;
            if request
                != json!({
                    "query": RELEASE_SIGNATURE_QUERY,
                    "variables": {
                        "owner": "NVIDIA",
                        "name": "yaml-sigil-traits",
                        "number": 7,
                    },
                })
            {
                return Err("unexpected GitHub GraphQL request".to_string());
            }
            let value = self
                .responses
                .get("graphql:release-signature")
                .cloned()
                .ok_or_else(|| "unexpected GitHub GraphQL read".to_string())?;
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn mutate<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            _method: &str,
            path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            Err(format!("unexpected GitHub mutation: {path}"))
        }
    }

    #[derive(Default)]
    struct CountingRegistry {
        exact_version_calls: usize,
    }

    impl Registry for CountingRegistry {
        fn exact_version(
            &mut self,
            _package: &str,
            _version: &str,
        ) -> Result<Option<crate::crate_archive::RegistryVersion>, String> {
            self.exact_version_calls += 1;
            Err("unexpected registry read".to_string())
        }

        fn download(&mut self, _package: &str, _version: &str) -> Result<Vec<u8>, String> {
            Err("unexpected registry download".to_string())
        }
    }

    struct TagMutationGapGithub {
        main_reads: usize,
        tag_posts: usize,
        ref_posts: usize,
        policy: String,
        moved: String,
        spec: ReleaseSpec,
    }

    impl Transport for TagMutationGapGithub {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            let main_path = format!("repos/{REPOSITORY}/git/ref/heads/main");
            let compare_path = format!(
                "repos/{REPOSITORY}/compare/{}...{}?per_page=1&page=1",
                self.spec.source, self.policy
            );
            let value = if path == main_path {
                let sha = if self.main_reads == 0 {
                    &self.policy
                } else {
                    &self.moved
                };
                self.main_reads += 1;
                json!({
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": sha},
                })
            } else if path == compare_path {
                json!({
                    "status": "ahead",
                    "base_commit": {"sha": self.spec.source},
                    "merge_base_commit": {"sha": self.spec.source},
                })
            } else {
                return Err(format!("unexpected GitHub read: {path}"));
            };
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            let expected = format!("repos/{REPOSITORY}/git/ref/tags/{}", self.spec.tag);
            if path == expected {
                Ok(None)
            } else {
                Err(format!("unexpected optional GitHub read: {path}"))
            }
        }

        fn mutate<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            method: &str,
            path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            if method != "POST" {
                return Err(format!("unexpected GitHub mutation method: {method}"));
            }
            if path == format!("repos/{REPOSITORY}/git/tags") {
                self.tag_posts += 1;
                serde_json::from_value(json!({
                    "sha": "d".repeat(40),
                    "tag": self.spec.tag,
                    "message": self.spec.tag_message(),
                    "object": {"type": "commit", "sha": self.spec.source},
                    "tagger": {
                        "name": APP_LOGIN,
                        "email": APP_EMAIL,
                        "date": self.spec.tagger_date,
                    },
                }))
                .map_err(|error| error.to_string())
            } else if path == format!("repos/{REPOSITORY}/git/refs") {
                self.ref_posts += 1;
                Err("unexpected visible tag-ref mutation".to_string())
            } else {
                Err(format!("unexpected GitHub mutation: {path}"))
            }
        }
    }

    struct ReleaseMutationGapGithub {
        compare_reads: usize,
        main_reads: usize,
        release_posts: usize,
        policy: String,
        moved: String,
        spec: ReleaseSpec,
    }

    impl Transport for ReleaseMutationGapGithub {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            let main_path = format!("repos/{REPOSITORY}/git/ref/heads/main");
            let compare_path = format!(
                "repos/{REPOSITORY}/compare/{}...{}?per_page=1&page=1",
                self.spec.source, self.policy
            );
            let value = if path == compare_path {
                self.compare_reads += 1;
                json!({
                    "status": "ahead",
                    "base_commit": {"sha": self.spec.source},
                    "merge_base_commit": {"sha": self.spec.source},
                })
            } else if path == main_path {
                self.main_reads += 1;
                if self.compare_reads != 1 {
                    return Err("live-main read did not follow the ancestry read".to_string());
                }
                json!({
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": self.moved},
                })
            } else {
                return Err(format!("unexpected GitHub read: {path}"));
            };
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            let expected = format!("repos/{REPOSITORY}/releases/tags/{}", self.spec.tag);
            if path == expected {
                Ok(None)
            } else {
                Err(format!("unexpected optional GitHub read: {path}"))
            }
        }

        fn mutate<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            method: &str,
            path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            if method == "POST" && path == format!("repos/{REPOSITORY}/releases") {
                self.release_posts += 1;
                Err("unexpected Release mutation".to_string())
            } else {
                Err(format!("unexpected GitHub mutation: {path}"))
            }
        }
    }

    #[derive(Clone, Copy)]
    enum TagDriftAfterRelease {
        Deleted,
        LightweightReplacement,
        ObjectReplacement,
        SemanticallyIdenticalObjectReplacement,
        SourceDrift,
    }

    struct ReleaseTagMutationGapGithub {
        policy: String,
        release_posts: usize,
        release_reads: usize,
        tag_reads: usize,
        tag_object_sha: String,
        drift: TagDriftAfterRelease,
        spec: ReleaseSpec,
    }

    impl Transport for ReleaseTagMutationGapGithub {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            let compare_path = format!(
                "repos/{REPOSITORY}/compare/{}...{}?per_page=1&page=1",
                self.spec.source, self.policy
            );
            let main_path = format!("repos/{REPOSITORY}/git/ref/heads/main");
            let object_path = format!("repos/{REPOSITORY}/git/tags/{}", self.tag_object_sha);
            let value = if path == compare_path {
                json!({
                    "status": "ahead",
                    "base_commit": {"sha": self.spec.source},
                    "merge_base_commit": {"sha": self.spec.source},
                })
            } else if path == main_path {
                json!({
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": self.policy},
                })
            } else if path == object_path && self.release_posts == 0 {
                annotated_tag_json(&self.spec, &self.tag_object_sha)
            } else if path == format!("repos/{REPOSITORY}/git/tags/{}", "e".repeat(40))
                && self.release_posts > 0
            {
                let mut replacement = annotated_tag_json(&self.spec, &"e".repeat(40));
                match self.drift {
                    TagDriftAfterRelease::ObjectReplacement => {
                        replacement["message"] = json!("replacement tag object");
                    }
                    TagDriftAfterRelease::SemanticallyIdenticalObjectReplacement => {}
                    TagDriftAfterRelease::SourceDrift => {
                        replacement["object"]["sha"] = json!("f".repeat(40));
                    }
                    TagDriftAfterRelease::Deleted
                    | TagDriftAfterRelease::LightweightReplacement => {
                        return Err("unexpected replacement tag object read".to_string());
                    }
                }
                replacement
            } else {
                return Err(format!("unexpected GitHub read: {path}"));
            };
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            let release_path = format!("repos/{REPOSITORY}/releases/tags/{}", self.spec.tag);
            let tag_path = format!("repos/{REPOSITORY}/git/ref/tags/{}", self.spec.tag);
            let value = if path == release_path {
                self.release_reads += 1;
                (self.release_posts > 0).then(|| github_release_json(&self.spec))
            } else if path == tag_path {
                self.tag_reads += 1;
                if self.release_posts == 0 {
                    Some(tag_reference_json(&self.spec, &self.tag_object_sha))
                } else {
                    match self.drift {
                        TagDriftAfterRelease::Deleted => None,
                        TagDriftAfterRelease::LightweightReplacement => Some(json!({
                            "ref": format!("refs/tags/{}", self.spec.tag),
                            "object": {"type": "commit", "sha": self.spec.source},
                        })),
                        TagDriftAfterRelease::ObjectReplacement
                        | TagDriftAfterRelease::SemanticallyIdenticalObjectReplacement
                        | TagDriftAfterRelease::SourceDrift => Some(json!({
                            "ref": format!("refs/tags/{}", self.spec.tag),
                            "object": {"type": "tag", "sha": "e".repeat(40)},
                        })),
                    }
                }
            } else {
                return Err(format!("unexpected optional GitHub read: {path}"));
            };
            value
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| error.to_string())
        }

        fn mutate<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            method: &str,
            path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            if method == "POST" && path == format!("repos/{REPOSITORY}/releases") {
                self.release_posts += 1;
                serde_json::from_value(github_release_json(&self.spec))
                    .map_err(|error| error.to_string())
            } else {
                Err(format!("unexpected GitHub mutation: {path}"))
            }
        }
    }

    fn main_only_github(main: &str, pulls: Value) -> FakeGithub {
        FakeGithub {
            responses: BTreeMap::from([
                (
                    format!("repos/{REPOSITORY}/git/ref/heads/main"),
                    json!({
                        "ref": "refs/heads/main",
                        "object": {"type": "commit", "sha": main},
                    }),
                ),
                (
                    format!("repos/{REPOSITORY}/commits/{main}/pulls?per_page=100&page=1"),
                    pulls,
                ),
            ]),
        }
    }

    fn repository() -> Repository {
        Repository {
            full_name: REPOSITORY.to_string(),
        }
    }

    fn side(reference: &str, sha: &str) -> PullSide {
        PullSide {
            reference: reference.to_string(),
            sha: sha.to_string(),
            repo: repository(),
        }
    }

    fn pull(source: &str) -> PullRequest {
        PullRequest {
            number: 7,
            state: "closed".to_string(),
            merged_at: Some("2026-09-04T00:00:00Z".to_string()),
            merge_commit_sha: Some(source.to_string()),
            base: side("main", &"b".repeat(40)),
            head: side("release-plz-manual-0.4.0-rc.3", &"c".repeat(40)),
        }
    }

    fn commit(sha: &str, parent: &str, files: &[&str]) -> Commit {
        Commit {
            sha: sha.to_string(),
            author: Some(User {
                login: RELEASE_SIGNER_LOGIN.to_string(),
                id: RELEASE_SIGNER_ID,
                kind: "User".to_string(),
            }),
            committer: Some(User {
                login: RELEASE_SIGNER_LOGIN.to_string(),
                id: RELEASE_SIGNER_ID,
                kind: "User".to_string(),
            }),
            commit: CommitBody {
                message: format!("chore(release): prepare\n\n{DCO_TRAILER}"),
                author: GitSignature {
                    name: RELEASE_AUTHOR_NAME.to_string(),
                    email: RELEASE_AUTHOR_EMAIL.to_string(),
                    date: "2026-09-04T00:00:00Z".to_string(),
                },
                committer: GitSignature {
                    name: RELEASE_AUTHOR_NAME.to_string(),
                    email: RELEASE_AUTHOR_EMAIL.to_string(),
                    date: "2026-09-04T00:00:00Z".to_string(),
                },
                tree: GitObject {
                    sha: "e".repeat(40),
                    kind: "tree".to_string(),
                },
                verification: Verification {
                    verified: true,
                    reason: "valid".to_string(),
                },
            },
            parents: vec![GitObject {
                sha: parent.to_string(),
                kind: "commit".to_string(),
            }],
            files: files
                .iter()
                .map(|filename| CommitFile {
                    filename: (*filename).to_string(),
                    status: "modified".to_string(),
                    previous_filename: None,
                })
                .collect(),
        }
    }

    fn release_signature() -> VerifiedSignature {
        VerifiedSignature {
            kind: "SshSignature".to_string(),
            email: Some(RELEASE_AUTHOR_EMAIL.to_string()),
            is_valid: true,
            state: "VALID".to_string(),
            was_signed_by_github: false,
            signer: Some(SignatureSigner {
                database_id: Some(RELEASE_SIGNER_ID),
                login: RELEASE_SIGNER_LOGIN.to_string(),
                kind: "User".to_string(),
            }),
        }
    }

    fn release_signature_response(head: &str) -> Value {
        json!({
            "data": {
                "repository": {
                    "pullRequest": {
                        "commits": {
                            "totalCount": 1,
                            "nodes": [{
                                "commit": {
                                    "oid": head,
                                    "signature": {
                                        "__typename": "SshSignature",
                                        "email": RELEASE_AUTHOR_EMAIL,
                                        "isValid": true,
                                        "state": "VALID",
                                        "wasSignedByGitHub": false,
                                        "signer": {
                                            "databaseId": RELEASE_SIGNER_ID,
                                            "login": RELEASE_SIGNER_LOGIN,
                                            "__typename": "User",
                                        },
                                    },
                                },
                            }],
                            "pageInfo": {"hasNextPage": false},
                        },
                    },
                },
            },
        })
    }

    fn workflow() -> Workflow {
        Workflow {
            id: RELEASE_WORKFLOW_ID,
            path: RELEASE_WORKFLOW_PATH.to_string(),
            state: "active".to_string(),
        }
    }

    fn workflow_run(source: &str) -> WorkflowRun {
        WorkflowRun {
            id: 789,
            run_attempt: 2,
            workflow_id: RELEASE_WORKFLOW_ID,
            path: RELEASE_WORKFLOW_PATH.to_string(),
            event: "push".to_string(),
            status: "completed".to_string(),
            conclusion: Some("failure".to_string()),
            head_branch: Some("main".to_string()),
            head_sha: source.to_string(),
            repository: repository(),
        }
    }

    fn no_artifacts() -> ArtifactInventory {
        ArtifactInventory {
            total_count: 0,
            artifacts: Vec::new(),
        }
    }

    fn release_spec() -> ReleaseSpec {
        ReleaseSpec {
            version: Version::parse("0.4.0-rc.3").unwrap(),
            tag: "v0.4.0-rc.3".to_string(),
            body: "notes\n".to_string(),
            source: "a".repeat(40),
            tagger_date: "2026-09-04T00:00:00Z".to_string(),
        }
    }

    fn annotated_tag_json(spec: &ReleaseSpec, object_sha: &str) -> Value {
        json!({
            "sha": object_sha,
            "tag": spec.tag,
            "message": spec.tag_message(),
            "object": {"type": "commit", "sha": spec.source},
            "tagger": {
                "name": APP_LOGIN,
                "email": APP_EMAIL,
                "date": spec.tagger_date,
            },
        })
    }

    fn tag_reference_json(spec: &ReleaseSpec, object_sha: &str) -> Value {
        json!({
            "ref": format!("refs/tags/{}", spec.tag),
            "object": {"type": "tag", "sha": object_sha},
        })
    }

    fn github_release(spec: &ReleaseSpec) -> GitHubRelease {
        GitHubRelease {
            id: 1,
            tag_name: spec.tag.clone(),
            target_commitish: spec.source.clone(),
            name: spec.tag.clone(),
            body: spec.body.clone(),
            draft: false,
            prerelease: true,
            immutable: true,
            author: User {
                login: APP_LOGIN.to_string(),
                id: APP_ID,
                kind: "Bot".to_string(),
            },
            assets: Vec::new(),
        }
    }

    fn github_release_json(spec: &ReleaseSpec) -> Value {
        json!({
            "id": 1,
            "tag_name": spec.tag,
            "target_commitish": spec.source,
            "name": spec.tag,
            "body": spec.body,
            "draft": false,
            "prerelease": true,
            "immutable": true,
            "author": {
                "login": APP_LOGIN,
                "id": APP_ID,
                "type": "Bot",
            },
            "assets": [],
        })
    }

    #[test]
    fn pull_association_is_exact_and_unambiguous() {
        let source = "a".repeat(40);
        let valid = pull(&source);
        assert_eq!(
            select_merged_pull_request(std::slice::from_ref(&valid), &source)
                .unwrap()
                .map(|pull| pull.number),
            Some(7)
        );
        assert!(select_merged_pull_request(&[valid.clone(), valid], &source).is_err());
        assert!(select_merged_pull_request(&vec![pull(&source); 100], &source).is_err());
        assert!(
            select_merged_pull_request(&[pull(&"d".repeat(40))], &source)
                .unwrap()
                .is_none()
        );

        let mut wrong_base = pull(&source);
        wrong_base.base.reference = "develop".to_string();
        assert!(
            select_merged_pull_request(&[wrong_base], &source)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_main_push_is_a_noop_before_registry_reconciliation() {
        let source = "a".repeat(40);
        let mut github = main_only_github(&source, json!([]));
        let mut registry = CountingRegistry::default();
        let context = Context {
            source: source.clone(),
            event: "push".to_string(),
            sha: source,
        };

        let result = qualify(
            &crate::workspace_root(),
            &mut github,
            &mut registry,
            &context,
            QualificationMode::Push,
            None,
            None,
        )
        .unwrap();
        assert!(!result.qualified);
        assert_eq!(registry.exact_version_calls, 0);
    }

    #[test]
    fn post_approval_requalification_rejects_moved_main_before_registry_reads() {
        let source = "a".repeat(40);
        let policy = "b".repeat(40);
        let moved = "c".repeat(40);
        let mut github = main_only_github(&moved, json!([]));
        let mut registry = CountingRegistry::default();
        let context = Context {
            source: source.clone(),
            event: "push".to_string(),
            sha: policy,
        };

        assert!(
            qualify(
                &crate::workspace_root(),
                &mut github,
                &mut registry,
                &context,
                QualificationMode::Publish,
                None,
                None,
            )
            .is_err()
        );
        assert_eq!(registry.exact_version_calls, 0);
    }

    #[test]
    fn live_main_must_equal_staged_policy_sha() {
        let policy = "a".repeat(40);
        let mut exact = main_only_github(&policy, json!([]));
        require_live_policy_main(&mut exact, &policy).unwrap();

        let mut moved = main_only_github(&"b".repeat(40), json!([]));
        assert!(require_live_policy_main(&mut moved, &policy).is_err());
    }

    #[test]
    fn recovery_source_must_be_on_exact_policy_lineage() {
        let source = "a".repeat(40);
        let policy = "b".repeat(40);
        let path = format!("repos/{REPOSITORY}/compare/{source}...{policy}?per_page=1&page=1");
        let comparison = |status: &str, base: &str, merge_base: &str| {
            json!({
                "status": status,
                "base_commit": {"sha": base},
                "merge_base_commit": {"sha": merge_base},
            })
        };

        let mut github = FakeGithub {
            responses: BTreeMap::from([(path.clone(), comparison("ahead", &source, &source))]),
        };
        require_ancestor_of_policy(&mut github, &source, &policy).unwrap();

        let mut identical = FakeGithub {
            responses: BTreeMap::from([(
                format!("repos/{REPOSITORY}/compare/{source}...{source}?per_page=1&page=1"),
                comparison("identical", &source, &source),
            )]),
        };
        require_ancestor_of_policy(&mut identical, &source, &source).unwrap();

        for invalid in [
            comparison("behind", &source, &source),
            comparison("ahead", &policy, &source),
            comparison("ahead", &source, &"d".repeat(40)),
        ] {
            let mut github = FakeGithub {
                responses: BTreeMap::from([(path.clone(), invalid)]),
            };
            assert!(require_ancestor_of_policy(&mut github, &source, &policy).is_err());
        }
    }

    #[test]
    fn release_commits_reject_each_binding_drift() {
        let source = "a".repeat(40);
        let mut value = commit(&source, &"b".repeat(40), RELEASE_PATHS);
        validate_commit(&value, &source, true).unwrap();

        value.commit.verification.verified = false;
        assert!(validate_commit(&value, &source, true).is_err());
        value.commit.verification.verified = true;
        value.commit.message = "unsigned-off release".to_string();
        assert!(validate_commit(&value, &source, true).is_err());
        value.commit.message = format!("release\n\n{DCO_TRAILER}");
        value.files.push(CommitFile {
            filename: "src/lib.rs".to_string(),
            status: "modified".to_string(),
            previous_filename: None,
        });
        assert!(validate_commit(&value, &source, true).is_err());

        value = commit(&source, &"b".repeat(40), RELEASE_PATHS);
        value.files[0].status = "removed".to_string();
        assert!(validate_commit(&value, &source, true).is_err());
    }

    #[test]
    fn release_head_requires_exact_verified_signer_author_and_dco() {
        let source = "a".repeat(40);
        let valid = commit(&source, &"b".repeat(40), RELEASE_PATHS);
        let signature = release_signature();
        validate_release_head_signature(&valid, &signature).unwrap();

        let mut wrong = signature.clone();
        wrong.signer.as_mut().unwrap().database_id = Some(RELEASE_SIGNER_ID + 1);
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.signer.as_mut().unwrap().login = "lookalike".to_string();
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.email = Some("lookalike@example.invalid".to_string());
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.was_signed_by_github = true;
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.is_valid = false;
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.signer.as_mut().unwrap().kind = "Bot".to_string();
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        wrong = signature.clone();
        wrong.signer = None;
        assert!(validate_release_head_signature(&valid, &wrong).is_err());

        let mut missing_account = valid.clone();
        missing_account.author = None;
        assert!(validate_release_head_signature(&missing_account, &signature).is_err());

        let mut wrong_account = valid.clone();
        wrong_account.committer.as_mut().unwrap().id += 1;
        assert!(validate_release_head_signature(&wrong_account, &signature).is_err());

        let mut wrong_raw_author = valid.clone();
        wrong_raw_author.commit.author.name = "Lookalike".to_string();
        assert!(validate_release_head_signature(&wrong_raw_author, &signature).is_err());

        let mut wrong_raw_committer = valid.clone();
        wrong_raw_committer.commit.committer.email = "lookalike@example.invalid".to_string();
        assert!(validate_release_head_signature(&wrong_raw_committer, &signature).is_err());

        let mut forged_dco = valid;
        forged_dco.commit.message =
            format!("chore(release): prepare\n\nSigned-off-by: Lookalike <{RELEASE_AUTHOR_EMAIL}>");
        assert!(validate_release_head_signature(&forged_dco, &signature).is_err());
    }

    #[test]
    fn release_signature_query_is_exact_and_complete() {
        let head = "c".repeat(40);
        let mut github = FakeGithub {
            responses: BTreeMap::from([(
                "graphql:release-signature".to_string(),
                release_signature_response(&head),
            )]),
        };
        let signature = read_release_head_signature(&mut github, 7, &head).unwrap();
        assert_eq!(
            signature.signer.unwrap().database_id,
            Some(RELEASE_SIGNER_ID)
        );

        let mut incomplete = release_signature_response(&head);
        incomplete["data"]["repository"]["pullRequest"]["commits"]["totalCount"] = json!(2);
        let mut github = FakeGithub {
            responses: BTreeMap::from([("graphql:release-signature".to_string(), incomplete)]),
        };
        assert!(read_release_head_signature(&mut github, 7, &head).is_err());

        let mut null = release_signature_response(&head);
        null["data"]["repository"]["pullRequest"]["commits"]["nodes"][0]["commit"]["signature"]["signer"] =
            Value::Null;
        let response: SignatureEnvelope = serde_json::from_value(null).unwrap();
        let commits = response
            .data
            .repository
            .unwrap()
            .pull_request
            .unwrap()
            .commits;
        let signature = commits.nodes[0].commit.signature.as_ref().unwrap();
        assert!(
            validate_release_head_signature(
                &commit(&head, &"b".repeat(40), RELEASE_PATHS),
                signature
            )
            .is_err()
        );
    }

    #[test]
    fn release_head_must_be_one_commit_current_with_base() {
        let source = "a".repeat(40);
        let pull = pull(&source);
        let merged = commit(&source, &pull.base.sha, RELEASE_PATHS);
        let mut head = commit(&pull.head.sha, &pull.base.sha, RELEASE_PATHS);
        validate_release_head(&merged, &head, &pull).unwrap();
        let wrong_merged_parent = commit(&source, &"d".repeat(40), RELEASE_PATHS);
        assert!(validate_release_head(&wrong_merged_parent, &head, &pull).is_err());
        head.parents[0].sha = "d".repeat(40);
        assert!(validate_release_head(&merged, &head, &pull).is_err());
        head = commit(&pull.head.sha, &pull.base.sha, &["src/lib.rs"]);
        assert!(validate_release_head(&merged, &head, &pull).is_err());
        head = commit(&pull.head.sha, &pull.base.sha, RELEASE_PATHS);
        head.commit.tree.sha = "f".repeat(40);
        assert!(validate_release_head(&merged, &head, &pull).is_err());
    }

    #[test]
    fn release_objects_reject_assets_and_mutability() {
        let spec = release_spec();
        let mut release = github_release(&spec);
        validate_release(&release, &spec).unwrap();
        release.assets.push(json!({"id": 1}));
        assert!(validate_release(&release, &spec).is_err());
        release.assets.clear();
        release.immutable = false;
        assert!(validate_release(&release, &spec).is_err());
    }

    #[test]
    fn finalizer_accepts_only_exact_existing_objects() {
        let spec = release_spec();
        let tag_object_sha = "d".repeat(40);
        let tag_path = format!("repos/{REPOSITORY}/git/ref/tags/{}", spec.tag);
        let object_path = format!("repos/{REPOSITORY}/git/tags/{tag_object_sha}");
        let release_path = format!("repos/{REPOSITORY}/releases/tags/{}", spec.tag);
        let tag = annotated_tag_json(&spec, &tag_object_sha);
        let reference = tag_reference_json(&spec, &tag_object_sha);
        let release = github_release_json(&spec);
        let mut exact = FakeGithub {
            responses: BTreeMap::from([
                (tag_path.clone(), reference.clone()),
                (object_path.clone(), tag.clone()),
                (release_path.clone(), release.clone()),
            ]),
        };
        assert!(inspect_tag(&mut exact, &spec).unwrap().is_some());
        assert!(inspect_release(&mut exact, &spec).unwrap());
        assert_eq!(
            reconcile_tag(&mut exact, &spec, &"b".repeat(40)).unwrap(),
            tag_object_sha
        );
        reconcile_release(&mut exact, &spec, &tag_object_sha, &"b".repeat(40)).unwrap();

        let mut missing = FakeGithub {
            responses: BTreeMap::new(),
        };
        assert!(inspect_tag(&mut missing, &spec).unwrap().is_none());
        assert!(!inspect_release(&mut missing, &spec).unwrap());

        let mut conflicting_tag = tag;
        conflicting_tag["object"]["sha"] = json!("e".repeat(40));
        let mut conflict = FakeGithub {
            responses: BTreeMap::from([
                (tag_path, reference),
                (object_path, conflicting_tag),
                (release_path, release),
            ]),
        };
        assert!(inspect_tag(&mut conflict, &spec).is_err());
        let mut conflicting_release = github_release(&spec);
        conflicting_release.body = "different\n".to_string();
        assert!(validate_release(&conflicting_release, &spec).is_err());
    }

    #[test]
    fn existing_release_path_requires_exact_retained_tag() {
        let spec = release_spec();
        let expected_tag_object = "d".repeat(40);
        let replacement_tag_object = "e".repeat(40);
        let release_path = format!("repos/{REPOSITORY}/releases/tags/{}", spec.tag);
        let mut release_without_tag = FakeGithub {
            responses: BTreeMap::from([(release_path.clone(), github_release_json(&spec))]),
        };

        assert!(
            reconcile_release(
                &mut release_without_tag,
                &spec,
                &expected_tag_object,
                &"b".repeat(40)
            )
            .is_err()
        );

        let mut release_with_replaced_tag = FakeGithub {
            responses: BTreeMap::from([
                (release_path, github_release_json(&spec)),
                (
                    format!("repos/{REPOSITORY}/git/ref/tags/{}", spec.tag),
                    tag_reference_json(&spec, &replacement_tag_object),
                ),
                (
                    format!("repos/{REPOSITORY}/git/tags/{replacement_tag_object}"),
                    annotated_tag_json(&spec, &replacement_tag_object),
                ),
            ]),
        };
        assert_eq!(
            reconcile_release(
                &mut release_with_replaced_tag,
                &spec,
                &expected_tag_object,
                &"b".repeat(40)
            )
            .unwrap_err(),
            "annotated tag ref changed to another object"
        );
    }

    #[test]
    fn release_creation_requires_exact_tag_object_before_post() {
        let spec = release_spec();
        let policy = "b".repeat(40);
        let expected_tag_object = "d".repeat(40);
        let replacement_tag_object = "e".repeat(40);
        let mut github = FakeGithub {
            responses: BTreeMap::from([
                (
                    format!(
                        "repos/{REPOSITORY}/compare/{}...{policy}?per_page=1&page=1",
                        spec.source
                    ),
                    json!({
                        "status": "ahead",
                        "base_commit": {"sha": spec.source},
                        "merge_base_commit": {"sha": spec.source},
                    }),
                ),
                (
                    format!("repos/{REPOSITORY}/git/ref/heads/main"),
                    json!({
                        "ref": "refs/heads/main",
                        "object": {"type": "commit", "sha": policy},
                    }),
                ),
                (
                    format!("repos/{REPOSITORY}/git/ref/tags/{}", spec.tag),
                    tag_reference_json(&spec, &replacement_tag_object),
                ),
                (
                    format!("repos/{REPOSITORY}/git/tags/{replacement_tag_object}"),
                    annotated_tag_json(&spec, &replacement_tag_object),
                ),
            ]),
        };

        assert_eq!(
            reconcile_release(&mut github, &spec, &expected_tag_object, &policy).unwrap_err(),
            "annotated tag ref changed to another object"
        );
    }

    #[test]
    fn tag_ref_creation_rechecks_live_policy_after_object_creation() {
        let spec = release_spec();
        let policy = "b".repeat(40);
        let mut github = TagMutationGapGithub {
            main_reads: 0,
            tag_posts: 0,
            ref_posts: 0,
            policy: policy.clone(),
            moved: "c".repeat(40),
            spec: spec.clone(),
        };

        assert!(reconcile_tag(&mut github, &spec, &policy).is_err());
        assert_eq!(github.main_reads, 2);
        assert_eq!(github.tag_posts, 1);
        assert_eq!(github.ref_posts, 0);
    }

    #[test]
    fn release_creation_reads_live_policy_last_and_rejects_drift() {
        let spec = release_spec();
        let policy = "b".repeat(40);
        let mut github = ReleaseMutationGapGithub {
            compare_reads: 0,
            main_reads: 0,
            release_posts: 0,
            policy: policy.clone(),
            moved: "c".repeat(40),
            spec: spec.clone(),
        };

        assert!(reconcile_release(&mut github, &spec, &"d".repeat(40), &policy).is_err());
        assert_eq!(github.compare_reads, 1);
        assert_eq!(github.main_reads, 1);
        assert_eq!(github.release_posts, 0);
    }

    fn release_tag_drift_error(drift: TagDriftAfterRelease) -> String {
        let spec = release_spec();
        let policy = "b".repeat(40);
        let tag_object_sha = "d".repeat(40);
        let mut github = ReleaseTagMutationGapGithub {
            policy: policy.clone(),
            release_posts: 0,
            release_reads: 0,
            tag_reads: 0,
            tag_object_sha: tag_object_sha.clone(),
            drift,
            spec: spec.clone(),
        };

        let error = reconcile_release(&mut github, &spec, &tag_object_sha, &policy).unwrap_err();
        assert_eq!(github.release_posts, 1);
        assert_eq!(github.release_reads, 2);
        assert_eq!(github.tag_reads, 2);
        error
    }

    #[test]
    fn release_creation_rejects_tag_deletion_and_semantic_drift_after_readback() {
        for drift in [
            TagDriftAfterRelease::Deleted,
            TagDriftAfterRelease::LightweightReplacement,
            TagDriftAfterRelease::ObjectReplacement,
            TagDriftAfterRelease::SourceDrift,
        ] {
            let _ = release_tag_drift_error(drift);
        }
    }

    #[test]
    fn release_creation_rejects_semantically_identical_tag_object_replacement() {
        assert_eq!(
            release_tag_drift_error(TagDriftAfterRelease::SemanticallyIdenticalObjectReplacement),
            "annotated tag ref changed to another object"
        );
    }

    #[test]
    fn recovery_run_rejects_every_binding_drift() {
        let source = "a".repeat(40);
        let workflow = workflow();
        let run = workflow_run(&source);
        let artifacts = no_artifacts();
        validate_original_run_payload(&workflow, &run, &run, &artifacts, &source, 789, 2).unwrap();

        macro_rules! reject_run_drift {
            ($change:expr) => {{
                let mut value = run.clone();
                $change(&mut value);
                assert!(
                    validate_original_run_payload(
                        &workflow, &value, &run, &artifacts, &source, 789, 2
                    )
                    .is_err()
                );

                let mut current = run.clone();
                $change(&mut current);
                assert!(
                    validate_original_run_payload(
                        &workflow, &run, &current, &artifacts, &source, 789, 2
                    )
                    .is_err()
                );
            }};
        }

        reject_run_drift!(|value: &mut WorkflowRun| value.id = 790);
        reject_run_drift!(|value: &mut WorkflowRun| value.run_attempt = 3);
        reject_run_drift!(|value: &mut WorkflowRun| value.workflow_id = RELEASE_WORKFLOW_ID + 1);
        reject_run_drift!(|value: &mut WorkflowRun| value.path = "other.yml".to_string());
        reject_run_drift!(|value: &mut WorkflowRun| value.event = "workflow_dispatch".to_string());
        reject_run_drift!(|value: &mut WorkflowRun| value.status = "in_progress".to_string());
        reject_run_drift!(|value: &mut WorkflowRun| value.conclusion = Some("skipped".to_string()));
        reject_run_drift!(|value: &mut WorkflowRun| value.head_branch = Some("other".to_string()));
        reject_run_drift!(|value: &mut WorkflowRun| value.head_sha = "b".repeat(40));
        reject_run_drift!(
            |value: &mut WorkflowRun| value.repository.full_name = "NVIDIA/other".to_string()
        );

        let mut wrong_workflow = workflow.clone();
        wrong_workflow.id = 0;
        assert!(
            validate_original_run_payload(&wrong_workflow, &run, &run, &artifacts, &source, 789, 2)
                .is_err()
        );
        wrong_workflow = workflow.clone();
        wrong_workflow.path = ".github/workflows/other.yml".to_string();
        assert!(
            validate_original_run_payload(&wrong_workflow, &run, &run, &artifacts, &source, 789, 2)
                .is_err()
        );
        wrong_workflow = workflow.clone();
        wrong_workflow.state = "disabled_manually".to_string();
        assert!(
            validate_original_run_payload(&wrong_workflow, &run, &run, &artifacts, &source, 789, 2)
                .is_err()
        );

        let retained = ArtifactInventory {
            total_count: 1,
            artifacts: vec![json!({"id": 1})],
        };
        assert!(
            validate_original_run_payload(&workflow, &run, &run, &retained, &source, 789, 2)
                .is_err()
        );
    }

    #[test]
    fn recovery_rejects_a_self_consistent_wrong_workflow_id() {
        let source = "a".repeat(40);
        let mut workflow = workflow();
        workflow.id = RELEASE_WORKFLOW_ID + 1;
        let mut run = workflow_run(&source);
        run.workflow_id = workflow.id;

        assert_eq!(
            validate_original_run_payload(&workflow, &run, &run, &no_artifacts(), &source, 789, 2,)
                .unwrap_err(),
            "replacement publication workflow identity differs"
        );
    }

    #[test]
    fn recovery_rejects_a_newer_current_attempt() {
        let source = "a".repeat(40);
        let workflow = workflow();
        let selected_attempt = workflow_run(&source);
        let mut current_run = selected_attempt.clone();
        current_run.run_attempt += 1;

        assert_eq!(
            validate_original_run_payload(
                &workflow,
                &selected_attempt,
                &current_run,
                &no_artifacts(),
                &source,
                789,
                2,
            )
            .unwrap_err(),
            "original publication run does not bind the recovery source"
        );
    }

    #[test]
    fn finalizer_app_scope_is_exact() {
        let exact = InstallationRepositories {
            total_count: 1,
            repositories: vec![repository()],
        };
        validate_app_scope_payload(&exact).unwrap();

        let extra = InstallationRepositories {
            total_count: 2,
            repositories: vec![
                repository(),
                Repository {
                    full_name: "NVIDIA/other".to_string(),
                },
            ],
        };
        assert!(validate_app_scope_payload(&extra).is_err());
    }

    #[test]
    fn exact_changelog_heading_does_not_accept_version_prefixes() {
        assert!(is_changelog_heading(
            "## [0.4.0-rc.3](https://example.invalid) - 2026-09-04",
            "## [0.4.0-rc.3]"
        ));
        assert!(!is_changelog_heading(
            "## [0.4.0-rc.30](https://example.invalid)",
            "## [0.4.0-rc.3]"
        ));
        assert!(is_sha(&"a".repeat(40)));
        assert!(!is_sha(&"A".repeat(40)));
    }
}

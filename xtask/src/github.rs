// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded, provider-specific release automation for GitHub.

mod consts;
mod identity;
mod intent;
mod models;
mod release_objects;
mod release_pr;
mod release_train;
mod source;
mod transport;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::bounded_process::{self, OutputLimits};
use clap::{Args, Subcommand, ValueEnum};
use transport::GhCli;

use consts::RepositoryPolicy;
pub(crate) use consts::{
    APP_EMAIL, APP_ID, APP_LOGIN, APP_SLUG, MAX_FILE_BYTES, RELEASE_BRANCH, WEB_FLOW_EMAIL,
    WEB_FLOW_ID, WEB_FLOW_LOGIN, WEB_FLOW_NAME,
};

#[derive(Args)]
pub struct GithubArgs {
    #[command(subcommand)]
    command: GithubCommand,
}

#[derive(Subcommand)]
enum GithubCommand {
    /// Configure a token-derived repository-local Git identity.
    GitIdentity(GitIdentityArgs),
    /// Resolve, create, update, or finalize the release pull request.
    ReleasePr(ReleasePrArgs),
    /// Authorize one exact integrated release proposal.
    ReleaseSource(ReleaseSourceArgs),
    /// Verify or recover source-only official release objects.
    ReleaseObjects(ReleaseObjectsArgs),
    /// Capture, attest, finalize, or notify one source-only release train.
    ReleaseTrain(ReleaseTrainArgs),
}

#[derive(Args)]
struct GitIdentityArgs {
    #[command(subcommand)]
    command: GitIdentityCommand,
}

#[derive(Subcommand)]
enum GitIdentityCommand {
    /// Configure token-derived identity; local use requires a repository.
    Configure {
        /// Explicit local repository identity; forbidden in GitHub Actions.
        #[arg(long, value_name = "OWNER/REPO")]
        repository: Option<String>,
    },
}

#[derive(Args)]
struct ReleasePrArgs {
    #[command(subcommand)]
    command: ReleasePrCommand,
}

#[derive(Subcommand)]
enum ReleasePrCommand {
    /// Resolve one bounded App-owned release proposal.
    ResolveIntent,
    /// Create or finalize an exact App-signed release proposal.
    Apply {
        /// Mutation phase authorized by the surrounding workflow.
        #[arg(long, value_enum)]
        phase: ReleasePrPhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum ReleasePrPhase {
    Update,
    Finalize,
}

#[derive(Args)]
struct ReleaseSourceArgs {
    #[command(subcommand)]
    command: ReleaseSourceCommand,
}

#[derive(Subcommand)]
enum ReleaseSourceCommand {
    /// Authorize one exact integrated release proposal.
    Authorize {
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        #[arg(long, value_name = "SHA")]
        commit: String,
        #[arg(long)]
        baseline_version: String,
        #[arg(long, value_name = "SHA")]
        baseline_commit: String,
    },
}

#[derive(Args)]
struct ReleaseObjectsArgs {
    #[command(subcommand)]
    command: ReleaseObjectsCommand,
}

#[derive(Subcommand)]
enum ReleaseObjectsCommand {
    /// Reconcile source-only release objects before or after publication.
    Reconcile {
        #[arg(long, value_enum)]
        mode: ReconcileMode,
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        #[arg(long)]
        version: String,
        #[arg(long, value_name = "SHA")]
        commit: String,
    },
}

#[derive(Args)]
struct ReleaseTrainArgs {
    #[command(subcommand)]
    command: ReleaseTrainCommand,
}

#[derive(Subcommand)]
enum ReleaseTrainCommand {
    /// Discover fresh or partial-publication source before plan capture.
    Discover {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        commit: String,
    },
    /// Capture one canonical release plan from exact protected source.
    Capture {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        baseline_version: String,
        #[arg(long)]
        baseline_commit: String,
    },
    /// Recompute a captured plan and permit only exact registry progression.
    Verify {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        baseline_version: String,
        #[arg(long)]
        baseline_commit: String,
    },
    /// Wait at most 20 minutes for the complete planned registry train.
    Wait {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
    },
    /// Prepare the canonical release-train intent before token minting.
    PrepareIntent {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        origin_run_id: String,
        #[arg(long)]
        origin_run_attempt: String,
        #[arg(long)]
        ruleset_evidence_sha256: String,
    },
    /// Create or verify the App-authored release-train intent Check.
    CreateIntent {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        intent: String,
        #[arg(long)]
        expected_app_slug: String,
        #[arg(long)]
        expected_installation_id: String,
    },
    /// Re-read and verify the exact durable intent with a read-only token.
    VerifyIntent {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        intent: String,
        #[arg(long)]
        check_id: String,
    },
    /// Finalize the exact published registry prefix with a contents-only token.
    Finalize {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        intent: String,
        #[arg(long)]
        intent_check_id: String,
        #[arg(long)]
        expected_app_slug: String,
        #[arg(long)]
        expected_installation_id: String,
    },
    /// Emit one closed complete-train repository dispatch.
    Notify {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        plan: String,
        #[arg(long)]
        plan_digest: String,
        #[arg(long)]
        intent: String,
        #[arg(long)]
        intent_check_id: String,
        #[arg(long)]
        finalized_entries: String,
        #[arg(long)]
        expected_app_slug: String,
        #[arg(long)]
        expected_installation_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum ReconcileMode {
    Prepublish,
    Recover,
}

impl ReconcileMode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepublish => "prepublish",
            Self::Recover => "recover",
        }
    }
}

pub fn run(root: &Path, args: GithubArgs) -> Result<(), String> {
    require_token()?;
    let mut github = GhCli::new()?;
    match args.command {
        GithubCommand::GitIdentity(args) => match args.command {
            GitIdentityCommand::Configure { repository } => {
                identity::configure_command(root, repository.as_deref(), &mut github)
            }
        },
        GithubCommand::ReleasePr(args) => match args.command {
            ReleasePrCommand::ResolveIntent => intent::resolve(root, &mut github),
            ReleasePrCommand::Apply { phase } => release_pr::apply(root, phase, &mut github),
        },
        GithubCommand::ReleaseSource(args) => match args.command {
            ReleaseSourceCommand::Authorize {
                repository,
                commit,
                baseline_version,
                baseline_commit,
            } => source::authorize_command(
                root,
                &repository,
                &commit,
                &baseline_version,
                &baseline_commit,
                &mut github,
            ),
        },
        GithubCommand::ReleaseObjects(args) => match args.command {
            ReleaseObjectsCommand::Reconcile {
                mode,
                repository,
                version,
                commit,
            } => release_objects::reconcile_command(
                root,
                mode,
                &repository,
                &version,
                &commit,
                &mut github,
            ),
        },
        GithubCommand::ReleaseTrain(args) => match args.command {
            ReleaseTrainCommand::Discover { repository, commit } => {
                release_train::discover_command(root, &repository, &commit, &mut github)
            }
            ReleaseTrainCommand::Capture {
                repository,
                commit,
                baseline_version,
                baseline_commit,
            } => release_train::capture_command(
                root,
                &repository,
                &commit,
                &baseline_version,
                &baseline_commit,
                &mut github,
            ),
            ReleaseTrainCommand::Verify {
                repository,
                plan,
                plan_digest,
                baseline_version,
                baseline_commit,
            } => release_train::verify_command(
                root,
                &repository,
                &plan,
                &plan_digest,
                &baseline_version,
                &baseline_commit,
                &mut github,
            ),
            ReleaseTrainCommand::Wait {
                repository,
                plan,
                plan_digest,
            } => release_train::wait_command(&repository, &plan, &plan_digest),
            ReleaseTrainCommand::PrepareIntent {
                plan,
                plan_digest,
                origin_run_id,
                origin_run_attempt,
                ruleset_evidence_sha256,
            } => release_train::prepare_intent_command(
                root,
                release_train::PrepareIntentInput {
                    plan: &plan,
                    plan_digest: &plan_digest,
                    origin_run_id: &origin_run_id,
                    origin_run_attempt: &origin_run_attempt,
                    ruleset_evidence_sha256: &ruleset_evidence_sha256,
                },
            ),
            ReleaseTrainCommand::CreateIntent {
                repository,
                plan,
                plan_digest,
                intent,
                expected_app_slug,
                expected_installation_id,
            } => release_train::create_intent_command(
                release_train::CreateIntentInput {
                    repository: &repository,
                    plan: &plan,
                    plan_digest: &plan_digest,
                    intent: &intent,
                    expected_app_slug: &expected_app_slug,
                    expected_installation_id: &expected_installation_id,
                },
                &mut github,
            ),
            ReleaseTrainCommand::VerifyIntent {
                repository,
                plan,
                plan_digest,
                intent,
                check_id,
            } => release_train::verify_intent_command(
                &repository,
                &plan,
                &plan_digest,
                &intent,
                &check_id,
                &mut github,
            ),
            ReleaseTrainCommand::Finalize {
                repository,
                plan,
                plan_digest,
                intent,
                intent_check_id,
                expected_app_slug,
                expected_installation_id,
            } => release_train::finalize_command(
                release_train::FinalizeInput {
                    repository: &repository,
                    plan: &plan,
                    plan_digest: &plan_digest,
                    intent: &intent,
                    intent_check_id: &intent_check_id,
                    expected_app_slug: &expected_app_slug,
                    expected_installation_id: &expected_installation_id,
                },
                &mut github,
            ),
            ReleaseTrainCommand::Notify {
                repository,
                plan,
                plan_digest,
                intent,
                intent_check_id,
                finalized_entries,
                expected_app_slug,
                expected_installation_id,
            } => release_train::notify_command(
                release_train::NotifyInput {
                    repository: &repository,
                    plan: &plan,
                    plan_digest: &plan_digest,
                    intent: &intent,
                    intent_check_id: &intent_check_id,
                    finalized_entries: &finalized_entries,
                    expected_app_slug: &expected_app_slug,
                    expected_installation_id: &expected_installation_id,
                },
                &mut github,
            ),
        },
    }
}

fn require_token() -> Result<(), String> {
    if env::var_os("GH_TOKEN").is_some() || env::var_os("GITHUB_TOKEN").is_some() {
        Ok(())
    } else {
        Err("GH_TOKEN or GITHUB_TOKEN is required in the environment".to_string())
    }
}

pub(super) fn env_required(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        return Err(format!("{name} must be one nonempty line"));
    }
    Ok(value)
}

pub(super) fn env_bool(name: &str) -> Result<bool, String> {
    match env_required(name)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

pub(super) fn repository_policy_for_root(
    root: &Path,
    repository: &str,
) -> Result<&'static RepositoryPolicy, String> {
    let provider = consts::repository_policy(repository)
        .ok_or_else(|| "GitHub repository has no compiled release policy".to_string())?;
    let local = crate::release_policy::detect(root)?;
    let expected = consts::repository_for_family(local.family)
        .ok_or_else(|| "local release family has no compiled GitHub policy".to_string())?;
    if provider != expected {
        return Err("GitHub repository identity disagrees with local release policy".to_string());
    }
    Ok(provider)
}

pub(super) fn workflow_repository(root: &Path) -> Result<&'static RepositoryPolicy, String> {
    if env_required("GITHUB_ACTIONS")? != "true" {
        return Err("GitHub workflow commands require GITHUB_ACTIONS=true".to_string());
    }
    let repository = env_required("GITHUB_REPOSITORY")?;
    repository_policy_for_root(root, &repository)
}

pub(super) fn is_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn is_positive_integer(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && !value.starts_with('0')
}

pub(super) fn append_outputs(values: &[(&str, &str)]) -> Result<(), String> {
    let path = PathBuf::from(env_required("GITHUB_OUTPUT")?);
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open workflow output {}: {error}", path.display()))?;
    for (name, value) in values {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || value.contains(['\0', '\r', '\n'])
        {
            return Err("workflow output contains an invalid name or value".to_string());
        }
        writeln!(output, "{name}={value}")
            .map_err(|error| format!("write workflow output {}: {error}", path.display()))?;
    }
    Ok(())
}

pub(super) fn command_output(root: &Path, program: &str, args: &[&str]) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.current_dir(root).args(args);
    bounded_process::output(
        &mut command,
        OutputLimits {
            stdout: transport::MAX_RESPONSE_BYTES,
            stderr: transport::MAX_ERROR_BYTES,
        },
    )
    .map_err(|error| format!("run {program}: {error}"))
}

pub(super) fn git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = command_output(root, "git", args)?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            output_detail(&output)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))
}

pub(super) fn git_line(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_output(root, args)?;
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(&output);
    if line.is_empty() || line.contains(['\r', '\n']) {
        return Err(format!(
            "git {} did not return one exact line",
            args.join(" ")
        ));
    }
    Ok(line.to_string())
}

pub(super) fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

pub(super) fn validate_ref_component(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains(['\0', '\r', '\n', ' ', '~', '^', ':', '?', '*', '[', '\\'])
        || value.contains("..")
        || value.contains("@{")
        || value.ends_with('.')
        || value.ends_with('/')
        || value.starts_with('/')
    {
        Err(format!("{label} is not a safe Git ref component"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_identifiers_are_strict() {
        assert!(is_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_sha("0123456789ABCDEF0123456789ABCDEF01234567"));
        assert!(is_positive_integer("42"));
        assert!(!is_positive_integer("0"));
        assert!(validate_ref_component("release-plz-next", "branch").is_ok());
        assert!(validate_ref_component("../main", "branch").is_err());
    }
}

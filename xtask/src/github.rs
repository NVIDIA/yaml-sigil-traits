// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded, provider-specific release automation for GitHub.

mod consts;
mod identity;
mod intent;
mod models;
mod release_objects;
mod release_pr;
mod source;
mod transport;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use transport::GhCli;

use consts::RepositoryPolicy;
pub(crate) use consts::{
    APP_EMAIL, APP_ID, APP_LOGIN, APP_SLUG, MAX_FILE_BYTES, RELEASE_BRANCH, WEB_FLOW_EMAIL,
    WEB_FLOW_ID, WEB_FLOW_LOGIN, WEB_FLOW_NAME,
};

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    if matches!(args, [arg] if matches!(arg.as_str(), "help" | "--help" | "-h")) {
        eprintln!("{}", usage());
        return Ok(());
    }
    require_token()?;
    let mut github = GhCli::new()?;
    match args {
        [namespace, command, rest @ ..]
            if namespace == "git-identity" && command == "configure" =>
        {
            identity::configure_command(root, rest, &mut github)
        }
        [namespace, command] if namespace == "release-pr" && command == "resolve-intent" => {
            intent::resolve(root, &mut github)
        }
        [namespace, command, phase_flag, phase]
            if namespace == "release-pr"
                && command == "apply"
                && phase_flag == "--phase"
                && matches!(phase.as_str(), "update" | "finalize") =>
        {
            release_pr::apply(root, phase, &mut github)
        }
        [namespace, command, rest @ ..]
            if namespace == "release-source" && command == "authorize" =>
        {
            source::authorize_command(root, rest, &mut github)
        }
        [namespace, command, rest @ ..]
            if namespace == "release-objects" && command == "reconcile" =>
        {
            release_objects::reconcile_command(root, rest, &mut github)
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    [
        "usage: cargo xtask github <COMMAND>",
        "",
        "commands:",
        "  git-identity configure [--repository OWNER/REPO]",
        "      Configure token-derived identity; local use requires a repository.",
        "  release-pr resolve-intent",
        "      Resolve one bounded App-owned release proposal.",
        "  release-pr apply --phase update|finalize",
        "      Create or finalize an exact App-signed release proposal.",
        "  release-source authorize --repository OWNER/REPO --commit SHA \\",
        "      --baseline-version VERSION --baseline-commit SHA",
        "      Authorize one exact integrated release proposal.",
        "  release-objects reconcile --mode prepublish|recover \\",
        "      --repository OWNER/REPO --version VERSION --commit SHA",
        "      Reconcile source-only official release objects.",
    ]
    .join("\n")
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

pub(super) fn required_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let values: Vec<_> = args
        .windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
        .collect();
    match values.as_slice() {
        [] => Err(format!("missing {flag}")),
        [value] if !value.starts_with("--") => Ok(value),
        [_] => Err(format!("missing value for {flag}")),
        _ => Err(format!("duplicate {flag}")),
    }
}

pub(super) fn ensure_only_value_flags(args: &[String], flags: &[&str]) -> Result<(), String> {
    let mut seen = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !flags.contains(&flag) {
            return Err(format!("unexpected argument: {flag}"));
        }
        if seen.contains(&flag) {
            return Err(format!("duplicate {flag}"));
        }
        seen.push(flag);
        index += 1;
        if index >= args.len() || args[index].starts_with("--") {
            return Err(format!("missing value for {flag}"));
        }
        index += 1;
    }
    Ok(())
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
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.stdout.len() > transport::MAX_RESPONSE_BYTES
        || output.stderr.len() > transport::MAX_ERROR_BYTES
    {
        return Err(format!("{program} output exceeded its bound"));
    }
    Ok(output)
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

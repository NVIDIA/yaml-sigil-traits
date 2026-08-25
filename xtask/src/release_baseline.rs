// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral official-tag and crates.io baseline selection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml_edit::DocumentMut;

use crate::crate_archive::{CratesIo, Registry, RegistryVersion, inspect_archive, is_checksum};
use crate::release_policy::{ReleaseFamily, ReleasePolicy, detect};

const INVENTORY_SCHEMA: u64 = 3;
const READ_ONLY_PUSH_URL: &str = "disabled://yaml-sigil-release-proposal";
const REMOTE_ATTEMPTS: usize = 3;
const MAX_GIT_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    command: BaselineCommand,
}

#[derive(Subcommand)]
enum BaselineCommand {
    /// Prepare an archive-bound official release baseline.
    Prepare(BaselinePrepareArgs),
    /// Verify a previously persisted official-tag inventory.
    Verify(BaselineVerifyArgs),
}

#[derive(Args)]
struct BaselinePrepareArgs {
    /// Exact protected-main commit being analyzed.
    #[arg(long, value_name = "SHA")]
    head: String,
    /// New detached baseline directory.
    #[arg(long)]
    output: PathBuf,
    /// New JSON result file consumed by the workflow.
    #[arg(long)]
    result: PathBuf,
    /// Exact read-only repository fetch URL.
    #[arg(long)]
    expected_fetch_url: String,
    /// Require this exact official baseline version.
    #[arg(long, conflicts_with = "exclude_version")]
    version: Option<String>,
    /// Exclude the current release version while selecting its predecessor.
    #[arg(long, conflicts_with = "version")]
    exclude_version: Option<String>,
    /// New persisted official-tag inventory; derived from `--output` by default.
    #[arg(long)]
    inventory_output: Option<PathBuf>,
    /// Exact non-mutating push URL configured for baseline preparation.
    #[arg(long, default_value = READ_ONLY_PUSH_URL)]
    expected_push_url: String,
}

#[derive(Args)]
struct BaselineVerifyArgs {
    /// Exact protected-main commit being revalidated.
    #[arg(long, value_name = "SHA")]
    head: String,
    /// Persisted official-tag inventory to revalidate.
    #[arg(long)]
    inventory: PathBuf,
    /// Exact read-only repository fetch URL.
    #[arg(long)]
    expected_fetch_url: String,
    /// Exact non-mutating push URL configured for verification.
    #[arg(long, default_value = READ_ONLY_PUSH_URL)]
    expected_push_url: String,
}

pub(crate) fn run(root: &Path, args: BaselineArgs) -> Result<(), String> {
    match args.command {
        BaselineCommand::Prepare(args) => prepare_command(root, args),
        BaselineCommand::Verify(args) => verify_command(root, args),
    }
}

fn prepare_command(root: &Path, args: BaselinePrepareArgs) -> Result<(), String> {
    let parsed = ParsedArgs {
        head: args.head,
        expected_fetch_url: args.expected_fetch_url,
        expected_push_url: args.expected_push_url,
        version: args.version,
        exclude_version: args.exclude_version,
        output: Some(args.output),
        result: Some(args.result),
        inventory_output: args.inventory_output,
        inventory: None,
    };
    parsed.validate()?;
    let output = parsed.output.as_ref().expect("prepare output is typed");
    let result_path = parsed.result.as_ref().expect("prepare result is typed");
    let inventory_output = parsed.inventory_output.clone().unwrap_or_else(|| {
        output
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(
                "{}-official-tags.json",
                output
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("baseline")
            ))
    });
    let policy = detect(root)?;
    let mut registry = CratesIo::new();
    let result = prepare(
        root,
        policy,
        &parsed,
        output,
        &inventory_output,
        &mut registry,
    )?;
    write_new_json(result_path, &result)?;
    eprintln!(
        "release: prepared archive-bound official baseline {} at {}",
        result.commit, result.manifest
    );
    Ok(())
}

fn verify_command(root: &Path, args: BaselineVerifyArgs) -> Result<(), String> {
    let parsed = ParsedArgs {
        head: args.head,
        expected_fetch_url: args.expected_fetch_url,
        expected_push_url: args.expected_push_url,
        version: None,
        exclude_version: None,
        output: None,
        result: None,
        inventory_output: None,
        inventory: Some(args.inventory),
    };
    parsed.validate()?;
    let inventory = parsed
        .inventory
        .as_ref()
        .expect("verify inventory is typed");
    let policy = detect(root)?;
    let mut registry = CratesIo::new();
    verify_snapshot(root, policy, &parsed, inventory, &mut registry)?;
    eprintln!("release: verified unchanged official tags, archives, and current main");
    Ok(())
}

#[derive(Debug)]
struct ParsedArgs {
    head: String,
    expected_fetch_url: String,
    expected_push_url: String,
    version: Option<String>,
    exclude_version: Option<String>,
    output: Option<PathBuf>,
    result: Option<PathBuf>,
    inventory_output: Option<PathBuf>,
    inventory: Option<PathBuf>,
}

impl ParsedArgs {
    fn validate(&self) -> Result<(), String> {
        if !is_sha(&self.head) {
            return Err("--head must be a lowercase full SHA".to_string());
        }
        validate_url(&self.expected_fetch_url, "--expected-fetch-url")?;
        validate_url(&self.expected_push_url, "--expected-push-url")?;
        if self.version.is_some() && self.exclude_version.is_some() {
            return Err("--version and --exclude-version are mutually exclusive".to_string());
        }
        if let Some(value) = self.version.as_deref().or(self.exclude_version.as_deref()) {
            parse_version(value)?;
        }
        Ok(())
    }
}

fn validate_url(value: &str, flag: &str) -> Result<(), String> {
    if value.is_empty() || value.starts_with('-') || value.contains(['\0', '\r', '\n']) {
        Err(format!("{flag} must be one non-option URL"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct InventorySnapshot {
    schema: u64,
    family: String,
    head: String,
    fetch_url: String,
    push_url: String,
    selected_version: String,
    selected_commit: String,
    excluded_version: Option<String>,
    official_tags: Vec<TagRecord>,
    archives: Vec<ArchiveRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct TagRecord {
    name: String,
    object: String,
    commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ArchiveRecord {
    package: String,
    version: String,
    checksum: String,
    commit: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BaselineResult {
    commit: String,
    manifest: String,
    tags: Vec<String>,
    version: String,
    inventory: String,
}

fn prepare(
    root: &Path,
    policy: &ReleasePolicy,
    args: &ParsedArgs,
    output: &Path,
    inventory_output: &Path,
    registry: &mut impl Registry,
) -> Result<BaselineResult, String> {
    require_repository_state(root, args)?;
    let tags = synchronized_inventory(root, policy)?;
    if let Some(excluded) = args.exclude_version.as_deref() {
        require_excluded_current_version(root, policy, excluded, &args.head, &tags)?;
    }
    let selected = select_baseline(
        root,
        policy,
        &args.head,
        args.version.as_deref(),
        args.exclude_version.as_deref(),
        &tags,
        registry,
    )?;
    let version = selected.version.clone();
    let baseline = selected.commit.clone();
    let expected_tags: Vec<_> = policy
        .packages
        .iter()
        .map(|package| package.tag(&version))
        .collect();

    if output.exists() {
        return Err(format!(
            "baseline output already exists: {}",
            output.display()
        ));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create baseline parent {}: {error}", parent.display()))?;
    }
    git_status(
        root,
        &[
            "worktree",
            "add",
            "--detach",
            "--quiet",
            path_text(output)?,
            &baseline,
        ],
    )?;
    if git_line(output, &["rev-parse", "HEAD"])? != baseline
        || !git_output(output, &["status", "--porcelain"])?.is_empty()
    {
        return Err("detached baseline checkout is not exact and clean".to_string());
    }
    let manifest = output.join("Cargo.toml");
    if manifest_version(&manifest, policy.family)? != version {
        return Err("detached baseline manifest does not match its official tag".to_string());
    }

    let snapshot = InventorySnapshot {
        schema: INVENTORY_SCHEMA,
        family: family_name(policy.family).to_string(),
        head: args.head.clone(),
        fetch_url: args.expected_fetch_url.clone(),
        push_url: args.expected_push_url.clone(),
        selected_version: version.clone(),
        selected_commit: baseline.clone(),
        excluded_version: args.exclude_version.clone(),
        official_tags: tags.values().cloned().collect(),
        archives: selected.archives,
    };
    write_new_json(inventory_output, &snapshot)?;
    verify_snapshot(root, policy, args, inventory_output, registry)?;
    Ok(BaselineResult {
        commit: baseline,
        manifest: absolute_text(&manifest)?,
        tags: expected_tags,
        version,
        inventory: absolute_text(inventory_output)?,
    })
}

fn verify_snapshot(
    root: &Path,
    policy: &ReleasePolicy,
    args: &ParsedArgs,
    path: &Path,
    registry: &mut impl Registry,
) -> Result<(), String> {
    let snapshot: InventorySnapshot = read_canonical_json(path)?;
    if snapshot.schema != INVENTORY_SCHEMA
        || snapshot.family != family_name(policy.family)
        || snapshot.head != args.head
        || snapshot.fetch_url != args.expected_fetch_url
        || snapshot.push_url != args.expected_push_url
        || !is_sha(&snapshot.selected_commit)
        || parse_version(&snapshot.selected_version).is_err()
        || snapshot
            .excluded_version
            .as_deref()
            .is_some_and(|version| parse_version(version).is_err())
        || snapshot.excluded_version.as_deref() == Some(&snapshot.selected_version)
        || snapshot
            .official_tags
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .len()
            != snapshot.official_tags.len()
        || snapshot
            .archives
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .len()
            != snapshot.archives.len()
    {
        return Err("official baseline inventory has an invalid schema or binding".to_string());
    }
    require_repository_state(root, args)?;
    let tags = synchronized_inventory(root, policy)?;
    let expected_tags: Vec<_> = tags.values().cloned().collect();
    if expected_tags != snapshot.official_tags {
        return Err("official tag inventory changed after release analysis".to_string());
    }
    if let Some(excluded) = snapshot.excluded_version.as_deref() {
        require_excluded_current_version(root, policy, excluded, &args.head, &tags)?;
    }
    let selected = select_baseline(
        root,
        policy,
        &args.head,
        Some(&snapshot.selected_version),
        snapshot.excluded_version.as_deref(),
        &tags,
        registry,
    )?;
    if selected.version != snapshot.selected_version
        || selected.commit != snapshot.selected_commit
        || selected.archives != snapshot.archives
    {
        return Err(
            "official registry archive inventory changed after release analysis".to_string(),
        );
    }
    require_repository_state(root, args)?;
    if synchronized_inventory(root, policy)? != tags {
        return Err("official tag inventory changed during verification".to_string());
    }
    Ok(())
}

#[derive(Debug)]
struct SelectedBaseline {
    version: String,
    commit: String,
    archives: Vec<ArchiveRecord>,
}

fn select_baseline(
    root: &Path,
    policy: &ReleasePolicy,
    head: &str,
    requested: Option<&str>,
    excluded: Option<&str>,
    tags: &BTreeMap<String, TagRecord>,
    registry: &mut impl Registry,
) -> Result<SelectedBaseline, String> {
    let mut grouped: BTreeMap<String, BTreeMap<String, &TagRecord>> = BTreeMap::new();
    for record in tags.values() {
        if let Some((version, package)) = classify_tag(policy, &record.name) {
            grouped
                .entry(version)
                .or_default()
                .insert(package.to_string(), record);
        }
    }
    let mut candidates = Vec::new();
    let mut mismatched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (version, records) in grouped {
        if excluded == Some(version.as_str()) {
            continue;
        }
        if records.len() != policy.packages.len()
            || policy
                .packages
                .iter()
                .any(|package| !records.contains_key(package.package))
        {
            return Err(format!(
                "official version {version} has an incomplete official tag set"
            ));
        }
        let commits: BTreeSet<_> = records
            .values()
            .map(|record| record.commit.clone())
            .collect();
        if commits.len() != 1 {
            mismatched.insert(version, commits);
            continue;
        }
        let commit = commits.into_iter().next().expect("one commit");
        if !is_ancestor(root, &commit, head)? {
            continue;
        }
        let Some(archives) = candidate_archives(policy, &version, &commit, registry)? else {
            continue;
        };
        let distance = git_line(root, &["rev-list", "--count", &format!("{commit}..{head}")])?
            .parse::<u64>()
            .map_err(|_| "git returned an invalid baseline distance".to_string())?;
        candidates.push((distance, version, commit, archives));
    }
    let nearest = candidates
        .iter()
        .map(|candidate| candidate.0)
        .min()
        .ok_or_else(|| {
            "no reachable archive-bound official annotated release exists".to_string()
        })?;
    let mut nearest_candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.0 == nearest)
        .collect();
    if nearest_candidates.len() != 1 {
        return Err("the last archive-bound official release is not unique".to_string());
    }
    let (_, version, commit, archives) = nearest_candidates.pop().expect("one baseline");
    if requested.is_some_and(|requested| requested != version) {
        return Err("requested version is not the last archive-bound official release".to_string());
    }
    let selected_version = parse_version(&version)?;
    for (split_version, commits) in mismatched {
        let split = parse_version(&split_version)?;
        let mut fully_superseded = split < selected_version;
        for candidate in commits {
            fully_superseded &= candidate != commit && is_ancestor(root, &candidate, &commit)?;
        }
        if !fully_superseded {
            return Err(format!(
                "official version {split_version} tags resolve to different commits"
            ));
        }
    }
    Ok(SelectedBaseline {
        version,
        commit,
        archives,
    })
}

fn candidate_archives(
    policy: &ReleasePolicy,
    version: &str,
    commit: &str,
    registry: &mut impl Registry,
) -> Result<Option<Vec<ArchiveRecord>>, String> {
    let mut records = Vec::new();
    for package in policy.packages {
        let Some(record) = registry.exact_version(package.package, version)? else {
            return Ok(None);
        };
        if record.num != version || record.yanked {
            return Ok(None);
        }
        records.push(verify_archive_record(
            registry, package, version, commit, record,
        )?);
    }
    Ok(Some(records))
}

fn verify_archive_record(
    registry: &mut impl Registry,
    package: &crate::release_policy::PackagePolicy,
    version: &str,
    commit: &str,
    record: RegistryVersion,
) -> Result<ArchiveRecord, String> {
    if !is_checksum(&record.checksum) {
        return Err(format!(
            "crates.io returned an invalid checksum for {}",
            package.package
        ));
    }
    let archive = registry.download(package.package, version)?;
    if format!("{:x}", Sha256::digest(&archive)) != record.checksum {
        return Err(format!(
            "crates.io checksum differs for {} {version}",
            package.package
        ));
    }
    inspect_archive(&archive, package, version, commit)?;
    Ok(ArchiveRecord {
        package: package.package.to_string(),
        version: version.to_string(),
        checksum: record.checksum,
        commit: commit.to_string(),
    })
}

fn require_excluded_current_version(
    root: &Path,
    policy: &ReleasePolicy,
    version: &str,
    head: &str,
    tags: &BTreeMap<String, TagRecord>,
) -> Result<(), String> {
    if manifest_version(&root.join("Cargo.toml"), policy.family)? != version {
        return Err("excluded retry version does not match current source".to_string());
    }
    for package in policy.packages {
        let tag = package.tag(version);
        if let Some(record) = tags.get(&tag)
            && record.commit != head
        {
            return Err("excluded retry version does not tag exact current source".to_string());
        }
    }
    Ok(())
}

fn synchronized_inventory(
    root: &Path,
    policy: &ReleasePolicy,
) -> Result<BTreeMap<String, TagRecord>, String> {
    let local = local_inventory(root, policy)?;
    let remote = remote_inventory(root, policy)?;
    if local != remote {
        return Err("local official tag inventory differs from origin".to_string());
    }
    Ok(local)
}

fn local_inventory(
    root: &Path,
    policy: &ReleasePolicy,
) -> Result<BTreeMap<String, TagRecord>, String> {
    let output = git_output(
        root,
        &[
            "for-each-ref",
            "--format=%(refname:strip=2)%09%(objecttype)%09%(objectname)",
            "refs/tags",
        ],
    )?;
    let mut inventory = BTreeMap::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err("git returned an invalid local tag inventory".to_string());
        }
        let tag = fields[0];
        if classify_tag(policy, tag).is_none() {
            continue;
        }
        if fields[1] != "tag" || !is_sha(fields[2]) {
            return Err(format!("official tag {tag} is not annotated"));
        }
        let commit = git_line(
            root,
            &[
                "rev-parse",
                "--verify",
                &format!("refs/tags/{tag}^{{commit}}"),
            ],
        )?;
        if !is_sha(&commit) {
            return Err(format!("official tag {tag} has an invalid commit"));
        }
        let record = TagRecord {
            name: tag.to_string(),
            object: fields[2].to_string(),
            commit,
        };
        if inventory.insert(tag.to_string(), record).is_some() {
            return Err(format!("duplicate official tag {tag}"));
        }
    }
    Ok(inventory)
}

fn remote_inventory(
    root: &Path,
    policy: &ReleasePolicy,
) -> Result<BTreeMap<String, TagRecord>, String> {
    let output = remote_git_output(root, &["ls-remote", "--tags", "origin"])?;
    let mut raw: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    for line in output.lines() {
        let (sha, reference) = line
            .split_once('\t')
            .ok_or_else(|| "origin returned an invalid tag inventory".to_string())?;
        if !is_sha(sha) {
            return Err("origin returned an invalid tag object".to_string());
        }
        let peeled = reference.ends_with("^{}");
        let base = reference.strip_suffix("^{}").unwrap_or(reference);
        let Some(tag) = base.strip_prefix("refs/tags/") else {
            continue;
        };
        if classify_tag(policy, tag).is_none() {
            continue;
        }
        let state = raw.entry(tag.to_string()).or_default();
        let slot = if peeled { &mut state.1 } else { &mut state.0 };
        if slot.replace(sha.to_string()).is_some() {
            return Err(format!("origin returned duplicate state for {reference}"));
        }
    }
    let mut inventory = BTreeMap::new();
    for (name, (object, commit)) in raw {
        let (Some(object), Some(commit)) = (object, commit) else {
            return Err(format!("official tag {name} is not annotated on origin"));
        };
        inventory.insert(
            name.clone(),
            TagRecord {
                name,
                object,
                commit,
            },
        );
    }
    Ok(inventory)
}

fn classify_tag(policy: &ReleasePolicy, tag: &str) -> Option<(String, &'static str)> {
    let mut match_value = None;
    for package in policy.packages {
        let Some(version) = tag.strip_prefix(package.tag_prefix) else {
            continue;
        };
        if parse_version(version).is_ok() {
            if match_value.is_some() {
                return None;
            }
            match_value = Some((version.to_string(), package.package));
        }
    }
    match_value
}

fn require_repository_state(root: &Path, args: &ParsedArgs) -> Result<(), String> {
    if git_line(root, &["rev-parse", "HEAD"])? != args.head {
        return Err("checkout is not at the exact expected source commit".to_string());
    }
    if git_line(root, &["remote", "get-url", "origin"])? != args.expected_fetch_url {
        return Err("origin does not use the expected read-only fetch URL".to_string());
    }
    let push_urls = git_output(root, &["config", "--get-all", "remote.origin.pushurl"])?;
    let push_urls: Vec<_> = push_urls.lines().collect();
    if push_urls != [args.expected_push_url.as_str()] {
        return Err("origin does not have the exact disabled push URL".to_string());
    }
    let main = remote_git_output(
        root,
        &["ls-remote", "--exit-code", "origin", "refs/heads/main"],
    )?;
    let (sha, reference) = main
        .trim_end()
        .split_once('\t')
        .ok_or_else(|| "origin returned invalid main state".to_string())?;
    if sha != args.head || reference != "refs/heads/main" {
        return Err("origin/main advanced beyond the checked-out commit".to_string());
    }
    Ok(())
}

fn manifest_version(path: &Path, family: ReleaseFamily) -> Result<String, String> {
    let body = fs::read_to_string(path)
        .map_err(|error| format!("read baseline manifest {}: {error}", path.display()))?;
    let document = body
        .parse::<DocumentMut>()
        .map_err(|error| format!("parse baseline manifest {}: {error}", path.display()))?;
    let value = match family {
        ReleaseFamily::Traits => document
            .get("package")
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
        ReleaseFamily::RustWorkspace => document
            .get("workspace")
            .and_then(|item| item.get("package"))
            .and_then(|item| item.get("version"))
            .and_then(toml_edit::Item::as_str),
    }
    .ok_or_else(|| "baseline manifest has no release version".to_string())?;
    parse_version(value)?;
    Ok(value.to_string())
}

fn parse_version(value: &str) -> Result<Version, String> {
    let version = Version::parse(value)
        .map_err(|error| format!("unsupported release version {value}: {error}"))?;
    if !version.build.is_empty() {
        return Err("release version contains build metadata".to_string());
    }
    if !version.pre.is_empty() {
        let number = version
            .pre
            .as_str()
            .strip_prefix("rc.")
            .ok_or_else(|| "release prerelease is not rc.N".to_string())?;
        if number.starts_with('0') || number.parse::<u64>().ok().is_none_or(|number| number == 0) {
            return Err("release prerelease is not canonical positive rc.N".to_string());
        }
    }
    Ok(version)
}

fn family_name(family: ReleaseFamily) -> &'static str {
    match family {
        ReleaseFamily::Traits => "traits",
        ReleaseFamily::RustWorkspace => "rust-workspace",
    }
}

fn is_ancestor(root: &Path, ancestor: &str, descendant: &str) -> Result<bool, String> {
    let output = git_process(root, &["merge-base", "--is-ancestor", ancestor, descendant])?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!("git merge-base failed: {}", detail(&output))),
    }
}

fn git_line(root: &Path, args: &[&str]) -> Result<String, String> {
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

fn git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_process(root, args)?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            detail(&output)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))
}

fn remote_git_output(root: &Path, args: &[&str]) -> Result<String, String> {
    let mut last = None;
    for attempt in 1..=REMOTE_ATTEMPTS {
        let output = git_process(root, args)?;
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map_err(|_| "remote Git returned non-UTF-8 output".to_string());
        }
        let error = format!("git {} failed: {}", args.join(" "), detail(&output));
        if attempt == REMOTE_ATTEMPTS || !transient(&error) {
            return Err(error);
        }
        last = Some(error);
        thread::sleep(Duration::from_secs(attempt as u64));
    }
    Err(last.unwrap_or_else(|| "remote Git read failed".to_string()))
}

fn git_status(root: &Path, args: &[&str]) -> Result<(), String> {
    let output = git_process(root, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            detail(&output)
        ))
    }
}

fn git_process(root: &Path, args: &[&str]) -> Result<Output, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| format!("run git {}: {error}", args.join(" ")))?;
    if output.stdout.len() > MAX_GIT_OUTPUT || output.stderr.len() > MAX_GIT_OUTPUT {
        return Err("Git output exceeded its bound".to_string());
    }
    Ok(output)
}

fn detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn transient(value: &str) -> bool {
    [
        "timed out",
        "Could not resolve",
        "Connection reset",
        "failed to connect",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let path = absolute(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create JSON output parent {}: {error}", parent.display()))?;
    }
    let mut body = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize JSON output: {error}"))?;
    body.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create JSON output {}: {error}", path.display()))?;
    output
        .write_all(&body)
        .map_err(|error| format!("write JSON output {}: {error}", path.display()))
}

fn read_canonical_json<T>(path: &Path) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let raw =
        fs::read(path).map_err(|error| format!("read inventory {}: {error}", path.display()))?;
    if raw.len() > MAX_GIT_OUTPUT {
        return Err("official baseline inventory exceeded its bound".to_string());
    }
    let value: T = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse inventory {}: {error}", path.display()))?;
    let mut canonical = serde_json::to_vec_pretty(&value)
        .map_err(|error| format!("serialize inventory: {error}"))?;
    canonical.push(b'\n');
    if raw != canonical {
        return Err("official baseline inventory is not canonical".to_string());
    }
    Ok(value)
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|root| root.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

fn absolute_text(path: &Path) -> Result<String, String> {
    path_text(&absolute(path)?).map(str::to_string)
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

fn is_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    const FIXTURE_FETCH_URL: &str = "https://example.invalid/repository";

    #[test]
    fn tag_classifier_ignores_unrelated_higher_snapshots() {
        let policy = &crate::release_policy::TRAITS_POLICY;
        assert_eq!(
            classify_tag(policy, "v0.4.0"),
            Some(("0.4.0".to_string(), policy.packages[0].package))
        );
        assert_eq!(classify_tag(policy, "snapshot-v99.0.0"), None);
        assert_eq!(classify_tag(policy, "v99.0.0-snapshot.1"), None);
    }

    #[test]
    fn baseline_flags_reject_collisions_and_ambiguous_modes() {
        let parsed = ParsedArgs {
            head: "a".repeat(40),
            expected_fetch_url: FIXTURE_FETCH_URL.to_string(),
            expected_push_url: READ_ONLY_PUSH_URL.to_string(),
            version: Some("0.4.0".to_string()),
            exclude_version: Some("0.5.0".to_string()),
            output: None,
            result: None,
            inventory_output: None,
            inventory: None,
        };
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn snapshot_representation_is_canonical() {
        let snapshot = InventorySnapshot {
            schema: INVENTORY_SCHEMA,
            family: "traits".to_string(),
            head: "a".repeat(40),
            fetch_url: FIXTURE_FETCH_URL.to_string(),
            push_url: READ_ONLY_PUSH_URL.to_string(),
            selected_version: "0.4.0".to_string(),
            selected_commit: "b".repeat(40),
            excluded_version: None,
            official_tags: vec![],
            archives: vec![],
        };
        let body = serde_json::to_string_pretty(&snapshot).unwrap();
        assert!(body.starts_with("{\n  \"schema\": 3,"));
    }

    #[derive(Default)]
    struct FakeRegistry {
        versions: BTreeMap<(String, String), RegistryVersion>,
        archives: BTreeMap<(String, String), Vec<u8>>,
    }

    impl Registry for FakeRegistry {
        fn exact_version(
            &mut self,
            package: &str,
            version: &str,
        ) -> Result<Option<RegistryVersion>, String> {
            Ok(self
                .versions
                .get(&(package.to_string(), version.to_string()))
                .cloned())
        }

        fn download(&mut self, package: &str, version: &str) -> Result<Vec<u8>, String> {
            self.archives
                .get(&(package.to_string(), version.to_string()))
                .cloned()
                .ok_or_else(|| format!("missing fake archive for {package} {version}"))
        }
    }

    fn source_archive(
        package: &crate::release_policy::PackagePolicy,
        version: &str,
        commit: &str,
    ) -> Vec<u8> {
        let vcs = serde_json::json!({
            "git": {"sha1": commit},
            "path_in_vcs": package.path_in_vcs,
        })
        .to_string();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(vcs.len() as u64);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{}-{version}/.cargo_vcs_info.json", package.package),
                vcs.as_bytes(),
            )
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn add_release(
        registry: &mut FakeRegistry,
        package: &crate::release_policy::PackagePolicy,
        version: &str,
        commit: &str,
        yanked: bool,
    ) {
        let archive = source_archive(package, version, commit);
        let checksum = format!("{:x}", Sha256::digest(&archive));
        let key = (package.package.to_string(), version.to_string());
        registry.versions.insert(
            key.clone(),
            RegistryVersion {
                num: version.to_string(),
                yanked,
                checksum,
            },
        );
        registry.archives.insert(key, archive);
    }

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn linear_repository() -> (tempfile::TempDir, String, String) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--quiet"]);
        git(root.path(), &["config", "user.name", "Test"]);
        git(
            root.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(
            root.path(),
            &["commit", "--quiet", "--allow-empty", "-m", "old"],
        );
        let old = git(root.path(), &["rev-parse", "HEAD"]);
        git(
            root.path(),
            &["commit", "--quiet", "--allow-empty", "-m", "new"],
        );
        let new = git(root.path(), &["rev-parse", "HEAD"]);
        (root, old, new)
    }

    fn tag(name: String, object: char, commit: &str) -> TagRecord {
        TagRecord {
            name,
            object: object.to_string().repeat(40),
            commit: commit.to_string(),
        }
    }

    #[test]
    fn baseline_skips_missing_or_yanked_archives_but_rejects_an_older_request() {
        let (root, old, new) = linear_repository();
        let policy = &crate::release_policy::TRAITS_POLICY;
        let package = &policy.packages[0];
        let tags = BTreeMap::from([
            ("v0.3.0".to_string(), tag("v0.3.0".to_string(), 'c', &old)),
            ("v0.4.0".to_string(), tag("v0.4.0".to_string(), 'd', &new)),
        ]);

        let mut missing = FakeRegistry::default();
        add_release(&mut missing, package, "0.3.0", &old, false);
        assert_eq!(
            select_baseline(root.path(), policy, &new, None, None, &tags, &mut missing,)
                .unwrap()
                .version,
            "0.3.0"
        );

        let mut yanked = FakeRegistry::default();
        add_release(&mut yanked, package, "0.3.0", &old, false);
        add_release(&mut yanked, package, "0.4.0", &new, true);
        assert_eq!(
            select_baseline(root.path(), policy, &new, None, None, &tags, &mut yanked,)
                .unwrap()
                .version,
            "0.3.0"
        );

        let mut complete = FakeRegistry::default();
        add_release(&mut complete, package, "0.3.0", &old, false);
        add_release(&mut complete, package, "0.4.0", &new, false);
        assert!(
            select_baseline(
                root.path(),
                policy,
                &new,
                Some("0.3.0"),
                None,
                &tags,
                &mut complete,
            )
            .is_err()
        );
    }

    #[test]
    fn workspace_rejects_a_newer_split_official_tag_set() {
        let (root, old, new) = linear_repository();
        let policy = &crate::release_policy::RUST_POLICY;
        let mut tags = BTreeMap::new();
        let mut registry = FakeRegistry::default();
        for (index, package) in policy.packages.iter().enumerate() {
            let old_tag = package.tag("0.3.0");
            tags.insert(
                old_tag.clone(),
                tag(old_tag, char::from(b'1' + index as u8), &old),
            );
            add_release(&mut registry, package, "0.3.0", &old, false);

            let new_tag = package.tag("0.4.0");
            let split = if index == 0 { &old } else { &new };
            tags.insert(
                new_tag.clone(),
                tag(new_tag, char::from(b'5' + index as u8), split),
            );
        }
        assert!(
            select_baseline(root.path(), policy, &new, None, None, &tags, &mut registry,).is_err()
        );
    }
}

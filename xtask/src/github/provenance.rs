// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Exact Git-object provenance for a reviewed support source. Workflow bytes
//! are never read or interpreted; only the reviewed JSON inventory and opaque
//! blob identities are inspected. Current main selects the line and anchor.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, ValueEnum};
use serde::Deserialize;

use super::REPOSITORY;
use super::support::{self, Inventory};
use super::transport::Transport;
use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::release_base::git;
use crate::release_policy::ReleaseLine;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum Operation {
    Fresh,
    Recover,
}

#[derive(Args)]
pub(super) struct RebindArgs {
    #[arg(long)]
    pub(super) repository: Option<String>,
    #[arg(long)]
    pub(super) base_ref: String,
    #[arg(long, value_enum)]
    pub(super) operation: Operation,
    #[arg(long)]
    pub(super) source_root: PathBuf,
    #[arg(long)]
    pub(super) source_sha: String,
    #[arg(long)]
    pub(super) version: semver::Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    line: ReleaseLine,
    operation: Operation,
    main: String,
    source: String,
    anchor: Option<String>,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "ref")]
    name: String,
    object: Object,
}
#[derive(Deserialize)]
struct Object {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}
#[derive(Deserialize)]
struct Comparison {
    status: String,
    base_commit: Commit,
    merge_base_commit: Commit,
}
#[derive(Deserialize)]
struct Commit {
    sha: String,
}

impl Binding {
    /// The object database contains both exact protected-main and source history.
    /// Neither a source inventory nor caller-selected paths can define authority.
    pub(super) fn load(
        root: &Path,
        main: &str,
        source: &str,
        line: ReleaseLine,
        operation: Operation,
    ) -> Result<Self, String> {
        if !support::is_sha(main) || !support::is_sha(source) {
            return Err("provenance requires exact commit identities".into());
        }
        let anchor = match line {
            ReleaseLine::Main => None,
            ReleaseLine::Support { .. } => {
                let path = inventory_path(line)?;
                let inventories = git(
                    root,
                    &[
                        "ls-tree",
                        "-r",
                        "--name-only",
                        main,
                        "--",
                        ".github/support-lines/",
                    ],
                )?;
                if inventories != path {
                    return Err("main must select exactly one active support inventory".into());
                }
                let active = inventory(root, main, line)?;
                let recorded = inventory(root, source, line)?;
                if active.anchor != recorded.anchor {
                    return Err("source inventory changed the protected activation anchor".into());
                }
                ancestor(root, &active.anchor, source)?;
                ancestor(root, &active.anchor, main)?;
                if git(root, &["merge-base", source, main])? != active.anchor {
                    return Err(
                        "support source fork point differs from its immutable anchor".into(),
                    );
                }
                historical_chain(root, main, source, line, &recorded)?;
                if operation == Operation::Fresh && active.enforce {
                    // Fresh publication must be recoverable and carry every path
                    // selected by current protected main with its current bytes.
                    if !recorded.enforce || recorded.blobs.keys().ne(active.blobs.keys()) {
                        return Err(
                            "fresh source inventory differs from main's required path set".into(),
                        );
                    }
                    for (path, expected) in &recorded.blobs {
                        if support::blob(root, main, path)? != *expected {
                            return Err(format!(
                                "fresh support policy differs from main at {path}"
                            ));
                        }
                    }
                }
                Some(active.anchor)
            }
        };
        Ok(Self {
            line,
            operation,
            main: main.into(),
            source: source.into(),
            anchor,
        })
    }

    pub(super) fn verify(&self, github: &mut impl Transport) -> Result<(), String> {
        let base = read_ref(github, &self.line.base_ref())?;
        if self.operation == Operation::Fresh && base != self.source {
            return Err("fresh release source is no longer the exact protected base tip".into());
        }
        let comparison = compare(github, &self.source, &base)?;
        if !matches!(comparison.status.as_str(), "ahead" | "identical")
            || comparison.base_commit.sha != self.source
            || comparison.merge_base_commit.sha != self.source
        {
            return Err("release source is no longer on the protected base lineage".into());
        }
        if let Some(anchor) = &self.anchor {
            // Check both S and current tip T: recovery retains S, but refuses a
            // support lineage that was merged with main after activation.
            for commit in [&self.source, &base] {
                let comparison = compare(github, commit, &self.main)?;
                if comparison.base_commit.sha != *commit
                    || comparison.merge_base_commit.sha != *anchor
                {
                    return Err(
                        "protected support lineage has a different activation anchor".into(),
                    );
                }
            }
        }
        if read_ref(github, &self.line.base_ref())? != base {
            return Err("protected release base moved during provenance binding".into());
        }
        if read_ref(github, "refs/heads/main")? != self.main {
            return Err("executing release policy is no longer exact current main".into());
        }
        Ok(())
    }

    fn verify_git(&self, root: &Path, base: &str) -> Result<(), String> {
        if self.operation == Operation::Fresh && base != self.source {
            return Err("fresh release requires the exact protected base tip".into());
        }
        ancestor(root, &self.source, base)?;
        if let Some(anchor) = &self.anchor
            && git(root, &["merge-base", base, &self.main])? != *anchor
        {
            return Err("protected support tip changed its activation anchor".into());
        }
        Ok(())
    }
}

fn read_ref(github: &mut impl Transport, base: &str) -> Result<String, String> {
    let branch = base.strip_prefix("refs/").ok_or("invalid protected ref")?;
    let reference: Reference = github.get(&format!("repos/{REPOSITORY}/git/ref/{branch}"))?;
    if reference.name != base
        || reference.object.kind != "commit"
        || !support::is_sha(&reference.object.sha)
    {
        return Err("protected base is not one exact commit ref".into());
    }
    Ok(reference.object.sha)
}

fn compare(github: &mut impl Transport, source: &str, tip: &str) -> Result<Comparison, String> {
    github.get(&format!("repos/{REPOSITORY}/compare/{source}...{tip}"))
}

fn ancestor(root: &Path, older: &str, newer: &str) -> Result<(), String> {
    git(root, &["merge-base", "--is-ancestor", older, newer])
        .map(|_| ())
        .map_err(|_| "recorded commit is not on the required protected lineage".into())
}

fn inventory_path(line: ReleaseLine) -> Result<String, String> {
    match line {
        ReleaseLine::Support { major, minor } => {
            Ok(format!(".github/support-lines/{major}.{minor}.json"))
        }
        ReleaseLine::Main => Err("main has no support inventory".into()),
    }
}

fn inventory(root: &Path, commit: &str, line: ReleaseLine) -> Result<Inventory, String> {
    let path = inventory_path(line)?;
    // Inventory paths are deliberately excluded from policy blob maps, but
    // their own storage must also be one regular, bounded Git blob.
    let tree = git(root, &["ls-tree", commit, "--", &path])?;
    if !tree.starts_with("100644 blob ")
        || !tree.ends_with(&format!("\t{path}"))
        || tree.contains('\n')
    {
        return Err("support inventory is not one regular Git blob".into());
    }
    let data = git(root, &["show", &format!("{commit}:{path}")])?;
    if data.len() > 128 * 1024 {
        return Err("support inventory exceeds its bound".into());
    }
    let value: Inventory =
        serde_json::from_str(&data).map_err(|e| format!("invalid support inventory: {e}"))?;
    if value.schema_version != 1
        || value.base_ref != line.base_ref()
        || !support::is_sha(&value.anchor)
        || !support::is_sha(&value.policy_commit)
        || value.blobs.is_empty()
        || value.blobs.len() > 256
    {
        return Err("support inventory identity or path count is invalid".into());
    }
    for (path, sha) in &value.blobs {
        support::require_path(path)?;
        if !support::is_sha(sha) {
            return Err("support inventory blob is not a full object ID".into());
        }
    }
    Ok(value)
}

fn historical_chain(
    root: &Path,
    main: &str,
    source: &str,
    line: ReleaseLine,
    recorded: &Inventory,
) -> Result<(), String> {
    ancestor(root, &recorded.policy_commit, main)?;
    let path = inventory_path(line)?;
    let historical_paths =
        if git(root, &["ls-tree", &recorded.policy_commit, "--", &path])?.is_empty() {
            // Initial activation records the reviewed main seed before its first
            // per-line inventory exists. Later main inventories own their path set.
            if !recorded.enforce {
                return Err("initial historical inventory must enforce its seed".into());
            }
            support::seed_inventory(root, line, &recorded.anchor, &recorded.policy_commit)?.blobs
        } else {
            let historical = inventory(root, &recorded.policy_commit, line)?;
            if historical.anchor != recorded.anchor || historical.enforce != recorded.enforce {
                return Err("historical inventory authority differs".into());
            }
            historical.blobs
        };
    if recorded.blobs.keys().ne(historical_paths.keys()) {
        return Err("source chose a different historical required path set".into());
    }
    for (path, expected) in &recorded.blobs {
        if support::blob(root, source, path)? != *expected
            || support::blob(root, &recorded.policy_commit, path)? != *expected
        {
            return Err(format!(
                "historical support blob chain is inconsistent at {path}"
            ));
        }
    }
    Ok(())
}

/// Anonymous, read-only rebind immediately before publication authority. The
/// scratch fetch has no inherited Git configuration, remote, or credentials.
pub(super) fn rebind(root: &Path, args: &RebindArgs) -> Result<(), String> {
    support::require_repository(args.repository.as_deref())?;
    support::validate_package_family(root)?;
    let line = ReleaseLine::from_base_ref(&args.base_ref)?;
    line.require_version(&args.version)?;
    support::validate_package_family(&args.source_root)?;
    if support::source_version(&args.source_root)? != args.version {
        return Err("rebound source version differs from qualification".into());
    }
    let policy = exact_root(root)?;
    let source = exact_root(&args.source_root)?;
    if policy == source || policy.starts_with(&source) || source.starts_with(&policy) {
        return Err("policy and source require separate, non-nested roots".into());
    }
    if !support::is_sha(&args.source_sha)
        || git(&source, &["rev-parse", "HEAD"])? != args.source_sha
    {
        return Err("source checkout differs from its qualified source".into());
    }
    let scratch = tempfile::tempdir().map_err(|e| format!("create provenance checkout: {e}"))?;
    git(scratch.path(), &["init", "--quiet"])?;
    let remote = format!("https://github.com/{REPOSITORY}.git");
    fetch(scratch.path(), &remote, line)?;
    let main = git(scratch.path(), &["rev-parse", "refs/remotes/origin/main"])?;
    let base = git(scratch.path(), &["rev-parse", &line.tracking_ref()])?;
    if git(&policy, &["rev-parse", "HEAD"])? != main {
        return Err("executing policy is no longer exact current main".into());
    }
    let binding = Binding::load(
        scratch.path(),
        &main,
        &args.source_sha,
        line,
        args.operation,
    )?;
    binding.verify_git(scratch.path(), &base)?;
    // Re-read both live refs after the complete object-chain check.
    fetch(scratch.path(), &remote, line)?;
    if git(scratch.path(), &["rev-parse", "refs/remotes/origin/main"])? != main
        || git(scratch.path(), &["rev-parse", &line.tracking_ref()])? != base
    {
        return Err("protected refs moved during policy rebind".into());
    }
    println!(
        "Bound {0} source {1} to main {main} ({2:?}).",
        args.base_ref, args.source_sha, args.operation
    );
    Ok(())
}

fn exact_root(root: &Path) -> Result<PathBuf, String> {
    let actual = root.canonicalize().map_err(|e| e.to_string())?;
    let top = PathBuf::from(git(root, &["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if actual != top
        || !git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty()
    {
        return Err("release checkout must be its exact clean Git root".into());
    }
    Ok(actual)
}

fn fetch(root: &Path, remote: &str, line: ReleaseLine) -> Result<(), String> {
    let mut command = Command::new("git");
    // A fresh scratch repository and empty config prevent credential helpers,
    // URL rewrites, hooks, and caller-selected network transport from executing.
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| key.starts_with("GIT_")) {
            command.env_remove(key);
        }
    }
    command
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GIT_TOKEN")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .current_dir(root)
        .args([
            "-c",
            "credential.helper=",
            "fetch",
            "--quiet",
            "--no-tags",
            remote,
            "+refs/heads/main:refs/remotes/origin/main",
        ]);
    if line != ReleaseLine::Main {
        command.arg(format!("+{}:{}", line.base_ref(), line.tracking_ref()));
    }
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .map_err(|e| format!("fetch protected history: {e}"))?;
    if !output.status.success() {
        return Err("anonymous protected-history fetch failed".into());
    }
    Ok(())
}

// A JSON object must not silently replace an earlier expectation for one path.
pub(super) fn unique_blobs<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique policy paths")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((path, sha)) = map.next_entry::<String, String>()? {
                if result.len() >= 256 || result.insert(path, sha).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive policy paths",
                    ));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fs;

    const LINE: ReleaseLine = ReleaseLine::Support { major: 0, minor: 5 };

    struct Fixture {
        dir: tempfile::TempDir,
        anchor: String,
        policy: String,
        main: String,
        source: String,
        inventory: Inventory,
    }
    fn commit(root: &Path, name: &str) -> String {
        git(root, &["add", "."]).unwrap();
        git(
            root,
            &[
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                name,
            ],
        )
        .unwrap();
        git(root, &["rev-parse", "HEAD"]).unwrap()
    }
    fn write_inventory(root: &Path, inventory: &Inventory) {
        fs::create_dir_all(root.join(".github/support-lines")).unwrap();
        fs::write(
            root.join(inventory_path(LINE).unwrap()),
            serde_json::to_vec(inventory).unwrap(),
        )
        .unwrap();
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            git(root, &["init", "--quiet"]).unwrap();
            fs::create_dir_all(root.join(".github")).unwrap();
            fs::write(
                root.join(".github/support-policy-paths.txt"),
                "policy.txt\n",
            )
            .unwrap();
            fs::write(root.join("policy.txt"), "reviewed policy\n").unwrap();
            let anchor = commit(root, "stable anchor");
            fs::write(root.join("main.txt"), "stable successor\n").unwrap();
            let policy = commit(root, "main successor");
            let inventory = support::seed_inventory(root, LINE, &anchor, &policy).unwrap();
            write_inventory(root, &inventory);
            let main = commit(root, "activate reviewed inventory");
            git(root, &["checkout", "--quiet", "--detach", &anchor]).unwrap();
            write_inventory(root, &inventory);
            fs::write(root.join("source.txt"), "prepared release S\n").unwrap();
            let source = commit(root, "support source");
            Self {
                dir,
                anchor,
                policy,
                main,
                source,
                inventory,
            }
        }
        fn binding(
            &self,
            main: &str,
            source: &str,
            operation: Operation,
        ) -> Result<Binding, String> {
            Binding::load(self.dir.path(), main, source, LINE, operation)
        }
    }

    #[test]
    fn recovery_keeps_s_after_t_and_main_policy_move() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        let fresh = fixture
            .binding(&fixture.main, &fixture.source, Operation::Fresh)
            .unwrap();
        fresh.verify_git(root, &fixture.source).unwrap();
        fs::write(root.join("source.txt"), "later support tip T\n").unwrap();
        let tip = commit(root, "later fix");
        assert!(fresh.verify_git(root, &tip).is_err());
        git(root, &["checkout", "--quiet", "--detach", &fixture.main]).unwrap();
        fs::write(root.join("policy.txt"), "new main policy\n").unwrap();
        let main = commit(root, "change main policy");
        let recovered = fixture
            .binding(&main, &fixture.source, Operation::Recover)
            .unwrap();
        recovered.verify_git(root, &tip).unwrap();
        assert!(
            fixture
                .binding(&main, &fixture.source, Operation::Fresh)
                .is_err()
        );
        assert!(fixture.binding(&main, &tip, Operation::Fresh).is_err());
        // A later fresh source becomes eligible only after a reviewed policy
        // backport and an inventory naming the real new main blob.
        git(root, &["checkout", "--quiet", "--detach", &tip]).unwrap();
        fs::write(root.join("policy.txt"), "new main policy\n").unwrap();
        let mut inventory = fixture.inventory.clone();
        inventory.policy_commit = main.clone();
        inventory.blobs.insert(
            "policy.txt".into(),
            support::blob(root, &main, "policy.txt").unwrap(),
        );
        write_inventory(root, &inventory);
        let next = commit(root, "backport reviewed policy");
        fixture.binding(&main, &next, Operation::Fresh).unwrap();
    }

    #[test]
    fn historical_chain_rejects_stale_forged_and_untrusted_inventories() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        for variant in 0..6 {
            git(root, &["checkout", "--quiet", "--detach", &fixture.source]).unwrap();
            let mut inventory = fixture.inventory.clone();
            match variant {
                0 => {
                    inventory.blobs.insert("policy.txt".into(), "a".repeat(40));
                }
                1 => {
                    inventory.policy_commit = fixture.source.clone();
                }
                2 => {
                    inventory.anchor = fixture.policy.clone();
                }
                3 => {
                    inventory.blobs.clear();
                }
                4 => {
                    inventory
                        .blobs
                        .insert(".github/support-lines/0.5.json".into(), "a".repeat(40));
                }
                5 => {
                    inventory.enforce = false;
                }
                _ => unreachable!(),
            }
            write_inventory(root, &inventory);
            let source = commit(root, "invalid inventory");
            for operation in [Operation::Fresh, Operation::Recover] {
                assert!(
                    fixture.binding(&fixture.main, &source, operation).is_err(),
                    "variant {variant}"
                );
            }
        }
        // Matching current files cannot conceal stale source inventory metadata.
        git(root, &["checkout", "--quiet", "--detach", &fixture.source]).unwrap();
        fs::write(root.join("policy.txt"), "source-only invented content\n").unwrap();
        let changed = commit(root, "source policy differs");
        let mut invented = fixture.inventory.clone();
        invented.blobs.insert(
            "policy.txt".into(),
            support::blob(root, &changed, "policy.txt").unwrap(),
        );
        write_inventory(root, &invented);
        let source = commit(root, "invented blob expectation");
        assert!(
            fixture
                .binding(&fixture.main, &source, Operation::Recover)
                .unwrap_err()
                .contains("blob chain")
        );
    }

    #[test]
    fn inventory_is_unique_and_main_controls_active_line_and_anchor() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        let encoded = serde_json::to_string(&fixture.inventory).unwrap();
        let needle = format!(
            "\"policy.txt\":\"{}\"",
            fixture.inventory.blobs["policy.txt"]
        );
        assert!(
            serde_json::from_str::<Inventory>(
                &encoded.replace(&needle, &format!("{needle},{needle}"))
            )
            .is_err()
        );
        git(root, &["checkout", "--quiet", "--detach", &fixture.main]).unwrap();
        fs::copy(
            root.join(inventory_path(LINE).unwrap()),
            root.join(".github/support-lines/0.4.json"),
        )
        .unwrap();
        let main = commit(root, "second active line");
        assert!(
            fixture
                .binding(&main, &fixture.source, Operation::Recover)
                .is_err()
        );
        git(root, &["checkout", "--quiet", "--detach", &fixture.main]).unwrap();
        let mut inventory = fixture.inventory.clone();
        inventory.anchor = fixture.policy.clone();
        write_inventory(root, &inventory);
        let main = commit(root, "change trusted anchor");
        assert!(
            fixture
                .binding(&main, &fixture.source, Operation::Recover)
                .is_err()
        );
    }

    struct Api {
        replies: BTreeMap<String, Value>,
    }
    impl Transport for Api {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            serde_json::from_value(
                self.replies
                    .get(path)
                    .ok_or_else(|| format!("unexpected GET {path}"))?
                    .clone(),
            )
            .map_err(|e| e.to_string())
        }
        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            _path: &str,
        ) -> Result<Option<T>, String> {
            Err("unexpected optional GET".into())
        }
        fn mutate<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            _method: &str,
            _path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            Err("provenance must be read-only".into())
        }
    }
    #[test]
    fn live_binding_requires_protected_lineage_and_exact_current_policy() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        fs::write(root.join("source.txt"), "later support tip\n").unwrap();
        let tip = commit(root, "tip");
        let binding = fixture
            .binding(&fixture.main, &fixture.source, Operation::Recover)
            .unwrap();
        let mut replies = BTreeMap::new();
        for (base, sha) in [
            (LINE.base_ref(), &tip),
            ("refs/heads/main".into(), &fixture.main),
        ] {
            replies.insert(
                format!(
                    "repos/{REPOSITORY}/git/ref/{}",
                    base.strip_prefix("refs/").unwrap()
                ),
                json!({"ref":base,"object":{"type":"commit","sha":sha}}),
            );
        }
        replies.insert(format!("repos/{REPOSITORY}/compare/{}...{tip}", fixture.source), json!({"status":"ahead","base_commit":{"sha":fixture.source},"merge_base_commit":{"sha":fixture.source}}));
        for source in [&fixture.source, &tip] {
            replies.insert(format!("repos/{REPOSITORY}/compare/{source}...{}", fixture.main), json!({"status":"diverged","base_commit":{"sha":source},"merge_base_commit":{"sha":fixture.anchor}}));
        }
        binding
            .verify(&mut Api {
                replies: replies.clone(),
            })
            .unwrap();
        let mut moved = replies.clone();
        moved
            .get_mut(&format!("repos/{REPOSITORY}/git/ref/heads/main"))
            .unwrap()["object"]["sha"] = json!("a".repeat(40));
        assert!(binding.verify(&mut Api { replies: moved }).is_err());
        let mut outside = replies.clone();
        outside
            .get_mut(&format!(
                "repos/{REPOSITORY}/compare/{}...{tip}",
                fixture.source
            ))
            .unwrap()["merge_base_commit"]["sha"] = json!(fixture.anchor);
        assert!(binding.verify(&mut Api { replies: outside }).is_err());
        let mut wrong_tip_anchor = replies;
        wrong_tip_anchor
            .get_mut(&format!(
                "repos/{REPOSITORY}/compare/{tip}...{}",
                fixture.main
            ))
            .unwrap()["merge_base_commit"]["sha"] = json!(fixture.policy);
        assert!(
            binding
                .verify(&mut Api {
                    replies: wrong_tip_anchor
                })
                .is_err()
        );
    }

    #[test]
    fn anonymous_fetch_reads_only_selected_refs_and_exact_roots_reject_drift() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        git(root, &["update-ref", "refs/heads/main", &fixture.main]).unwrap();
        git(root, &["update-ref", &LINE.base_ref(), &fixture.source]).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        git(scratch.path(), &["init", "--quiet"]).unwrap();
        fetch(scratch.path(), root.to_str().unwrap(), LINE).unwrap();
        assert_eq!(
            git(scratch.path(), &["rev-parse", "refs/remotes/origin/main"]).unwrap(),
            fixture.main
        );
        assert_eq!(
            git(scratch.path(), &["rev-parse", &LINE.tracking_ref()]).unwrap(),
            fixture.source
        );
        assert_eq!(git(scratch.path(), &["tag", "--list"]).unwrap(), "");
        exact_root(root).unwrap();
        assert!(exact_root(&root.join(".github")).is_err());
        fs::write(root.join("untracked"), "drift").unwrap();
        assert!(exact_root(root).is_err());
    }
}

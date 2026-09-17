// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Read-only support activation proposal, bound to exact protected main.

use std::collections::BTreeMap;
use std::path::Path;

use semver::Version;
use serde::{Deserialize, Serialize};

use super::transport::{GhCli, Transport};
use super::{APP_EMAIL, APP_LOGIN, REPOSITORY};
use crate::release_base::git;
use crate::release_policy::ReleaseLine;

const SEED_PATH: &str = ".github/support-policy-paths.txt";
const MAX_TAGS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    pub(super) schema_version: u32,
    pub(super) base_ref: String,
    pub(super) anchor: String,
    pub(super) policy_commit: String,
    pub(super) enforce: bool,
    #[serde(deserialize_with = "super::provenance::unique_blobs")]
    pub(super) blobs: BTreeMap<String, String>,
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
struct Tag {
    sha: String,
    tag: String,
    object: Object,
    tagger: Tagger,
}

#[derive(Deserialize)]
struct Tagger {
    name: String,
    email: String,
}

pub(super) fn start(
    root: &Path,
    version: &Version,
    repository: Option<&str>,
) -> Result<(), String> {
    require_repository(repository)?;
    validate_package_family(root)?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err("support activation requires a published stable version".into());
    }
    let line = ReleaseLine::Support {
        major: version.major,
        minor: version.minor,
    };
    ReleaseLine::from_base_ref(&line.base_ref())?;
    let mut github = GhCli::new()?;
    let main: Reference = github.get(&format!("repos/{REPOSITORY}/git/ref/heads/main"))?;
    if main.name != "refs/heads/main" || main.object.kind != "commit" || !is_sha(&main.object.sha) {
        return Err("main is not one exact commit ref".into());
    }
    // Local proposal generation must inspect the same reviewed policy that a
    // main-dispatched operation would execute. It never fetches or writes refs.
    if root.canonicalize().map_err(|e| e.to_string())?
        != Path::new(&git(root, &["rev-parse", "--show-toplevel"])?)
            .canonicalize()
            .map_err(|e| e.to_string())?
        || git(root, &["rev-parse", "HEAD"])? != main.object.sha
        || !git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty()
    {
        return Err("start-support requires an exact clean current-main checkout".into());
    }
    let active: Vec<Reference> = github.get(&format!(
        "repos/{REPOSITORY}/git/matching-refs/heads/support/"
    ))?;
    if !active.is_empty()
        || !git(
            root,
            &[
                "ls-tree",
                "--name-only",
                &main.object.sha,
                ".github/support-lines/",
            ],
        )?
        .is_empty()
    {
        return Err(
            "an existing support ref or inventory must be retired before opening another line"
                .into(),
        );
    }
    let tags: Vec<Reference> = github.get(&format!(
        "repos/{REPOSITORY}/git/matching-refs/tags/{}",
        tag_prefixes()[0]
    ))?;
    let successor = select_successor(&tags, line, version)?;
    let anchor = published_source(
        &mut github,
        root,
        version,
        &main.object.sha,
        verify_packages,
    )?;
    published_source(
        &mut github,
        root,
        &successor,
        &main.object.sha,
        verify_packages,
    )?;
    let inventory = seed_inventory(root, line, &anchor, &main.object.sha)?;
    // Complete all reads before printing a transaction that an operator may use.
    let current: Reference = github.get(&format!("repos/{REPOSITORY}/git/ref/heads/main"))?;
    if current.name != main.name
        || current.object.kind != "commit"
        || current.object.sha != main.object.sha
    {
        return Err("protected main changed during proposal generation".into());
    }
    println!("Eligible after stable main publication {successor}; anchor {anchor}.");
    println!("Review the protection transaction before executing this absent-ref push:");
    println!(
        "git push --force-with-lease={}: origin {}:{}",
        line.base_ref(),
        anchor,
        line.base_ref()
    );
    println!(
        "Proposed .github/support-lines/{}.{}.json:",
        version.major, version.minor
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&inventory).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub(super) fn require_repository(explicit: Option<&str>) -> Result<(), String> {
    let observed = if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        if std::env::var("GITHUB_REF").as_deref() != Ok("refs/heads/main") {
            return Err("release policy executes only from protected main".into());
        }
        let actual =
            std::env::var("GITHUB_REPOSITORY").map_err(|_| "GITHUB_REPOSITORY is required")?;
        if explicit.is_some_and(|value| value != actual) {
            return Err("repository argument differs from GitHub's repository identity".into());
        }
        actual
    } else {
        explicit
            .ok_or("local start-support requires --repository")?
            .to_string()
    };
    if observed != REPOSITORY {
        return Err("repository differs from compiled release policy".into());
    }
    Ok(())
}

pub(super) fn require_fresh_progression(
    github: &mut impl Transport,
    line: ReleaseLine,
    selected: &Version,
) -> Result<(), String> {
    if line == ReleaseLine::Main {
        return Ok(());
    }
    let prefix = tag_prefixes()[0];
    let references: Vec<Reference> = github.get(&format!(
        "repos/{REPOSITORY}/git/matching-refs/tags/{prefix}"
    ))?;
    if references.len() > MAX_TAGS {
        return Err("release tag inventory exceeds its bound".into());
    }
    let mut published = Vec::new();
    for reference in references {
        let raw = reference
            .name
            .strip_prefix(&format!("refs/tags/{prefix}"))
            .ok_or("unexpected release tag prefix")?;
        if let Ok(version) = Version::parse(raw)
            && version.to_string() == raw
        {
            if reference.object.kind != "tag" || !is_sha(&reference.object.sha) {
                return Err("release progression requires annotated release tags".into());
            }
            published.push(version);
        }
    }
    line.require_advancement(selected, &published)
}

fn select_successor(
    tags: &[Reference],
    line: ReleaseLine,
    selected: &Version,
) -> Result<Version, String> {
    if tags.len() > MAX_TAGS {
        return Err("release tag inventory exceeds its bound".into());
    }
    let mut versions = Vec::new();
    let prefix = format!("refs/tags/{}", tag_prefixes()[0]);
    for tag in tags {
        let raw = tag
            .name
            .strip_prefix(&prefix)
            .ok_or("unexpected release tag prefix")?;
        // Historical non-SemVer names do not establish typed release eligibility.
        if let Ok(version) = Version::parse(raw)
            && version.to_string() == raw
        {
            versions.push(version);
        }
    }
    if versions
        .iter()
        .filter(|v| line.admits(v) && v.pre.is_empty() && v.build.is_empty())
        .max()
        != Some(selected)
    {
        return Err("activation must use the line's latest tagged stable version".into());
    }
    versions
        .into_iter()
        .filter(|v| line.require_successor(v).is_ok())
        .max()
        .ok_or_else(|| {
            "main has no tagged stable successor outside the old line; an RC is insufficient".into()
        })
}

fn published_source(
    github: &mut impl Transport,
    root: &Path,
    version: &Version,
    main: &str,
    verify: impl FnOnce(&str, &Version) -> Result<(), String>,
) -> Result<String, String> {
    let mut source = None;
    for prefix in tag_prefixes() {
        let name = format!("{prefix}{version}");
        let reference: Reference =
            github.get(&format!("repos/{REPOSITORY}/git/ref/tags/{name}"))?;
        if reference.name != format!("refs/tags/{name}")
            || reference.object.kind != "tag"
            || !is_sha(&reference.object.sha)
        {
            return Err("activation requires annotated release tags".into());
        }
        let tag: Tag = github.get(&format!(
            "repos/{REPOSITORY}/git/tags/{}",
            reference.object.sha
        ))?;
        if tag.sha != reference.object.sha
            || tag.tag != name
            || tag.object.kind != "commit"
            || !is_sha(&tag.object.sha)
            || tag.tagger.name != APP_LOGIN
            || tag.tagger.email != APP_EMAIL
        {
            return Err("activation release tag differs from the compiled App policy".into());
        }
        if source
            .as_ref()
            .is_some_and(|value| value != &tag.object.sha)
        {
            return Err("release package tags disagree on source".into());
        }
        source = Some(tag.object.sha);
    }
    let source = source.ok_or("compiled package policy has no release tags")?;
    git(root, &["merge-base", "--is-ancestor", &source, main]).map_err(
        |_| "published source is not on current main; fetch the exact history before retrying",
    )?;
    verify(&source, version)?;
    Ok(source)
}

pub(super) fn seed_inventory(
    root: &Path,
    line: ReleaseLine,
    anchor: &str,
    main: &str,
) -> Result<Inventory, String> {
    let seed = git(root, &["show", &format!("{main}:{SEED_PATH}")])?;
    let mut blobs = BTreeMap::new();
    for path in seed
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        require_path(path)?;
        if blobs
            .insert(path.to_string(), blob(root, main, path)?)
            .is_some()
        {
            return Err("duplicate support policy seed path".into());
        }
    }
    if blobs.is_empty() || blobs.len() > 256 {
        return Err("support policy inventory must contain 1 through 256 paths".into());
    }
    Ok(Inventory {
        schema_version: 1,
        base_ref: line.base_ref(),
        anchor: anchor.into(),
        policy_commit: main.into(),
        enforce: true,
        blobs,
    })
}

pub(super) fn require_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with(".github/support-lines/")
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte))
    {
        return Err("invalid support policy path or self-referential inventory".into());
    }
    Ok(())
}

pub(super) fn blob(root: &Path, commit: &str, path: &str) -> Result<String, String> {
    require_path(path)?;
    if !is_sha(commit) {
        return Err("policy commit must be a full lowercase SHA".into());
    }
    let row = git(root, &["ls-tree", commit, "--", path])?;
    let (metadata, actual) = row.split_once('\t').ok_or("policy path is absent")?;
    let fields: Vec<_> = metadata.split(' ').collect();
    if actual != path
        || fields.len() != 3
        || !matches!(fields[0], "100644" | "100755")
        || fields[1] != "blob"
        || !is_sha(fields[2])
    {
        return Err("support policy path is not one regular Git blob".into());
    }
    Ok(fields[2].to_string())
}

pub(super) fn is_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn tag_prefixes() -> Vec<&'static str> {
    vec![crate::release_policy::TRAITS_PACKAGE.tag_prefix]
}

pub(super) fn source_version(root: &Path) -> Result<Version, String> {
    crate::release::manifest_version(root)
}

pub(super) fn validate_package_family(root: &Path) -> Result<(), String> {
    crate::release::check_manifest(root)
}

fn verify_packages(source: &str, version: &Version) -> Result<(), String> {
    crate::crate_archive::require_archive(
        &mut crate::crate_archive::CratesIo::new(),
        &crate::release_policy::TRAITS_PACKAGE,
        &version.to_string(),
        source,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(version: &str) -> Reference {
        Reference {
            name: format!("refs/tags/{}{version}", tag_prefixes()[0]),
            object: Object {
                kind: "tag".into(),
                sha: "a".repeat(40),
            },
        }
    }

    #[test]
    fn activation_requires_a_stable_successor_and_last_stable_anchor() {
        let line = ReleaseLine::Support { major: 0, minor: 5 };
        let version = Version::parse("0.5.1").unwrap();
        assert!(
            select_successor(
                &[reference("1alpha1"), reference("0.5.1"), reference("0.6.0")],
                line,
                &version
            )
            .is_ok()
        );
        assert!(
            select_successor(
                &[reference("0.5.1"), reference("0.6.0-rc.1")],
                line,
                &version
            )
            .is_err()
        );
        assert!(
            select_successor(&[reference("0.5.1"), reference("0.4.9")], line, &version).is_err()
        );
        assert_eq!(
            select_successor(&[reference("0.5.1"), reference("0.6.0")], line, &version).unwrap(),
            Version::parse("0.6.0").unwrap()
        );
        assert!(
            select_successor(
                &[reference("0.5.1"), reference("0.5.2"), reference("0.6.0")],
                line,
                &version
            )
            .is_err()
        );
    }

    #[test]
    fn policy_paths_exclude_self_reference_and_git_pathspecs() {
        for bad in [
            "../workflow",
            "/workflow",
            "a//b",
            "a/./b",
            ":(glob)**",
            ".github/support-lines/0.5.json",
            "a\nb",
        ] {
            assert!(require_path(bad).is_err());
        }
        assert!(require_path(".github/workflows/publish.yml").is_ok());
    }

    fn fixture() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "--quiet", "--initial-branch=main"]).unwrap();
        std::fs::create_dir_all(dir.path().join(".github")).unwrap();
        std::fs::write(dir.path().join(SEED_PATH), "policy.txt\n").unwrap();
        std::fs::write(dir.path().join("policy.txt"), "policy\n").unwrap();
        git(dir.path(), &["add", "."]).unwrap();
        git(
            dir.path(),
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        )
        .unwrap();
        let sha = git(dir.path(), &["rev-parse", "HEAD"]).unwrap();
        (dir, sha)
    }

    #[test]
    fn inventory_records_exact_regular_blobs_without_reading_their_contents() {
        let (dir, sha) = fixture();
        let line = ReleaseLine::Support { major: 0, minor: 5 };
        let inventory = seed_inventory(dir.path(), line, &sha, &sha).unwrap();
        assert_eq!(
            inventory.blobs["policy.txt"],
            git(dir.path(), &["rev-parse", &format!("{sha}:policy.txt")]).unwrap()
        );
        assert_eq!(inventory.anchor, sha);
        assert!(inventory.enforce);
        assert!(blob(dir.path(), &sha, "missing.txt").is_err());
        assert!(blob(dir.path(), &sha, ".github").is_err());
    }

    struct ReadOnlyGithub(BTreeMap<String, serde_json::Value>);

    impl Transport for ReadOnlyGithub {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            serde_json::from_value(self.0.get(path).cloned().ok_or("unexpected read")?)
                .map_err(|e| e.to_string())
        }
        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            self.0
                .get(path)
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| e.to_string())
        }
        fn mutate<T: serde::de::DeserializeOwned, P: Serialize>(
            &mut self,
            _method: &str,
            _path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            panic!("activation attempted mutation")
        }
    }

    fn github_fixture(sha: &str, version: &Version) -> ReadOnlyGithub {
        let mut responses = BTreeMap::new();
        for (index, prefix) in tag_prefixes().iter().enumerate() {
            let tag = format!("{prefix}{version}");
            let object = format!("{index:040x}");
            responses.insert(
                format!("repos/{REPOSITORY}/git/ref/tags/{tag}"),
                serde_json::json!({
                    "ref": format!("refs/tags/{tag}"), "object": {"type":"tag", "sha":object}
                }),
            );
            responses.insert(
                format!("repos/{REPOSITORY}/git/tags/{object}"),
                serde_json::json!({
                    "sha":object, "tag":tag, "object":{"type":"commit", "sha":sha},
                    "tagger":{"name":APP_LOGIN,"email":APP_EMAIL}
                }),
            );
        }
        ReadOnlyGithub(responses)
    }

    #[test]
    fn activation_binds_annotated_app_tags_to_main_and_published_sources() {
        let (dir, sha) = fixture();
        let version = Version::parse("0.5.1").unwrap();
        let mut github = github_fixture(&sha, &version);
        assert_eq!(
            published_source(&mut github, dir.path(), &version, &sha, |source, v| {
                assert_eq!(source, sha);
                assert_eq!(v, &version);
                Ok(())
            })
            .unwrap(),
            sha
        );
        assert!(
            published_source(&mut github, dir.path(), &version, &sha, |_, _| Err(
                "partial registry".into()
            ))
            .is_err()
        );
        let key = format!("repos/{REPOSITORY}/git/tags/{:040x}", 0);
        github.0.get_mut(&key).unwrap()["tagger"]["email"] =
            serde_json::json!("wrong@example.invalid");
        assert!(
            published_source(&mut github, dir.path(), &version, &sha, |_, _| panic!(
                "registry must not precede tag validation"
            ))
            .is_err()
        );
        let mut github = github_fixture(&sha, &version);
        let key = format!(
            "repos/{REPOSITORY}/git/ref/tags/{}{version}",
            tag_prefixes()[0]
        );
        github.0.get_mut(&key).unwrap()["object"]["type"] = serde_json::json!("commit");
        assert!(
            published_source(&mut github, dir.path(), &version, &sha, |_, _| panic!(
                "lightweight tag reached registry"
            ))
            .is_err()
        );
        let mut github = github_fixture(&"f".repeat(40), &version);
        assert!(
            published_source(&mut github, dir.path(), &version, &sha, |_, _| panic!(
                "off-main source reached registry"
            ))
            .is_err()
        );
    }
}

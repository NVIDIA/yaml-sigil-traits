// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral release version transactions.

use std::fs;
use std::path::Path;

use semver::{Prerelease, Version};

const CHANGELOG: &str = "CHANGELOG.md";

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage());
    };

    match command {
        "show" if args.len() == 1 => {
            println!("{}", read_version(root)?);
            Ok(())
        }
        "check" if args.len() == 1 => {
            let version = read_version(root)?;
            eprintln!("release-version: manifest version is {version}");
            Ok(())
        }
        "snapshot" => {
            let pr = required_value(args, "--pr")?
                .parse::<u64>()
                .map_err(|_| "--pr must be a positive pull-request number".to_string())?;
            if pr == 0 {
                return Err("--pr must be a positive pull-request number".to_string());
            }
            let sha = required_value(args, "--sha")?;
            ensure_only_flags(args, &["--pr", "--sha"])?;
            let version = snapshot_version(&read_version(root)?, pr, sha)?;
            write_version(root, &version)?;
            println!("{version}");
            Ok(())
        }
        "candidate" => {
            let published = Version::parse(required_value(args, "--published")?)
                .map_err(|error| format!("invalid --published version: {error}"))?;
            let bump = required_value(args, "--bump")?;
            let date = required_value(args, "--date")?;
            validate_date(date)?;
            ensure_only_flags(
                args,
                &["--published", "--bump", "--date", "--release-notes"],
            )?;
            let release_notes = args.iter().any(|arg| arg == "--release-notes");
            let current = read_version(root)?;
            let target = candidate_version(&published, &current, bump)?;
            write_version(root, &target)?;
            if release_notes {
                ensure_candidate_changelog(root, &current, &target, date)?;
            }
            println!("{target}");
            Ok(())
        }
        "promote-stable" => {
            let date = required_value(args, "--date")?;
            validate_date(date)?;
            ensure_only_flags(args, &["--date"])?;
            let current = read_version(root)?;
            let stable = stable_version(&current)?;
            promote_changelog(root, &current, &stable, date)?;
            write_version(root, &stable)?;
            println!("{stable}");
            Ok(())
        }
        "help" | "--help" | "-h" => {
            eprintln!("{}", usage());
            Ok(())
        }
        _ => Err(usage()),
    }
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let version = read_version(root)?;
    eprintln!("release-version: manifest version is {version}");
    Ok(())
}

fn usage() -> String {
    "usage: cargo xtask release-version \
     <show|check|snapshot --pr N --sha SHA|candidate --published VERSION \
     --bump auto|patch|minor|major --date YYYY-MM-DD [--release-notes]|\
     promote-stable --date YYYY-MM-DD>"
        .to_string()
}

fn required_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("missing {flag}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn ensure_only_flags(args: &[String], flags: &[&str]) -> Result<(), String> {
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();
        if !flags.contains(&arg) {
            return Err(format!("unexpected argument: {arg}"));
        }
        index += 1;
        if arg != "--release-notes" {
            if index >= args.len() || args[index].starts_with("--") {
                return Err(format!("missing value for {arg}"));
            }
            index += 1;
        }
    }
    Ok(())
}

fn validate_date(date: &str) -> Result<(), String> {
    let bytes = date.as_bytes();
    if bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err("--date must use YYYY-MM-DD".to_string())
    }
}

fn read_version(root: &Path) -> Result<Version, String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("read Cargo.toml: {error}"))?;
    let value = section_version(&manifest, "[package]")?
        .ok_or_else(|| "missing [package] version in Cargo.toml".to_string())?;
    Version::parse(&value).map_err(|error| format!("invalid package version {value}: {error}"))
}

fn write_version(root: &Path, version: &Version) -> Result<(), String> {
    let path = root.join("Cargo.toml");
    let manifest =
        fs::read_to_string(&path).map_err(|error| format!("read Cargo.toml: {error}"))?;
    let updated = replace_section_version(&manifest, "[package]", &version.to_string())?;
    if updated != manifest {
        fs::write(path, updated).map_err(|error| format!("write Cargo.toml: {error}"))?;
    }
    Ok(())
}

fn section_version(manifest: &str, section: &str) -> Result<Option<String>, String> {
    let mut in_section = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == section {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            break;
        }
        if in_section && trimmed.starts_with("version = ") {
            let value = trimmed
                .strip_prefix("version = ")
                .and_then(|value| value.strip_prefix('"'))
                .and_then(|value| value.split('"').next())
                .ok_or_else(|| format!("invalid version line: {line}"))?;
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn replace_section_version(manifest: &str, section: &str, version: &str) -> Result<String, String> {
    let mut in_section = false;
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == section {
            in_section = true;
        } else if in_section && trimmed.starts_with('[') {
            in_section = false;
        }

        if in_section && trimmed.starts_with("version = ") {
            if replaced {
                return Err(format!("multiple version entries in {section}"));
            }
            let prefix_end = line
                .find('"')
                .ok_or_else(|| format!("invalid version line: {line}"))?
                + 1;
            let suffix_start = prefix_end
                + line[prefix_end..]
                    .find('"')
                    .ok_or_else(|| format!("invalid version line: {line}"))?;
            lines.push(format!(
                "{}{}{}",
                &line[..prefix_end],
                version,
                &line[suffix_start..]
            ));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        return Err(format!("missing version entry in {section}"));
    }
    let mut output = lines.join("\n");
    output.push('\n');
    Ok(output)
}

fn snapshot_version(current: &Version, pr: u64, sha: &str) -> Result<Version, String> {
    if sha.len() < 12 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--sha must contain at least 12 hexadecimal characters".to_string());
    }
    let short_sha = sha[..12].to_ascii_lowercase();
    Version::parse(&format!(
        "{}.{}.{}-0.pr.{pr}.commit.sha{short_sha}",
        current.major, current.minor, current.patch
    ))
    .map_err(|error| format!("construct snapshot version: {error}"))
}

fn candidate_version(
    published: &Version,
    current: &Version,
    bump: &str,
) -> Result<Version, String> {
    let mut target = match bump {
        "auto" if current != published => {
            if current.pre.is_empty() {
                with_rc(current, 1)?
            } else {
                require_rc(current)?;
                current.clone()
            }
        }
        "auto" => {
            if published.pre.is_empty() {
                bumped_core(published, "patch")?
            } else {
                let rc = require_rc(published)?;
                with_rc(published, rc.checked_add(1).ok_or("rc number overflow")?)?
            }
        }
        "patch" | "minor" | "major" => bumped_core(published, bump)?,
        _ => return Err("--bump must be auto, patch, minor, or major".to_string()),
    };
    target.build = semver::BuildMetadata::EMPTY;
    Ok(target)
}

fn bumped_core(version: &Version, bump: &str) -> Result<Version, String> {
    let (major, minor, patch) = match bump {
        "patch" => (
            version.major,
            version.minor,
            version
                .patch
                .checked_add(1)
                .ok_or("patch version overflow")?,
        ),
        "minor" => (
            version.major,
            version
                .minor
                .checked_add(1)
                .ok_or("minor version overflow")?,
            0,
        ),
        "major" => (
            version
                .major
                .checked_add(1)
                .ok_or("major version overflow")?,
            0,
            0,
        ),
        _ => return Err(format!("unsupported bump: {bump}")),
    };
    with_rc(&Version::new(major, minor, patch), 1)
}

fn require_rc(version: &Version) -> Result<u64, String> {
    let value = version.pre.as_str();
    let number = value
        .strip_prefix("rc.")
        .ok_or_else(|| format!("expected an rc.N prerelease, found {version}"))?;
    number
        .parse::<u64>()
        .map_err(|_| format!("expected an rc.N prerelease, found {version}"))
}

fn with_rc(version: &Version, rc: u64) -> Result<Version, String> {
    let mut version = Version::new(version.major, version.minor, version.patch);
    version.pre = Prerelease::new(&format!("rc.{rc}"))
        .map_err(|error| format!("construct rc prerelease: {error}"))?;
    Ok(version)
}

fn stable_version(version: &Version) -> Result<Version, String> {
    require_rc(version)?;
    Ok(Version::new(version.major, version.minor, version.patch))
}

fn ensure_candidate_changelog(
    root: &Path,
    generated: &Version,
    target: &Version,
    date: &str,
) -> Result<(), String> {
    let path = root.join(CHANGELOG);
    let body = fs::read_to_string(&path).map_err(|error| format!("read {CHANGELOG}: {error}"))?;
    let generated_prefix = format!("## [{generated}](");
    let target_prefix = format!("## [{target}](");
    let mut changed = false;
    let mut output = Vec::new();
    for line in body.lines() {
        if line.starts_with(&generated_prefix) && generated != target {
            output.push(line.replacen(&generated.to_string(), &target.to_string(), 2));
            changed = true;
        } else {
            output.push(line.to_string());
        }
    }
    let mut updated = output.join("\n");
    updated.push('\n');
    if !updated.lines().any(|line| line.starts_with(&target_prefix)) {
        updated = insert_after_unreleased(
            &updated,
            &format!(
                "## [{target}](https://github.com/NVIDIA/yaml-sigil-traits/releases/tag/v{target}) - {date}\n\n### Other\n\n- No crate-specific changes."
            ),
        )?;
        changed = true;
    }
    if changed {
        fs::write(path, updated).map_err(|error| format!("write {CHANGELOG}: {error}"))?;
    }
    Ok(())
}

fn promote_changelog(
    root: &Path,
    rc: &Version,
    stable: &Version,
    date: &str,
) -> Result<(), String> {
    let path = root.join(CHANGELOG);
    let body = fs::read_to_string(&path).map_err(|error| format!("read {CHANGELOG}: {error}"))?;
    let section = changelog_section(&body, rc)?;
    let promoted = format!(
        "## [{stable}](https://github.com/NVIDIA/yaml-sigil-traits/releases/tag/v{stable}) - {date}\n{section}"
    );
    let updated = insert_after_unreleased(&body, &promoted)?;
    fs::write(path, updated).map_err(|error| format!("write {CHANGELOG}: {error}"))
}

fn changelog_section(body: &str, version: &Version) -> Result<String, String> {
    let lines: Vec<_> = body.lines().collect();
    let prefix = format!("## [{version}](");
    let start = lines
        .iter()
        .position(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("missing changelog section for {version}"))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.starts_with("## ["))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let section = lines[start + 1..end].join("\n");
    Ok(format!("{}\n", section.trim_end()))
}

fn insert_after_unreleased(body: &str, section: &str) -> Result<String, String> {
    let marker = "## [Unreleased]";
    let start = body
        .find(marker)
        .ok_or_else(|| "missing [Unreleased] changelog heading".to_string())?;
    let insert_at = start + marker.len();
    let mut output = String::with_capacity(body.len() + section.len() + 3);
    output.push_str(&body[..insert_at]);
    output.push_str("\n\n");
    output.push_str(section.trim());
    output.push_str("\n\n");
    output.push_str(body[insert_at..].trim_start_matches('\n'));
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_uses_core_and_twelve_hex_characters() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            snapshot_version(&current, 17, "ABCDEF0123456789").unwrap(),
            Version::parse("0.4.0-0.pr.17.commit.shaabcdef012345").unwrap()
        );
    }

    #[test]
    fn auto_advances_rc() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&current, &current, "auto").unwrap(),
            Version::parse("0.4.0-rc.4").unwrap()
        );
    }

    #[test]
    fn auto_starts_next_patch_rc_after_stable() {
        let current = Version::parse("0.4.0").unwrap();
        assert_eq!(
            candidate_version(&current, &current, "auto").unwrap(),
            Version::parse("0.4.1-rc.1").unwrap()
        );
    }

    #[test]
    fn explicit_minor_starts_new_rc_train() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&published, &published, "minor").unwrap(),
            Version::parse("0.5.0-rc.1").unwrap()
        );
    }

    #[test]
    fn inserted_changelog_sections_remain_separated() {
        let body = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n";
        let section = "## [0.2.0](new) - 2026-08-19\n\n- New.";

        assert_eq!(
            insert_after_unreleased(body, section).unwrap(),
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0](new) - 2026-08-19\n\n- New.\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n"
        );
    }
}

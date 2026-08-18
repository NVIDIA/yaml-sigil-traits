# Release `yaml-sigil-traits`

This repository publishes `yaml-sigil-traits` as a crates.io `.crate` source
package. Release-plz also creates a version tag and a GitHub Release whose body
comes from the reviewed changelog. It does not build or attach binary assets,
and the workflow retains no artifacts or separately generated archives. GitHub's
automatic source archives are source-only and are expected. Cargo disables
automatic binary targets, and hosted release validation rejects an explicit
binary target. Do not distribute compiled executables from this repository.

## Release source and authorization

Prepare each version in a pull request whose branch starts with
`release-plz-`. From a clean branch based on current `main`, use release-plz to
update the version and changelog:

```shell
release-plz update --config .release-plz.toml
```

Review `Cargo.toml`, `Cargo.lock` when present, and `CHANGELOG.md`, then commit
the result with the repository's required SSH signature and DCO sign-off. Open
the release pull request, require its exact head to pass `Required CI` and the
platform jobs, and integrate that exact head only after approval.

This human-signed release-PR preparation keeps the normal DCO and commit-signing
controls. The release-plz GitHub Action is not used to author the pull request
commit because its generated commit cannot carry this repository's required DCO
trailer. The `release-plz-` branch prefix is significant: with
`release_always = false`, release-plz publishes only when the current `main`
commit is associated with a merged release pull request using that prefix.

The protected branch, reviewed release PR, package manifests, changelog, and
`.release-plz.toml` define the release. The workflow does not hard-code a source
commit or crate version.

## Prerequisites

Before validation or publication:

- Confirm `main` is the exact integrated head of the intended `release-plz-`
  pull request and contains the reviewed version, dependency requirements,
  package contents, and changelog.
- Confirm that commit is SSH-signed, DCO-compliant, GitHub Verified, and green
  under required and platform CI.
- Confirm the crates.io owner and reusable Trusted Publisher configuration are
  correct for this repository, `.github/workflows/publish.yml`, and the
  `crates-io` environment.
- Confirm the `crates-io` environment requires its configured approval and has
  no long-lived registry token.
- Confirm the intended version is absent from crates.io and that its tag and
  GitHub Release do not already exist.

Do not enable the crates.io setting that requires Trusted Publishing for every
new version until the planned prerelease publication trains have succeeded.

## Validate

Run the default operation from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=validate
```

Watch it to completion:

```shell
gh run watch --exit-status
```

Validation uses Cargo's ordinary `cargo package` checks and a release-plz dry
run against the versions in the checked-out manifests. It verifies that the
current commit is eligible under the release-PR authorization rule. It has no
OIDC permission, uploads nothing, and does not enter the protected environment.
Inspect the completed run before publication and confirm that it retained no
artifacts.

## Publish

Inspect crates.io, repository tags, and GitHub Releases immediately before
dispatch. If any object for the manifest version already exists, determine
whether it came from an earlier partial or completed run before continuing.

Dispatch the stable publication operation from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=publish
```

The validation job runs first. The publication job can start only after
validation succeeds and the configured reviewer approves the `crates-io`
environment. Only that job receives `id-token: write` and `contents: write`.
Release-plz exchanges the workflow identity for a short-lived crates.io
credential, publishes the source package, creates the version tag, and creates
a GitHub Release using the reviewed changelog. Pre-release versions are marked
as GitHub pre-releases. The workflow has no Cargo registry token input or
secret, and no step builds or attaches release assets.

The publication invocation omits release-plz's `dry_run` input. Setting that
input to the string `false` would still enable dry-run behavior.

## Verify publication

The workflow reads the expected version from Cargo metadata, waits for crates.io
to expose it as non-yanked, and confirms that Cargo can resolve it from the
registry. After the run:

- inspect the crates.io package page and owner list;
- confirm the version tag targets the exact released `main` commit;
- confirm the GitHub Release uses that tag and the reviewed changelog;
- confirm the GitHub Release has no attached assets; and
- record the workflow run, package, tag, and release evidence in the workspace
  release records.

## Recover from a partial run

Never blindly retry a failed publication. Inspect crates.io, the version tag,
and the GitHub Release first:

- If the crate exists and is correct, do not try to overwrite it. Determine
  whether a carefully reviewed retry is needed only to complete a missing tag
  or GitHub Release.
- If the crate exists but is defective, decide explicitly whether to yank it.
  A yank does not permit reusing the same version. Prepare and review a later
  release PR.
- If the crate is absent, diagnose validation, release-PR association,
  environment approval, OIDC exchange, or Cargo publication before considering
  another dispatch.
- If a tag or GitHub Release exists with incorrect metadata, stop and review the
  exact remote state before changing or deleting it.

Release-plz skips an exact version that is already published, which lets a
carefully reviewed retry resume a partial publication. Do not replace Trusted
Publishing with a long-lived token, bypass the environment, or attach binary
assets as a recovery shortcut.

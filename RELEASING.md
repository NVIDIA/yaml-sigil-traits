# Release `yaml-sigil-traits`

This repository publishes `yaml-sigil-traits` as a crates.io `.crate` source
package. Official publications also create a version tag and a source-only
GitHub Release from the reviewed changelog. Neither release-plz nor any other
release step builds or attaches binary assets. The workflow retains no build
artifacts or separately generated archives. GitHub's automatic source archives
are expected.

Cargo disables implicit binary targets, and release validation rejects an
explicit binary target. Do not distribute compiled executables from this
repository.

## Release authorization

The `Release proposal` workflow owns the `release-plz-next` branch and opens or
updates its pull request against `main`. Release-plz analyzes Conventional
Commits and generates changelog content. The repository xtask applies the RC
policy described below. A least-privilege GitHub App creates the commit through
GitHub, so GitHub reports the commit as Verified. The commit also includes a
DCO trailer for the App bot identity.

Do not add human commits to `release-plz-next`. The workflow refuses to replace
the branch if it contains a commit by another identity. Review and merge the
release pull request through the normal protected-branch path. Its exact head
must pass `Required CI`, including all three Rust platform jobs. Merging that
pull request is the authorization signal for release-plz because
`.release-plz.toml` sets `release_always = false` and the branch uses the
`release-plz-` prefix.

The workflow remains a successful no-op while the GitHub App configuration is
absent. It also waits without advancing the train until the version on `main`
is available and non-yanked on crates.io.

### Manual release-proposal fallback

> [!IMPORTANT]
> This fallback changes proposal authorship only. It does not authorize local
> publication, a crates.io token, a protected-environment bypass, or binary
> artifacts. Official publication still uses the protected Trusted Publishing
> workflow.

Use this procedure when the App is unavailable or cannot safely update its
owned proposal. A repository writer may prepare the same release transaction
on a human-authored branch. Use release-plz `0.3.160`. Create a same-repository
branch named `release-plz-manual-<target>` from the exact current `main`; do
not reuse the workflow-owned `release-plz-next` branch. Confirm that the
version currently in `Cargo.toml` is available and non-yanked on crates.io
before advancing it.

Before creating the manual branch, inspect any existing `release-plz-next`
proposal. Do not append a human commit to it or replace its App-owned head.
Finish or close that proposal and verify current `main` and crates.io state, or
leave it intact while using the distinctly named manual branch. Do not run the
two proposal paths concurrently.

For the next substantive RC proposal, run:

```shell
published_version="$(cargo xtask release-version show)"
release_date="$(date -u +%F)"
bump="auto"
# Generate the Conventional Commit changelog and preliminary version change.
release-plz update --config .release-plz.toml
git diff --name-only -- CHANGELOG.md
```

The command must list `CHANGELOG.md` as changed. If it does not, stop before
advancing the version: a manual proposal must not create an empty seed. Once
the expected changelog change is present, complete the candidate transaction:

```shell
cargo xtask release-version candidate \
  --published "${published_version}" \
  --bump "${bump}" \
  --date "${release_date}" \
  --release-notes
```

The captured `published_version` must be the exact non-yanked crates.io
version. Leave `bump` as `auto` unless the reviewed change requires an explicit
`patch`, `minor`, or `major` version-line advance.

For stable promotion, first apply every provenance check in
"Promote an RC to stable" and confirm the published RC tag resolves to the
exact current `main` commit. Then create the manual branch and run:

```shell
release_date="$(date -u +%F)"
cargo xtask release-version promote-stable --date "${release_date}"
```

For either path, review the generated transaction and run:

```shell
cargo xtask release-version check
cargo xtask ci
bash .github/scripts/check-release-packages.sh yaml-sigil-traits
git diff --check
git status --short
```

The complete diff must contain only the intended `Cargo.toml` and
`CHANGELOG.md` changes. The release-package helper is the Cargo metadata and
library-only package gate. Do not commit a generated `Cargo.lock` or package
archive. Commit the complete transaction with an SSH signature and DCO
sign-off. Validate the clean exact commit before pushing it:

```shell
cargo package
git status --short
```

Push the branch and open its pull request against `main`. The pull request
association is required for a useful release-plz dry run because
`release_always = false` authorizes only commits from a `release-plz-*` branch.
After the pull request exists, run:

```shell
# Supply the existing gh credential only for read-only forge discovery.
GIT_TOKEN="$(gh auth token)" \
  release-plz release --dry-run --config .release-plz.toml
git status --short
```

The process-scoped `GIT_TOKEN` must not be echoed, pasted, or persisted. Verify
that the dry run plans the expected crate and does not report that the current
commit is not from a release pull request. It must not publish or create tags
or GitHub Releases.

Review and integrate the exact head through the ordinary protected path only
after `Required CI` and all three Rust platform jobs pass. If a repair is
needed, amend the signed commit while retaining one DCO trailer, force-push
with lease, and repeat the clean-commit and dry-run checks. Merging that
`release-plz-*` pull request is the authorization signal for the protected
official publication workflow. Do not run a local non-dry-run release command.

After the manual proposal is integrated or closed, delete only its manual
branch, confirm the exact current `main` and crates.io state, and dispatch a
fresh `Release proposal` run. Let the workflow recreate or update its own
branch from that state. Do not copy the human-authored commit onto
`release-plz-next`.

## RC progression

The default release progression is:

- a published stable `MAJOR.MINOR.PATCH` starts the next patch train as
  `MAJOR.MINOR.(PATCH+1)-rc.1`;
- a published `MAJOR.MINOR.PATCH-rc.N` advances to
  `MAJOR.MINOR.PATCH-rc.(N+1)`; and
- release-plz updates the active proposal when later Conventional Commits add
  release notes or imply a discoverable version-line change.

An empty next-version seed remains a draft pull request. A proposal with
release notes is marked ready for review.

When the required `major`, `minor`, or `patch` advance is not discoverable from
the commits, a repository writer can dispatch `Release proposal` with mode
`next-candidate` and the intended bump. The workflow records that override in
the pull-request body and retains it across later automatic updates. Dispatch
the same mode with `auto` to clear the override.

The manifest and changelog changes for an RC or stable release must be part of
the release pull request. Official publication rejects a dirty source tree.

## Promote an RC to stable

Stable promotion is an explicit review operation. First publish and verify the
RC from `main`. Its `vMAJOR.MINOR.PATCH-rc.N` tag must resolve to the exact
current `main` commit. Then dispatch `Release proposal` with mode
`promote-stable`. The workflow creates a pull request that removes the
prerelease component and copies the reviewed RC changelog section to the stable
version.

Review and merge that exact proposal before publishing the stable version. Do
not edit a contributor branch to remove `rc.N`, and do not promote source that
differs from the tagged RC.

## Publish a tested pull-request snapshot

A repository writer can publish the exact head of an open pull request that
targets `main` after that head has a successful completed `CI` workflow run.
Use the manual workflow form with `validate-pr` or `publish-pr` and the pull
request number:

```shell
gh workflow run publish.yml --ref main \
  -f operation=validate-pr -f pr_number=123
gh workflow run publish.yml --ref main \
  -f operation=publish-pr -f pr_number=123
```

The workflow rechecks the caller's repository permission, pull-request state,
exact head SHA, and exact-head CI immediately before publication. Trusted
tooling from `main` applies this ephemeral version:

```text
<base>-0.pr.<pr-number>.commit.sha<12-hex-sha>
```

For example, pull request 123 at `0123456789abcdef` from a `0.4.0-rc.2`
manifest becomes `0.4.0-0.pr.123.commit.sha0123456789ab`. The workflow permits
the resulting dirty checkout so it does not commit to or mutate the
contributor's branch.

Snapshots use the separate `crates-io-pr` Trusted Publisher environment. They
create no tag or GitHub Release and retain no artifact. A successful snapshot
does not advance the official RC train.

## Validate an official release

Before validation or publication, confirm:

- `main` is the exact merged head of the intended `release-plz-*` pull request;
- the head is GitHub Verified, DCO-compliant, and green under required and
  platform CI;
- the crates.io Trusted Publisher matches
  `.github/workflows/publish.yml` and the `crates-io` environment;
- the `crates-io` environment requires its configured approval and has no
  long-lived registry token; and
- the version, tag, and GitHub Release do not already exist, except when
  deliberately recovering a partial run.

Run validation from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=validate
```

Validation uses ordinary `cargo package` and a release-plz dry run. It has no
OIDC permission, uploads nothing, and does not enter the publication
environment.

## Publish an official release

Dispatch publication from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=publish
```

The validation job runs first. The publication job starts only after
validation succeeds and the `crates-io` environment is approved. Only that job
receives `id-token: write` and `contents: write`. Release-plz exchanges the job
identity for a short-lived crates.io credential, publishes the source package,
and creates the configured tag and source-only GitHub Release. A prerelease
version becomes a GitHub prerelease.

The publication invocation deliberately omits release-plz's `dry_run` input.
Any nonempty value, including the string `false`, enables dry-run behavior.
After a successful publication, the workflow requests the next release
proposal.

## Verify and recover

The workflow waits for crates.io to expose the expected version as non-yanked
and confirms Cargo can resolve it. Afterward, verify the package owner list,
exact tag target, changelog-based Release body, and absence of attached assets.
Record the workflow run, package, tag, and Release in the workspace release
records.

Never blindly retry a failed publication. Inspect crates.io, the tag, and the
GitHub Release first. An existing crate version cannot be overwritten, even if
yanked. Release-plz skips an exact version already on crates.io, so a reviewed
retry can complete missing release objects after a partial run. Do not replace
Trusted Publishing with a long-lived token, bypass an environment, reuse a
version, or attach binary assets as a recovery shortcut.

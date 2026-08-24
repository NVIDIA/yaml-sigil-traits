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

Release proposals enter `protected-automation`, which is restricted to exact
`main` and supplies only the App credential. Official publication enters
`crates-io`, whose configured approval gates the OIDC-enabled publication job.
Validation enters neither environment and receives no OIDC permission.

Every proposal resolves its comparison baseline from the last official
annotated `v<version>` tag. The workflow confirms that the tag matches origin,
is an ancestor of current remote `main`, and identifies the exact non-yanked
version on crates.io. Registry prereleases that have no official tag never
become release-analysis baselines.

### Manual release-proposal fallback

> [!IMPORTANT]
> This fallback changes proposal authorship only. It does not authorize local
> publication, a crates.io token, a protected-environment bypass, or binary
> artifacts. Official publication still uses the protected Trusted Publishing
> workflow.

Use this procedure when the App is unavailable or cannot safely update its
owned proposal. A repository writer may prepare the same release transaction
on a human-authored branch. Use Rust `1.95.0`, cargo-binstall `1.20.1`,
release-plz `0.3.160`, and cargo-semver-checks `0.50.0`. Create a
same-repository branch named
`release-plz-manual-<target>` from exact current `main`; do not reuse the
workflow-owned `release-plz-next` branch.

Before creating the manual branch, inspect any existing `release-plz-next`
proposal. Do not append a human commit to it or replace its App-owned head.
Finish or close that proposal and verify current `main` and crates.io state, or
leave it intact while using the distinctly named manual branch. Do not run the
two proposal paths concurrently.

Before either proposal mode, fetch current main and tags, verify the analyzer
versions, and prepare the detached official baseline:

```shell
export RUSTUP_TOOLCHAIN=1.95.0
fetch_url="https://github.com/NVIDIA/yaml-sigil-traits"
test "$(git remote get-url origin)" = "${fetch_url}"
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
rustc_version="$(rustc --version)"
test "${rustc_version%% (*}" = "rustc 1.95.0"
test "$(cargo-binstall --version)" = "cargo-binstall 1.20.1"
cargo xtask release install-tools
published_version="$(cargo xtask release-version show)"
cargo xtask release verify-registry \
  --check-version "${published_version}" yaml-sigil-traits
baseline_parent="$(mktemp -d)"
baseline_root="${baseline_parent}/official-release"
inventory_path="${baseline_parent}/official-tags.json"
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  python3 .github/scripts/prepare_release_baseline.py \
    --repository NVIDIA/yaml-sigil-traits \
    --version "${published_version}" \
    --head "$(git rev-parse HEAD)" \
    --output "${baseline_root}" \
    --inventory-output "${inventory_path}" \
    --expected-fetch-url "${fetch_url}"
registry_manifest_path="${baseline_root}/Cargo.toml"
```

Stop if current main, the registry record, tag type, tag target, ancestry, or
remote ref differs. For the next substantive RC proposal, set the reviewed
intent and run:

```shell
release_date="$(date -u +%F)"
bump="patch"
# Generate the Conventional Commit changelog and preliminary version change.
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  release-plz update \
    --config .release-plz.toml \
    --registry-manifest-path "${registry_manifest_path}"
git diff --name-only -- CHANGELOG.md
```

The command must list `CHANGELOG.md` as changed. If it does not, stop before
advancing the version: a manual proposal must not create an empty seed. Once
the expected changelog change is present, complete the candidate transaction:

```shell
target="$(cargo xtask release-version candidate \
  --published "${published_version}" \
  --bump "${bump}" \
  --date "${release_date}" \
  --release-notes)"
```

Set `bump` explicitly to the reviewed `patch`, `minor`, or `major` version-line
advance. A patch advances the current RC on the same core, or starts the next
patch RC after a stable release. Never infer the baseline from a higher
registry prerelease.

For stable promotion, use the same baseline preparation and require its commit
to equal exact current `main`. Then create the manual branch and run:

```shell
release_date="$(date -u +%F)"
bump="patch"
test "$(git rev-parse "v${published_version}^{commit}")" = "$(git rev-parse HEAD)"
target="$(cargo xtask release-version promote-stable --date "${release_date}")"
```

For either path, review the generated transaction and run:

```shell
cargo xtask release-version check
cargo xtask release-version check-compatibility \
  --baseline-manifest "${registry_manifest_path}" \
  --current-manifest Cargo.toml \
  --package yaml-sigil-traits \
  --expected-baseline-version "${published_version}" \
  --expected-current-version "${target}" \
  --intent "${bump}"
cargo xtask ci
cargo xtask release check-packages yaml-sigil-traits
git diff --check
git status --short
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  python3 .github/scripts/prepare_release_baseline.py \
    --repository NVIDIA/yaml-sigil-traits \
    --head "$(git rev-parse HEAD)" \
    --verify-inventory "${inventory_path}" \
    --expected-fetch-url "${fetch_url}"
```

The direct compatibility check converts the selected bump into Cargo's
pre-`1.0` release type and treats every analyzer error as a failure.
Release-plz's built-in semver check is disabled so it cannot reinterpret that
result. The complete diff must contain only the intended `Cargo.toml` and
`CHANGELOG.md` changes. `cargo xtask release check-packages` applies the exact
Cargo metadata and library-only package gate. The related
`verify-registry` command preserves exit status `3` for an exact missing
version and treats yanked, malformed, or failed registry responses as errors.
Do not commit a generated `Cargo.lock` or package archive. Commit the complete
transaction with an SSH signature and DCO sign-off. Validate the clean exact
commit before pushing it:

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

If either `release-plz-next` or the selected manual branch already exists,
inspect its owner, exact ref, open pull request, and commits before proceeding.
Never overwrite a foreign or unexpected branch. Resolve the collision by
finishing, closing, or deliberately renaming the human branch, then rerun all
main, tag, registry, and baseline checks. Updates to the App-owned branch use
an exact-old-SHA force-with-lease; a concurrent ref change stops the update.

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

For every `major`, `minor`, or `patch` advance, a repository writer can
dispatch `Release proposal` with mode `next-candidate` and the intended bump.
The workflow records that concrete intent in the pull-request body and retains
it across later background updates. In the absence of an earlier marker, a
background update deterministically selects `patch`.

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

Validation compares the candidate with the detached last official tagged
source using cargo-semver-checks before it runs ordinary `cargo package` and a
release-plz dry run. It has no OIDC permission, uploads nothing, and does not
enter the publication environment.

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

Both validation and publication independently require exact current `main` to
be the merge result of one reviewed App proposal or the documented signed
same-repository manual fallback. Stable promotion additionally requires that
proposal's base and the release commit's sole parent be the exact tagged RC
commit, so intervening source cannot enter the stable release. Immediately
before publication, the workflow rechecks the complete official-tag inventory
and remote `main`. Its ephemeral release-plz configuration differs from the
reviewed configuration only by authorizing the already-checked checkout and
using a Git-invalid pull-request branch prefix, so release-plz cannot select or
check out another commit.

The publication invocation deliberately omits release-plz's `--dry-run` CLI
flag.
After a successful publication, the workflow requests the next release
proposal.

## Verify and recover

The workflow waits for crates.io to expose the expected version as non-yanked
and confirms Cargo can resolve it. It then requires `v<version>` to be an
annotated tag whose object targets exact publication `main`. The GitHub Release
must use that tag and name, contain the exact reviewed version section from
`CHANGELOG.md`, have the expected prerelease state, and have no attached
assets. Record the workflow run, package, tag, and Release in the workspace
release records.

Never blindly retry a failed publication. Inspect crates.io, the annotated tag,
and the GitHub Release first. An existing crate version cannot be overwritten,
even if yanked. On a reviewed retry, the workflow distinguishes two states:

- If the exact non-yanked crate version is absent, both forge objects must also
  be absent. Exact remote `main` is rechecked immediately before release-plz
  receives Trusted Publishing authority.
- If the exact non-yanked crate version already exists, the workflow skips
  release-plz and every registry mutation. It may create only a missing
  annotated tag and/or missing source-only GitHub Release after independently
  rechecking crates.io. Before either write, it verifies the crates.io API
  checksum, downloads that exact `.crate`, rejects unsafe archive entries,
  requires clean `.cargo_vcs_info.json` provenance at publication `main`, and
  reproduces all commit-controlled source content with exact Cargo `1.95.0` in
  an ephemeral directory. The generated root `Cargo.lock` must be valid and
  bound to the exact package in both archives, but its dependency resolution
  may differ because Cargo regenerates it; every other packaged file remains
  byte-identical. The workflow rechecks the same non-yanked checksum after the
  final forge objects are present.

Recovery never moves or replaces an existing ref, edits an existing Release,
deletes an object, or uploads an asset. A lightweight or wrong-target tag, a
mismatched Release body or state, any attached asset, a missing or yanked crate,
or a creation race fails closed for operator review. Do not replace Trusted
Publishing with a long-lived token, bypass an environment, reuse a version, or
attach binary assets as a recovery shortcut.

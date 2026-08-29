# Release `yaml-sigil-traits`

This repository publishes `yaml-sigil-traits` as a crates.io `.crate` source
package. Official publications also create a version tag and a source-only
GitHub Release from the reviewed changelog. Release-plz has source-crate
publication authority only. After exact registry confirmation, a protected
GitHub App finalizer creates the annotated tag and immutable, zero-asset
Release. No release step builds or attaches binary assets. The workflow retains
no build artifacts or separately generated archives. GitHub's automatic source
archives are expected.

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

### Preserve reviewed commits at integration

Preserve a release pull request's individual commits when review finds them
coherent, correctly scoped, and useful to retain on `main`. Every retained
commit must carry its own cryptographic signature and DCO sign-off and leave
the repository in a coherent state. If the submitted sequence is noisy,
partial, or not independently meaningful, curate or squash it on the
contributor branch and re-sign the result before requesting final
authorization. Do not make the integrating repository writer repair avoidable
history problems at merge time.

Do not use GitHub's **Rebase and merge** option. It rewrites reviewed commits
on the server and cannot preserve their signatures. **Squash and merge** also
replaces the reviewed commits. Use it when review concludes that the submitted
commit sequence is not worth retaining as-is, not as the default for coherent
history. This repository disables server-side rebase merging.

Bring a human-owned branch up to date before final CI with
`git rebase --gpg-sign origin/main` and the approved SSH signing key. Push
rewritten history only with `--force-with-lease`, then request `Required CI`
for the new exact head SHA. Do not rewrite `release-plz-next`; have the
`Release proposal` workflow refresh that App-owned branch instead. Every
rewritten head invalidates the earlier authorization and check.

After the exact head is current, GitHub Verified, DCO-compliant, and green
under `Required CI`, a repository writer re-fetches `origin` and integrates
that immutable commit with a normal fast-forward push:

```shell
git fetch origin
expected_main="$(git rev-parse origin/main)"
expected_head="<exact-40-character-PR-head-SHA>"
git merge-base --is-ancestor "${expected_main}" "${expected_head}"
git push origin "${expected_head}:refs/heads/main"
```

Re-check the pull request's base, head, and `Required CI` binding immediately
before the push. A concurrent `main` update makes the normal push fail closed;
rebase and re-sign the human-owned branch, or refresh the App-owned proposal,
then rerun exact-head CI. Never force-push `main`.

When enabled, the workflow remains a successful no-op while the GitHub App
configuration is absent. It also waits without advancing the train until the
version on `main` is available and non-yanked on crates.io.

The manually bounded `release-pr.yml` entrypoint accepts pushes to `main` and
writer dispatches. It calls `release-proposal.yml`, which is call-only and has
no public event entrypoint. After a complete official publication, the enabled
`publish.yml` receiver authenticates the closed, versioned
`official-release-published` payload before calling that same reusable
workflow. The dispatch name is unchanged; its payload is an internal
sender/receiver contract, not a public external trigger contract.

A trusted background entrypoint may create one default `patch` proposal when
no exact App-owned proposal exists. Once that proposal exists, background
events leave it untouched. A repository writer must dispatch `Release
proposal` with an explicit `patch`, `minor`, or `major` selection to revise the
proposal. The workflow uses that dispatch input directly and does not store
release intent in pull-request text.

Proposal mutation, release intent, finalization, and notification enter
`protected-automation` only when they need the narrowly scoped App credential.
Official source-crate publication enters `crates-io`, whose configured approval
gates the OIDC-enabled publication job. Validation and readiness enter neither
environment and receive no OIDC permission.

### Bound workflow activation

Keep the event entrypoints `release-pr.yml` and `publish.yml` manually disabled
between bounded release operations. The reusable `release-proposal.yml` remains
enabled but is call-only. Check all three actual GitHub states, including
disabled workflows, with:

```shell
gh workflow list --repo NVIDIA/yaml-sigil-traits --all
```

Enable only the workflow needed for the current operation. To create or revise
the next RC proposal from exact current `main`, keep `publish.yml` disabled and
run:

```shell
gh workflow enable release-pr.yml --repo NVIDIA/yaml-sigil-traits
gh workflow run release-pr.yml --repo NVIDIA/yaml-sigil-traits \
  --ref main -f mode=next-candidate -f bump=patch
```

Replace `patch` only with the reviewed `minor` or `major` intent. Stable
promotion uses `mode=promote-stable` and `bump=patch`. Wait for the selected
run to close, then disable the proposal workflow immediately:

```shell
gh workflow disable release-pr.yml --repo NVIDIA/yaml-sigil-traits
```

Do not rely on a push that occurred while `release-pr.yml` was disabled; use a
fresh explicit dispatch after enabling it. Do not enable proposal and
publication entrypoints at the same time. The later validation and publication
procedures enable only `publish.yml`. A successful publication keeps
`publish.yml` enabled until its authenticated receiver run completes; that
receiver may call the reusable proposal workflow while `release-pr.yml` remains
disabled.

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
release-plz `0.3.160`, and cargo-semver-checks `0.49.0`. Create a
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
test "$(cargo-binstall -V)" = "1.20.1"
cargo xtask release install-tools
published_version="$(cargo xtask release-version show)"
cargo xtask release verify-registry \
  --check-version "${published_version}" yaml-sigil-traits
baseline_parent="$(mktemp -d)"
baseline_root="${baseline_parent}/official-release"
inventory_path="${baseline_parent}/official-tags.json"
baseline_result="${baseline_parent}/baseline-result.json"
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  cargo xtask release baseline prepare \
    --version "${published_version}" \
    --head "$(git rev-parse HEAD)" \
    --output "${baseline_root}" \
    --result "${baseline_result}" \
    --inventory-output "${inventory_path}" \
    --expected-fetch-url "${fetch_url}"
registry_manifest_path="$(jq --exit-status --raw-output \
  '.manifest' "${baseline_result}")"
test "$(jq --exit-status --raw-output '.inventory' "${baseline_result}")" = \
  "${inventory_path}"
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
  cargo xtask release baseline verify \
    --head "$(git rev-parse HEAD)" \
    --inventory "${inventory_path}" \
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
- a trusted push or authenticated post-publication notification creates a
  default patch proposal only when the App-owned proposal does not already
  exist.

An empty next-version seed remains a draft pull request. A proposal with
release notes is marked ready for review.

For every `major`, `minor`, or `patch` advance, a repository writer can
dispatch `Release proposal` with mode `next-candidate` and the intended bump.
That manual dispatch may create the proposal or replace its App-owned commit.
Later pushes and post-publication notifications do not revise an existing
proposal; another explicit writer dispatch is required to incorporate later
changes or select a different release line.

The manifest and changelog changes for an RC or stable release must be part of
the release pull request. Official publication rejects a dirty source tree.

## Promote an RC to stable

Stable promotion is an explicit review operation. First publish and verify the
RC from `main`. Its `vMAJOR.MINOR.PATCH-rc.N` tag must resolve to the exact
current `main` commit. Then a repository writer must manually dispatch
`Release proposal` with mode `promote-stable`. Background events cannot select
stable promotion. The workflow deterministically uses patch compatibility
intent, creates a pull request that removes the prerelease component, and
copies the reviewed RC changelog section to the stable version.

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
- repository administrators have reviewed the exact proposed release-tag
  creation and update/deletion rulesets and prospective immutable-Release
  setting, without changing them as part of workflow validation;
- `.github/legacy-release-inventory.json` still pins all four historical,
  mutable, zero-asset source-only Releases; and
- the version, tag, and GitHub Release do not already exist, except when
  deliberately recovering a partial run.

Run validation from `main`:

```shell
gh workflow enable publish.yml --repo NVIDIA/yaml-sigil-traits
gh workflow run publish.yml --repo NVIDIA/yaml-sigil-traits \
  --ref main -f operation=validate
```

Validation compares the candidate with the detached last official tagged
source using cargo-semver-checks before it runs ordinary `cargo package` and a
release-plz dry run. It has no OIDC permission, uploads nothing, and does not
enter the publication environment. The readiness job also verifies the pinned
legacy Release inventory and prints a digest binding the captured release SHA,
run ID, run attempt, and required repository settings. It does not read or
change administrator-only settings.

If validation fails or publication will not begin immediately, disable
`publish.yml` before investigating. When an authorized publication follows the
successful validation immediately, leave it active only through that one
publication run.

## Publish an official release

Dispatch publication from `main`:

```shell
gh workflow run publish.yml --repo NVIDIA/yaml-sigil-traits \
  --ref main -f operation=publish
```

The validation job runs first. The publication job starts only after
validation succeeds and the `crates-io` environment is approved. Only that job
receives `id-token: write`; it retains `contents: read` and
`pull-requests: read`. Release-plz exchanges the job identity for a short-lived
crates.io credential and publishes only the source package. It cannot create a
tag or GitHub Release.

Before approving the pending deployment, a repository administrator must run
the tracked read-only preflight from the exact current `main` checkout with the
four values displayed by the selected readiness run:

```shell
GH_TOKEN="$(gh auth token)" \
python3 .github/scripts/release_settings_preflight.py \
  --repository NVIDIA/yaml-sigil-traits \
  --release-sha <release-sha> \
  --run-id <run-id> \
  --run-attempt <run-attempt> \
  --expected-evidence-sha256 <readiness-digest>
```

The preflight must report `repository_admin_settings=valid`, reproduce the
workflow evidence digest, and bind its readback to the active exact-SHA run. It
verifies immutable Releases, the exact main and release-tag rulesets, the
Release App bypass, and absence of a required-check name collision. It performs
no mutation. Approve the `crates-io` deployment before the printed
`approve_before_utc` deadline, at most five minutes after the readback. Any run,
attempt, head, workflow, setting, or deadline change requires a fresh readback.

Approve only the pending `crates-io` deployment on the selected exact-SHA run.
Use `gh run view <run-id> --web` to open it, confirm the readiness job passed,
the run still identifies current `main`, and the fresh administrator readback
remains inside its deadline, then record the environment approval. An earlier
authorization or a deployment for another run is not a substitute for this
per-run gate.

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

For the manual fallback, source authorization rechecks both the merger's and
proposal owner's current repository write permission after its final `main`
and pull-request reread.

The publication invocation deliberately omits release-plz's `--dry-run` CLI
flag. After exact registry confirmation, separate App-authenticated jobs attest
the release intent, create the annotated tag and immutable zero-asset Release,
and emit the authenticated internal notification. These jobs receive no OIDC
credential; the finalizer's App token has repository `contents: write` and the
notifier's separately minted token is isolated to notification.

If publication succeeds, wait for the resulting authenticated receiver run to
complete before disabling `publish.yml`. If the publication run fails before
notification, disable it after the failure is understood. Then confirm both
event entrypoints are disabled and the call-only reusable workflow remains
active:

```shell
gh workflow disable publish.yml --repo NVIDIA/yaml-sigil-traits
gh workflow list --repo NVIDIA/yaml-sigil-traits --all
```

After a successful publication, the authenticated receiver may create the next
default proposal while `release-pr.yml` remains disabled. It never replaces an
existing exact App-owned proposal. Use the bounded proposal procedure later for
an explicit bump or revision; do not leave either event entrypoint enabled.

## Verify and recover

The workflow waits for crates.io to expose the expected version as non-yanked
and confirms Cargo can resolve it. The App finalizer then requires `v<version>`
to be an annotated tag whose object targets the captured publication commit.
The App-authored GitHub Release must be immutable, use that tag and name,
contain the exact reviewed version section from `CHANGELOG.md`, have the
expected prerelease state, and have no attached assets. Record the workflow
run, package, tag, Release, readback digest, and captured SHA in the workspace
release records.

The immutable-Release setting is prospective. The four historical releases in
the pinned inventory remain mutable and are never rewritten; their exact tags,
source archives, bodies, author, state, and zero-asset inventories are checked
before every new finalization.

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
  an ephemeral directory. The Cargo-generated `Cargo.lock` remains opaque; its
  bytes and Cargo archive metadata must match exactly, and no archive entry is
  excluded from the published-versus-reproduced comparison. The workflow
  rechecks the same non-yanked checksum after the final forge objects are
  present.

Recovery never moves or replaces an existing ref, edits an existing Release,
deletes an object, or uploads an asset. A lightweight or wrong-target tag, a
mismatched Release body or state, any attached asset, a missing or yanked crate,
or a creation race fails closed for operator review. Do not replace Trusted
Publishing with a long-lived token, bypass an environment, reuse a version, or
attach binary assets as a recovery shortcut.

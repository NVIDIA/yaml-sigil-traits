# Release `yaml-sigil-traits`

Official releases publish the `yaml-sigil-traits` source crate to crates.io.
The protected finalizer then creates one annotated tag and one immutable,
zero-asset GitHub Release. Do not attach or retain compiled executables,
executable WebAssembly, installers, containers, or build artifacts.

## Prepare the release pull request

Install the fixed toolchain and analyzer, then bind the release base to a clean
current `origin/main`. `base_sha` is the later squash-parent expectation.

```shell
rustup toolchain install 1.98.0 --component clippy,rustfmt
export RUSTUP_TOOLCHAIN=1.98.0
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
test -z "$(git status --porcelain)"
base_sha="$(git rev-parse origin/main)"
cargo binstall --force --locked --no-confirm release-plz@0.3.160
test "$(release-plz --version)" = "release-plz 0.3.160"
```

Create a new canonical branch. `prepare` strips release credentials, runs
`release-plz update`, and accepts changes only to the manifest and changelog.

```shell
version="<SEMVER>"
git switch --create "release-plz-manual-${version}" origin/main
cargo xtask release prepare --version "${version}"
git diff --check
git diff -- CHANGELOG.md Cargo.toml
cargo xtask ci
```

Stop if the diff contains anything except `CHANGELOG.md` and `Cargo.toml`, or
if the selected version, changelog, or package inventory differs from the
intended release.

Create the sole release commit with the approved SSH key and DCO identity.
`check` then proves the committed transaction without credentials or
publication.

```shell
git config user.name ddurst
git config user.email 267424412+ddurst-nvidia@users.noreply.github.com
git add CHANGELOG.md Cargo.toml
git commit -S --signoff -m "chore(release): prepare yaml-sigil-traits ${version}"
git verify-commit HEAD
cargo xtask release check --version "${version}"
```

Push only the canonical branch and open its same-repository pull request.

```shell
git push origin "HEAD:refs/heads/release-plz-manual-${version}"
gh pr create \
  --base main \
  --head "release-plz-manual-${version}" \
  --title "chore(release): prepare yaml-sigil-traits ${version}" \
  --body "Prepare the reviewed source-only yaml-sigil-traits ${version} release."
```

Authorize exactly that head for copied-ref CI. The protected reporter pauses at
`protected-automation`; approve that one deployment only after checking its PR,
head, candidate run, and attempt.

```shell
pr_number="<PR_NUMBER>"
release_head="$(git rev-parse HEAD)"
gh pr comment "${pr_number}" \
  --repo NVIDIA/yaml-sigil-traits \
  --body "/ok to test ${release_head}"
```

Wait until GitHub shows one open same-repository pull request from the
canonical branch to `main`, the commit is Verified, and exact-head
`Required CI` succeeds. At that unchanged reviewed head, give pinned
release-plz an existing process-scoped, read-only forge credential and retain
the dry-run output outside the checkout:

```shell
git fetch origin \
  "+refs/heads/main:refs/remotes/origin/main" \
  "+refs/heads/release-plz-manual-${version}:refs/remotes/origin/release-plz-manual-${version}"
release_head="$(git rev-parse HEAD)"
test "$(git rev-parse "origin/release-plz-manual-${version}")" = "${release_head}"
test "$(git rev-parse HEAD^)" = "$(git rev-parse origin/main)"
test -n "${READ_ONLY_GIT_TOKEN:-}"
evidence="<APPROVED-EVIDENCE-DIR>/release-plz-dry-run-${release_head}.log"
set -o pipefail
# The process-scoped read-only token lets pinned release-plz inspect this
# existing PR; dry-run grants no publication, tag, or Release authority.
env -u CARGO_REGISTRY_TOKEN \
  -u CARGO_REGISTRIES_CRATES_IO_TOKEN \
  -u GH_TOKEN \
  -u GITHUB_TOKEN \
  GIT_TOKEN="${READ_ONLY_GIT_TOKEN}" \
  release-plz release --dry-run \
    --config .release-plz.toml \
    --manifest-path Cargo.toml 2>&1 | tee "${evidence}"
test "$(git rev-parse HEAD)" = "${release_head}"
sha256sum "${evidence}"
```

Record the output checksum with `release_head` as acceptance evidence. Never
add the evidence file to the repository or upload it as a workflow artifact.
If the pull-request head changes, treat the old evidence as superseded and
repeat the exact-head checks and dry run.

After `Required CI` succeeds, squash only the unchanged reviewed head. These
checks prove tree equality, sole-parent history, DCO, GitHub verification, and
PR association before treating the resulting `main` push as release authority.

```shell
git fetch --no-tags origin main
test "$(git rev-parse refs/remotes/origin/main)" = "${base_sha}"
test "$(git rev-parse HEAD^)" = "${base_sha}"
gh pr merge "${pr_number}" \
  --repo NVIDIA/yaml-sigil-traits \
  --squash \
  --match-head-commit "${release_head}" \
  --subject "chore(release): prepare yaml-sigil-traits ${version} (#${pr_number})" \
  --body "Signed-off-by: ddurst <267424412+ddurst-nvidia@users.noreply.github.com>"
git fetch origin main
main_sha="$(git rev-parse origin/main)"
test "$(git rev-parse "${main_sha}^")" = "${base_sha}"
test "$(git rev-parse "${main_sha}^{tree}")" = \
  "$(git rev-parse "${release_head}^{tree}")"
git show -s --format=%B "${main_sha}" | \
  grep -Fx 'Signed-off-by: ddurst <267424412+ddurst-nvidia@users.noreply.github.com>'
test "$(gh api "repos/NVIDIA/yaml-sigil-traits/commits/${main_sha}" \
  --jq .commit.verification.verified)" = true
test "$(gh api "repos/NVIDIA/yaml-sigil-traits/commits/${main_sha}/pulls" \
  --jq "map(select(.number == ${pr_number})) | length")" = 1
```

The resulting `publish.yml` run enters `crates-io` only for this qualified
release. Approve its one exact publication deployment after binding the run,
source, version, and absent target objects. release-plz is the sole publisher.

## Validate or recover publication

The `validate` workflow dispatch checks the protected current-main release
policy and makes every mutation job skip. It has no OIDC, App token, or
release-plz invocation. Dispatch it against the exact current `main`:

```shell
git fetch origin main
source_sha="$(git rev-parse origin/main)"
gh workflow run publish.yml \
  --repo NVIDIA/yaml-sigil-traits \
  --ref main \
  -f operation=validate \
  -f source_sha="${source_sha}"
```

Use `recover` only with the full source SHA and original push run coordinates:

```shell
source_sha="FULL_ORIGINAL_SOURCE_SHA"
original_run_id="ORIGINAL_PUSH_RUN_ID"
original_run_attempt="ORIGINAL_RUN_ATTEMPT"
gh workflow run publish.yml \
  --repo NVIDIA/yaml-sigil-traits \
  --ref main \
  -f operation=recover \
  -f source_sha="${source_sha}" \
  -f original_run_id="${original_run_id}" \
  -f original_run_attempt="${original_run_attempt}"
```

Recovery revalidates that original run and source, verifies any published
crate checksum and bounded `.cargo_vcs_info.json`, and never advances the
release to a newer `main`.

The separately reviewed `crates-io` environment remains the publication gate.
After publication and the exact-source registry wait succeed, the finalizer
waits for the `protected-automation` environment. Immediately before approving
that deployment, a repository admin performs this read-only preflight. The
`run_id` and `run_attempt` identify the current publication or recovery run,
while `source_sha` is the exact qualified release source:

```shell
repository="NVIDIA/yaml-sigil-traits"
workflow_id="337393638"
operation="push" # Use "recover" only for a bounded recovery run.
policy_sha="FULL_CURRENT_MAIN_SHA"
source_sha="FULL_QUALIFIED_RELEASE_SOURCE_SHA"
run_id="CURRENT_RUN_ID"
run_attempt="CURRENT_RUN_ATTEMPT"
[[ "${policy_sha}" =~ ^[0-9a-f]{40}$ ]]
[[ "${source_sha}" =~ ^[0-9a-f]{40}$ ]]
[[ "${run_id}" =~ ^[1-9][0-9]*$ ]]
[[ "${run_attempt}" =~ ^[1-9][0-9]*$ ]]

operator="$(gh api user --jq .login)"
test "$(gh api "repos/${repository}/collaborators/${operator}/permission" \
  --jq .permission)" = admin
test "$(gh api "repos/${repository}" --jq .full_name)" = "${repository}"
test "$(gh api "repos/${repository}" --jq .default_branch)" = main
test "$(gh api "repos/${repository}/git/ref/heads/main" \
  --jq .object.sha)" = "${policy_sha}"

# Ordinary publication and recovery have different source-lineage bindings.
case "${operation}" in
  push)
    expected_event=push
    test "${source_sha}" = "${policy_sha}"
    ;;
  recover)
    expected_event=workflow_dispatch
    comparison="$(gh api \
      "repos/${repository}/compare/${source_sha}...${policy_sha}")"
    jq -e --arg source "${source_sha}" \
      '(.merge_base_commit.sha == $source) and
       (.status == "ahead" or .status == "identical")' \
      <<< "${comparison}"
    ;;
  *)
    exit 1
    ;;
esac

run="$(gh api "repos/${repository}/actions/runs/${run_id}")"
jq -e \
  --arg event "${expected_event}" \
  --arg policy "${policy_sha}" \
  --arg repository "${repository}" \
  --argjson attempt "${run_attempt}" \
  --argjson run_id "${run_id}" \
  --argjson workflow_id "${workflow_id}" \
  '.id == $run_id and .run_attempt == $attempt and
   .workflow_id == $workflow_id and
   .path == ".github/workflows/publish.yml" and
   .repository.full_name == $repository and
   .head_branch == "main" and .head_sha == $policy and
   .event == $event and .conclusion == null and
   (.status == "queued" or .status == "in_progress" or
    .status == "waiting" or .status == "pending")' <<< "${run}"

jobs="$(gh api \
  "repos/${repository}/actions/runs/${run_id}/attempts/${run_attempt}/jobs?per_page=100")"
jq -e '
  ([.jobs[] | select(
    .name == "Await exact crates.io source" and .status == "completed" and
    .conclusion == "success")] | length == 1) and
  ([.jobs[] | select(
    .name == "Finalize immutable source-only Release" and
    .status == "waiting" and .conclusion == null)] | length == 1)
' <<< "${jobs}"

pending="$(gh api \
  "repos/${repository}/actions/runs/${run_id}/pending_deployments")"
jq -e '
  length == 1 and
  .[0].environment.id == 20345456172 and
  .[0].environment.name == "protected-automation" and
  .[0].current_user_can_approve == true
' <<< "${pending}"

environment="$(gh api \
  "repos/${repository}/environments/protected-automation")"
jq -e '
  .id == 20345456172 and .name == "protected-automation" and
  .can_admins_bypass == false and
  .deployment_branch_policy.protected_branches == false and
  .deployment_branch_policy.custom_branch_policies == true and
  (.protection_rules | length) == 2 and
  ([.protection_rules[] | select(.type == "branch_policy")] | length == 1) and
  ([.protection_rules[] | select(
    .type == "required_reviewers" and .prevent_self_review == false and
    (.reviewers | length) == 1 and .reviewers[0].type == "User" and
    .reviewers[0].reviewer.login == "ddurst-nvidia" and
    .reviewers[0].reviewer.id == 267424412)] | length == 1)
' <<< "${environment}"

branch_policies="$(gh api \
  "repos/${repository}/environments/protected-automation/deployment-branch-policies?per_page=100")"
jq -e '
  .total_count == 1 and (.branch_policies | length) == 1 and
  .branch_policies[0].id == 57933875 and
  .branch_policies[0].name == "main" and
  .branch_policies[0].type == "branch"
' <<< "${branch_policies}"

test "$(gh api "repos/${repository}/immutable-releases" \
  --jq .enabled)" = true

creation_rule="$(gh api "repos/${repository}/rulesets/21898910")"
jq -e --arg repository "${repository}" '
  .id == 21898910 and .name == "Protect release tag creation" and
  .source == $repository and .source_type == "Repository" and
  .target == "tag" and .enforcement == "active" and
  has("bypass_actors") and .bypass_actors == [{
    "actor_id": 4653064,
    "actor_type": "Integration",
    "bypass_mode": "always"
  }] and
  .conditions.ref_name.exclude == [] and
  .conditions.ref_name.include == ["refs/tags/v*"] and
  [.rules[].type] == ["creation"]
' <<< "${creation_rule}"

update_rule="$(gh api "repos/${repository}/rulesets/21898911")"
jq -e --arg repository "${repository}" '
  .id == 21898911 and
  .name == "Protect release tag updates and deletion" and
  .source == $repository and .source_type == "Repository" and
  .target == "tag" and .enforcement == "active" and
  has("bypass_actors") and .bypass_actors == [] and
  .conditions.ref_name.exclude == [] and
  .conditions.ref_name.include == ["refs/tags/v*"] and
  ([.rules[].type] | sort) == ["deletion", "update"]
' <<< "${update_rule}"

test "$(gh api "repos/${repository}/collaborators/${operator}/permission" \
  --jq .permission)" = admin
test "$(gh api "repos/${repository}/git/ref/heads/main" \
  --jq .object.sha)" = "${policy_sha}"
```

This preflight uses no workflow credential and must not change repository
settings, Apps, rulesets, environments, tags, or Releases. If any value drifts,
do not approve. If publication has not occurred, prepare a fresh proposal and
run from newly reviewed main. If any source crate is already public, correct
the setting and use only bounded recovery with the original source SHA, run,
and attempt; never advance that transaction to newer source. The finalizer
rechecks current protected policy after approval and immediately before each
tag or Release mutation.

After finalization, verify the crates.io checksum and VCS commit, annotated tag
target, stable-versus-prerelease flag, immutable zero-asset Release, and exact
changelog body. Never replace a conflicting crate, tag, or Release.

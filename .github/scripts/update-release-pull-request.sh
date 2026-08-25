#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Commit an already validated release diff through GitHub's signing service and
# create or update its pull request. This provider-specific helper deliberately
# contains no release-version or Cargo policy.

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must contain the GitHub App installation token}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA must identify the checked-out main commit}"
: "${APP_SLUG:?APP_SLUG is required}"
: "${RELEASE_BRANCH:?RELEASE_BRANCH is required}"
: "${RELEASE_TITLE:?RELEASE_TITLE is required}"
: "${RELEASE_BODY_FILE:?RELEASE_BODY_FILE is required}"
: "${RELEASE_DRAFT:?RELEASE_DRAFT is required}"
RELEASE_OPERATION="${RELEASE_OPERATION:-update}"
RELEASE_HOLD_DRAFT="${RELEASE_HOLD_DRAFT:-false}"

# Limit this helper to an update phase and a post-validation review-state phase.
case "${RELEASE_OPERATION}" in
  update | finalize) ;;
  *)
    echo "RELEASE_OPERATION must be update or finalize." >&2
    exit 1
    ;;
esac
# Only the repository's dedicated release App and branch own this automation.
if [[ "${APP_SLUG}" != "nvidia-yamlsigil-release-pr" \
  || "${RELEASE_BRANCH}" != "release-plz-next" ]]; then
  echo "The release proposal App or branch identity is unexpected." >&2
  exit 1
fi
# Reject values that cannot be sent as a typed GitHub API boolean.
if [[ "${RELEASE_DRAFT}" != "true" && "${RELEASE_DRAFT}" != "false" ]]; then
  echo "RELEASE_DRAFT must be true or false." >&2
  exit 1
fi
# Reject values that could silently bypass the pre-validation draft hold.
if [[ "${RELEASE_HOLD_DRAFT}" != "true" \
  && "${RELEASE_HOLD_DRAFT}" != "false" ]]; then
  echo "RELEASE_HOLD_DRAFT must be true or false." >&2
  exit 1
fi
# Require the generated body file rather than accepting shell-expanded prose.
if [[ ! -f "${RELEASE_BODY_FILE}" ]]; then
  echo "RELEASE_BODY_FILE must name the generated pull-request body." >&2
  exit 1
fi
RELEASE_BODY="$(<"${RELEASE_BODY_FILE}")"

bot_login="${APP_SLUG}[bot]"
expected_bot_id=318780254
bot="$(gh api "users/${bot_login}")"
bot_id="$(jq --raw-output .id <<<"${bot}")"
# The App identity endpoint must resolve the exact expected bot and numeric ID.
if ! jq --exit-status --arg bot "${bot_login}" \
  --argjson bot_id "${expected_bot_id}" \
  '.login == $bot and .id == $bot_id' \
  <<<"${bot}" >/dev/null; then
  echo "GitHub did not return the expected release App bot identity." >&2
  exit 1
fi
bot_email="${bot_id}+${bot_login}@users.noreply.github.com"
rest_committer="web-flow"
rest_committer_id=19864447
raw_committer_name="GitHub"
raw_committer_email="noreply@github.com"

# Finalization changes only the review state after checkout-bound validation.
if [[ "${RELEASE_OPERATION}" == "finalize" ]]; then
  : "${RELEASE_COMMIT:?RELEASE_COMMIT is required for finalization}"
  : "${RELEASE_PR_NUMBER:?RELEASE_PR_NUMBER is required for finalization}"
  # Require exact typed identifiers before using them in API paths or filters.
  if [[ ! "${RELEASE_COMMIT}" =~ ^[0-9a-f]{40}$ \
    || ! "${RELEASE_PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Finalization requires an exact commit and pull-request number." >&2
    exit 1
  fi
  # The post-association validator must leave the checkout on the App commit.
  if [[ "$(git rev-parse HEAD)" != "${RELEASE_COMMIT}" ]]; then
    echo "Finalization is not running at the validated App commit." >&2
    exit 1
  fi
  remote_main="$(
    gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
  )"
  release_sha="$(
    gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${RELEASE_BRANCH}" \
      --jq .object.sha
  )"
  # Finalization cannot outlive its exact main parent or App-owned branch head.
  if [[ "${remote_main}" != "${GITHUB_SHA}" \
    || "${release_sha}" != "${RELEASE_COMMIT}" ]]; then
    echo "Release proposal state changed before finalization." >&2
    exit 1
  fi
  release_commit="$(
    gh api "repos/${GITHUB_REPOSITORY}/commits/${RELEASE_COMMIT}"
  )"
  # Rebind finalization to the exact Verified, DCO-compliant App commit.
  if ! jq --exit-status \
    --arg bot "${bot_login}" \
    --argjson bot_id "${bot_id}" \
    --arg bot_email "${bot_email}" \
    --arg rest_committer "${rest_committer}" \
    --argjson rest_committer_id "${rest_committer_id}" \
    --arg raw_committer_name "${raw_committer_name}" \
    --arg raw_committer_email "${raw_committer_email}" \
    --arg dco "Signed-off-by: ${bot_login} <${bot_email}>" \
    --arg parent "${GITHUB_SHA}" \
    '.author.login == $bot
      and .author.id == $bot_id
      and .committer.login == $rest_committer
      and .committer.id == $rest_committer_id
      and .commit.author.name == $bot
      and .commit.author.email == $bot_email
      and .commit.committer.name == $raw_committer_name
      and .commit.committer.email == $raw_committer_email
      and .commit.verification.verified == true
      and .commit.verification.reason == "valid"
      and ([.commit.message | split("\n")[]
        | select(startswith("Signed-off-by: "))] == [$dco])
      and (.parents | length == 1)
      and .parents[0].sha == $parent' \
    <<<"${release_commit}" >/dev/null; then
    echo "Finalization did not resolve the exact valid App commit." >&2
    exit 1
  fi
  held_pr="$(
    gh api "repos/${GITHUB_REPOSITORY}/pulls/${RELEASE_PR_NUMBER}"
  )"
  # Only the exact held-draft review surface may be finalized.
  if ! jq --exit-status \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg branch "${RELEASE_BRANCH}" \
    --arg sha "${RELEASE_COMMIT}" \
    --arg main "${GITHUB_SHA}" \
    --arg bot "${bot_login}" \
    --argjson bot_id "${bot_id}" \
    --arg title "${RELEASE_TITLE}" \
    --arg body "${RELEASE_BODY}" \
    --argjson number "${RELEASE_PR_NUMBER}" \
    '.number == $number
      and .state == "open"
      and .user.login == $bot
      and .user.id == $bot_id
      and .head.repo.full_name == $repository
      and .head.ref == $branch
      and .head.sha == $sha
      and .base.repo.full_name == $repository
      and .base.ref == "main"
      and .base.sha == $main
      and .title == $title
      and .body == $body
      and .commits == 1
      and (.node_id | type == "string" and length > 0)
      and .draft == true' \
    <<<"${held_pr}" >/dev/null; then
    echo "The release pull request is not the exact held draft." >&2
    exit 1
  fi
  # A substantive proposal leaves draft only after every exact-commit check.
  if [[ "${RELEASE_DRAFT}" == "false" ]]; then
    pull_request_id="$(jq --raw-output .node_id <<<"${held_pr}")"
    # Keep GraphQL's `$id` variable literal for the API rather than the shell.
    # shellcheck disable=SC2016
    transition_response="$(
      gh api graphql \
        -f query='mutation($id: ID!) {
          markPullRequestReadyForReview(input: {pullRequestId: $id}) {
            pullRequest { number isDraft }
          }
        }' \
        -f "id=${pull_request_id}"
    )"
    # GitHub must report the exact transitioned pull request as ready.
    if ! jq --exit-status --argjson number "${RELEASE_PR_NUMBER}" \
      '.data.markPullRequestReadyForReview.pullRequest.number == $number
        and .data.markPullRequestReadyForReview.pullRequest.isDraft == false' \
      <<<"${transition_response}" >/dev/null; then
      echo "GitHub did not mark the exact release pull request ready." >&2
      exit 1
    fi
  fi
  final_pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${RELEASE_PR_NUMBER}")"
  # The final review state must retain every exact binding and requested state.
  if ! jq --exit-status \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg branch "${RELEASE_BRANCH}" \
    --arg sha "${RELEASE_COMMIT}" \
    --arg main "${GITHUB_SHA}" \
    --arg bot "${bot_login}" \
    --argjson bot_id "${bot_id}" \
    --arg title "${RELEASE_TITLE}" \
    --arg body "${RELEASE_BODY}" \
    --argjson number "${RELEASE_PR_NUMBER}" \
    --argjson draft "${RELEASE_DRAFT}" \
    '.number == $number
      and .state == "open"
      and .user.login == $bot
      and .user.id == $bot_id
      and .head.repo.full_name == $repository
      and .head.ref == $branch
      and .head.sha == $sha
      and .base.repo.full_name == $repository
      and .base.ref == "main"
      and .base.sha == $main
      and .title == $title
      and .body == $body
      and .commits == 1
      and .draft == $draft' \
    <<<"${final_pr}" >/dev/null; then
    echo "GitHub returned an unexpected finalized pull-request state." >&2
    exit 1
  fi
  final_main="$(
    gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
  )"
  final_release="$(
    gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${RELEASE_BRANCH}" \
      --jq .object.sha
  )"
  # A concurrent main or branch change invalidates the completed transition.
  if [[ "${final_main}" != "${GITHUB_SHA}" \
    || "${final_release}" != "${RELEASE_COMMIT}" ]]; then
    echo "Release proposal state changed during finalization." >&2
    exit 1
  fi
  echo "commit_sha=${RELEASE_COMMIT}" >>"${GITHUB_OUTPUT}"
  echo "pr_number=${RELEASE_PR_NUMBER}" >>"${GITHUB_OUTPUT}"
  echo "Finalized PR #${RELEASE_PR_NUMBER} at validated commit ${RELEASE_COMMIT}."
  exit 0
fi

: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required for an update}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required for an update}"

# Bind the generated diff to the exact triggering main commit.
if [[ "$(git rev-parse HEAD)" != "${GITHUB_SHA}" ]]; then
  echo "The release diff must be based on the triggering main commit." >&2
  exit 1
fi
# Refuse to replace the release branch if main advanced during this run.
remote_main="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
)"
# Only the exact current main commit may replace the release branch.
if [[ "${remote_main}" != "${GITHUB_SHA}" ]]; then
  echo "Main advanced while the release proposal was being generated." >&2
  exit 1
fi

git diff --check
# The helper consumes one unstaged generated diff and no index or untracked state.
if ! git diff --cached --quiet; then
  echo "Release automation may not consume staged changes." >&2
  exit 1
fi
mapfile -t untracked_paths < <(git ls-files --others --exclude-standard)
# Generated release automation may not leave files outside the tracked diff.
if ((${#untracked_paths[@]} != 0)); then
  echo "Release automation may only modify existing files." >&2
  exit 1
fi
# Mode changes are outside the generated release file-content boundary.
if [[ -n "$(git diff --summary)" ]]; then
  echo "Release automation may not change file modes or path identity." >&2
  exit 1
fi
mapfile -t changed_paths < <(git diff --name-only --no-renames)
# Refuse to create an empty commit or an authorization-only empty PR.
if ((${#changed_paths[@]} == 0)); then
  echo "The release proposal has no file changes." >&2
  exit 1
fi

for path in "${changed_paths[@]}"; do
  # Limit App-authored commits to generated versions and changelogs.
  case "${GITHUB_REPOSITORY}:${path}" in
    NVIDIA/yaml-sigil-traits:Cargo.toml | \
      NVIDIA/yaml-sigil-traits:CHANGELOG.md | \
      NVIDIA/yaml-sigil-rs:Cargo.toml | \
      NVIDIA/yaml-sigil-rs:crates/yaml-sigil-core/CHANGELOG.md | \
      NVIDIA/yaml-sigil-rs:crates/yaml-sigil-transcription/CHANGELOG.md | \
      NVIDIA/yaml-sigil-rs:crates/yaml-sigil-signing/CHANGELOG.md | \
      NVIDIA/yaml-sigil-rs:crates/yaml-sigil-verification/CHANGELOG.md) ;;
    *)
      echo "Release automation may not commit ${path}." >&2
      exit 1
      ;;
  esac
done

# Generated release commits may change only files already present on main.
while IFS=$'\t' read -r status path; do
  # Added, deleted, renamed, or type-changed paths exceed release authority.
  if [[ "${status}" != "M" ]]; then
    echo "Release automation may only modify existing files; found ${status} ${path}." >&2
    exit 1
  fi
done < <(git diff --name-status --no-renames)

# Never overwrite unique commits that were not authored by this App. Commits
# already integrated into main are not unique and do not block a new train.
target_exists=false
target_response=""
# A matching-ref query distinguishes absence from permission and API failures.
target_refs="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${RELEASE_BRANCH}"
)"
# Prefix matches, duplicates, symbolic refs, and malformed objects are collisions.
if ! jq --exit-status \
  --arg ref "refs/heads/${RELEASE_BRANCH}" \
  'type == "array"
    and length <= 1
    and all(.[];
      .ref == $ref
      and .object.type == "commit"
      and (.object.sha | test("^[0-9a-f]{40}$")))' \
  <<<"${target_refs}" >/dev/null; then
  echo "GitHub returned ambiguous release branch state." >&2
  exit 1
fi
# Inspect ownership only when the exact reusable release branch already exists.
if [[ "$(jq 'length' <<<"${target_refs}")" == "1" ]]; then
  target_exists=true
  target_response="$(jq --compact-output '.[0]' <<<"${target_refs}")"
  target_sha="$(jq --raw-output '.object.sha // empty' <<<"${target_response}")"
  compare="$(
    gh api "repos/${GITHUB_REPOSITORY}/compare/main...${RELEASE_BRANCH}"
  )"
  # Preserve branches with multiple unique commits, incomplete pagination, or
  # a unique commit not authored and committed by this exact App.
  if ! jq --exit-status \
    --arg bot "${bot_login}" \
    --argjson bot_id "${bot_id}" \
    --arg committer "${rest_committer}" \
    --argjson committer_id "${rest_committer_id}" \
    '.ahead_by <= 1
      and .ahead_by == (.commits | length)
      and all(.commits[];
        .author.login == $bot
        and .author.id == $bot_id
        and .committer.login == $committer
        and .committer.id == $committer_id)' \
    <<<"${compare}" >/dev/null; then
    echo "${RELEASE_BRANCH} contains a non-App commit and will not be overwritten." >&2
    exit 1
  fi
  # A unique existing App commit must retain its signature, DCO, and one parent.
  if [[ "$(jq '.ahead_by' <<<"${compare}")" == "1" ]]; then
    existing_commit="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${target_sha}")"
    # Reject an App-looking branch whose repository-visible commit is invalid.
    if ! jq --exit-status \
      --arg bot "${bot_login}" \
      --argjson bot_id "${bot_id}" \
      --arg bot_email "${bot_email}" \
      --arg rest_committer "${rest_committer}" \
      --argjson rest_committer_id "${rest_committer_id}" \
      --arg raw_committer_name "${raw_committer_name}" \
      --arg raw_committer_email "${raw_committer_email}" \
      --arg dco "Signed-off-by: ${bot_login} <${bot_email}>" \
      '.author.login == $bot
        and .author.id == $bot_id
        and .committer.login == $rest_committer
        and .committer.id == $rest_committer_id
        and .commit.author.name == $bot
        and .commit.author.email == $bot_email
        and .commit.committer.name == $raw_committer_name
        and .commit.committer.email == $raw_committer_email
        and .commit.verification.verified == true
        and .commit.verification.reason == "valid"
        and ([.commit.message | split("\n")[]
          | select(startswith("Signed-off-by: "))] == [$dco])
        and (.parents | length == 1)' \
      <<<"${existing_commit}" >/dev/null; then
      echo "${RELEASE_BRANCH} contains an invalid App commit." >&2
      exit 1
    fi
  fi
fi

pulls="$(
  gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls" \
    -f state=open -f "head=${GITHUB_REPOSITORY%%/*}:${RELEASE_BRANCH}"
)"
effective_draft="${RELEASE_DRAFT}"
# A held proposal remains draft until a separate exact-commit finalization.
if [[ "${RELEASE_HOLD_DRAFT}" == "true" ]]; then
  effective_draft=true
fi
# More than one open pull request for the durable branch is ambiguous.
if [[ "$(jq 'length' <<<"${pulls}")" -gt 1 ]]; then
  echo "Multiple open release pull requests use ${RELEASE_BRANCH}." >&2
  exit 1
fi
pr_number="$(jq --raw-output '.[0].number // empty' <<<"${pulls}")"
# An existing PR must bind the exact owned ref to this repository's main.
if [[ -n "${pr_number}" ]]; then
  # A missing owned ref or any mismatched PR field blocks all Git writes.
  if [[ "${target_exists}" != "true" ]] \
    || ! jq --exit-status \
      --arg repository "${GITHUB_REPOSITORY}" \
      --arg branch "${RELEASE_BRANCH}" \
      --arg sha "${target_sha}" \
      --arg bot "${bot_login}" \
      --argjson bot_id "${bot_id}" \
      'length == 1
        and .[0].state == "open"
        and .[0].user.login == $bot
        and .[0].user.id == $bot_id
        and .[0].head.repo.full_name == $repository
        and .[0].head.ref == $branch
        and .[0].head.sha == $sha
        and .[0].base.repo.full_name == $repository
        and .[0].base.ref == "main"
        and .[0].commits == 1
        and (.[0].node_id | type == "string" and length > 0)
        and (.[0].draft | type == "boolean")' \
      <<<"${pulls}" >/dev/null; then
    echo "The existing release pull request has unexpected ownership or refs." >&2
    exit 1
  fi
  current_draft="$(jq --raw-output '.[0].draft' <<<"${pulls}")"
  # Reduce an existing ready PR to draft before changing any Git object or ref.
  if [[ "${RELEASE_HOLD_DRAFT}" == "true" \
    && "${current_draft}" == "false" ]]; then
    pull_request_id="$(jq --raw-output '.[0].node_id' <<<"${pulls}")"
    # Keep GraphQL's `$id` variable literal for the API rather than the shell.
    # shellcheck disable=SC2016
    transition_response="$(
      gh api graphql \
        -f query='mutation($id: ID!) {
          convertPullRequestToDraft(input: {pullRequestId: $id}) {
            pullRequest { number isDraft }
          }
        }' \
        -f "id=${pull_request_id}"
    )"
    # GitHub must report the exact existing pull request as held in draft.
    if ! jq --exit-status --argjson number "${pr_number}" \
      '.data.convertPullRequestToDraft.pullRequest.number == $number
        and .data.convertPullRequestToDraft.pullRequest.isDraft == true' \
      <<<"${transition_response}" >/dev/null; then
      echo "GitHub did not convert the exact release pull request to draft." >&2
      exit 1
    fi
    held_pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}")"
    # Verify the draft hold against the exact pre-update branch and PR identity.
    if ! jq --exit-status \
      --arg repository "${GITHUB_REPOSITORY}" \
      --arg branch "${RELEASE_BRANCH}" \
      --arg sha "${target_sha}" \
      --arg bot "${bot_login}" \
      --argjson bot_id "${bot_id}" \
      --argjson number "${pr_number}" \
      '.number == $number
        and .state == "open"
        and .user.login == $bot
        and .user.id == $bot_id
        and .head.repo.full_name == $repository
        and .head.ref == $branch
        and .head.sha == $sha
        and .base.repo.full_name == $repository
        and .base.ref == "main"
        and .commits == 1
        and .draft == true' \
      <<<"${held_pr}" >/dev/null; then
      echo "GitHub did not retain the exact release pull request as draft." >&2
      exit 1
    fi
  fi
fi

tree_entries='[]'
while IFS=$'\t' read -r status path; do
  # Translate the already allowlisted text diff into one exact Git tree.
  case "${status}" in
    M)
      tree_entries="$(
        jq --compact-output \
          --arg path "${path}" --rawfile contents "${path}" \
          ". + [{path: \$path, mode: \"100644\", type: \"blob\", content: \$contents}]" \
          <<<"${tree_entries}"
      )"
      ;;
    *)
      echo "Unsupported release diff status ${status} for ${path}." >&2
      exit 1
      ;;
  esac
done < <(git diff --name-status --no-renames)

staging_branch="automation/release-staging-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
staging_created=false
cleanup_staging() {
  # Best-effort cleanup prevents temporary signing branches from accumulating.
  if [[ "${staging_created}" == "true" ]]; then
    gh api --method DELETE \
      "repos/${GITHUB_REPOSITORY}/git/refs/heads/${staging_branch}" \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup_staging EXIT

staging_response=""
# Start from an exact-main ref that the App can fast-forward after signing.
if ! staging_response="$(
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f "ref=refs/heads/${staging_branch}" -f "sha=${GITHUB_SHA}"
)"; then
  echo "GitHub did not create the exact-main staging branch." >&2
  exit 1
fi
staging_created=true
# The creation response must bind the explicit staging ref to exact main.
if ! jq --exit-status \
  --arg ref "refs/heads/${staging_branch}" \
  --arg sha "${GITHUB_SHA}" \
  '.ref == $ref and .object.type == "commit" and .object.sha == $sha' \
  <<<"${staging_response}" >/dev/null; then
  echo "GitHub created an unexpected staging ref." >&2
  exit 1
fi

message_body="Signed-off-by: ${bot_login} <${bot_email}>"
commit_message="${RELEASE_TITLE}"$'\n\n'"${message_body}"
base_tree="$(git rev-parse --verify "${GITHUB_SHA}^{tree}")"
# GitHub's tree API requires the exact parent tree, not its commit identifier.
if [[ ! "${base_tree}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "The triggering main commit did not resolve to one exact tree." >&2
  exit 1
fi
tree_payload="$(
  jq --null-input \
    --arg base_tree "${base_tree}" \
    --argjson tree "${tree_entries}" \
    "{base_tree: \$base_tree, tree: \$tree}"
)"
tree_response=""
# A tree based on the triggering SHA makes every generated path explicit.
if ! tree_response="$(
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" \
    --input - <<<"${tree_payload}"
)"; then
  echo "GitHub did not create the generated release tree." >&2
  exit 1
fi
tree_sha="$(jq --raw-output '.sha // empty' <<<"${tree_response}")"
# Refuse to create a commit without a lowercase full tree identity.
if [[ ! "${tree_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GitHub did not return the generated release tree SHA." >&2
  exit 1
fi

commit_payload="$(
  jq --null-input \
    --arg message "${commit_message}" \
    --arg tree "${tree_sha}" \
    --arg parent "${GITHUB_SHA}" \
    "{message: \$message, tree: \$tree, parents: [\$parent]}"
)"
commit_response=""
# Installation-token commit creation invokes GitHub's App signing service.
if ! commit_response="$(
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" \
    --input - <<<"${commit_payload}"
)"; then
  echo "GitHub did not create the App release proposal commit." >&2
  exit 1
fi
commit_sha="$(jq --raw-output '.sha // empty' <<<"${commit_response}")"
# A malformed object indicates a Git Database validation or authorization failure.
if [[ ! "${commit_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GitHub did not create the release proposal commit." >&2
  exit 1
fi

# The create-commit response is authoritative before any ref makes the commit
# reachable through the repository's higher-level commits API.
# Move no durable release ref until GitHub reports the exact App-authored,
# bot-DCO-compliant, single-parent commit with a valid signature.
if ! jq --exit-status \
  --arg bot "${bot_login}" \
  --argjson bot_id "${bot_id}" \
  --arg bot_email "${bot_email}" \
  --arg raw_committer_name "${raw_committer_name}" \
  --arg raw_committer_email "${raw_committer_email}" \
  --arg dco "${message_body}" \
  --arg parent "${GITHUB_SHA}" \
  --arg tree "${tree_sha}" \
  '.author.name == $bot
    and .author.email == $bot_email
    and .committer.name == $raw_committer_name
    and .committer.email == $raw_committer_email
    and .verification.verified == true
    and .verification.reason == "valid"
    and ([.message | split("\n")[]
      | select(startswith("Signed-off-by: "))] == [$dco])
    and .tree.sha == $tree
    and (.parents | length == 1)
    and .parents[0].sha == $parent' \
  <<<"${commit_response}" >/dev/null; then
  echo "GitHub did not report the generated App commit as valid." >&2
  exit 1
fi

# Main must remain the exact proposal parent until the durable ref moves.
remote_main="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
)"
# Do not publish a proposal based on a main commit that is no longer current.
if [[ "${remote_main}" != "${GITHUB_SHA}" ]]; then
  echo "Main advanced while the release proposal commit was being signed." >&2
  exit 1
fi

# Fast-forwarding an existing ref is GitHub's documented final App-signing
# step and makes the verified commit reachable before any durable ref moves.
if ! staging_response="$(
  gh api --method PATCH \
    "repos/${GITHUB_REPOSITORY}/git/refs/heads/${staging_branch}" \
    -f "sha=${commit_sha}" -F force=false
)"; then
  echo "GitHub did not fast-forward the App staging branch." >&2
  exit 1
fi
# The staged ref must now make only the exact signed commit reachable.
if ! jq --exit-status --arg sha "${commit_sha}" \
  '.object.type == "commit" and .object.sha == $sha' \
  <<<"${staging_response}" >/dev/null; then
  echo "GitHub fast-forwarded the staging ref to an unexpected object." >&2
  exit 1
fi
reachable_commit=""
# Require the repository view to resolve the same commit through its new ref.
if ! reachable_commit="$(
  gh api "repos/${GITHUB_REPOSITORY}/commits/${commit_sha}"
)"; then
  echo "GitHub did not resolve the staged App commit." >&2
  exit 1
fi
# Recheck the repository-visible identity, signature, DCO, and exact parent.
if ! jq --exit-status \
  --arg bot "${bot_login}" \
  --argjson bot_id "${bot_id}" \
  --arg bot_email "${bot_email}" \
  --arg rest_committer "${rest_committer}" \
  --argjson rest_committer_id "${rest_committer_id}" \
  --arg raw_committer_name "${raw_committer_name}" \
  --arg raw_committer_email "${raw_committer_email}" \
  --arg dco "${message_body}" \
  --arg parent "${GITHUB_SHA}" \
  '.author.login == $bot
    and .author.id == $bot_id
    and .committer.login == $rest_committer
    and .committer.id == $rest_committer_id
    and .commit.author.name == $bot
    and .commit.author.email == $bot_email
    and .commit.committer.name == $raw_committer_name
    and .commit.committer.email == $raw_committer_email
    and .commit.verification.verified == true
    and .commit.verification.reason == "valid"
    and ([.commit.message | split("\n")[]
      | select(startswith("Signed-off-by: "))] == [$dco])
    and (.parents | length == 1)
    and .parents[0].sha == $parent' \
  <<<"${reachable_commit}" >/dev/null; then
  echo "GitHub did not report the staged App commit as valid." >&2
  exit 1
fi

local_staging_ref="refs/remotes/origin/${staging_branch}"
# Fetch the staged object by its exact temporary ref before the atomic push.
if ! git fetch --no-tags --force origin \
  "refs/heads/${staging_branch}:${local_staging_ref}"; then
  echo "Git did not fetch the exact staged App commit." >&2
  exit 1
fi
# The locally pushable object must be the same repository-verified commit.
if [[ "$(git rev-parse --verify "${local_staging_ref}^{commit}")" != "${commit_sha}" ]]; then
  echo "The fetched staging ref does not identify the verified App commit." >&2
  exit 1
fi

expected_old_sha=""
# An existing branch lease binds the write to the exact ref inspected above.
if [[ "${target_exists}" == "true" ]]; then
  expected_old_sha="${target_sha}"
fi

# Re-read main after the staging fetch so a proposal that became stale during
# those network operations cannot move the durable branch or mutate its PR.
remote_main="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
)"
# This is the final stale-source gate immediately before the atomic ref write.
if [[ "${remote_main}" != "${GITHUB_SHA}" ]]; then
  echo "Main advanced before the durable release branch update." >&2
  exit 1
fi
# A held existing proposal must still be draft at the last pre-ref gate.
if [[ "${RELEASE_HOLD_DRAFT}" == "true" && -n "${pr_number}" ]]; then
  held_pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}")"
  # Reject a review-state or identity race before the App-owned ref changes.
  if ! jq --exit-status \
    --arg repository "${GITHUB_REPOSITORY}" \
    --arg branch "${RELEASE_BRANCH}" \
    --arg sha "${target_sha}" \
    --arg bot "${bot_login}" \
    --argjson bot_id "${bot_id}" \
    --argjson number "${pr_number}" \
    '.number == $number
      and .state == "open"
      and .user.login == $bot
      and .user.id == $bot_id
      and .head.repo.full_name == $repository
      and .head.ref == $branch
      and .head.sha == $sha
      and .base.repo.full_name == $repository
      and .base.ref == "main"
      and .commits == 1
      and .draft == true' \
    <<<"${held_pr}" >/dev/null; then
    echo "The release pull request did not remain draft before the branch update." >&2
    exit 1
  fi
fi
credential_helper="!f() { printf \"%s\\n\" \"username=x-access-token\" \"password=\${GH_TOKEN}\"; }; f"
# Git receive-pack applies the expected-old-SHA lease atomically. An empty
# expected value permits creation only while the durable ref remains absent.
if ! GIT_TERMINAL_PROMPT=0 git \
  -c credential.helper= \
  -c "credential.helper=${credential_helper}" \
  push --porcelain \
  --force-with-lease="refs/heads/${RELEASE_BRANCH}:${expected_old_sha}" \
  "https://github.com/${GITHUB_REPOSITORY}.git" \
  "${commit_sha}:refs/heads/${RELEASE_BRANCH}"; then
  echo "The App-owned release branch changed before its atomic update." >&2
  exit 1
fi
release_sha="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${RELEASE_BRANCH}" \
    --jq .object.sha
)"
# Do not open or update a PR until the durable branch resolves exactly.
if [[ "${release_sha}" != "${commit_sha}" ]]; then
  echo "The App-owned release branch does not identify the verified commit." >&2
  exit 1
fi

# Create the first PR for a train; otherwise update the existing open PR.
if [[ -z "${pr_number}" ]]; then
  pr="$(
    gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" \
      -f "title=${RELEASE_TITLE}" \
      -f "head=${RELEASE_BRANCH}" \
      -f base=main \
      -f "body=${RELEASE_BODY}" \
      -F "draft=${effective_draft}"
  )"
  pr_number="$(jq --raw-output .number <<<"${pr}")"
else
  pr="$(
    gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" \
      -f "title=${RELEASE_TITLE}" -f "body=${RELEASE_BODY}"
  )"
  current_draft="$(jq --raw-output .draft <<<"${pr}")"
  # Keep the PR's review state aligned with the generated proposal state.
  if [[ "${current_draft}" != "${effective_draft}" ]]; then
    pull_request_id="$(jq --raw-output .node_id <<<"${pr}")"
    # Ready proposals leave draft state; empty seed proposals return to draft.
    if [[ "${effective_draft}" == "false" ]]; then
      # Keep GraphQL's `$id` variable literal for the API rather than the shell.
      # shellcheck disable=SC2016
      transition_response="$(
        gh api graphql \
          -f query='mutation($id: ID!) {
            markPullRequestReadyForReview(input: {pullRequestId: $id}) {
              pullRequest { number isDraft }
            }
          }' \
          -f "id=${pull_request_id}"
      )"
      # Bind the ready transition to this exact pull request and state.
      if ! jq --exit-status --argjson number "${pr_number}" \
        '.data.markPullRequestReadyForReview.pullRequest.number == $number
          and .data.markPullRequestReadyForReview.pullRequest.isDraft == false' \
        <<<"${transition_response}" >/dev/null; then
        echo "GitHub did not mark the exact release pull request ready." >&2
        exit 1
      fi
    else
      # Keep GraphQL's `$id` variable literal for the API rather than the shell.
      # shellcheck disable=SC2016
      transition_response="$(
        gh api graphql \
          -f query='mutation($id: ID!) {
            convertPullRequestToDraft(input: {pullRequestId: $id}) {
              pullRequest { number isDraft }
            }
          }' \
          -f "id=${pull_request_id}"
      )"
      # Bind the draft transition to this exact pull request and state.
      if ! jq --exit-status --argjson number "${pr_number}" \
        '.data.convertPullRequestToDraft.pullRequest.number == $number
          and .data.convertPullRequestToDraft.pullRequest.isDraft == true' \
        <<<"${transition_response}" >/dev/null; then
        echo "GitHub did not convert the exact release pull request to draft." >&2
        exit 1
      fi
    fi
  fi
fi

final_pr="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}")"
# Bind the final review surface to the exact repository, refs, commit, and body.
if ! jq --exit-status \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg branch "${RELEASE_BRANCH}" \
  --arg sha "${commit_sha}" \
  --arg bot "${bot_login}" \
  --argjson bot_id "${bot_id}" \
  --arg title "${RELEASE_TITLE}" \
  --arg body "${RELEASE_BODY}" \
  --argjson number "${pr_number}" \
  --argjson draft "${effective_draft}" \
  '.number == $number
    and .state == "open"
    and .user.login == $bot
    and .user.id == $bot_id
    and .head.repo.full_name == $repository
    and .head.ref == $branch
    and .head.sha == $sha
    and .base.repo.full_name == $repository
    and .base.ref == "main"
    and .title == $title
    and .body == $body
    and .commits == 1
    and .draft == $draft' \
  <<<"${final_pr}" >/dev/null; then
  echo "GitHub returned an unexpected release pull-request state." >&2
  exit 1
fi

final_main="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha
)"
# A proposal that raced with main is stale even if its PR was created cleanly.
if [[ "${final_main}" != "${GITHUB_SHA}" ]]; then
  echo "Main advanced before the release pull request was finalized." >&2
  exit 1
fi

# Remove the exact temporary signing ref before reporting proposal success.
if ! gh api --method DELETE \
  "repos/${GITHUB_REPOSITORY}/git/refs/heads/${staging_branch}" >/dev/null; then
  echo "GitHub did not remove the App staging branch." >&2
  exit 1
fi
remaining_staging_refs="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${staging_branch}"
)"
# A successful run must leave no exact temporary ref for this run attempt.
if ! jq --exit-status --arg ref "refs/heads/${staging_branch}" \
  'type == "array"
    and all(.[]; (.ref | type == "string") and .ref != $ref)' \
  <<<"${remaining_staging_refs}" >/dev/null; then
  echo "GitHub still reports the App staging branch." >&2
  exit 1
fi
staging_created=false

echo "commit_sha=${commit_sha}" >>"${GITHUB_OUTPUT}"
echo "pr_number=${pr_number}" >>"${GITHUB_OUTPUT}"
echo "Created or updated PR #${pr_number} at Verified commit ${commit_sha}."

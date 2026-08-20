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
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${APP_SLUG:?APP_SLUG is required}"
: "${RELEASE_BRANCH:?RELEASE_BRANCH is required}"
: "${RELEASE_TITLE:?RELEASE_TITLE is required}"
: "${RELEASE_BODY_FILE:?RELEASE_BODY_FILE is required}"
: "${RELEASE_DRAFT:?RELEASE_DRAFT is required}"

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
# Preserve release-plz's merged-PR source-authorization convention.
if [[ "${RELEASE_BRANCH}" != release-plz-* ]]; then
  echo "The release branch must use the release-plz- prefix." >&2
  exit 1
fi
# Reject values that cannot be sent as a typed GitHub API boolean.
if [[ "${RELEASE_DRAFT}" != "true" && "${RELEASE_DRAFT}" != "false" ]]; then
  echo "RELEASE_DRAFT must be true or false." >&2
  exit 1
fi
# Require the generated body file rather than accepting shell-expanded prose.
if [[ ! -f "${RELEASE_BODY_FILE}" ]]; then
  echo "RELEASE_BODY_FILE must name the generated pull-request body." >&2
  exit 1
fi
RELEASE_BODY="$(<"${RELEASE_BODY_FILE}")"

git diff --check
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

bot_login="${APP_SLUG}[bot]"
bot="$(gh api "users/${bot_login}")"
bot_id="$(jq --raw-output .id <<<"${bot}")"
bot_email="${bot_id}+${bot_login}@users.noreply.github.com"

# Never overwrite unique commits that were not authored by this App. Commits
# already integrated into main are not unique and do not block a new train.
target_ref=""
# Inspect ownership only when the reusable release branch already exists.
if target_ref="$(
  gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${RELEASE_BRANCH}" 2>/dev/null
)"; then
  compare="$(
    gh api "repos/${GITHUB_REPOSITORY}/compare/main...${RELEASE_BRANCH}"
  )"
  # Preserve any branch that contains a unique human or other-App commit.
  if ! jq --exit-status --arg bot "${bot_login}" \
    'all(.commits[]; .author.login == $bot)' <<<"${compare}" >/dev/null; then
    echo "${RELEASE_BRANCH} contains a non-App commit and will not be overwritten." >&2
    exit 1
  fi
fi

additions='[]'
deletions='[]'
while IFS=$'\t' read -r status path; do
  # Translate the already allowlisted text diff into GraphQL file changes.
  case "${status}" in
    A | M)
      contents="$(base64 --wrap=0 "${path}")"
      additions="$(
        jq --compact-output \
          --arg path "${path}" --arg contents "${contents}" \
          '. + [{path: $path, contents: $contents}]' <<<"${additions}"
      )"
      ;;
    D)
      deletions="$(
        jq --compact-output --arg path "${path}" \
          '. + [{path: $path}]' <<<"${deletions}"
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

staging_ref=""
# The REST response supplies the exact Ref node that GraphQL must commit to.
if ! staging_ref="$(
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f "ref=refs/heads/${staging_branch}" -f "sha=${GITHUB_SHA}"
)"; then
  echo "GitHub did not create the App staging branch." >&2
  exit 1
fi
staging_created=true
staging_id="$(jq --raw-output '.node_id // empty' <<<"${staging_ref}")"
# Refuse a name-based fallback because a newly created ref may not yet resolve
# consistently across the REST and GraphQL APIs.
if [[ -z "${staging_id}" ]]; then
  echo "GitHub did not return the App staging Ref node ID." >&2
  exit 1
fi

message_body="Signed-off-by: ${bot_login} <${bot_email}>"
mutation="mutation(\$input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: \$input) { commit { oid } }
}"
payload="$(
  jq --null-input \
    --arg query "${mutation}" \
    --arg staging_id "${staging_id}" \
    --arg expected "${GITHUB_SHA}" \
    --arg headline "${RELEASE_TITLE}" \
    --arg body "${message_body}" \
    --argjson additions "${additions}" \
    --argjson deletions "${deletions}" \
    '{
      query: $query,
      variables: {
        input: {
          branch: {id: $staging_id},
          expectedHeadOid: $expected,
          message: {headline: $headline, body: $body},
          fileChanges: {additions: $additions, deletions: $deletions}
        }
      }
    }'
)"
response="$(gh api graphql --input - <<<"${payload}")"
commit_sha="$(jq --raw-output '.data.createCommitOnBranch.commit.oid // empty' <<<"${response}")"
# A missing object indicates a GraphQL validation or authorization failure.
if [[ -z "${commit_sha}" ]]; then
  echo "GitHub did not create the release proposal commit." >&2
  jq '.errors // .' <<<"${response}" >&2
  exit 1
fi

commit="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${commit_sha}")"
# Move no durable release ref until GitHub reports a valid signature.
if ! jq --exit-status \
  '.commit.verification.verified == true and .commit.verification.reason == "valid"' \
  <<<"${commit}" >/dev/null; then
  echo "GitHub did not report the generated commit as Verified." >&2
  exit 1
fi

# Update an owned branch atomically, or create it for the first release train.
if [[ -n "${target_ref}" ]]; then
  gh api --method PATCH \
    "repos/${GITHUB_REPOSITORY}/git/refs/heads/${RELEASE_BRANCH}" \
    -f "sha=${commit_sha}" -F force=true >/dev/null
else
  gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f "ref=refs/heads/${RELEASE_BRANCH}" -f "sha=${commit_sha}" >/dev/null
fi

pulls="$(
  gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls" \
    -f state=open -f "head=${GITHUB_REPOSITORY%%/*}:${RELEASE_BRANCH}"
)"
pr_number="$(jq --raw-output '.[0].number // empty' <<<"${pulls}")"
# Create the first PR for a train; otherwise update the existing open PR.
if [[ -z "${pr_number}" ]]; then
  pr="$(
    gh api --method POST "repos/${GITHUB_REPOSITORY}/pulls" \
      -f "title=${RELEASE_TITLE}" \
      -f "head=${RELEASE_BRANCH}" \
      -f base=main \
      -f "body=${RELEASE_BODY}" \
      -F "draft=${RELEASE_DRAFT}"
  )"
  pr_number="$(jq --raw-output .number <<<"${pr}")"
else
  pr="$(
    gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" \
      -f "title=${RELEASE_TITLE}" -f "body=${RELEASE_BODY}"
  )"
  # A substantive update may promote an earlier empty draft to ready status.
  if [[ "${RELEASE_DRAFT}" == "false" \
    && "$(jq --raw-output .draft <<<"${pr}")" == "true" ]]; then
    pull_request_id="$(jq --raw-output .node_id <<<"${pr}")"
    # Keep GraphQL's `$id` variable literal for the API rather than the shell.
    # shellcheck disable=SC2016
    gh api graphql \
      -f query='mutation($id: ID!) {
        markPullRequestReadyForReview(input: {pullRequestId: $id}) {
          pullRequest { number }
        }
      }' \
      -f "id=${pull_request_id}" >/dev/null
  fi
fi

echo "commit_sha=${commit_sha}" >>"${GITHUB_OUTPUT}"
echo "pr_number=${pr_number}" >>"${GITHUB_OUTPUT}"
echo "Created or updated PR #${pr_number} at Verified commit ${commit_sha}."

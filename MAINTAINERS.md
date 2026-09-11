# Maintainer guide

This is the concise human maintainer operations runbook for
`yaml-sigil-traits`. Contributor and release procedures live in
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`RELEASING.md`](RELEASING.md).

If an agent performs repository work, require it to read
[`AGENTS.md`](AGENTS.md) first. That file defines agent-specific skill and
documentation requirements; this file defines the maintainer policy the agent
must follow.

## Pull-request and main operations

### Authority and trust

- A **trusted writer** has a current GitHub `write`, `maintain`, or `admin`
  role and is eligible to act as a `copy-pr-bot` vetter. Familiarity with an
  author does not establish this role.
- A trusted writer may authorize the exact head of their own reviewed pull
  request. Every other author, including an external contributor or a bot
  without that role, needs a trusted writer to review and authorize the exact
  head.
- `/ok to test` authorizes isolated candidate execution only. It grants no
  merge, release, secret, environment, or ruleset authority.
- Candidate jobs remain credential-free, non-publishing, and artifact-free
  regardless of who authored or authorized the change.
- Obtain explicit human merge authorization under repository policy for the
  exact pull-request head. Test authorization is not merge authorization.

### Classify the change

An **ordinary change** leaves protected CI and release policy unchanged. A
**protected-policy change** modifies `.github/workflows/**` or supporting
configuration or scripts that materialize a candidate, bind a pull request,
report `Required CI`, or control a release.

Review the complete base-to-head diff. Confirm that the head is rebased onto
its exact current base, its commits are linear, and each human-authored commit
is GitHub Verified and DCO-compliant. Route compatible work and every protected-
policy change to `main`. Route breaking or dependent next-line work only to an
advertised, protected `dev/MAJOR.MINOR.PATCH` coordination branch. Recheck after
the base, protected `main` policy, or head moves.

### Test an ordinary pull request

1. Record the full current head:

   ```shell
   gh pr view <PR-URL> --json headRefOid --jq .headRefOid
   ```

2. After reviewing that exact head, an eligible writer comments:

   ```text
   /ok to test <full-40-character-head-sha>
   ```

3. Wait for the App-owned `Required CI` check on that same SHA.
   NVIDIA Linux is authoritative; macOS and Windows are advisory.
4. If the PR head or `main` changes, rebase, review, and authorize the new
   exact head. Never reuse a stale command or verdict.

### Create and activate a coordination line

Landing coordination support does not activate a line. Use this procedure only
for a concrete approved next version, with one separately reviewed repository-
administrator activation packet and explicit authorization for its exact
objects and settings. The activation version is an unpublished `rc.0`
placeholder; release preparation remains main-only.

1. Select exactly one unused `dev/MAJOR.MINOR.PATCH` line. Record exact
   current `main`, the full coordination and
   `refs/heads/rollback/dev/MAJOR.MINOR.PATCH` refs, active runs, and complete
   branch and tag rulesets. Require both new refs to be absent.
2. Prepare one signed, DCO-compliant activation commit from exact `main`.
   The bounded xtask selects the non-release `${target}-rc.0` safety stub and
   accepts only the manifest change. Release-plz first participates after
   promotion when a maintainer prepares an actual release:

   ```shell
   target=MAJOR.MINOR.PATCH
   git fetch origin main --tags
   main_sha="$(git rev-parse origin/main)"
   git switch --detach "${main_sha}"
   git switch --create "activate-${target}"
   cargo xtask release activate --version "${target}"
   cargo xtask ci
   test -f Cargo.lock
   test ! -L Cargo.lock
   rm -- Cargo.lock
   git diff --check
   git diff -- Cargo.toml
   git add Cargo.toml
   git commit -S --signoff -m "chore: activate dev/${target}"
   git verify-commit HEAD
   activation_sha="$(git rev-parse HEAD)"
   test "$(git rev-parse "${activation_sha}^")" = "${main_sha}"
   ```

   Stop if any path except `Cargo.toml` changes or validation fails. This
   commit must not be tagged, released, published, or reused for another
   target.
3. Before ref creation, prepare, authorize, apply, and read back the exact
   coordination and rollback protection payloads, required context
   `Required CI [refs/heads/dev/MAJOR.MINOR.PATCH]`, any minimum creation-only
   exception, and unconditional restoration/readback. The rules must retain
   non-fast-forward and deletion protection, exclude rollback from CI, and
   grant no release, environment, App-token, or publication path.
4. Bind creation to the exact activation commit and an absent destination:

   ```shell
   repository=NVIDIA/yaml-sigil-traits
   line="dev/${target}"
   destination="refs/heads/${line}"
   rollback="refs/heads/rollback/${line}"
   test "$(gh api "repos/${repository}/git/ref/heads/main" \
     --jq .object.sha)" = "${main_sha}"
   test -z "$(git ls-remote origin "${destination}" "${rollback}")"
   git merge-base --is-ancestor "${main_sha}" "${activation_sha}"
   git push --force-with-lease="${destination}:" \
     origin "${activation_sha}:${destination}"
   test "$(gh api "repos/${repository}/git/ref/heads/${line}" \
     --jq .object.sha)" = "${activation_sha}"
   ```

   The empty expected value in the exact lease is an absent-ref compare-and-
   swap guard. It does not authorize a rewrite or a generic force push. Never
   retry an ambiguous push; read the ref and stop on any value other than the
   exact proposed SHA.
5. In the same serialized window, reread the new ref and unconditionally
   remove any creation-only exception. Digest-compare the complete protected
   state with the reviewed target and prove tag protection unchanged.
6. Require the automatic coordination-ref CI at the exact activation SHA to
   succeed, including advisory hosts, with zero artifacts, deployments, tags,
   Releases, or publication effects. Advertise the full ref as a pull-request
   base only after every check and settings readback is exact. Keep the rollback
   ref absent until the first authorized synchronization.

### Test a coordination-line pull request

Use this only after a `dev/MAJOR.MINOR.PATCH` base has been explicitly
activated, advertised, and protected. Landing this runbook or its workflow
support does not activate a line.

1. Record the full current protected-policy, contribution-base, and candidate
   objects:

   ```shell
   gh api repos/NVIDIA/yaml-sigil-traits/git/ref/heads/main --jq .object.sha
   gh api repos/NVIDIA/yaml-sigil-traits/git/ref/heads/dev/MAJOR.MINOR.PATCH \
     --jq .object.sha
   gh pr view <PR-URL> --json baseRefName,baseRefOid,headRefOid
   ```

2. Require the pull request to target the recorded coordination ref and its
   base SHA. Require its workflow and root Cargo configuration to match exact
   protected `main`; the coordination line cannot admit its own policy.
3. Review the exact head, then use the same `/ok to test <HEAD-SHA>` command.
4. Require App-owned
   `Required CI [refs/heads/dev/MAJOR.MINOR.PATCH]` on that exact head. The
   ordinary `Required CI` context and a result for another line do not count.
5. Immediately before integration, reread all three objects, the open pull
   request, reviews, and the exact required context. Any movement requires a
   fresh rebase, review, and test. Use default squash until the line's optional
   writer-preserved intake procedure has separately passed its readiness test.

After source integration, require the secretless coordination-branch Linux
result, inspect advisory hosts, and require zero retained artifacts. No
coordination ref may trigger publication, a protected environment, App-token
minting, or a tag or Release mutation.

### Integrate a coordination-line pull request

Use the default squash procedure below unless the repository has separately
proved and enabled writer-preserved intake for the active line. For either
method, re-read protected `main`, the coordination ref, the pull request, and
the exact base-specific required check immediately before integration.

Writer-preserved intake is available only when the pull-request author is a
current trusted writer and explicit authorization covers the exact pull
request, destination, old object, new object, and retained commit series.
Every retained commit must be linear, GitHub Verified, DCO-compliant, and
intentionally distinct.

1. Record `OLD-SHA` from the live coordination ref and `NEW-SHA` from the
   current pull-request head. Require the pull-request base SHA to equal
   `OLD-SHA`, then prove a fast-forward:

   ```shell
   git merge-base --is-ancestor <OLD-SHA> <NEW-SHA>
   ```

2. Capture and digest all applicable branch and tag protection. Keep an
   independent no-bypass non-fast-forward rule effective. Prepare exact
   restoration before any temporary PR-admission exception.
3. Re-read every bound object, then update only the full coordination ref:

   ```shell
   destination=refs/heads/<LINE>
   git push --force-with-lease="${destination}:<OLD-SHA>" \
     origin "<NEW-SHA>:${destination}"
   ```

   The exact lease is a stale-ref compare-and-swap guard, not permission to
   rewrite history. Never use a generic force option or retry an ambiguous
   update.
4. Restore protection before interpreting the update. Read back the ref,
   terminal pull-request association, retained commits, signatures, DCO,
   branch CI, artifacts, deployments, and unchanged tag protection.

### Synchronize a coordination line

Synchronization rebases the complete next-line series onto current `main`.
It is a separately authorized coordinator operation, not contributor intake.

1. Pause intake. Record exact `main`, coordination, previous-main-base, and
   rollback objects plus complete applicable rules and active runs.
2. On the first synchronization, create the rollback ref only if it is absent:

   ```shell
   rollback=refs/heads/rollback/<LINE>
   git push --force-with-lease="${rollback}:" \
     origin "<OLD-LINE-SHA>:${rollback}"
   ```

   On every later synchronization, bind its movement to the old rollback SHA:

   ```shell
   rollback=refs/heads/rollback/<LINE>
   git push --force-with-lease="${rollback}:<OLD-ROLLBACK-SHA>" \
     origin "<OLD-LINE-SHA>:${rollback}"
   ```

   Run exactly one form and read the rollback ref back. Never use a generic
   force option. If live protection requires a one-operation maintenance
   exception, restore and digest-compare it before starting the local rebase.
3. In a clean isolated worktree, rebase only the recorded series. Preserve
   each original author and DCO trailer; make the authorized coordinator the
   committer and verified signer. First require the recorded previous-main
   object to be an ancestor of both current `main` and the old line, and reject
   merge commits in the line range. Account for every old and new commit and
   logical patch, including empty or equivalent commits, then run the complete
   local gate:

   ```shell
   previous_main_sha=<PREVIOUS-MAIN-SHA>
   main_sha=<MAIN-SHA>
   old_line_sha=<OLD-LINE-SHA>
   git merge-base --is-ancestor "${previous_main_sha}" "${main_sha}"
   git merge-base --is-ancestor "${previous_main_sha}" "${old_line_sha}"
   test -z "$(git rev-list --min-parents=2 \
     "${previous_main_sha}..${old_line_sha}")"
   git switch --detach "${old_line_sha}"
   git -c core.hooksPath=/dev/null rebase -S \
     --reapply-cherry-picks --empty=ask \
     --onto "${main_sha}" "${previous_main_sha}"
   new_line_sha="$(git rev-parse HEAD)"
   cargo xtask ci
   ```

   An empty-commit stop requires explicit reconciliation; never silently skip
   it or continue with an unaccounted series.
4. Under the separately reviewed synchronization exception, replace only the
   coordination ref with the exact old-head lease:

   ```shell
   destination=refs/heads/<LINE>
   git push --force-with-lease="${destination}:<OLD-LINE-SHA>" \
     origin "${new_line_sha}:${destination}"
   ```

   Immediately beforehand, require live `main`, coordination, and rollback to
   equal the recorded objects. Never update `main` in this step. Restore and
   read back protection before interpreting an ambiguous result.
5. Require fresh coordination-ref CI with zero artifacts or privileged effects,
   refresh affected pull requests, and only then resume intake.

### Close and promote a coordination line

1. Freeze the line, remove unready work through review, finish migration
   guidance, replace temporary dependencies, and complete one final
   synchronization.
2. Open exactly one cumulative pull request from the coordination ref to
   `main`. Record its exact base and head and the exhaustive ordered provenance
   for every retained source-derived and coordinator-created commit. Compare
   the frozen line with the rolling rollback ref and explicitly record every
   intentionally removed or superseded old-line commit. The protected verifier
   proves the final series and each named source pull request; it does not infer
   source pull requests that human review omitted.
3. Run authorized candidate testing, then invoke only the protected-current-
   `main` promotion verifier. Require its App-owned `Required CI` result on the
   exact promotion head. An ordinary source-PR verdict does not count.
4. After explicit promotion authorization, pause both refs and re-read every
   bound object and protection payload. Prove `main` is an ancestor of the
   promotion head, then use the proved protected-main exact-history transaction
   with the exact old-`main` lease. Do not use the Web UI merge button or
   squash the promotion.
5. Restore protection before interpreting the update. Require exact retained
   history and terminal promotion-PR association, current-main CI, unchanged
   tag protection, zero artifacts and deployments, and no tag, Release, or
   publication effect. Promotion is not release authorization.

#### Prepare and dispatch promotion evidence

Keep the manifest outside the repository; it is per-run evidence, not project
configuration. Record every value from a fresh GitHub readback. `policy_sha`
and `base_sha` are the same exact live `main` object, `head_sha` is both the
live coordination ref and cumulative pull-request head, and the run ID and
attempt identify its successful authorized candidate run.

For every final-series commit, fetch the exact GitHub diff and compute the
whitespace-sensitive ID used by protected policy:

```shell
repository="NVIDIA/yaml-sigil-traits"
commit_sha="FULL_40_CHARACTER_COMMIT_SHA"
diff_file="$(mktemp)"
gh api -H "Accept: application/vnd.github.diff" \
  "repos/${repository}/commits/${commit_sha}" > "${diff_file}"
git patch-id --verbatim < "${diff_file}"
```

Require exactly one output line. For a `source` entry, run this for both the
final-series `sha` and retained `original_sha` and require equal patch IDs.
Use the source PR's exact retained commit order. A squash intake names its
generated merge object; exact-history intake names every original PR commit.
For coordinator-created entries, list every changed path once in sorted order;
a rename or copy lists both its source and destination. Rust activation must be
one ordinary `Cargo.toml` modification, never a rename or copy into that path.

Write one JSON object with no additional fields, in final-series order:

```json
{
  "version": 1,
  "repository": "NVIDIA/<REPOSITORY>",
  "policy_sha": "<MAIN-SHA>",
  "promotion_pull": 123,
  "base_ref": "refs/heads/main",
  "base_sha": "<MAIN-SHA>",
  "head_sha": "<PROMOTION-HEAD-SHA>",
  "coordination_ref": "refs/heads/<LINE>",
  "candidate_run_id": 123456789,
  "candidate_run_attempt": 1,
  "coordinator": {"id": 12345, "login": "<LOGIN>"},
  "entries": [
    {
      "kind": "source",
      "sha": "<FINAL-SERIES-SHA>",
      "patch_id": "<VERBATIM-PATCH-ID>",
      "source_pull": 122,
      "original_sha": "<RETAINED-SOURCE-SHA>"
    },
    {
      "kind": "integration",
      "sha": "<COORDINATOR-COMMIT-SHA>",
      "patch_id": "<VERBATIM-PATCH-ID>",
      "paths": ["<FIRST-SORTED-PATH>", "<SECOND-SORTED-PATH>"]
    }
  ]
}
```

Specification promotions cannot contain `activation`. Rust promotions must
begin with exactly one `activation` entry whose sole path is `Cargo.toml`; its
shape otherwise matches `integration`. Confirm the file is valid and bounded,
then dispatch the protected workflow from `main`:

```shell
manifest_file="/absolute/path/to/promotion-manifest.json"
jq -e . "${manifest_file}"
wc -c < "${manifest_file}"
gh workflow run required-ci.yml --ref main \
  --field "manifest=@${manifest_file}"
```

Require fewer than 49,152 bytes and capture the returned run URL directly.
Never retry an ambiguous dispatch; locate and read back the single attempted
run instead. The `protected-automation` deployment proceeds automatically
under its main-only branch policy; bind it to the exact recorded policy SHA,
manifest, and run and require it to succeed. Require the resulting App-owned
check on the exact head and zero artifacts before the separately authorized
promotion.

### Retire, abandon, or restart a line

After the first accepted main-origin version for a promoted line, delete its
coordination and rollback refs through a separately authorized cleanup. To
abandon an unpromoted line, first stop intake and close or retarget its pull
requests. In either case, record both exact heads and use one exact lease per
existing ref. Treat an already absent rollback ref as clean:

```shell
git push --force-with-lease=refs/heads/<LINE>:<LINE-SHA> \
  origin :refs/heads/<LINE>
git push --force-with-lease=refs/heads/rollback/<LINE>:<ROLLBACK-SHA> \
  origin :refs/heads/rollback/<LINE>
```

Read back each ambiguous response instead of retrying. Remove line-specific
settings only after both refs are absent; restore and digest-compare every
temporary exception and prove tag protection unchanged. A never-promoted line
may restart only as a new activation from then-current `main`, after both old
refs are absent and all eligibility and review evidence is fresh. After
promotion, corrections use the ordinary reviewed `main` path. Do not create an
archive ref; the closed pull requests and existing commit history are the
durable record.

### Test a protected-policy change

The reporter deliberately rejects a candidate `ci.yml` that differs from
protected current `main`. Do not weaken that binding to make a proposal pass.

1. Complete the same exact-head review. Confirm the staging workflow has no
   publication, OIDC, protected environment, secret, cache-save, or retained
   artifact path.
2. A writer pushes the exact reviewed, current-with-`main` head
   without force to a new `ci-testing/<purpose>-<YYYYMMDD>` branch:

   ```shell
   git push origin <HEAD-SHA>:refs/heads/ci-testing/<purpose>-<YYYYMMDD>
   ```

3. Bind the trusted push run to that ref and SHA. Require authoritative CI to
   pass, inspect every advisory result, and require zero retained artifacts.
4. If `Required CI` can bind without using changed policy, use the ordinary
   merge path. Otherwise stop. Use the exceptional transaction below only
   after proving the changed policy or a platform outage caused the evaluation
   failure and equivalent exact-head validation passed.
5. After integration, verify the workflow from exact current `main`. If
   contributor admission changed, run one inert outside-account canary and
   close it without merging.
6. After the pull-request lifecycle and every bound run are terminal, read the
   exact `ci-testing/*` ref. Treat an already absent ref as clean. Otherwise,
   require it still equals the staged SHA before one deletion, then prove it
   is absent. Stop if the ref moved or the result is ambiguous.

For a release-policy change, also use the validation-only procedure in
`RELEASING.md`. Never exercise publication from `ci-testing/*`.

An external contributor cannot stage an upstream `ci-testing/*` ref. The
permitted maintainer may stage the contributor's exact reviewed commit; that
does not authorize integration.

### Merge an accepted, passing pull request

#### Default squash

1. Re-read the exact head and current base. Require the App-owned verdict for
   that exact base—`Required CI` for `main`, or the base-specific coordination
   context—plus resolved review threads, verified signatures, DCO, and explicit
   merge authorization.
2. Guard the merge against head drift:

   ```shell
   gh pr merge <PR-URL> --squash \
     --match-head-commit <HEAD-SHA>
   ```

   Clean up an owned upstream source branch only after verifying the merge
   outcome and rereading that ref at the exact reviewed SHA.
3. Verify the merge commit has one parent, its tree equals the reviewed head,
   GitHub marks it Verified, its DCO trailer is correct, and it is associated
   with the pull request.
4. Require CI success on the updated destination with zero retained artifacts. A
   `main` merge must also leave release qualification as a no-op unless it is
   the separately prepared release pull request.

#### Preserve exact commits

Default to squash. Preserve an exact commit series only when its author is a
current trusted writer, explicit human authorization covers the exact series,
and every retained commit is linear, GitHub Verified, DCO-compliant, and worth
preserving as a distinct change. This path remains a pull-request integration
operation; it does not authorize unrelated direct pushes or history rewrites.

1. Record the exact pull request, its current base and head, and the current
   `main` object as `OLD-SHA`. Require the base and `main` to equal `OLD-SHA`,
   the pull-request head to equal `NEW-SHA`, all threads to be resolved, and
   App-owned `Required CI` to have succeeded on `NEW-SHA`.
2. Prove locally that the proposed update is a fast-forward:

   ```shell
   git merge-base --is-ancestor <OLD-SHA> <NEW-SHA>
   ```

3. Require a separate active ruleset that targets only `main`, has no bypass
   actors, and independently enforces linear history plus deletion and
   non-fast-forward protection. Capture, canonicalize, and digest it, the
   complete `Protect main and require CI` ruleset, and every tag ruleset.
   Include each ruleset's target, enforcement, conditions, rules, and bypass
   actors. Prepare the exact admission-ruleset restoration payload, readback,
   and cleanup path before mutation.
4. Serialize repository mutations. Add only the authenticated maintainer as a
   temporary `User` bypass actor with `bypass_mode: always` to
   `Protect main and require CI`. Read back the complete ruleset and prove this
   is the only change. The independent history ruleset and tag rulesets remain
   unchanged.
5. Re-read the pull request, `main`, and the source branch. Stop on any drift.
   Bind the fast-forward to the recorded old object:

   ```shell
   git push \
     --force-with-lease=refs/heads/main:<OLD-SHA> \
     origin <NEW-SHA>:refs/heads/main
   ```

   This exact lease is only a stale-ref compare-and-swap guard. It never
   permits a non-fast-forward update; the independent server rule must reject
   one. Generic `--force-with-lease` and every retry of an ambiguous update are
   prohibited.
6. Restore the complete original admission ruleset unconditionally before
   interpreting the update. If restoration is ambiguous, read it back before
   another exact restoration attempt. Until the original digest is restored,
   stop unrelated repository mutations, but continue the prepared restoration,
   readback, and escalation path.
7. Read back `main`. Require it to equal `NEW-SHA`, verify every preserved
   commit and pull-request association, then require current-main CI success,
   an ordinary non-release Publish no-op, and zero retained artifacts or
   deployments. Prove the independent history-ruleset and tag-ruleset digests
   are unchanged.

Before first use and after changing this command, exercise the same lease
against a disposable local Git remote. Advance the destination after recording
the old object, then prove the push fails and leaves the destination unchanged.

### Merge with accepted failing checks

- Bind each failure to the exact head, run, and job.
- If the App-owned verdict required for the exact base succeeded and only a
  documented advisory check failed, obtain explicit acceptance of that failure
  and use the normal squash path.
- A candidate-caused required-verdict failure remains merge-blocking. The
  exceptional transaction is eligible only when exact evidence proves that
  the reviewed protected-policy change itself prevents the current check
  mechanism from evaluating it, or a platform outage prevents check creation,
  and equivalent exact-head authoritative validation passed.
- A failed or missing check without that causal evidence remains blocking.
  Never use the exception to accept candidate-caused failure or skip candidate
  validation.
- Never disable the required check, broaden a bypass, or admit an unreviewed
  head merely to make a pull request mergeable.

### Revert commits on main

#### Normal revert

1. Start a dedicated branch from exact current `main`.
2. Create a new cryptographically signed, DCO-compliant revert:

   ```shell
   git revert -S --signoff <COMMIT-SHA>
   ```

3. Push it, open a pull request, run ordinary exact-head testing, and
   squash-merge after explicit approval.
4. Verify current-main CI and zero retained artifacts.

#### Protected-policy or urgent revert

Validate a protected-policy revert on `ci-testing/*` first. If the affected
policy or an outage prevents `Required CI` from succeeding, use the
exceptional transaction and its SHA-guarded squash. Never directly update,
erase, or rewrite `main` for a revert.

### Exceptional protected-main transaction

Use this only for an explicitly authorized, fully reviewed head that the
normal required-check path cannot evaluate for one of the causes above. It
requires equivalent exact-head validation and repository-admin access, not an
organization-owner settings change.

1. Freeze the exact old `main`, target head, pull request, active runs, and
   every rule applicable to `main`. Prove every requirement except the named
   App check is satisfied. Canonicalize and digest the complete original
   `Protect main and require CI` payload, including its name, target,
   enforcement, conditions, rules, and bypass actors. Prepare its exact
   restoration payload before mutation. Also capture and digest every tag
   ruleset so the postflight can prove tag protection is unchanged.
2. Serialize this window against every other admission, merge, release, and
   settings mutation. Prepare the exact restoration command, readback, and
   escalation path, then establish a guaranteed cleanup/finally boundary for
   unconditional restoration before the first ruleset change. Restoration and
   its readback remain authorized until the original digest is confirmed.
3. Add only the authenticated maintainer as one temporary `User` bypass actor
   with `bypass_mode: pull_request`. Read back the complete ruleset and prove
   that this addition is the only change. Never alter tag rulesets.
4. Re-read `main` and the target head. Stop on drift.
5. Integrate one target through the narrowest mechanism. For squash, submit
   the administrative merge request with an exact-head guard:

   ```shell
   gh pr merge <PR-URL> --admin --squash \
     --match-head-commit <HEAD-SHA>
   ```

   Do not delete the branch in this command. After protection is restored,
   perform branch cleanup only as the separate exact-ref operation above.
   This transaction does not authorize a direct ref update or exact-history
   preservation.
6. Whether integration succeeds, fails, or returns ambiguously, restore the
   complete original ruleset before interpreting or retrying the result. Never
   retry an ambiguous integration update. After an ambiguous restoration,
   perform authoritative readback before another restoration attempt. If the
   original digest is absent, stop every unrelated repository mutation and
   continue only exact restoration, readback, and escalation until the
   original digest is confirmed.
7. Only after restoration is confirmed, read and interpret the integration
   state. Verify the tree, ancestry, signature, DCO, pull-request association,
   current-main CI, zero artifacts, and unchanged tag-ruleset digests when
   integration succeeded.

The temporary bypass must never bypass another unsatisfied rule.

## Commit messages

Use Conventional Commits for every commit. Format the subject as
`<type>(<optional scope>): <description>`, keep it under 72 characters, and
choose the smallest accurate type. Follow the sign-off requirements in
`CONTRIBUTING.md`.

## Repository development guidance

Repository scope, commands, documentation and style, third-party material
and attribution, coordinated Buf upgrades, and other working guidance remain
in [`AGENTS.md`](AGENTS.md). Agents performing maintainer operations must
read both files completely.

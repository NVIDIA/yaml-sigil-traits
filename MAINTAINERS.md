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

Direct updates to `main` are not a general pull-request integration method.
Use the default squash path. An exact-history operation requires its own
separately landed, operation-specific policy and runbook; explicit
authorization alone does not create that path.

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

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
current `main`, its commits are linear, and each human-authored commit is
GitHub Verified and DCO-compliant. Recheck after either `main` or the head
moves.

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

1. Re-read the exact head and current base. Require App-owned `Required CI`
   success, resolved review threads, verified signatures, DCO, and explicit
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
4. Require current-main CI success with zero retained artifacts.

#### Preserve exact commits

Normal integration is squash-only. Preserve commit SHAs only with explicit
authorization and when every commit in the exact linear range is signed and
DCO-compliant. Use the exceptional transaction and make one non-force
fast-forward:

```shell
git push origin <HEAD-SHA>:refs/heads/main
```

Verify the ancestry and pull-request association afterward. Never force-push
`main` for this operation.

### Merge with accepted failing checks

- Bind each failure to the exact head, run, and job.
- If App-owned `Required CI` succeeded and only a documented advisory check
  failed, obtain explicit acceptance of that failure and use the normal squash
  path.
- A candidate-caused `Required CI` failure remains merge-blocking. The
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
exceptional transaction. Preserve the signed revert commit by direct
fast-forward only when explicitly required. Never erase or rewrite reverted
history.

### Exceptional protected-main transaction

Use this only for an explicitly authorized, fully reviewed head that the
normal required-check path cannot evaluate for one of the causes above. It
requires equivalent exact-head validation and repository-admin access, not an
organization-owner settings change.

1. Freeze the exact old `main`, target head, pull request, active runs, and
   every rule applicable to `main`. Prove every requirement except the named
   App check is satisfied. Prepare and digest the complete
   `Protect main and require CI` ruleset's original canonical payload and exact
   restoration payload before mutation. Preserve every unrelated field and
   existing bypass actor.
2. Serialize this window against every other admission, merge, release, and
   settings mutation. Establish a guaranteed cleanup/finally boundary for
   unconditional restoration before the first ruleset change.
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
   Exact-history preservation is a separate exceptional transaction. It
   requires its own explicit authorization for a temporary `User` bypass with
   `bypass_mode: always`, the exact non-force `main` update, and the same
   unconditional restoration. Never reuse or broaden the pull-request-only
   bypass payload.
6. Whether integration succeeds, fails, or returns ambiguously, restore the
   complete original ruleset before interpreting or retrying the result. Prove
   restoration by authoritative readback and canonical digest. If restoration
   cannot be proven, stop every repository mutation and escalate.
7. After restoration, read the integration state. Do not retry an ambiguous
   result blindly. Verify the tree, ancestry, signature, DCO, PR association,
   current-main CI, and zero artifacts when integration succeeded.

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

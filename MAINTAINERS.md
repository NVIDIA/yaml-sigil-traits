# Maintainer guide

<!-- Inert candidate admission check; close this pull request without merging. -->

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

Review the complete base-to-head diff. Before authorizing an externally
authored head, review every executable input, including workflow files and
helpers, `build.rs`, procedural-macro and build dependencies, xtask code,
Cargo configuration, aliases and wrappers, and test setup. Confirm that the
head is rebased onto its exact current base, its commits are linear, and each
human-authored commit is DCO-compliant. Ordinary contributor commits need not
be cryptographically signed. Route compatible work and every protected-policy
change to `main`.
Route breaking or dependent next-line work only to an advertised, protected
`dev/MAJOR.MINOR.PATCH` coordination branch. Recheck after the base, protected
`main` policy, or head moves.

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

Release preparation can advance an unchanged `rc.N` to its immediate successor
on the same version core. Pinned release-plz applies that explicit selection
after `update`; follow `RELEASING.md` for the normal source checks and approvals.

### Maintain dependency license exceptions

Review the resolved dependency's license terms before changing an exception.
Keep each exception scoped to its intended crate, license, and version range,
and explain its purpose and scope in an adjacent Cargo Deny configuration
comment. After dependency or policy changes, run the documented Cargo Deny
checks for every affected dependency graph.

### Diagnose copied-ref binding failures

The anonymous binder reports the failed endpoint, HTTP status, request ID,
validated rate-limit headers, and retry attempt before candidate checkout.
Recognized rate limits and transient server errors receive at most three
complete binding attempts within two minutes, including requests and waits.
Each request is capped at 30 seconds or the remaining budget. Retries honor
server delays; otherwise secondary limits wait 60 seconds with exponential
backoff, and transient server errors wait one then two seconds. Every retry
rereads all binding metadata against the originally supplied head and policy.
Ordinary forbidden responses, invalid metadata, and stale bindings fail closed.

If a quota reset exceeds the budget, wait until the reported reset time, then
recheck the current head and `main` before authorizing another run. A primary
limit without a valid reset time fails without guessing. Error bodies and
arbitrary headers are not logged. These diagnostics distinguish rate limiting
from other forbidden responses; HTTP 403 alone does not establish the cause.

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

The shared candidate binder emits `promotion_branch` only for
`yaml-sigil-rs`, whose content-based release guard needs the separate
coordination-stub check. It is empty here; the traits release-path validator
and this repository's promotion procedure remain independent.

1. Freeze the line, remove unready work through review, finish migration
   guidance, replace temporary dependencies, and complete one final
   synchronization.
2. Open exactly one cumulative pull request from the coordination ref to
   `main`. Record its exact base and head, then review the complete aggregate
   diff, resulting tree, and ordered linear series. Account for retained source
   work, coordinator changes, and every removed or superseded old-line commit.
3. Compare the cumulative head's `.github/workflows/ci.yml`,
   `ci-trusted.yml`, and `ci-candidate.yml` with exact protected current
   `main`. If all three are byte-identical, review and authorize that head
   through `/ok to test <FULL-40-CHARACTER-HEAD-SHA>`. Require the automatic
   App-owned `Required CI` result for that exact head and current `main` base.
   That verdict validates candidate execution under the existing protected
   reporter; it does not empirically validate a reporter change proposed by
   the head. If any of those files differs, use the staging procedure in
   [Test a protected-policy change](#test-a-protected-policy-change);
   do not manufacture a promotion App check.
4. Treat either form of exact-head validation only as test evidence. It does
   not authenticate provenance or authorize promotion. If changed policy
   prevents the normal App check, proceed only through the separately
   authorized exceptional exact-history and protection transaction.
5. Independently verify the exact `main`, line, and pull-request objects; the
   complete linear signed and DCO-compliant series; source and synchronization
   provenance; the aggregate diff and tree; current branch and tag protection;
   zero artifacts and deployments; and no publication effect. After explicit
   promotion authorization, pause both refs and prove that `main` is an
   ancestor of the promotion head.
6. Use the proved protected-main exact-history transaction with the exact old-
   `main` lease. Do not use the Web UI merge button or squash the promotion.
   Restore and digest-compare protection before interpreting an ambiguous
   update, and never retry that update.
7. Read back the exact retained history and terminal pull-request association,
   current-main CI, unchanged tag protection, zero artifacts and deployments,
   and no tag, Release, or publication effect. Promotion is not release
   authorization.

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

Choose the test path from the exact reviewed workflow. Ordinary copied-ref
CI requires `.github/workflows/ci.yml`, `ci-trusted.yml`, and
`ci-candidate.yml` to match current `main`. Keep that equality guard intact.
If the workflows are unchanged, use the ordinary exact-head `/ok to test`
path. Its verdict exercises existing protected policy;
a reporter change still needs focused tests and an inert current-main canary
after integration before the new reporter is considered operational.

The `CI` workflow selects one local reusable workflow before expanding jobs.
`Trusted CI` runs main, coordination/support where supported, and staging
checks; `Candidate CI` runs explicitly admitted copied refs. The inactive
route has a static skipped name. The trusted `Linux result` aggregate requires
all authoritative policy and Linux jobs. Copied refs retain their policy/base
attestation under `Candidate CI / Candidate CI (Linux)`. macOS and Windows
remain advisory where present; the specification repository is Linux-only.
The tool-pin source check validates both local callees independently.

For changed workflow policy, use the separate maintainer staging route:

1. Review the complete exact-head executable input set and require an open PR
   targeting `main`, with a linear, DCO-compliant series rebased onto current
   `main`. Confirm the staging workflow has no publication, OIDC, protected
   environment, secret, cache-save, or retained-artifact path. Review every
   authoritative Linux check and the aggregate named `Trusted CI / Linux result`.
   That aggregate must fail unless all authoritative checks pass; advisory
   platforms do not control its result.
2. A writer permitted by the live `ci-testing/*` rules pushes the reviewed
   head without force to a new canonical ref. Use the decimal PR number and
   full lowercase 40-character head SHA in both positions:

   ```shell
   git push origin <HEAD-SHA>:refs/heads/ci-testing/pr-<PR-NUMBER>-<HEAD-SHA>
   ```

   This push is exact-head test authorization, not merge authorization. A
   changed head requires fresh review and a new ref. An external contributor
   cannot perform this upstream staging operation; an eligible maintainer may
   stage the contributor's reviewed head.
3. Wait for automatic App-owned `Required CI` on that head and inspect advisory
   results. The protected-main reporter authenticates the original pushing
   user's current write permission, exact PR/ref/head, current-main parent
   chain, CI workflow and attempt, unique Linux aggregate and zero artifacts.
   It repeats mutable checks before writing. Staging may exercise changed
   workflow bytes; ordinary copied refs still require protected blob equality.
4. Use the ordinary passing-PR merge procedure after the required verdict and
   merge review succeed. Other `ci-testing/*` names supply test evidence only.
   A missing or rejected verdict remains blocking; inspect the reporter's
   diagnostic and refresh stale bindings instead of manually creating a check.
   A workflow without the expected aggregate cannot qualify automatically.
   The exceptional procedure remains limited to its separately authorized
   mechanism-failure or outage cases.
5. After integration, verify exact current-main CI. If contributor admission
   changed, run one inert outside-account canary and close it without merging.
6. Once the PR and every bound run are terminal, read the staging ref and its
   live deletion rules. Treat an absent ref as clean. Otherwise require the
   reviewed SHA before one separately authorized deletion and absence proof.
   Stop on ref drift, a blocked deletion, or an ambiguous response.

For a release-policy change, also use the validation-only procedure in
`RELEASING.md`. Never exercise publication from `ci-testing/*`. Review release-provenance
comparisons as exact Git path/blob identity checks. They may inspect only the
reviewed inventory and Git object identities; workflow syntax and semantics
remain in hosted policy tooling. A support-line activation still requires its
own eligible stable release and separately authorized protection transaction.

### Merge an accepted, passing pull request

#### Default squash

1. Re-read the exact head and current base. Require the App-owned verdict for
   that exact base—`Required CI` for `main`, or the base-specific coordination
   context—plus resolved review threads, DCO, and explicit merge authorization.
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

## Support readiness commands

Release procedures pass a canonical `--base-ref` explicitly, including every
detached CI checkout. Use `refs/heads/main` for the current release path.
`release prepare` and `release check` also understand `refs/heads/support/M.N`;
the support version must stay on that line. The selected base controls the
preparation starting point and release transaction checks.

From exact clean current `main`, with a read-only GitHub token supplied through
`GH_TOKEN`, inspect a future activation proposal with:

```shell
cargo xtask github release start-support \
  --repository NVIDIA/yaml-sigil-traits --version MAJOR.MINOR.PATCH
```

The command requires the line's latest stable release, verifies its annotated
App tags and exact non-yanked source archives, and proves that a later stable
version was published from main outside the line. A release candidate does not
establish eligibility. It refuses an existing support ref or inventory and
prints the absent-ref push plus `.github/support-lines/M.N.json` for review.
The enumerated seed is `.github/support-policy-paths.txt`; maintain it when
load-bearing release policy gains a file. Inventories exclude themselves.

This readiness command applies no settings, creates no refs, and publishes
nothing. Opening a line still requires the separately reviewed protection and
activation transaction. The workflow admits an activated support line only
through a dispatch on protected main; a support push runs CI without publication.

## Latest selection during finalization

The finalizer reads GitHub's current Latest release before creating a Release
and sends `make_latest` explicitly. Stable main releases advance Latest;
prereleases and support releases preserve it. Recovery of an older main
version also preserves it, while recovery of a newer stable main version
advances it. The decision precedes the write and is verified through the
`releases/latest` endpoint afterward. Existing immutable Releases are retained.

If Latest moves between qualification and creation, stop and requalify. If
readback differs from the intended outcome, inspect the exact existing tags,
Releases, and Latest selection before retrying. Never recreate an immutable
Release to change its Latest status. Publication remains serialized across
the repository.

## Review support-line contributions

After a line is separately activated and advertised, its PR base may be the
canonical `support/M.N`, with each component between 0 and 999999999 and no
leading zeros. Protected current main still supplies candidate policy. Bind
the exact main policy, support-base SHA, and reviewed head, then require the
App-owned `Required CI [refs/heads/support/M.N]` result for that same triple.
A main or another line's check does not qualify the head.

Ordinary backports use the existing candidate path. A same-repository
`release-plz-manual-VERSION` branch may target support only when its version's
major and minor match the base. Detached validation receives that exact base
explicitly; release paths and package validators retain their repository's
existing boundaries. Support admission creates no publication authority and
activates no support ref or ruleset.

### Maintain support provenance and recover an interrupted release

Review `.github/support-lines/M.N.json` on protected main and on the support
line. It records schema version `1`, the full `base_ref`, immutable `anchor`,
historical main `policy_commit`, explicit `enforce` state, and a `blobs` object
mapping reviewed paths to full Git blob IDs. Exclude the inventory itself.
Current main selects the active line, anchor, and required path set. Initial
activation uses the reviewed `.github/support-policy-paths.txt` seed; later
path-set or enforcement changes require an explicit main policy review.

After a protected-policy change, backport the required files and update the
support inventory to name the exact main commit and its actual blob IDs.
Fresh qualification checks the complete historical chain as well as current
main equality, so current files cannot conceal stale inventory metadata. A
line explicitly retired from current-content enforcement still needs a valid
historical source inventory and protected lineage. Never change its anchor.

Recovery uses the original source even when the support tip has advanced. It
requires published source-package evidence, exact release-PR binding, valid
historical inventory, and any existing deterministic annotated tags and
immutable Releases. It does not require the old source to match newer main
content. The support run ID and attempt are audit context only; main recovery
retains its original push-run validation. Every recovery requires a fresh
dispatch and the existing applicable environment approvals.

Zero-package recovery is rejected. Start a fresh release from the current tip
when nothing was published. Partial crate publication must be a dependency-
ordered prefix with no forge objects; all crates must be public before any
tag or Release can exist. A Release without its exact retained tag, a
conflicting tag, or a mismatched source archive requires investigation rather
than replacement. The one-crate traits repository has no nonempty partial
crate prefix.

The workflow calls `github release rebind-policy` with explicit base, source,
version, and fresh/recovery operation before publication authority and before
minting the finalizer token. It fetches anonymously, reads no workflow bytes,
and checks exact separate clean roots. The finalizer repeats the live lineage
and policy check at each mutation boundary. These controls do not authorize
support activation or publication by themselves.

## Dispatch an activated support release

Support push CI is nonpublishing. After the exact release PR has passed its
base-specific required check and received human integration approval, verify
the resulting support squash has the reviewed tree, sole expected parent,
Verified signature, DCO, and exact PR association. Run the same preparation,
source check, and read-only release-plz acceptance procedure in
[`RELEASING.md`](RELEASING.md), selecting the support base explicitly.

Dispatch `publish.yml` on `main` with `operation=validate`, `base_ref`, and the
exact selected tip before publication. This operation skips every mutation job.
For an authorized fresh release, dispatch `operation=release` with that same
base and source and its exact `version`. Main releases retain automatic
qualification after their release PR squash; `release` dispatch is support-only.

Recovery always uses a fresh main dispatch with `operation=recover`, the
original base, source, version, run ID, and attempt. It never substitutes the
current support tip. A support recovery must already have published source
packages; original-run coordinates provide audit context. Main recovery still
validates its original main-push run.

The protected-main input binder rejects noncanonical bases, source IDs,
versions, and invalid operation combinations before source checkout. Typed
qualification proves the selected source and inventory. Requalification after
approval, anonymous policy rebind, registry confirmation, and finalization
retain the same base/source/version/operation. A changed main policy requires
a new dispatch. All privileged jobs and existing environments remain main-only,
and publication is serialized across the whole repository. Each recovery
receives fresh applicable environment approvals; an older approval is not reused.

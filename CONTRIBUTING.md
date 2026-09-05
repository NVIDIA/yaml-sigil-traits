# Contributing to yaml-sigil-traits

`yaml-sigil-traits` is developed agent-first. Use agents to explore the trait
and DTO contract, compare it to the pinned specification, and draft changes,
then review the result as the responsible author before submitting it.

## The Critical Rule

**You must understand your code.** AI-assisted contributions are welcome, but
you must be able to explain what changed, why it changed, and how it affects the
public trait and DTO contract. Do not submit generated code, tests, or
documentation that you cannot defend without the agent open.

## AI Usage

`yaml-sigil-traits` is agent-first, not agent-only.

- **Do** use agents to read the crate, compare specification vocabulary, run
  checks, generate drafts, and iterate on implementations.
- **Do** use the skills in `.agents/skills/`; they capture repository-specific
  workflows for spec pin updates and trait contract review.
- **Do** question the agent until you understand the compatibility impact, edge
  cases, and downstream implementation impact of your change.
- **Do not** submit changes you cannot explain in your own words.
- **Do not** use agents as a substitute for reading the relevant code, specs,
  and maintainer guidance.

## Declare release impact

Use an accurate Conventional Commit type and breaking-change marker when the
change establishes its release impact. Do not edit the package version on an
ordinary feature or fix branch. A maintainer selects the exact release version
and prepares the separate `release-plz-manual-<version>` pull request described
in `RELEASING.md`.

## Pull-request CI

The repository writer reviews the latest pull-request head and comments
`/ok to test <full-40-character-head-sha>`. The copy bot runs only that exact
head on a `pull-request/<number>` branch. Every new head needs another review
and exact-head command.

Candidate jobs have no repository credential, secret, OIDC permission,
protected environment, cache-save path, or retained artifact. NVIDIA Linux is
authoritative. They stage fixed validation tools before checkout, run static
policy checks before candidate code, and make candidate executable work the
terminal phase. GitHub-hosted macOS and Windows jobs are advisory. A separate
checkout-free protected reporter binds the completed run, attempt, repository,
open pull request, copied ref, current head, authoritative Linux result, and
zero-artifact count. A required reviewer then approves that exact reporter's
`protected-automation` deployment before the repository App creates
`Required CI`. Contributor admission therefore has two human gates, both of
which must be proven by a controlled canary before external contributor
execution is enabled. A changed head or run requires fresh authorization.

Every human-authored pull-request commit must form a linear history from
current `main`, be GitHub Verified, and contain a `Signed-off-by` trailer that
exactly matches its Git author. The contributor's fork branch remains the
pull-request head; a writer's command authorizes testing only and does not
authorize integration.

Before final authorization, fetch current upstream `main`, rebase the original
contributor branch with `git rebase --gpg-sign <upstream>/main`, and push the
rewritten branch back to the same fork with `--force-with-lease`. Confirm every
rewritten commit is GitHub Verified and DCO-compliant, then request testing for
the new exact SHA. Do not copy the contribution onto a repository-owned branch
merely to run CI.

#### Signing Off Your Work

* We require that all contributors "sign-off" on their commits. This certifies that the contribution is your original work, or you have rights to submit it under the same license, or a compatible license.

  * Any contribution which contains commits that are not Signed-Off will not be accepted.

* To sign off on a commit you simply use the `--signoff` (or `-s`) option when committing your changes:
  ```bash
  $ git commit -s -m "Add cool feature."
  ```
  This will append the following to your commit message:
  ```
  Signed-off-by: Your Name <your@email.com>
  ```

* Full text of the DCO (https://developercertificate.org/):

  ```
    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
  ```

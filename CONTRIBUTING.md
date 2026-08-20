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

## Express release-version intent

Use an accurate Conventional Commit type and breaking-change marker when the
change itself establishes its release impact. Do not edit the package version
on an ordinary feature or fix branch. The release-proposal workflow calculates
and commits release versions on its dedicated `release-plz-*` branch.

When the required `major`, `minor`, or `patch` advance is not discoverable from
the commits, state the intended impact in the contribution pull request. A
repository writer can dispatch the `Release proposal` workflow with
`next-candidate` and the matching bump override. The workflow records an
explicit override in the release pull request so later updates preserve it.
Dispatch `auto` to clear that override and return to automatic calculation.

When the release-proposal GitHub App is unavailable or cannot safely update its
owned branch, repository writers use the permanent manual release-proposal
fallback in `RELEASING.md`. Contributors still express version intent here and
do not edit versions on their change branches.

Pull-request snapshot publication does not change the contributor's branch.
The workflow applies its `0.pr` version only in an ephemeral checkout.

## Pull-request CI

Pull-request CI runs from a repository-owned `pull-request/<number>` branch at
the exact latest pull-request head. Do not push to these branches. Signed
commits from trusted organization members are copied automatically after the
pull request is ready for review; draft pull requests do not auto-sync.

If the copy bot requests validation, a maintainer must review the exact latest
head and comment `/ok to test <head-sha>`. Automated App-authored commits and
other untrusted heads require this SHA-bound approval. Every new untrusted head
requires a new review and comment. The copied branch reports checks to the
matching pull-request head and is removed when the pull request closes or
merges.

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

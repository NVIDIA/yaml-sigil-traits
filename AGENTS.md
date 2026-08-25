# AGENTS.md - yaml-sigil-traits

## Local Skill

Use `.agents/skills/yaml-sigil-traits-spec-update/SKILL.md` when updating the
pinned `yaml-sigil-spec` submodule or reconciling trait and DTO vocabulary after
YamlSigil specification changes.

## Agent Documentation Standards

Project-local skills exist under `.agents/skills/` and should remain
discoverable by agents working in this repository. Maintain those skills
according to the
[Agent Skills specification](https://agentskills.io/specification), and
maintain this file according to the
[AGENTS.md standard](https://agents.md/). Keep both portable across compatible
agent clients, without assumptions about user-specific paths or session state.

This repository is the standalone home for the `yaml-sigil-traits` crate.

## Commit messages

Use Conventional Commits for every commit. Format the subject as
`<type>(<optional scope>): <description>`, keep it under 72 characters, and
choose the smallest accurate type. Follow the sign-off requirements in
`CONTRIBUTING.md`.

## Scope

Keep this crate independent from the rest of the YamlSigil Rust implementation.
It may depend on crypto/error crates needed to type public DTOs, but it must not
depend on any crate delivered by the `yaml-sigil-rs` workspace.

The normative specification lives in `yaml-sigil-spec`. This crate mirrors
vocabulary from that spec but does not own it. Ordinary builds, docs.rs builds,
and published crates must not require a local spec checkout.

When the specification pin changes, use the
`.agents/skills/yaml-sigil-traits-spec-update` skill. Keep the update scoped to
this repository's public trait and DTO contract; do not add generated protobuf
dependencies, and do not coordinate downstream implementation updates from this
repo.

## Third-party material and attribution

`THIRD_PARTY_NOTICES.md` is the canonical attribution and redistribution
record for third-party standards material referenced or incorporated by this
crate. The pinned specification retains its complete, separately scoped notice
at `source-spec/THIRD_PARTY_NOTICES.md`; treat that file and the rest of the
submodule as read-only.

When adding or changing third-party material:

- Update the root `THIRD_PARTY_NOTICES.md` in the same change. Record the exact
  source, version, section, copyright holder, applicable copying conditions,
  warranty disclaimer, and patent or other intellectual-property caveat.
- Read the source's own copyright notice and terms. For an RFC, check its
  publication stream and the BCP 78 or IETF Trust terms in effect on its
  publication date. Do not assume that RFC test data, tables, ABNF, or code
  blocks are IETF Code Components or covered by a BSD license.
- Ensure every file or other independently distributed material that mentions
  or references either SEC source identifies it by its full title:
  *Standards for Efficient Cryptography 1 (SEC 1)* or
  *Standards for Efficient Cryptography 2 (SEC 2)*. Use the full title on the
  first source reference in each file; the `SEC 1` and `SEC 2` short forms may
  follow within that file.
- Add a short provenance comment next to copied or derived constants,
  algorithms, encodings, or validation rules. State when identified
  third-party material is not covered by a file's Apache-2.0 declaration.
- Do not add standards text, test vectors, parameter tables, or generated
  specification artifacts to the crate merely because they exist in
  `source-spec/`. Keep normal builds and crate packages independent of the
  submodule.
- Preserve applicable non-endorsement language. Do not present this crate as
  an official publication of, or as affiliated with or endorsed by, a cited
  author, publisher, or standards organization.

Keep these instructions durable and repository-focused. Do not record private
correspondence, reviewer identities, or approval history in repository
documentation. A specification-pin update may leave the Rust contract
unchanged when the imported delta affects attribution only.

## Documentation Style Guide

These rules apply to Markdown files in this trait crate, including README files,
release notes, and documentation that explains the public trait and DTO
contract.
Use GitHub Flavored Markdown as the source dialect unless a file documents a
narrower renderer requirement.

Write like you are explaining the contract to a colleague. Be direct, specific,
and concise. Be accurate about which behavior belongs to this crate, the pinned
specification, or downstream implementations.

The Markdown dialect target is GitHub Flavored Markdown (GFM), as rendered by
GitHub repository views. Rely on GitHub's generated document outline for
navigation.

### Voice And Tone

- Use active voice. Write "`yaml-sigil-traits` defines the public signing
  contract." not "The public signing contract is defined by
  `yaml-sigil-traits`."
- Use second person, `you`, when addressing the reader.
- Use present tense. Write "The trait returns a verification error." not "The
  trait will return a verification error."
- State facts. Do not hedge with "simply," "just," "easily," or "of course."

### Things To Avoid

These patterns make technical documentation harder to read. Remove them during
review.

| Pattern | Problem | Fix |
|---------|---------|-----|
| Unnecessary bold | "This is a **critical** trait bound" on routine instructions. | Reserve bold for UI labels, parameter names, and genuine warnings. |
| Repeated em dashes | "The async trait -- which uses AFIT/RPITIT -- returns a `Send` future." | Use commas or split the sentence. Use em dashes sparingly. |
| Superlatives | "`yaml-sigil-traits` provides a powerful, robust, seamless API." | Say what the trait or DTO represents. |
| Hedge words | "Simply use `<S: AsyncSigner>`." | Write "Use `<S: AsyncSigner>`." |
| Emoji in prose | "Implement `Verifier`." with an emoji prefix. | Do not use emoji in documentation prose. |
| Rhetorical questions | "Want to verify trusted facts?" | State the purpose directly. |

### Formatting Rules

- Never add line breaks inside an *italic* or **bold** span. If you must wrap
  the text, start the formatting again on the next line.
- Never add line breaks inside `[markdown](links)`.
- End every sentence with a period.
- Use `code` formatting for CLI commands, file paths, flags, parameter names,
  crate names, trait names, DTO names, feature names, and literal values.
- Use `shell` code blocks for copyable CLI examples. Do not prefix commands
  with `$`.

  ```shell
  cargo test --all-features
  ```

- Use `text` code blocks for transcripts, log output, and examples that should
  not be copied verbatim.
- Use tables for structured comparisons. Keep tables simple and avoid nested
  formatting.
- Use GitHub Flavored Markdown alert notices for non-normative notes and
  implementation asides when the content benefits from a visible notice label.
  Supported labels are `> [!NOTE]`, `> [!TIP]`, `> [!IMPORTANT]`,
  `> [!WARNING]`, and `> [!CAUTION]`. Use plain Markdown blockquotes (`>`) for
  lower-emphasis asides. Do not use bold callouts or documentation-framework
  components this repository does not use.
- Use itemized bullet lists when the instructions clearly benefit from them.
- Do not number section titles. Write "Implement async signing" not "Step 2:
  Implement async signing."
- Do not use colons in titles. Write "Implement async signing" not "Traits:
  Implement async signing."
- Use colons only to introduce a list. Do not use colons as general-purpose
  punctuation between clauses.

### Repository-Specific Documentation Rules

- Write repository READMEs for human readers. Keep agent workflows and durable
  repository instructions in `AGENTS.md`.
- Use absolute links in READMEs packaged with published crates so the links work
  on crates.io and docs.rs.
- Prefer inline-code `yaml-sigil` in prose. Use “YAML Sigil” when code styling
  reads awkwardly.
- Reserve `YamlSigil` and `YamlSigil.v1alpha1` for code or exact identifiers.
- Usually omit the protocol version. When the version is necessary, write the
  lowercase inline-code form `v1alpha1`.
- Link other crates with inline-code names and absolute crates.io URLs.
- Explain behavior in ordinary language before introducing specification
  terminology.
- Keep documentation centered on public traits, DTOs, errors, feature flags,
  and compatibility guarantees.
- Mirror specification vocabulary when documenting spec-derived terms, but do
  not imply this crate owns the normative specification.
- Use generic trait-bound examples. Do not require any crate delivered by the
  `yaml-sigil-rs` workspace, generated protobuf code, or runtime transport
  dependencies in examples for this crate.

## Commands

Run the complete non-release CI validation sequence from the repository root:

```shell
cargo xtask ci
```

To apply the validator from the current checkout to another repository
checkout, pass its root explicitly:

```shell
cargo xtask ci --candidate-root PATH
```

The command still builds and runs the xtask from the current checkout; only
the repository content being validated comes from `PATH`.

The command runs these checks in order:

```shell
rumdl check .
cargo fmt --all --check
cargo fmt --manifest-path xtask/Cargo.toml --all --check
cargo xtask release-version check
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-traits
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --locked --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --locked --manifest-path xtask/Cargo.toml
cargo-machete --with-metadata
cargo audit
cargo audit --file xtask/Cargo.lock
```

Install `rumdl`, `cargo-audit`, and `cargo-machete` with Cargo before running
the wrapper:

```shell
cargo install rumdl
cargo install cargo-audit
cargo install --locked cargo-machete --version 0.9.2
```

Keep the cargo-machete version aligned with hosted CI. The
`--with-metadata` check resolves normal, development, and build dependency
names across all features, but remains an unused-dependency heuristic; retain
the all-target, all-feature Clippy and test checks as the compilation proof.

Treat `cargo xtask ci` as the provider-neutral local validation entry point.
Keep its command plan and this exact-command documentation aligned. Do not make
the xtask parse, include, or test configuration owned by a hosted CI provider.
Validate provider-specific workflow syntax and policy with provider-appropriate
tooling instead.

The only permitted provider-specific xtask namespace is
`cargo xtask github`. Keep it limited to typed, repository-owned GitHub
operations that consolidate release automation. It must not become an
arbitrary `gh api` passthrough or a replacement for actionlint. It must never
parse, embed, snapshot, or validate workflow YAML, triggers, job names,
permissions, secrets, expressions, Action pins, or historical workflow files.
Accept tokens only through environment variables; never log them, serialize
them into fixtures, or pass them as command-line arguments.

Within GitHub Actions, bind repository selection to GitHub's default
`GITHUB_ACTIONS` and `GITHUB_REPOSITORY` variables and require an exact match
with a compiled repository-policy table and the local package family. Do not
use the mutable `CI` variable or configurable environment values as a trust
switch. Local mutation commands must take an explicit repository and bind it
to that same table and checkout.

`cargo xtask ci` and every non-`github` command must remain provider-neutral
and credential-free. The checkout-free protected-PR reporter and controller
remain Python so that immutable protected-main policy can run without
compiling candidate Rust. Keep
`.github/scripts/check-pull-request-commits.sh` identical across the YamlSigil
repositories. Small host-setup helpers may remain shell when moving them would
add complexity without consolidating policy.

The surviving provider helpers have deliberately narrow roles:

- `protected_pr_ci.py` and `test_protected_pr_ci.py` keep protected-main
  authorization checkout-free and test that immutable policy without compiling
  candidate Rust.
- `check-pull-request-commits.sh` enforces the shared exact-range, linear
  history, and DCO policy across all three YamlSigil repositories.
- `resolve-source-spec-gitlink.sh` reads one candidate gitlink without loading
  candidate-controlled submodule configuration.
- `remove-preinstalled-aws-tap.sh` performs one bounded macOS host cleanup
  before Rust setup.

Release intent, proposal mutation, publication authorization, baseline
selection, proposal generation, and release-object reconciliation belong in
the Rust commands described above, not in additional Python or shell helpers.

Hosted CI should expose equivalent validation commands as independent steps
where practical. It may also add provider-specific policy checks that do not
belong in the local command sequence. Document intentional differences between
hosted and local validation.

Hosted CI runs the provider-neutral Rust and Cargo portion of this sequence on
NVIDIA's `linux-amd64-cpu8` runner and GitHub's moving `macos-latest` and
`windows-latest` labels. Every matrix leg checks formatting, release-version
validity, package contents, Clippy, tests, unused dependencies, and the
dependency audit against that platform's resolved dependency graph. Linux
commit-policy, Markdown, provider-workflow, and aggregation jobs run on
`linux-amd64-cpu4`. The local command does not launch other operating systems.

Validate shell scripts under `.github/scripts` with Shuck before landing
changes. Install it from the `shuck-cli` crate and run it from the repository
root:

```shell
cargo install shuck-cli
shuck check .github/scripts
```

ShellCheck is an acceptable fallback:

```shell
shellcheck .github/scripts/check-pull-request-commits.sh
```

Hosted CI runs its pinned ShellCheck Action for these provider-specific scripts.
Keep this validation outside `cargo xtask ci`.

Treat every hosted Action `uses:` pin update as a potential
validation-behavior change. Compare the current and candidate immutable SHAs,
including commands, inputs and defaults, runtime, and transitive `uses:`
dependencies. When an update changes provider-neutral validation behavior,
reify that change in the xtask command plan and this exact-command
documentation without making the xtask depend on provider configuration.

The root crate does not commit `Cargo.lock`, so its Cargo checks must work from
a clean checkout without `--locked`.

Static package-content validation is part of the non-release CI sequence. Run
it independently with:

```shell
cargo xtask package-content
```

The command runs this exact list-only Cargo operation:

```shell
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-traits
```

It compares Cargo's source list with
`xtask/package-contents/yaml-sigil-traits.txt`. The committed inventory must be
UTF-8, contain one normalized crate-relative path per line, end with a newline,
and remain bytewise sorted with no blank lines, comments, or duplicates.
`--allow-dirty` permits inspection of a candidate worktree without altering
the contents Cargo selects. `--exclude-lockfile` prevents an ignored root
`Cargo.lock` from changing registry resolution during this list-only check; the
xtask adds Cargo's generated `Cargo.lock` path to the observed set before
comparison. Keep the raw command, generated-path model, committed inventory,
hosted check, and xtask tests aligned whenever package metadata or contents
change.

The following package-validation guidance refers to full archive assembly and
verification, not the static path-list comparison above.

Package validation is deliberately separate from the non-release CI sequence:

```shell
cargo package
```

Publish `yaml-sigil-traits` only as a crates.io `.crate` source package. Do not
add a custom publishing wrapper or distribute compiled native executables,
executable WebAssembly, installers, containers, retained CI or build outputs,
GitHub Release assets, or separately generated source archives. Local and
ephemeral compilation remains permitted for validation.

## Async Traits

Async traits use native AFIT/RPITIT with explicit `+ Send` returned-future
bounds and `Send + Sync` super-bounds. They are intentionally not object-safe;
callers should use generic bounds such as `<S: AsyncSigner>`.

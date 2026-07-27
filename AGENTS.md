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

## Scope

Keep this crate independent from the rest of the YamlSigil Rust implementation.
It may depend on crypto/error crates needed to type public DTOs, but it must not
depend on `yaml-sigil-core`, `yaml-sigil-signing`, `yaml-sigil-verification`, or
`yaml-sigil-transcription`.

The normative specification lives in `yaml-sigil-spec`. This crate mirrors
vocabulary from that spec but does not own it. Ordinary builds, docs.rs builds,
and published crates must not require a local spec checkout.

When the specification pin changes, use the
`.agents/skills/yaml-sigil-traits-spec-update` skill. Keep the update scoped to
this repository's public trait and DTO contract; do not add generated protobuf
dependencies, and do not coordinate downstream implementation updates from this
repo.

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

- Keep documentation centered on public traits, DTOs, errors, feature flags,
  and compatibility guarantees.
- Mirror specification vocabulary when documenting spec-derived terms, but do
  not imply this crate owns the normative specification.
- Use generic trait-bound examples. Do not require `yaml-sigil-rs`,
  generated protobuf code, or runtime transport dependencies in examples for
  this crate.

## Commands

```shell
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo package --dry-run
```

Publishing is disabled in this prelaunch cleanup branch. Do not add a custom
publishing wrapper for this single-crate repository.

## Async Traits

Async traits use native AFIT/RPITIT with explicit `+ Send` returned-future
bounds and `Send + Sync` super-bounds. They are intentionally not object-safe;
callers should use generic bounds such as `<S: AsyncSigner>`.

# Xtask guidance

The `xtask` package is a developer-only CLI. Keep its Clap subcommands typed,
small, and covered by `CommandFactory::debug_assert()`.

`cargo xtask ci`, `package-content`, and `release` are provider-neutral and
credential-free. They may run ordinary development commands, but they must not
inspect a CI provider, parse workflow YAML, call a forge API, or publish.

`cargo xtask release activate --version <MAJOR.MINOR.PATCH>` selects the
unpublished `<MAJOR.MINOR.PATCH>-rc.0` coordination safety stub from exact
clean `origin/main`. It does not invoke release-plz or edit a changelog, leaves
only `Cargo.toml` changed, and never creates or updates a remote ref.

The only provider-specific namespace is `cargo xtask github release`. Keep it
limited to typed qualification, finalization, and read-only support proposals:

- Qualification and finalization require `--source-root` pointing to a distinct,
  exact clean checkout. Keep compiled protected-main policy in place; never
  overwrite it with historical release source.
- `qualify` reads exact GitHub and crates.io state and makes ordinary main
  pushes a successful no-op. Its publication mode requalifies live main after
  protected-environment approval and rejects registry drift.
- `finalize` first waits for and verifies the published source archive without
  a credential. Its separate App-authorized phase rebinds current protected
  policy and the retained source lineage, immediately rechecks that archive,
  then reconciles only the deterministic annotated tag and immutable zero-asset
  Release.

Accept GitHub tokens only from environment variables. Compile the exact
repository, package, branch-prefix, App, tag, and allowed-path policy into the
typed command. Do not add an API passthrough or accept configurable endpoint,
repository, package, tag, or asset policy.

Retain bounded output handling, no-follow manifest reads, crates.io checksum
validation, and bounded `.cargo_vcs_info.json` inspection. Add unit tests for
new rejection and idempotency behavior without embedding or parsing workflow
YAML.

Run these checks after changes:

```shell
cargo fmt --manifest-path xtask/Cargo.toml --all --check
cargo clippy --locked --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path xtask/Cargo.toml
```

The existing release commands may compare reviewed path names and opaque Git
blob identities across exact commits solely to prove release-policy provenance.
This narrow exception permits no workflow-content parsing, semantic validation,
provider-policy snapshots, or general workflow checks. Keep the required path
set and activation anchor under protected `main`; source trees remain data.

`release prepare` and `release check` take `--base-ref refs/heads/main` or a
canonical `refs/heads/support/M.N`. Detached checkouts must supply it. A named
local branch may infer `main` only when it contains current `origin/main`.
Support versions must match their base; preparation requires the next patch
or the next RC for that patch. Keep `release activate` main-only.

`github release start-support --repository OWNER/REPO --version M.N.P` is
read-only. It binds the compiled repository and package family, checks exact
current-main policy, verifies annotated App-tagged published source archives,
and requires a stable main successor outside the old line. It prints the
absent-ref push and a proposed enumerated inventory. It grants no activation
or publication authority. Never replace its opaque Git blob comparisons with
workflow-content inspection.

`github release rebind-policy` is read-only and fetches exact protected refs
anonymously into an isolated temporary object database. Local use requires
`--repository`; Actions binds the default repository and main ref. Carry the
qualified base, source, version, and fresh/recovery operation explicitly.

Support qualification and finalization validate the reviewed per-line
inventory. Current main selects the active line, fixed anchor, and required
paths. A fresh source must be the protected support tip and match current
policy. Recovery retains the original source on that lineage and checks
`source blob == recorded blob == historical main blob`; the historical main
commit must remain an ancestor of current main. Never let candidate-selected
paths replace the trusted historical inventory or initial main seed.

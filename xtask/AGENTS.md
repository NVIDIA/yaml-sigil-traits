# Xtask guidance

The `xtask` package is a developer-only CLI. Keep its Clap subcommands typed,
small, and covered by `CommandFactory::debug_assert()`.

`cargo xtask ci`, `package-content`, and `release` are provider-neutral and
credential-free. They may run ordinary development commands, but they must not
inspect a CI provider, parse workflow YAML, call a forge API, or publish.

The only provider-specific namespace is `cargo xtask github release`. Keep it
limited to `qualify` and `finalize`:

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

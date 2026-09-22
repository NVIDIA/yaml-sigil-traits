# Xtask guidance

The `xtask` package is a developer-only CLI. Keep its Clap subcommands typed,
small, and covered by `CommandFactory::debug_assert()`.

The public crate is a standalone package with an ignored root `Cargo.lock`.
Keep the developer tool in its isolated `[workspace]` with a committed
`xtask/Cargo.lock`; joining it to the public crate would change that lock and
release boundary. `.cargo/config.toml` maps `cargo xtask` to
`cargo run --locked --manifest-path xtask/Cargo.toml --`. Keep `main.rs` thin;
the library owns parsing, command construction, execution, and tests.

`check` registers these steps in order:

1. `markdown`: run rumdl.
2. `fmt`: check root and xtask formatting.
3. `package-content`: validate release-manifest policy and compare the source
   package inventory.
4. `check`: compile all targets in both workspaces.
5. `clippy`: lint all targets in both workspaces with warnings denied.
6. `test`: run tests in both workspaces.
7. `machete`: check unused dependencies with Cargo metadata.
8. `deny`: check both dependency graphs' bans, licenses, and sources.
9. `audit`: audit both lockfiles.

Run every step by default, in that order, and fail at the first error. `ci` is
a visible alias on the same parser variant. Support `--only=STEP,...` or
`--exclude=STEP,...`; reject unknown, empty, conflicting, or fully excluded
selections. Deduplicate selections without changing registry order. Probe only
the selected tools and distinguish missing tools from tools that cannot run.

Share Cargo feature options across `check`, `coverage`, and `coverage-open`.
Default to `--all-features` only when no feature option is supplied. Allow
`--features` with `--no-default-features`; reject `--all-features` with either.
Apply feature selection to public-crate compilation, linting, tests, dependency
policy, and coverage. Keep xtask validation locked and all-feature regardless
of the public-crate selection. Formatting receives no feature flags. A narrow
audit generates the ignored root lockfile if it does not exist.

Coverage runs the public crate's library and integration tests. LLVM coverage
is the default; `--engine=tarpaulin` selects Tarpaulin. Keep separate reports:

- LLVM: `target/coverage/llvm-cov/html/index.html`.
- Tarpaulin: `target/coverage/tarpaulin/tarpaulin-report.html`.

Tarpaulin builds in `target/coverage/tarpaulin/build` so its cleanup does not
remove ordinary builds or the LLVM report. Exclude `xtask/*` from its source
scan to keep the report scoped to the public crate.

`coverage --open` and `coverage-open` share one implementation: remove the
previous report, generate and verify a fresh report, then open it. Linux uses
`xdg-open`, macOS uses `open`, and Windows passes the canonical path directly
to `ShellExecuteW`. Keep paths as arguments, never shell command text. Print
the absolute report path if an opener is unavailable.

Install coverage tools only when needed:

```shell
cargo install --locked cargo-llvm-cov
rustup component add llvm-tools-preview
cargo install --locked cargo-tarpaulin
```

Do not install tools or change host settings from an xtask. LLVM commands set
`CARGO_LLVM_COV_SETUP=no` so a missing component produces installation guidance.
For an installed but unusable tool, preserve its diagnostic, including missing
shared libraries. Use the root `AGENTS.md` installation commands for check
prerequisites and keep their versions aligned with CI.

Do not add `image`, `profile`, `profile-open`, or MCP commands: this library
owns no images, representative profiling workload, or MCP server.

Humans must keep workflows and scripts aligned with the command registry.
Trusted CI uses selected `check` steps. Candidate CI keeps its fixed tools and
Cargo overrides, completes policy checks first, and executes equivalent direct
commands only in its terminal phase. Keep workflow syntax and policy validation
outside this crate. Retain the bounded Python candidate-binding and reporting
helpers for their JSON and API work. Inspect callers and obtain approval before
replacing mature helpers; do not migrate them solely to change the language.

`cargo xtask check`, `coverage`, `package-content`, and `release` are
provider-neutral and credential-free. They may run ordinary development commands,
but they must not inspect a CI provider, parse workflow YAML, call a forge API,
or publish.

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

Also exercise a narrow selection such as `cargo xtask check --only=fmt,check`
and both coverage engines when changing their command plans. Unit tests must
cover selector and feature behavior, both workspace policies, prerequisite
diagnostics, and generation-before-opening without requiring a browser.

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

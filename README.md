# yaml-sigil-traits

[![GitHub license](https://img.shields.io/github/license/NVIDIA/yaml-sigil-traits)](https://github.com/NVIDIA/yaml-sigil-traits/blob/main/LICENSE)
[![CI](https://github.com/NVIDIA/yaml-sigil-traits/actions/workflows/ci.yml/badge.svg)](https://github.com/NVIDIA/yaml-sigil-traits/actions/workflows/ci.yml)

[![crates.io](https://img.shields.io/crates/v/yaml-sigil-traits.svg)](https://crates.io/crates/yaml-sigil-traits)
[![docs.rs](https://docs.rs/yaml-sigil-traits/badge.svg)](https://docs.rs/yaml-sigil-traits)

`yaml-sigil-traits` defines the shared Rust traits and data types for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr) signing,
transcription, and verification.

Use this crate when callers and implementations need a stable in-process API.
The specification defines document and signature behavior. This crate defines
the Rust trait shapes, request and response data, capabilities, errors, and
helper functions exposed by those traits.

## Contract surface

Select the contract through `yaml_sigil_traits::v1alpha1`. Its modules and
root exports mirror the existing crate surface. For example,
`v1alpha1::signing::Signer` and `signing::Signer` name the same trait, and
`v1alpha1::AlgorithmId` and `AlgorithmId` name the same type. Implementations
and values work across both import styles without adapters or conversions.

The unqualified paths remain supported as the `v1alpha1` default. The
specification identifier `v1alpha1` is independent of this crate's SemVer.

This namespace exposes the portable contract for these API areas.

| API | Sync trait | Async trait | Capability DTO |
|-----|------------|-------------|----------------|
| Signing | `Signer` | `AsyncSigner` | `SignerCapabilities` |
| Transcription | `Transcriber` | `AsyncTranscriber` | `TranscriberCapabilities` |
| Verification | `Verifier` | `AsyncVerifier` | `VerifierCapabilities` |

`v1alpha1` defines no magic bytes, registered media type, or required file
extension. Callers select forms through `OutputForm`, `TranscriptionForm`, and
`ArtifactForm`.

The YAML decompose and verify APIs require complete artifacts because
last-marker selection requires EOF.

The modules group the contract by concern:

- `algorithm` defines `AlgorithmId` and the canonical YAML `alg` string mapping.
- `conformance` defines portable policy vocabulary for YAML signature documents,
  protobuf wire decoding, and outer-envelope conformance.
- `signing` defines requests and outcomes, with DTOs for keys and outputs.
  It also defines errors and capabilities.
- `transcription` defines compose and decompose requests and responses. Its
  other DTOs describe artifacts and forms, errors and capabilities.
- `verification` defines verification request support DTOs, verifier states,
  pre-verification DTOs, invocation errors, generic public-key DTOs, and
  options.

The crate does not provide default signing, transcription, or verification
implementations. Implementation crates own free-function APIs such as `sign`,
`compose`, and `verify`, default zero-sized types, YAML parsing, protobuf
decoding, cryptographic operations, trust-store behavior, and transport policy.

Signer and verifier implementations choose the concrete key types they accept.
The shared `SigningKey`, `SignRequest`, and `PublicKeys` data types borrow those
keys without constructing or parsing them.

## Trait usage

Use the synchronous traits through generic bounds or trait objects.

```rust
use yaml_sigil_traits::v1alpha1::signing::{SignOutcome, SignRequest, Signer};

pub fn sign_with<S: Signer>(
    signer: &S,
    request: &SignRequest<'_, S::Ed25519SigningKey, S::P256SigningKey>,
) -> SignOutcome {
    signer.sign(request)
}
```

Use the async traits through generic bounds. Their native `impl Future`
returns have `Send` bounds, and implementations must be `Send + Sync`.
The async traits are not object-safe.

```rust
use yaml_sigil_traits::v1alpha1::verification::{
    ArtifactForm, AsyncVerifier, InvocationError, PublicKeys, VerifierOptions,
    VerifierState,
};

pub async fn verify_with<V: AsyncVerifier>(
    verifier: &V,
    artifact: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_, V::Ed25519VerifyingKey, V::P256VerifyingKey>,
) -> Result<VerifierState, InvocationError> {
    verifier
        .verify(artifact, form, keys, VerifierOptions::default())
        .await
}
```

`PublicKeys` carries caller-supplied verification keys indexed by algorithm.
The artifact's unsigned `keyid` is a deployment-specific lookup hint.
Concrete implementation crates own key parsing and may narrow behavior, such
as requiring a configured trust store. Document those narrowings in the
implementation crate.

## Specification source

The normative `yaml-sigil` specification lives in
[`yaml-sigil-spec`](https://github.com/NVIDIA/yaml-sigil-spec). It is
maintenance input for reviewing this crate's public trait and DTO vocabulary.
Normal builds, docs.rs builds, and published crates do not require a local spec
checkout.

The submodule uses `update = none` so Cargo consumers of this Git repository do
not fetch specification material that is not build input. Initialize the pinned
specification explicitly when reviewing a specification update:

```shell
git -c submodule.source-spec.update=checkout \
  submodule update --init source-spec
```

Keep specification-pin updates scoped to this crate's public trait and DTO
contract. Do not add generated protobuf dependencies or coordinate downstream
implementation updates from this repository.

## Build and test

The development toolchain follows Rust `stable` through
`rust-toolchain.toml`. The minimum supported Rust version (MSRV) is Rust
`1.95.0`, as declared in `Cargo.toml`.

```shell
cargo xtask check
cargo package
```

`cargo xtask check` validates Markdown, formatting, package contents, Rust
compilation, Clippy, tests, and both workspaces' dependencies. `cargo xtask ci`
is an alias for the same command. Run a subset with
`cargo xtask check --only=fmt,clippy,test`, or omit checks with
`--exclude=STEP,...`. Checks run in registry order and stop at the first error.

Compilation, Clippy, tests, and coverage use all public-crate features by
default. `--features=FEATURE,...` and `--no-default-features` select a different
set without changing the standalone xtask workspace's validation. Dependency
policy checks always inspect all features in both graphs. The public crate has
no optional features today. The GitHub Actions workflows expose Rust checks as
independent steps, with separate provider-policy and MSRV lanes.

`cargo package` performs separate local package assembly and
verification without uploading anything; it is not part of the non-release CI
sequence. Cargo rejects uncommitted changes to packaged files. Use
`cargo package --allow-dirty` for pre-commit validation, then rerun
`cargo package` after committing.

Generate public-crate coverage with either engine:

```shell
cargo xtask coverage
cargo xtask coverage --engine=tarpaulin
cargo xtask coverage-open
```

Install `cargo-llvm-cov` and the `llvm-tools-preview` Rust component for the
default engine, or `cargo-tarpaulin` for Tarpaulin. Reports appear at
`target/coverage/llvm-cov/html/index.html` and
`target/coverage/tarpaulin/tarpaulin-report.html`. `coverage --open` and
`coverage-open` both generate a fresh report before opening it, and accept the
same engine and feature options. Coverage covers library and integration tests;
the regular check command also runs doctests.

## Publishing

Releases are published to
[`yaml-sigil-traits` on crates.io](https://crates.io/crates/yaml-sigil-traits).
The manifest limits publication to the crates.io registry.

## Dependency boundary

`yaml-sigil-traits` stays independent from the rest of the `yaml-sigil` Rust
implementation and does not choose a cryptography library. Implementations
connect the generic signing and verification key slots to their concrete key
types through associated types.

## Third-party material

NVIDIA-authored crate material is licensed under Apache-2.0. The crate mirrors
standards-derived identifiers and public-key format behavior without
relicensing the cited standards material. Copyright, source, warranty,
patent/IP, and non-endorsement notices are collected in
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-traits/blob/main/THIRD_PARTY_NOTICES.md).

The pinned specification has its own complete notice at
[`source-spec/THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-spec/blob/30b143f09630448abbace14cfae2188279536f56/THIRD_PARTY_NOTICES.md).
The crate package excludes `source-spec/`; repository distributions that
initialize the submodule must preserve that notice.

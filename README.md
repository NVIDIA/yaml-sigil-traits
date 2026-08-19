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

This crate exposes the portable contract for these API areas.

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
- `signing` defines signing request, outcome, error, capability, key, and output
  DTOs.
- `transcription` defines compose and decompose request, response, error,
  capability, artifact, and form DTOs.
- `verification` defines verification request support DTOs, verifier states,
  pre-verification DTOs, invocation errors, public-key DTOs, options, and key
  resolution helpers.

The crate does not provide default signing, transcription, or verification
implementations. Implementation crates own free-function APIs such as `sign`,
`compose`, and `verify`, default zero-sized types, YAML parsing, protobuf
decoding, cryptographic operations, trust-store behavior, and transport policy.

## Trait usage

Use the synchronous traits through generic bounds or trait objects.

```rust
use yaml_sigil_traits::signing::{SignOutcome, SignRequest, Signer};

pub fn sign_with<S: Signer>(signer: &S, request: &SignRequest<'_>) -> SignOutcome {
    signer.sign(request)
}
```

Use the async traits through generic bounds. The async traits use native
AFIT/RPITIT with explicit `+ Send` returned-future bounds and `Send + Sync`
super-bounds, so they are intentionally not object-safe.

```rust
use yaml_sigil_traits::verification::{
    ArtifactForm, AsyncVerifier, InvocationError, PublicKeys, VerifierOptions,
    VerifierState,
};

pub async fn verify_with<V: AsyncVerifier>(
    verifier: &V,
    artifact: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
) -> Result<VerifierState, InvocationError> {
    verifier
        .verify(artifact, form, keys, VerifierOptions::default())
        .await
}
```

`PublicKeys` carries caller-supplied verification keys indexed by algorithm.
The artifact's unsigned `keyid` remains a deployment-specific lookup hint.
Downstream implementations may narrow behavior, such as requiring a configured
trust store. Document those narrowings in the implementation crate.

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
cargo xtask ci
cargo package
```

`cargo xtask ci` also checks Markdown, the standalone xtask workspace, and
dependency advisories. The GitHub Actions workflow runs the same validation as
independent steps. `cargo package` performs separate local package assembly and
verification without uploading anything; it is not part of the non-release CI
sequence.

## Publishing

Releases are published to
[`yaml-sigil-traits` on crates.io](https://crates.io/crates/yaml-sigil-traits).
The manifest limits publication to the crates.io registry.

## Dependency boundary

`yaml-sigil-traits` stays independent from the rest of the `yaml-sigil` Rust
implementation. It may depend on crates needed to type public DTOs, including
[`ed25519-dalek`](https://crates.io/crates/ed25519-dalek),
[`p256`](https://crates.io/crates/p256), and
[`thiserror`](https://crates.io/crates/thiserror), but we do seek to reduce
those over time.

## Third-party material

NVIDIA-authored crate material is licensed under Apache-2.0. The crate mirrors
standards-derived identifiers and public-key format behavior without
relicensing the cited standards material. Copyright, source, warranty,
patent/IP, and non-endorsement notices are collected in
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-traits/blob/main/THIRD_PARTY_NOTICES.md).

The pinned specification has its own complete notice at
[`source-spec/THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-spec/blob/0fa13f2bf7aac43afb492d9c7dad8e3bf9cfa2bc/THIRD_PARTY_NOTICES.md).
The crate package excludes `source-spec/`; repository distributions that
initialize the submodule must preserve that notice.

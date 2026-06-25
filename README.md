# yaml-sigil-traits

Rust Traits for [yaml-sigil](https://github.com/NVIDIA-dev/yaml-sigil-spec).

`yaml-sigil-traits` defines the shared Rust trait and DTO contract for the
YamlSigil `v1alpha1` signing, transcription, and verification APIs.

Use this crate when you need a stable in-process boundary between callers and
YamlSigil implementations. The crate mirrors vocabulary from the pinned
YamlSigil specification, but the specification owns protocol semantics. This
crate owns the Rust trait shapes, request DTOs, response DTOs, capability DTOs,
error enums, and helper functions that those traits expose.

## Contract surface

This crate exposes the portable contract for these API areas.

| API | Sync trait | Async trait | Capability DTO |
|-----|------------|-------------|----------------|
| Signing | `Signer` | `AsyncSigner` | `SignerCapabilities` |
| Transcription | `Transcriber` | `AsyncTranscriber` | `TranscriberCapabilities` |
| Verification | `Verifier` | `AsyncVerifier` | `VerifierCapabilities` |

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

## Dependency boundary

`yaml-sigil-traits` stays independent from the rest of the YamlSigil Rust
implementation. It may depend on crates needed to type public DTOs, including
`ed25519-dalek`, `p256`, and `thiserror`, but we do seek to reduce those over
time.

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

Downstream implementations may narrow behavior when their contract requires it.
For example, a verifier backed by a configured trust store may reject arbitrary
caller-supplied key bytes. Document those narrowings in the implementation
crate, not in this trait crate.

## Specification source

The normative YamlSigil specification lives in
[yaml-sigil-spec](https://github.com/NVIDIA-dev/yaml-sigil-spec). It is
maintenance input for reviewing this crate's public trait and DTO vocabulary.
Normal builds, docs.rs builds, and published crates do not require a local spec
checkout.

When the specification pin changes, use the repo-local
`.agents/skills/yaml-sigil-traits-spec-update` skill. Keep the update scoped to
this crate's public trait and DTO contract. Do not add generated protobuf
dependencies or coordinate downstream implementation updates from this
repository.

## Build and test

Rust is pinned to `1.95.0` through `rust-toolchain.toml`.

```shell
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo package --dry-run
```

## Publishing

Publishing is disabled in this prelaunch cleanup branch. Re-enable and validate
crates.io metadata in a later release-preparation change.

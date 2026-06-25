// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verification API: the `Verifier` / `AsyncVerifier` extension-trait pair and
//! the request/response/error/capability DTOs their signatures reference, plus
//! the key-resolution helpers their default method bodies delegate to.
//!
//! The verify free-function surface (`verify`, `pre_verify`, …) and the
//! `DefaultVerifier` / `DefaultAsyncVerifier` ZSTs live in
//! `yaml-sigil-verification`, which re-exports these items.

use std::convert::TryFrom;
use std::fmt;

use crate::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
use thiserror::Error;

/// Which artifact representation a verify or pre-verify call used (mirrors `Form` in `verification.proto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactForm {
    Yaml,
    Proto,
}

/// Conformance posture advertised by this build (IDL `ConformanceProfile`).
///
/// The three variants mirror the IDL's `CONFORMANCE_PROFILE_{STRICT,PERMISSIVE,SIGNATURE_STRICT}`
/// values; the IDL's `CONFORMANCE_PROFILE_UNSPECIFIED` is intentionally not modeled here because
/// `source-spec/verification-api.md` § "Conformance Profiles" declares it non-conforming for any
/// verifier that supports a wire form. The enum is `pub` so downstream `Verifier`
/// implementations can advertise whichever profile they actually satisfy.
///
/// `verifier_capabilities` (the default `DefaultVerifier` advertisement) always returns
/// [`AdvertisedConformanceProfile::Permissive`]. The spec requires Strict / SignatureStrict to
/// reject **duplicate known singular fields on both wire forms**; this workspace's protobuf
/// inner-decode path uses stock `buffa` / `prost` decoders, which apply last-wins to duplicate
/// scalars and merge to duplicate messages (Permissive behavior). The
/// `yaml-sigil-core`'s `yaml-strict-unknown-fields` feature tightens YAML signature-document
/// parsing (rejecting unknown mapping keys at parse) but does NOT change the protobuf-side
/// duplicate behavior; it would be non-conforming to advertise Strict in that cell because the
/// spec demands uniform rejection across both forms. See
/// the `yaml-sigil-rs` conformance validation notes
/// (§5a "resolved upstream") for the rationale; now formalized normatively in
/// `source-spec/verification-api.md` § "Strict inner-protobuf decode is not parser-emergent".
///
/// The unified profile applies to both wire forms (the IDL field rename
/// `protobuf_conformance_profile` → `conformance_profile` followed the same commit `ce35681`).
/// See also [`VerifierCapabilities::protobuf_wire_decode`] and the YAML policy fields on
/// [`VerifierCapabilities`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvertisedConformanceProfile {
    Strict,
    Permissive,
    SignatureStrict,
}

/// Typed verifier capability surface (mirrors `VerifierCapabilitiesResponse` in `verification.proto`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierCapabilities {
    /// Advertised conformance profile (IDL field `conformance_profile`; renamed from
    /// `protobuf_conformance_profile` in source-spec commit `ce35681` to reflect the
    /// unified-across-wire-forms semantics). See
    /// `source-spec/verification-api.md` § "Conformance Profiles".
    pub conformance_profile: AdvertisedConformanceProfile,
    /// Stock buffa/prost `decode` for `SignedYamlArtifact`; no profile-driven unknown-field policy.
    pub protobuf_wire_decode: ProtobufWireDecodeAdvertisement,
    /// How duplicate keys in the signature-document YAML mapping behave when this verifier parses YAML.
    pub yaml_signature_duplicate_key_policy: YamlSignatureDocumentDuplicateKeyPolicy,
    /// Default unknown-field policy (see `yaml_signature_unknown_field_policies` for strict options).
    pub yaml_signature_unknown_field_policy: YamlSignatureDocumentUnknownFieldPolicy,
    /// Policies this build can apply (default ignore-at-parse; optional strict parse/verify).
    pub yaml_signature_unknown_field_policies: Vec<YamlSignatureDocumentUnknownFieldPolicy>,
    pub supported_forms: &'static [ArtifactForm],
    pub supported_algorithms: &'static [AlgorithmId],
    pub supports_can_pre_verify: bool,
    pub supports_pre_verify: bool,
    pub implementation_name: &'static str,
    pub implementation_version: &'static str,
}

/// Distinguishable verifier states for a well-formed invocation (see `source-spec/verification-api.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierState {
    /// Cryptographic success; returns exact signed payload bytes.
    Verified {
        payload: Vec<u8>,
        algorithm: AlgorithmId,
    },
    /// No signing attempt (YAML only; protobuf inputs never produce this).
    Unsigned,
    /// Structural or metadata validation failed before or instead of successful crypto.
    MalformedAttemptedSigned,
    /// Artifact is fine; this verifier build does not implement the algorithm.
    SignedButAlgorithmUnsupported { algorithm: AlgorithmId },
    /// Crypto attempted and failed (bad signature, wrong key, etc.).
    SignedButFailedVerification,
}

impl fmt::Display for VerifierState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierState::Verified { .. } => f.write_str("Verified"),
            VerifierState::Unsigned => f.write_str("Unsigned"),
            VerifierState::MalformedAttemptedSigned => f.write_str("MalformedAttemptedSigned"),
            VerifierState::SignedButAlgorithmUnsupported { .. } => {
                f.write_str("SignedButAlgorithmUnsupported")
            }
            VerifierState::SignedButFailedVerification => {
                f.write_str("SignedButFailedVerification")
            }
        }
    }
}

/// Caller-side failures distinct from artifact states (mirrors `InvocationErrorCategory` in `verification.proto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvocationError {
    #[error("invalid algorithm parameters supplied by caller")]
    InvalidAlgorithmParameters,
    #[error("caller key material or handle could not be used for this verification")]
    KeyResolutionFailure,
    #[error("caller trust policy configuration is invalid")]
    TrustPolicyConfigurationError,
    #[error("pre-verify result is not structurally valid for verify_from_pre_verify")]
    InvalidPreVerifyResult,
    /// IDL request-shape failure for `FORM_UNSPECIFIED` or an unsupported artifact form.
    ///
    /// This is not an artifact state, a [`PreVerifyOutcome`], or a
    /// `CanPreVerify` false result.
    #[error("artifact form is unspecified or unsupported")]
    InvalidOrUnsupportedForm,
}

/// Resolve raw Ed25519 public-key bytes into a typed [`ed25519_dalek::VerifyingKey`].
///
/// Mirrors the spec's "key resolution" stage — the byte-slice → typed-key step
/// that produces [`InvocationError::KeyResolutionFailure`] when the caller-supplied
/// material cannot be used. Rejected cases:
///
/// - any input whose length is not 32 octets;
/// - non-canonical encodings (delegated to `ed25519_dalek::VerifyingKey::from_bytes`);
/// - small-order points (delegated to `ed25519_dalek::VerifyingKey::is_weak`).
///
/// See `source-spec/conformance/alg-ed25519/configured-key-small-order.txt`.
pub fn resolve_ed25519_verifying_key(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, InvocationError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| InvocationError::KeyResolutionFailure)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|_| InvocationError::KeyResolutionFailure)?;
    if vk.is_weak() {
        return Err(InvocationError::KeyResolutionFailure);
    }
    Ok(vk)
}

/// Resolve raw P-256 SEC1 public-key bytes into a typed [`p256::ecdsa::VerifyingKey`].
///
/// Mirrors the spec's "key resolution" stage. Rejected cases:
///
/// - the SEC1 §2.3.3 single-byte `0x00` identity encoding (the point at infinity);
/// - the all-zero 65-octet "uncompressed identity" some callers emit;
/// - any input that `p256::ecdsa::VerifyingKey::from_sec1_bytes` rejects
///   (off-curve, wrong length, wrong curve, etc.).
///
/// See `source-spec/conformance/alg-ecdsa/bad-key-*.txt`.
pub fn resolve_p256_verifying_key(
    bytes: &[u8],
) -> Result<p256::ecdsa::VerifyingKey, InvocationError> {
    if bytes == [0u8].as_slice() {
        return Err(InvocationError::KeyResolutionFailure);
    }
    if bytes.len() == 65 && bytes.iter().all(|&b| b == 0) {
        return Err(InvocationError::KeyResolutionFailure);
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|_| InvocationError::KeyResolutionFailure)
}

/// Public key material for the two supported algorithms (caller chooses which is populated).
#[derive(Debug, Clone, Copy)]
pub struct PublicKeys<'a> {
    pub ed25519: Option<&'a ed25519_dalek::VerifyingKey>,
    pub p256: Option<&'a p256::ecdsa::VerifyingKey>,
}

/// Optional knobs for algorithm support (defaults implement both wire algorithms).
#[derive(Debug, Clone)]
pub struct VerifierOptions {
    pub verify_ed25519: bool,
    pub verify_ecdsa_p256_sha256: bool,
    /// When true, reject signature documents whose carrier YAML has top-level keys outside Tier A.
    pub reject_unknown_signature_document_fields: bool,
    /// `VerifyRequest.algorithm_parameters` (IDL field). The two supported algorithms
    /// define no parameters; a non-empty value yields
    /// [`InvocationError::InvalidAlgorithmParameters`] before any artifact bytes are
    /// inspected. See `source-spec/conformance/alg-{ed25519,ecdsa}/algorithm-parameters-present.expected.txt`.
    pub algorithm_parameters: Vec<u8>,
}

impl Default for VerifierOptions {
    fn default() -> Self {
        Self {
            verify_ed25519: true,
            verify_ecdsa_p256_sha256: true,
            reject_unknown_signature_document_fields: false,
            algorithm_parameters: Vec::new(),
        }
    }
}

/// Result of `verify_with_metadata` (IDL `VerifierStateResult` + optional observations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub state: VerifierState,
    pub parser_observations: Vec<String>,
}

/// Outcome of structural pre-verification (IDL `PreVerifyOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreVerifyOutcome {
    Ok,
    Unsigned,
    StructuralFailure,
    MetadataParseFailure,
}

/// Signature metadata extracted before crypto (IDL `UnverifiedSignature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedSignature {
    pub algorithm: AlgorithmId,
    pub keyid: Option<String>,
    pub signature_octets: Vec<u8>,
}

/// Reified pre-verification result (IDL `PreVerifyResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreVerifyResponse {
    pub outcome: PreVerifyOutcome,
    pub form: ArtifactForm,
    pub unverified_payload_bytes: Option<Vec<u8>>,
    pub unverified_signature: Option<UnverifiedSignature>,
    pub parser_observations: Vec<String>,
}

impl TryFrom<i32> for ArtifactForm {
    type Error = InvocationError;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(ArtifactForm::Yaml),
            2 => Ok(ArtifactForm::Proto),
            _ => Err(InvocationError::InvalidOrUnsupportedForm),
        }
    }
}

/// Public extension point: any verifier implementation in the workspace (or downstream)
/// implements this trait. Mirrors the free-function surface so callers can swap
/// implementations behind `&dyn Verifier` or generic bounds.
///
/// Downstream implementations (e.g. those with a configured `TrustedKey`
/// set) MAY document additional contract narrowings — for example, ignoring the
/// caller-supplied `keys` argument and consulting their own trust store. Such
/// narrowings belong in the implementation crate's README, not in this trait's
/// contract.
pub trait Verifier {
    /// Capability surface this verifier advertises.
    fn capabilities(&self) -> VerifierCapabilities;
    /// Structural + metadata pre-verify (IDL `PreVerify`).
    fn pre_verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> PreVerifyResponse;
    /// Full verify (IDL `Verify`).
    fn verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError>;
    /// Verify with optional parser observations.
    fn verify_with_metadata(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError>;
    /// Run only the verification stage from a prior [`PreVerifyResponse`] (IDL `VerifyFromPreVerify`).
    fn verify_from_pre_verify(
        &self,
        pre: &PreVerifyResponse,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError>;
    /// Resolve raw Ed25519 public-key bytes into a typed key (key-resolution stage).
    ///
    /// Default impl delegates to the free function
    /// [`resolve_ed25519_verifying_key`]. Downstream implementations MAY narrow
    /// the contract (e.g. consult their own trust store and refuse arbitrary
    /// caller-supplied bytes); record such narrowings in the implementation's
    /// README and in `docs/conformance-validation.md` if they affect fixtures.
    fn resolve_ed25519_verifying_key(
        &self,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::VerifyingKey, InvocationError> {
        resolve_ed25519_verifying_key(bytes)
    }
    /// Resolve raw P-256 SEC1 public-key bytes into a typed key (key-resolution stage).
    ///
    /// Default impl delegates to the free function
    /// [`resolve_p256_verifying_key`]. Downstream implementations MAY narrow
    /// the contract; see the Ed25519 doc above.
    fn resolve_p256_verifying_key(
        &self,
        bytes: &[u8],
    ) -> Result<p256::ecdsa::VerifyingKey, InvocationError> {
        resolve_p256_verifying_key(bytes)
    }
}

/// Async sibling of [`Verifier`]. Same method semantics; the verify and
/// pre-verify entries return `Future`s instead of being synchronous.
///
/// Trait shape uses native AFIT/RPITIT with explicit `+ Send` on every
/// returned future and `Send + Sync` super-bounds on the trait. This is the
/// forward-compatible choice (no `async-trait` heap allocation) at the cost of
/// not being object-safe — use generic bounds (`<V: AsyncVerifier>`), not
/// `&dyn AsyncVerifier`. See this repository's `AGENTS.md`.
///
/// The `resolve_*_verifying_key` methods have default impls that wrap the
/// synchronous resolvers in an `async` block; downstream verifiers that own
/// async key-resolution paths can override them.
pub trait AsyncVerifier: Send + Sync {
    /// Capability surface this verifier advertises.
    fn capabilities(&self) -> VerifierCapabilities;
    /// Structural + metadata pre-verify (IDL `PreVerify`).
    fn pre_verify<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> impl core::future::Future<Output = PreVerifyResponse> + Send + 'a;
    /// Full verify (IDL `Verify`).
    fn verify<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        keys: &'a PublicKeys<'_>,
        options: VerifierOptions,
    ) -> impl core::future::Future<Output = Result<VerifierState, InvocationError>> + Send + 'a;
    /// Verify with optional parser observations.
    fn verify_with_metadata<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        keys: &'a PublicKeys<'_>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> impl core::future::Future<Output = Result<VerifyResult, InvocationError>> + Send + 'a;
    /// Run only the verification stage from a prior [`PreVerifyResponse`] (IDL `VerifyFromPreVerify`).
    fn verify_from_pre_verify<'a>(
        &'a self,
        pre: &'a PreVerifyResponse,
        keys: &'a PublicKeys<'_>,
        options: VerifierOptions,
    ) -> impl core::future::Future<Output = Result<VerifierState, InvocationError>> + Send + 'a;
    /// Resolve raw Ed25519 public-key bytes into a typed key.
    ///
    /// Default impl delegates to the synchronous free function
    /// [`resolve_ed25519_verifying_key`]; downstream verifiers that own async
    /// key-resolution paths MAY override.
    fn resolve_ed25519_verifying_key<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> impl core::future::Future<Output = Result<ed25519_dalek::VerifyingKey, InvocationError>>
    + Send
    + 'a {
        async move { resolve_ed25519_verifying_key(bytes) }
    }
    /// Resolve raw P-256 SEC1 public-key bytes into a typed key.
    ///
    /// Default impl delegates to the synchronous free function
    /// [`resolve_p256_verifying_key`]; downstream verifiers that own async
    /// key-resolution paths MAY override.
    fn resolve_p256_verifying_key<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> impl core::future::Future<Output = Result<p256::ecdsa::VerifyingKey, InvocationError>> + Send + 'a
    {
        async move { resolve_p256_verifying_key(bytes) }
    }
}

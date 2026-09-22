// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verification traits and their request, response, error, and capability types.
//!
//! `yaml-sigil-verification` re-exports these types and provides verification
//! functions such as `verify` and `pre_verify`, with the `DefaultVerifier`
//! and `DefaultAsyncVerifier` zero-sized types.

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

/// Conformance profile advertised by a verifier (IDL `ConformanceProfile`).
///
/// Advertise one profile that the implementation satisfies across every supported
/// wire form. These variants mirror the IDL's
/// `CONFORMANCE_PROFILE_{STRICT,PERMISSIVE,SIGNATURE_STRICT}` values.
/// `CONFORMANCE_PROFILE_UNSPECIFIED` is excluded because the specification
/// requires a concrete profile when a verifier supports a wire form.
///
/// Strict and SignatureStrict require rejection of duplicate known singular
/// fields in both wire forms. Stock `buffa` and `prost` decoders use the last
/// duplicate scalar and merge duplicate messages. A verifier using those
/// decoders must enforce the profile's duplicate-field rules separately to
/// advertise Strict or SignatureStrict. Rejecting unknown YAML mapping keys
/// alone does not establish either profile.
///
/// See the specification's [conformance profiles] and the decoder and YAML
/// policy fields on [`VerifierCapabilities`].
///
/// [conformance profiles]: https://github.com/NVIDIA/yaml-sigil-spec/blob/main/verification-api.md#conformance-profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvertisedConformanceProfile {
    Strict,
    Permissive,
    SignatureStrict,
}

/// Typed verifier capability surface (mirrors `VerifierCapabilitiesResponse` in `verification.proto`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierCapabilities {
    /// Profile satisfied across every supported wire form (IDL `conformance_profile`).
    pub conformance_profile: AdvertisedConformanceProfile,
    /// Advertised protobuf decoder behavior for `SignedYamlArtifact`.
    pub protobuf_wire_decode: ProtobufWireDecodeAdvertisement,
    /// How duplicate keys in the signature-document YAML mapping behave when this verifier parses YAML.
    pub yaml_signature_duplicate_key_policy: YamlSignatureDocumentDuplicateKeyPolicy,
    /// Default unknown-field policy (see `yaml_signature_unknown_field_policies` for strict options).
    pub yaml_signature_unknown_field_policy: YamlSignatureDocumentUnknownFieldPolicy,
    /// Unknown-field policies this implementation can apply.
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
    ///
    /// A signature document within `payload` remains payload content.
    Verified {
        payload: Vec<u8>,
        algorithm: AlgorithmId,
    },
    /// No signing attempt (YAML only; protobuf inputs never produce this).
    Unsigned,
    /// Structural or metadata validation failed before cryptographic verification.
    ///
    /// This includes empty decoded signature octets. Full verification applies that check before
    /// runtime algorithm-support classification.
    MalformedAttemptedSigned,
    /// Artifact metadata and algorithm-independent signature content are valid, but this verifier
    /// build does not implement the algorithm.
    SignedButAlgorithmUnsupported { algorithm: AlgorithmId },
    /// Cryptographic verification was attempted with an implemented algorithm and failed.
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

/// Caller-supplied verification keys, indexed by algorithm.
///
/// Implementations own deployment-specific key selection and trust-policy behavior. An artifact's
/// unsigned `keyid` is only a lookup hint.
#[derive(Debug)]
pub struct PublicKeys<'a, Ed25519: ?Sized, P256: ?Sized> {
    pub ed25519: Option<&'a Ed25519>,
    pub p256: Option<&'a P256>,
}

impl<Ed25519: ?Sized, P256: ?Sized> Clone for PublicKeys<'_, Ed25519, P256> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Ed25519: ?Sized, P256: ?Sized> Copy for PublicKeys<'_, Ed25519, P256> {}

/// Algorithm selection and parsing options. Both algorithms are enabled by default.
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
    /// Structural processing and metadata extraction succeeded.
    ///
    /// The extracted signature octets may be empty because the non-empty check belongs to full
    /// verification.
    Ok,
    /// The YAML artifact contains no signing attempt.
    Unsigned,
    /// The artifact could not be structurally decomposed.
    StructuralFailure,
    /// Signature metadata extraction failed.
    ///
    /// This includes a missing or incorrect YAML signature-document schema identity.
    MetadataParseFailure,
}

/// Signature metadata extracted before crypto (IDL `UnverifiedSignature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedSignature {
    pub algorithm: AlgorithmId,
    /// Unsigned lookup hint for deployment-specific key selection.
    pub keyid: Option<String>,
    /// Raw decoded signature octets.
    ///
    /// These may be empty in a [`PreVerifyOutcome::Ok`] result. Full verification classifies an
    /// empty signature as [`VerifierState::MalformedAttemptedSigned`] before runtime
    /// algorithm-support classification.
    pub signature_octets: Vec<u8>,
}

/// Pre-verification result (IDL `PreVerifyResponse`).
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

/// Synchronous verification contract for interchangeable implementations.
///
/// Use generic bounds or trait objects with explicit associated key types.
/// An implementation may narrow this contract, such as consulting its own
/// trust store and ignoring the caller-supplied `keys` argument. Document any
/// narrowing in the implementation crate's README.
pub trait Verifier {
    /// Concrete Ed25519 verifying-key type accepted by this implementation.
    type Ed25519VerifyingKey: ?Sized;
    /// Concrete ECDSA P-256 verifying-key type accepted by this implementation.
    type P256VerifyingKey: ?Sized;

    /// Capability surface this verifier advertises.
    fn capabilities(&self) -> VerifierCapabilities;
    /// Extract structure and signature metadata (IDL `PreVerify`).
    ///
    /// This stage does not enforce the runtime non-empty signature rule or classify runtime
    /// algorithm support.
    fn pre_verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> PreVerifyResponse;
    /// Full verify (IDL `Verify`).
    ///
    /// This stage enforces the non-empty signature rule before classifying runtime algorithm
    /// support.
    fn verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError>;
    /// Verify with optional parser observations.
    fn verify_with_metadata(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError>;
    /// Run only the verification stage from a prior [`PreVerifyResponse`] (IDL `VerifyFromPreVerify`).
    ///
    /// This stage enforces the non-empty signature rule before classifying runtime algorithm
    /// support.
    fn verify_from_pre_verify(
        &self,
        pre: &PreVerifyResponse,
        keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError>;
}

/// Async verification with the same method semantics as [`Verifier`].
///
/// Verification and pre-verification return native `impl Future` values with
/// `Send` bounds. Implementations must be `Send + Sync`. Use generic bounds
/// such as `<V: AsyncVerifier>`; this trait is not object-safe.
pub trait AsyncVerifier: Send + Sync {
    /// Concrete Ed25519 verifying-key type accepted by this implementation.
    type Ed25519VerifyingKey: Sync + ?Sized;
    /// Concrete ECDSA P-256 verifying-key type accepted by this implementation.
    type P256VerifyingKey: Sync + ?Sized;

    /// Capability surface this verifier advertises.
    fn capabilities(&self) -> VerifierCapabilities;
    /// Extract structure and signature metadata (IDL `PreVerify`).
    ///
    /// This stage does not enforce the runtime non-empty signature rule or classify runtime
    /// algorithm support.
    fn pre_verify<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> impl core::future::Future<Output = PreVerifyResponse> + Send + 'a;
    /// Full verify (IDL `Verify`).
    ///
    /// This stage enforces the non-empty signature rule before classifying runtime algorithm
    /// support.
    fn verify<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        keys: &'a PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
    ) -> impl core::future::Future<Output = Result<VerifierState, InvocationError>> + Send + 'a;
    /// Verify with optional parser observations.
    fn verify_with_metadata<'a>(
        &'a self,
        input_bytes: &'a [u8],
        form: ArtifactForm,
        keys: &'a PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> impl core::future::Future<Output = Result<VerifyResult, InvocationError>> + Send + 'a;
    /// Run only the verification stage from a prior [`PreVerifyResponse`] (IDL `VerifyFromPreVerify`).
    ///
    /// This stage enforces the non-empty signature rule before classifying runtime algorithm
    /// support.
    fn verify_from_pre_verify<'a>(
        &'a self,
        pre: &'a PreVerifyResponse,
        keys: &'a PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        options: VerifierOptions,
    ) -> impl core::future::Future<Output = Result<VerifierState, InvocationError>> + Send + 'a;
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Signing traits and their request, response, error, and capability types.
//!
//! `yaml-sigil-signing` re-exports these types and provides the `sign`,
//! `sign_yaml`, and `sign_proto` functions, with the `DefaultSigner` and
//! `DefaultAsyncSigner` zero-sized types.

use std::fmt;

use crate::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
use thiserror::Error;

/// Advertised output forms for this build (IDL `OutputForm`, excluding `UNSPECIFIED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputForm {
    Yaml,
    Protobuf,
}

/// Typed capability surface corresponding to the IDL `SignerCapabilitiesResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerCapabilities {
    pub protobuf_wire_decode: ProtobufWireDecodeAdvertisement,
    pub yaml_signature_duplicate_key_policy: YamlSignatureDocumentDuplicateKeyPolicy,
    pub yaml_signature_unknown_field_policy: YamlSignatureDocumentUnknownFieldPolicy,
    pub supported_output_forms: &'static [OutputForm],
    pub supported_algorithms: &'static [AlgorithmId],
    pub best_effort_yaml_validation: bool,
    pub implementation_name: &'static str,
    pub implementation_version: &'static str,
}

/// Request-shape failures before payload processing (IDL `SignerInvocationError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignInvocationError {
    #[error("unsupported or invalid algorithm selection for this signer")]
    InvalidOrUnsupportedAlgorithm,
    #[error("invalid algorithm parameters")]
    InvalidAlgorithmParameters,
    #[error("invalid or unsupported output form")]
    InvalidOrUnsupportedOutputForm,
    #[error("invalid keyid (empty, over 1024 UTF-8 octets, or contains CR or LF)")]
    InvalidKeyid,
}

/// Sign-time failures after request-shape validation (IDL `SignerError`), plus output extensions.
///
/// The `sign_yaml` and `sign_proto` convenience wrappers map
/// [`SignInvocationError`] into this error type, including
/// [`InvalidAlgorithmParameters`](SignError::InvalidAlgorithmParameters),
/// and return `Result<_, SignError>`.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("invalid payload bytes (UTF-8, BOM, or line terminator rules)")]
    InvalidPayloadBytes,
    #[error("non-empty payload missing trailing newline and caller did not authorize appending LF")]
    PayloadLineTerminatorRefusal,
    #[error("unsupported or invalid algorithm selection")]
    InvalidOrUnsupportedAlgorithm,
    #[error("invalid algorithm parameters")]
    InvalidAlgorithmParameters,
    #[error("invalid or unsupported output form")]
    InvalidOrUnsupportedOutputForm,
    #[error("invalid keyid (empty, over 1024 UTF-8 octets, or contains CR or LF)")]
    InvalidKeyid,
    #[error("key operation failed")]
    KeyOperationFailure,
    #[error("YAML validation failed at sign time")]
    YamlValidationFailure,
    #[error("YAML serialization failed: {0}")]
    YamlSerialize(String),
}

/// Signing success or an error from invocation validation or signing.
#[derive(Debug)]
pub enum SignOutcome {
    Success(SignSuccess),
    Invocation(SignInvocationError),
    Signer(SignError),
}

/// Successful signing output (IDL `SignSuccess`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignSuccess {
    pub artifact: Vec<u8>,
    /// Populated when the signer appended one LF for the line-terminator rule.
    pub modified_payload: Vec<u8>,
}

/// Signing request corresponding to IDL `SignRequest`, with a borrowed key.
pub struct SignRequest<'a, Ed25519: ?Sized, P256: ?Sized> {
    pub payload: &'a [u8],
    pub algorithm: AlgorithmId,
    pub key: SigningKey<'a, Ed25519, P256>,
    /// Optional unsigned lookup hint. When present, it contains 1..=1024 UTF-8
    /// octets without CR or LF.
    pub keyid: Option<&'a str>,
    pub append_missing_final_newline: bool,
    pub output_form: OutputForm,
    pub algorithm_parameters: &'a [u8],
}

/// Borrowed signing keys for supported algorithms. `Debug` redacts key material.
pub enum SigningKey<'a, Ed25519: ?Sized, P256: ?Sized> {
    Ed25519(&'a Ed25519),
    EcdsaP256Sha256(&'a P256),
}

impl<Ed25519: ?Sized, P256: ?Sized> Clone for SigningKey<'_, Ed25519, P256> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Ed25519: ?Sized, P256: ?Sized> Copy for SigningKey<'_, Ed25519, P256> {}

impl<Ed25519: ?Sized, P256: ?Sized> fmt::Debug for SigningKey<'_, Ed25519, P256> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningKey::Ed25519(_) => f.write_str("SigningKey::Ed25519(***)"),
            SigningKey::EcdsaP256Sha256(_) => f.write_str("SigningKey::EcdsaP256Sha256(***)"),
        }
    }
}

/// Synchronous signing contract for interchangeable implementations.
///
/// Use generic bounds or trait objects with explicit associated key types.
///
/// An implementation may narrow this contract, such as ignoring `req.key`
/// when it owns no key. Document any narrowing in the implementation crate's README.
pub trait Signer {
    /// Concrete Ed25519 signing-key type accepted by this implementation.
    type Ed25519SigningKey: ?Sized;
    /// Concrete ECDSA P-256 signing-key type accepted by this implementation.
    type P256SigningKey: ?Sized;

    /// Capability surface this signer advertises (IDL `SignerCapabilitiesResponse`).
    fn capabilities(&self) -> SignerCapabilities;
    /// Unified sign entry (IDL `Sign`).
    fn sign(
        &self,
        req: &SignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
    ) -> SignOutcome;
}

/// Async signing with the same method semantics as [`Signer`].
///
/// [`AsyncSigner::sign`] returns a native `impl Future` with a `Send` bound.
/// Implementations must be `Send + Sync`. Use generic bounds such as
/// `<S: AsyncSigner>`; this trait is not object-safe.
///
/// Implementations may document the contract narrowings permitted by [`Signer`].
pub trait AsyncSigner: Send + Sync {
    /// Concrete Ed25519 signing-key type accepted by this implementation.
    type Ed25519SigningKey: Sync + ?Sized;
    /// Concrete ECDSA P-256 signing-key type accepted by this implementation.
    type P256SigningKey: Sync + ?Sized;

    /// Capability surface this signer advertises (same shape as the sync trait).
    fn capabilities(&self) -> SignerCapabilities;
    /// Unified async sign entry.
    fn sign<'a>(
        &'a self,
        req: &'a SignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
    ) -> impl core::future::Future<Output = SignOutcome> + Send + 'a;
}

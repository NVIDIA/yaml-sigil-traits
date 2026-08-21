// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Signing API: the `Signer` / `AsyncSigner` extension-trait pair and the
//! request/response/error/capability DTOs their signatures reference.
//!
//! The free-function surface (`sign`, `sign_yaml`, `sign_proto`, …) and the
//! `DefaultSigner` / `DefaultAsyncSigner` ZSTs live in `yaml-sigil-signing`,
//! which re-exports these items.

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
/// [`InvalidAlgorithmParameters`](SignError::InvalidAlgorithmParameters) are also returned by
/// convenience wrappers `sign_yaml` / `sign_proto` when mapping [`SignInvocationError`], so
/// existing callers keep stable `Result<_, SignError>` typing.
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

/// Unified signing outcome: success, invocation error, or sign-time error.
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

/// Unified sign request (subset of IDL `SignRequest`: no private-key handle).
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

/// Private key material for supported algorithms (never logged).
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

/// Public extension point: any signer implementation in the workspace (or downstream)
/// implements this trait. Mirrors the free-function surface so callers can swap
/// implementations behind `&dyn Signer` or generic bounds.
///
/// Downstream implementations MAY document additional contract narrowings — for
/// example, ignoring `req.key` when the signer owns no key. Such narrowings
/// belong in the implementation crate's README,
/// not in this trait's contract.
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

/// Async sibling of [`Signer`]. Same method semantics; the only difference is
/// that [`AsyncSigner::sign`] returns a `Future`.
///
/// Trait shape uses native AFIT/RPITIT with explicit `+ Send` on the returned
/// future and `Send + Sync` super-bounds on the trait. This is the
/// forward-compatible choice (no `async-trait` heap allocation) at the cost of
/// not being object-safe — use generic bounds (`<S: AsyncSigner>`), not
/// `&dyn AsyncSigner`. See this repository's `AGENTS.md`.
///
/// Downstream implementations MAY document the same contract narrowings
/// the sync trait permits.
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

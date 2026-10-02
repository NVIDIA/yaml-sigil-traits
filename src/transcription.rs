// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Transcription traits and their request, response, error, and capability types.
//!
//! `yaml-sigil-transcription` re-exports these types and provides `compose`
//! and `decompose`, with the `DefaultTranscriber` and
//! `DefaultAsyncTranscriber` zero-sized types.

use crate::{ArtifactResourceError, ArtifactResourceLimits, EncodeError, OuterConformance};
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
use thiserror::Error;

/// Envelope form (IDL `TranscriptionForm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranscriptionForm {
    Yaml,
    Protobuf,
}

/// Structural outcome of Decompose (IDL `DecomposeOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecomposeOutcome {
    Ok,
    Unsigned,
    MalformedAttemptedSigned,
}

/// Payload and signature carrier recovered by successful decomposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractArtifact<'input> {
    pub payload: &'input [u8],
    pub signature_carrier: &'input [u8],
}

/// Request-shape failure (IDL `TranscriberInvocationError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TranscriberInvocationError {
    #[error("invalid or unsupported form")]
    InvalidOrUnsupportedForm,
    #[error("invalid or unsupported outer conformance")]
    InvalidOrUnsupportedOuterConformance,
}

/// Compose-time failure after invocation validation (IDL `TranscriberError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TranscriberError {
    #[error("invalid payload bytes")]
    InvalidPayloadBytes,
    #[error("signature carrier contains a constrained marker at a line start")]
    InvalidSignatureCarrier,
}

/// Failures of composition, separated by stage.
#[derive(Debug, Error)]
pub enum ComposeError {
    #[error(transparent)]
    Invocation(#[from] TranscriberInvocationError),
    #[error(transparent)]
    Resource(#[from] ArtifactResourceError),
    #[error(transparent)]
    Encoding(#[from] EncodeError),
    #[error(transparent)]
    Content(#[from] TranscriberError),
}

/// Owned composition output or a categorized error.
#[cfg(feature = "alloc")]
pub type ComposeOutcome = Result<ComposeSuccess, ComposeError>;

/// Successful Compose output.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeSuccess {
    pub artifact: Vec<u8>,
    pub form: TranscriptionForm,
}

/// Invocation and resource failures of decomposition.
#[derive(Debug, Error)]
pub enum DecomposeError {
    #[error(transparent)]
    Invocation(#[from] TranscriberInvocationError),
    #[error(transparent)]
    Resource(#[from] ArtifactResourceError),
}

/// Structural artifact state or an invocation/resource error.
#[cfg(feature = "alloc")]
pub type DecomposeResponse<'input> = Result<DecomposeStructuralResult<'input>, DecomposeError>;

/// Structural Decompose output (IDL `DecomposeStructuralResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub struct DecomposeStructuralResult<'input> {
    pub outcome: DecomposeOutcome,
    pub payload: Option<&'input [u8]>,
    pub signature_carrier: Option<&'input [u8]>,
    pub detail: Option<String>,
}

/// Inputs to Compose.
pub struct ComposeRequest<'a> {
    pub payload: &'a [u8],
    pub signature_carrier: &'a [u8],
    pub form: TranscriptionForm,
    pub resource_limits: ArtifactResourceLimits,
}

/// Inputs to Decompose.
pub struct DecomposeRequest<'a> {
    pub artifact: &'a [u8],
    pub form: TranscriptionForm,
    /// Use `Some` for protobuf and `None` for YAML.
    ///
    /// Report [`TranscriberInvocationError::InvalidOrUnsupportedOuterConformance`]
    /// if the policy does not match the requested form.
    pub outer_conformance: Option<OuterConformance>,
    pub resource_limits: ArtifactResourceLimits,
}

/// Typed capability surface (IDL `TranscriberCapabilitiesResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriberCapabilities {
    pub supported_forms: &'static [TranscriptionForm],
    pub supported_outer_conformances: &'static [OuterConformance],
    pub emits_canonical_yaml_envelope: bool,
    pub implementation_name: &'static str,
    pub implementation_version: &'static str,
}

/// Synchronous transcription contract for interchangeable implementations.
#[cfg(feature = "alloc")]
pub trait Transcriber {
    /// Capability surface this transcriber advertises.
    fn capabilities(&self) -> TranscriberCapabilities;
    /// Compose envelope-form bytes from an abstract Artifact.
    fn compose(&self, req: &ComposeRequest<'_>) -> ComposeOutcome;
    /// Decompose envelope-form bytes back to an abstract Artifact.
    fn decompose<'input>(&self, req: &DecomposeRequest<'input>) -> DecomposeResponse<'input>;
}

/// Async transcription with the same method semantics as [`Transcriber`].
///
/// `compose` and `decompose` return native `impl Future` values with `Send`
/// bounds. Implementations must be `Send + Sync`. Use generic bounds such as
/// `<T: AsyncTranscriber>`; this trait is not object-safe.
#[cfg(feature = "alloc")]
pub trait AsyncTranscriber: Send + Sync {
    /// Capability surface this transcriber advertises.
    fn capabilities(&self) -> TranscriberCapabilities;
    /// Compose envelope-form bytes from an abstract Artifact.
    fn compose<'a>(
        &'a self,
        req: &'a ComposeRequest<'_>,
    ) -> impl core::future::Future<Output = ComposeOutcome> + Send + 'a;
    /// Decompose envelope-form bytes back to an abstract Artifact.
    fn decompose<'call, 'input: 'call>(
        &'call self,
        req: &'call DecomposeRequest<'input>,
    ) -> impl core::future::Future<Output = DecomposeResponse<'input>> + Send + 'call;
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Transcription API: the `Transcriber` / `AsyncTranscriber` extension-trait
//! pair and the request/response/error/capability DTOs their signatures
//! reference.
//!
//! The free-function surface (`compose`, `decompose`, …) and the
//! `DefaultTranscriber` / `DefaultAsyncTranscriber` ZSTs live in
//! `yaml-sigil-transcription`, which re-exports these items.

use crate::OuterConformance;
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

/// Recovered abstract Artifact when [`DecomposeOutcome`] is `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractArtifact {
    pub payload: Vec<u8>,
    pub signature_carrier: Vec<u8>,
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
}

/// Unified Compose result.
#[derive(Debug)]
pub enum ComposeOutcome {
    Success(ComposeSuccess),
    Invocation(TranscriberInvocationError),
    Error(TranscriberError),
}

/// Successful Compose output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeSuccess {
    pub artifact: Vec<u8>,
    pub form: TranscriptionForm,
}

/// Unified Decompose result.
#[derive(Debug)]
pub enum DecomposeResponse {
    Structural(DecomposeStructuralResult),
    Invocation(TranscriberInvocationError),
}

/// Structural Decompose output (IDL `DecomposeStructuralResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecomposeStructuralResult {
    pub outcome: DecomposeOutcome,
    pub payload: Option<Vec<u8>>,
    pub signature_carrier: Option<Vec<u8>>,
    pub detail: Option<String>,
}

/// Inputs to Compose.
pub struct ComposeRequest<'a> {
    pub payload: &'a [u8],
    pub signature_carrier: &'a [u8],
    pub form: TranscriptionForm,
}

/// Inputs to Decompose.
pub struct DecomposeRequest<'a> {
    pub artifact: &'a [u8],
    pub form: TranscriptionForm,
    /// Required for protobuf; must be `Unspecified` only for YAML (not represented — use invocation error if set wrongly).
    pub outer_conformance: Option<OuterConformance>,
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

/// Public extension point: any transcriber implementation in the workspace (or
/// downstream) implements this trait. Mirrors the free-function surface.
pub trait Transcriber {
    /// Capability surface this transcriber advertises.
    fn capabilities(&self) -> TranscriberCapabilities;
    /// Compose envelope-form bytes from an abstract Artifact.
    fn compose(&self, req: &ComposeRequest<'_>) -> ComposeOutcome;
    /// Decompose envelope-form bytes back to an abstract Artifact.
    fn decompose(&self, req: &DecomposeRequest<'_>) -> DecomposeResponse;
}

/// Async sibling of [`Transcriber`]. Same method semantics; `compose` and
/// `decompose` return `Future`s instead of being synchronous.
///
/// Trait shape uses native AFIT/RPITIT with explicit `+ Send` on returned
/// futures and `Send + Sync` super-bounds. Not object-safe — use generic
/// bounds (`<T: AsyncTranscriber>`), not `&dyn AsyncTranscriber`. See
/// this repository's `AGENTS.md`.
pub trait AsyncTranscriber: Send + Sync {
    /// Capability surface this transcriber advertises.
    fn capabilities(&self) -> TranscriberCapabilities;
    /// Compose envelope-form bytes from an abstract Artifact.
    fn compose<'a>(
        &'a self,
        req: &'a ComposeRequest<'_>,
    ) -> impl core::future::Future<Output = ComposeOutcome> + Send + 'a;
    /// Decompose envelope-form bytes back to an abstract Artifact.
    fn decompose<'a>(
        &'a self,
        req: &'a DecomposeRequest<'_>,
    ) -> impl core::future::Future<Output = DecomposeResponse> + Send + 'a;
}

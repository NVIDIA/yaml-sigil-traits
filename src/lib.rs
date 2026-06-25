// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared trait + DTO surface for the YamlSigil v1alpha1 APIs.
//!
//! Houses the synchronous + async extension-trait pairs and the
//! request/response/error/capability DTOs their method signatures reference:
//!
//! - [`signing::Signer`] / [`signing::AsyncSigner`]
//! - [`transcription::Transcriber`] / [`transcription::AsyncTranscriber`]
//! - [`verification::Verifier`] / [`verification::AsyncVerifier`]
//!
//! The free-function implementations and the `Default*` ZSTs live in the three
//! API crates (`yaml-sigil-signing`, `yaml-sigil-transcription`,
//! `yaml-sigil-verification`), which depend on this crate and re-export these
//! items so existing import paths (e.g. `yaml_sigil_signing::Signer`) keep
//! working.
//!
//! The async traits use native AFIT/RPITIT with explicit `+ Send` bounds and
//! `Send + Sync` super-bounds (no `async-trait`), so they are not object-safe —
//! use generic bounds (`<S: AsyncSigner>`), not `&dyn AsyncSigner`. See
//! this repository's `AGENTS.md`.

pub mod algorithm;
pub mod conformance;
pub mod signing;
pub mod transcription;
pub mod verification;

pub use algorithm::AlgorithmId;
pub use conformance::{
    OuterConformance, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};

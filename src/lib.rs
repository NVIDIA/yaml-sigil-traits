// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared Rust traits and data types for the YamlSigil v1alpha1 APIs.
//!
//! Use the synchronous or async traits with their request, response, error,
//! and capability types:
//!
//! - [`signing::Signer`] / [`signing::AsyncSigner`]
//! - [`transcription::Transcriber`] / [`transcription::AsyncTranscriber`]
//! - [`verification::Verifier`] / [`verification::AsyncVerifier`]
//!
//! Implementation crates own free-function APIs, default zero-sized types,
//! parsing, and cryptography. The `yaml-sigil-signing`,
//! `yaml-sigil-transcription`, and `yaml-sigil-verification` crates depend on
//! this crate and re-export its traits and data types.
//!
//! Async traits return native `impl Future` values with `Send` bounds and
//! require `Send + Sync` implementations. Use generic bounds such as
//! `<S: AsyncSigner>`; these traits are not object-safe.

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

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared Rust traits and data types for the YamlSigil v1alpha1 APIs.
//!
//! With `alloc`, use the synchronous or async traits with their request,
//! response, error, and capability types:
//!
//! - [`v1alpha1::signing`]: `Signer` / `AsyncSigner`
//! - [`v1alpha1::transcription`]: `Transcriber` / `AsyncTranscriber`
//! - [`v1alpha1::verification`]: `Verifier` / `AsyncVerifier`
//!
//! Select [`v1alpha1`] explicitly in new integrations. The unqualified paths
//! remain the default for this specification version and name the same traits
//! and types. The specification identifier is independent of this crate's
//! package version.
//!
//! Implementation crates own free-function APIs, default zero-sized types,
//! parsing, and cryptography. The `yaml-sigil-signing`,
//! `yaml-sigil-transcription`, and `yaml-sigil-verification` crates depend on
//! this crate and re-export its traits and data types.
//!
//! Async traits return native `impl Future` values with `Send` bounds and
//! require `Send + Sync` implementations. Use generic bounds such as
//! `<S: AsyncSigner>`; these traits are not object-safe.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

pub mod algorithm;
pub mod codec;
pub mod conformance;
pub mod resource;
pub mod signing;
pub mod transcription;
pub mod verification;

pub use algorithm::AlgorithmId;
pub use codec::{
    ArtifactDecodeError, ArtifactEncodeError, DecodeError, DecodeErrorKind, EncodeError,
    EncodeErrorKind,
};
pub use conformance::{
    OuterConformance, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
pub use resource::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};

/// The YamlSigil `v1alpha1` trait and data contract.
///
/// These are re-exports of the existing definitions. Values and trait
/// implementations work through either path without conversion or adapters.
/// Unqualified paths remain supported as the `v1alpha1` default.
///
/// ```
/// use yaml_sigil_traits::{AlgorithmId, v1alpha1};
///
/// let versioned: v1alpha1::AlgorithmId = AlgorithmId::Ed25519;
/// let default: AlgorithmId = versioned;
/// assert_eq!(default, v1alpha1::algorithm::AlgorithmId::Ed25519);
/// ```
pub mod v1alpha1 {
    pub use crate::{
        AlgorithmId, ArtifactDecodeError, ArtifactEncodeError, ArtifactResourceError,
        ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
        ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES, DecodeError, DecodeErrorKind,
        EncodeError, EncodeErrorKind, OuterConformance, ProtobufWireDecodeAdvertisement,
        YamlSignatureDocumentDuplicateKeyPolicy, YamlSignatureDocumentUnknownFieldPolicy,
        algorithm, codec, conformance, resource, signing, transcription, verification,
    };
}

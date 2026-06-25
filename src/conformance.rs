// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Portable conformance and capability vocabulary shared by the public trait DTOs.
//!
//! Build-specific policy defaults and YAML-backend helpers live in
//! `yaml-sigil-core`; this module owns only the protobuf/YAML-backend-free
//! enum vocabulary needed by downstream trait implementations.

/// Duplicate keys in the signature-document YAML mapping (e.g. two `alg:` keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YamlSignatureDocumentDuplicateKeyPolicy {
    /// With every optional YAML backend enabled in CI (`cargo test --all-features`),
    /// parsing the signature document returns an error whose message contains
    /// `"duplicate"`.
    RejectedAtParse,
}

/// Unknown top-level keys in the signature-document mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YamlSignatureDocumentUnknownFieldPolicy {
    /// Default: serde without `deny_unknown_fields`; extra keys are dropped at parse.
    IgnoredAtParse,
    /// Parse-time rejection, e.g. when `yaml-sigil-core` enables
    /// `yaml-strict-unknown-fields`.
    RejectedAtParse,
    /// Verify-time rejection after enumerating signature-document keys.
    RejectedAtVerify,
}

/// How protobuf `SignedYamlArtifact` wire bytes are decoded in this workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtobufWireDecodeAdvertisement {
    /// Stock **buffa** or **prost** generated `decode`; no custom decoder and no Strict / Permissive /
    /// SignatureStrict profile flag.
    UnprofiledStockDecoder,
}

/// Outer-envelope conformance for protobuf-form `Decompose` (Transcription API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OuterConformance {
    /// Reject unknown outer fields and duplicate outer `payload` / `signature`.
    Strict,
    /// Reject duplicate outer `signature`; permissive on other outer unknowns; last-wins `payload`.
    SignatureStrict,
}

// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Portable conformance and capability vocabulary shared by the public trait DTOs.
//!
//! Implementations advertise these policies through capability DTOs. They
//! own the parser backends and policy defaults; this module defines the enum
//! vocabulary without depending on a YAML or protobuf backend.

/// Policy for duplicate keys in a signature-document YAML mapping, such as two `alg:` keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YamlSignatureDocumentDuplicateKeyPolicy {
    /// The parser rejects duplicate signature-document keys with an error
    /// message containing `"duplicate"`.
    RejectedAtParse,
}

/// Unknown top-level keys in the signature-document mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YamlSignatureDocumentUnknownFieldPolicy {
    /// The parser drops unknown keys.
    IgnoredAtParse,
    /// The parser rejects unknown keys.
    RejectedAtParse,
    /// The verifier rejects unknown keys after enumerating the signature document.
    RejectedAtVerify,
}

/// Advertised decoding behavior for protobuf `SignedYamlArtifact` wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtobufWireDecodeAdvertisement {
    /// Use a stock generated `buffa` or `prost` decoder without a
    /// Strict, Permissive, or SignatureStrict profile flag.
    UnprofiledStockDecoder,
}

/// Outer-envelope conformance for protobuf-form `Decompose` (Transcription API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OuterConformance {
    /// Reject unknown outer fields and duplicate outer `payload` / `signature`.
    Strict,
    /// Reject duplicate outer `signature` fields, accept unknown outer fields,
    /// and use the last outer `payload` value.
    SignatureStrict,
}

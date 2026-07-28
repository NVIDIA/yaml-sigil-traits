// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Canonical algorithm identifiers and YAML `alg:` string mapping.
//!
//! Per the `yaml-sigil-spec` README "The Signature Document": YAML `alg:` and
//! JSON Schema use the unprefixed canonical names;
//! the protobuf `Algorithm` enum uses Buf-prefixed constants
//! (`ALGORITHM_…_…`). This module keeps the portable, protobuf-crate-free
//! contract identifier. Protobuf enum conversions live in `yaml-sigil-core`.

/// Implementation-authoritative algorithm identifiers (wire + YAML).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmId {
    /// Ed25519 PureEdDSA, raw `R || S` 64 octets, canonical-encoding rejection.
    /// YAML / JSON Schema spelling: `ED25519_PUREEDDSA_RAW_RS64_CANONICAL`.
    /// Protobuf enum constant: `ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL` (slot 1).
    Ed25519,
    /// ECDSA over secp256r1 (NIST P-256) with SHA-256, raw `R || S` 64 octets.
    /// YAML / JSON Schema spelling: `ECDSA_SECP256R1_SHA256_RAW_RS64`.
    /// Protobuf enum constant: `ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64` (slot 2).
    EcdsaP256Sha256,
}

impl AlgorithmId {
    pub const fn as_yaml_str(self) -> &'static str {
        match self {
            AlgorithmId::Ed25519 => "ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
            AlgorithmId::EcdsaP256Sha256 => "ECDSA_SECP256R1_SHA256_RAW_RS64",
        }
    }

    /// Parses an exact canonical YAML `alg` scalar value.
    ///
    /// This function does not trim or otherwise normalize the input.
    pub fn from_yaml_str(s: &str) -> Option<Self> {
        match s {
            "ED25519_PUREEDDSA_RAW_RS64_CANONICAL" => Some(AlgorithmId::Ed25519),
            "ECDSA_SECP256R1_SHA256_RAW_RS64" => Some(AlgorithmId::EcdsaP256Sha256),
            _ => None,
        }
    }

    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(AlgorithmId::Ed25519),
            2 => Some(AlgorithmId::EcdsaP256Sha256),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AlgorithmId;

    #[test]
    fn yaml_str_mapping() {
        assert_eq!(
            AlgorithmId::from_yaml_str("ED25519_PUREEDDSA_RAW_RS64_CANONICAL"),
            Some(AlgorithmId::Ed25519)
        );
        assert_eq!(
            AlgorithmId::from_yaml_str("ECDSA_SECP256R1_SHA256_RAW_RS64"),
            Some(AlgorithmId::EcdsaP256Sha256)
        );
        assert_eq!(AlgorithmId::from_yaml_str("nope"), None);
        assert_eq!(
            AlgorithmId::from_yaml_str("ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL"),
            None,
            "protobuf-prefixed form is not a valid YAML alg"
        );
        assert_eq!(
            AlgorithmId::Ed25519.as_yaml_str(),
            "ED25519_PUREEDDSA_RAW_RS64_CANONICAL"
        );
    }

    #[test]
    fn yaml_str_mapping_rejects_surrounding_whitespace() {
        for value in [
            " ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
            "ED25519_PUREEDDSA_RAW_RS64_CANONICAL ",
            "\tECDSA_SECP256R1_SHA256_RAW_RS64",
            "ECDSA_SECP256R1_SHA256_RAW_RS64\n",
        ] {
            assert_eq!(AlgorithmId::from_yaml_str(value), None);
        }
    }

    #[test]
    fn wire_i32_mapping() {
        assert_eq!(AlgorithmId::from_i32(1), Some(AlgorithmId::Ed25519));
        assert_eq!(AlgorithmId::from_i32(2), Some(AlgorithmId::EcdsaP256Sha256));
        assert_eq!(AlgorithmId::from_i32(0), None);
        assert_eq!(AlgorithmId::from_i32(99), None);
    }
}

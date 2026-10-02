// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Portable, content-free protobuf format error categories.

use core::fmt;

/// Stable categories for protobuf decoding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input ended before the current value was complete.
    UnexpectedEnd,
    /// A varint exceeded the protobuf encoding width.
    InvalidVarint,
    /// A tag contained field number zero or an unrepresentable field number.
    InvalidFieldNumber,
    /// A tag used a wire type that protobuf does not define.
    InvalidWireType,
    /// A known field used a wire type other than its schema-defined type.
    UnexpectedWireType,
    /// A protobuf `string` field was not valid UTF-8.
    InvalidUtf8,
    /// The input exceeded the protobuf message-size ceiling.
    MessageTooLarge,
    /// The input exceeded the decoder's nesting safeguard.
    RecursionLimitExceeded,
    /// The input exceeded the decoder's unknown-field safeguard.
    UnknownFieldLimitExceeded,
    /// The input exceeded the decoder's element-memory safeguard.
    ElementMemoryLimitExceeded,
    /// A protobuf group was incomplete or had a mismatched terminator.
    InvalidGroup,
    /// A decoder failure did not match another stable category.
    Other,
}

impl DecodeErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::UnexpectedEnd => "unexpected end of input",
            Self::InvalidVarint => "invalid varint",
            Self::InvalidFieldNumber => "invalid field number",
            Self::InvalidWireType => "invalid wire type",
            Self::UnexpectedWireType => "unexpected wire type for field",
            Self::InvalidUtf8 => "invalid UTF-8 string field",
            Self::MessageTooLarge => "message exceeds the protobuf size ceiling",
            Self::RecursionLimitExceeded => "decoder recursion safeguard exceeded",
            Self::UnknownFieldLimitExceeded => "decoder unknown-field safeguard exceeded",
            Self::ElementMemoryLimitExceeded => "decoder element-memory safeguard exceeded",
            Self::InvalidGroup => "invalid protobuf group",
            Self::Other => "other protobuf decode failure",
        }
    }
}

/// Opaque, redacted protobuf decoding error.
#[derive(Clone, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeErrorKind,
}

impl DecodeError {
    /// Return the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    /// Construct a content-free error from its portable category.
    #[must_use]
    pub const fn from_kind(kind: DecodeErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Debug for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "protobuf decode failed: {}",
            self.kind.description()
        )
    }
}

impl core::error::Error for DecodeError {}

/// Stable categories for protobuf encoding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeErrorKind {
    /// The encoded message would exceed the protobuf size ceiling.
    MessageTooLarge,
    /// An encoder failure did not match another stable category.
    Other,
}

impl EncodeErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::MessageTooLarge => "message exceeds the protobuf size ceiling",
            Self::Other => "other protobuf encode failure",
        }
    }
}

/// Opaque, redacted protobuf encoding error.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodeError {
    kind: EncodeErrorKind,
}

impl EncodeError {
    /// Return the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> EncodeErrorKind {
        self.kind
    }

    pub const fn message_too_large() -> Self {
        Self {
            kind: EncodeErrorKind::MessageTooLarge,
        }
    }

    pub const fn other() -> Self {
        Self {
            kind: EncodeErrorKind::Other,
        }
    }
}

impl fmt::Debug for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "protobuf encode failed: {}",
            self.kind.description()
        )
    }
}

impl core::error::Error for EncodeError {}

/// Failure to decode an artifact under its complete-input policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactDecodeError {
    /// The original encoded input exceeds the selected resource policy.
    #[error(transparent)]
    Resource(#[from] crate::ArtifactResourceError),
    /// The input violates protobuf encoding or decoder safeguards.
    #[error(transparent)]
    Decoding(#[from] DecodeError),
}

/// Failure to encode an artifact under its complete-output policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactEncodeError {
    /// Projected output violates the selected resource policy.
    #[error(transparent)]
    Resource(#[from] crate::ArtifactResourceError),
    /// Output violates protobuf encoding limits.
    #[error(transparent)]
    Encoding(#[from] EncodeError),
}

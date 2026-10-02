// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Opt-in complete-artifact resource policy.
//!
//! YamlSigil `v1alpha1` does not define a maximum complete artifact size.
//! This module provides implementation-local limits that callers can select
//! explicitly at a trust boundary. Existing entry points do not apply these
//! limits implicitly.
//!
//! # Selecting a policy
//!
//! [`ArtifactResourceLimits::default`] selects
//! [`DEFAULT_MAX_ARTIFACT_BYTES`]. You can lower, raise, or disable that
//! ceiling without changing the operation that receives the policy.
//!
//! ```
//! use core::num::NonZeroUsize;
//! use yaml_sigil_traits::v1alpha1::{ArtifactResourceLimits, DEFAULT_MAX_ARTIFACT_BYTES};
//!
//! let default_limit = ArtifactResourceLimits::default();
//! assert_eq!(
//!     default_limit.max_artifact_bytes().unwrap().get(),
//!     DEFAULT_MAX_ARTIFACT_BYTES,
//! );
//!
//! let lower = ArtifactResourceLimits::unbounded()
//!     .with_max_artifact_bytes(NonZeroUsize::new(1024 * 1024).unwrap());
//! let higher = ArtifactResourceLimits::unbounded()
//!     .with_max_artifact_bytes(NonZeroUsize::new(32 * 1024 * 1024).unwrap());
//! let unbounded = ArtifactResourceLimits::unbounded();
//!
//! assert_eq!(lower.max_artifact_bytes().unwrap().get(), 1024 * 1024);
//! assert_eq!(higher.max_artifact_bytes().unwrap().get(), 32 * 1024 * 1024);
//! assert_eq!(unbounded.max_artifact_bytes(), None);
//! ```
//!
//! # Filtering existing operations
//!
//! The input check returns the original slice, so you can apply it before an
//! existing operation without copying bytes.
//!
//! ```
//! use yaml_sigil_traits::v1alpha1::{
//!     ArtifactResourceForm, ArtifactResourceLimits,
//! };
//!
//! let input = b"document: true\n";
//! let checked = ArtifactResourceLimits::default()
//!     .check_input_size(ArtifactResourceForm::Yaml, input)
//!     .unwrap();
//! assert_eq!(checked.as_ptr(), input.as_ptr());
//! ```

use core::fmt;
use core::num::NonZeroUsize;

/// The explicitly selected `yaml-sigil-rs` default artifact ceiling, in bytes.
///
/// This is an implementation default, not a YamlSigil specification
/// requirement.
pub const DEFAULT_MAX_ARTIFACT_BYTES: usize = 4_194_304;

/// Encoded artifact form used by resource-policy diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactResourceForm {
    /// Signed YAML stream bytes.
    Yaml,
    /// Protobuf `SignedYamlArtifact` wire bytes.
    Protobuf,
}

impl ArtifactResourceForm {
    const fn description(self) -> &'static str {
        match self {
            Self::Yaml => "YAML",
            Self::Protobuf => "protobuf",
        }
    }
}

/// Stable category for an artifact resource-policy failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactResourceErrorKind {
    /// A complete encoded input exceeds the configured ceiling.
    InputArtifactTooLarge,
    /// A complete encoded output exceeds the configured ceiling.
    OutputArtifactTooLarge,
    /// The complete output size cannot be represented safely.
    SizeComputationOverflow,
}

impl ArtifactResourceErrorKind {
    const fn description(self) -> &'static str {
        match self {
            Self::InputArtifactTooLarge => "input artifact exceeds the configured byte ceiling",
            Self::OutputArtifactTooLarge => "output artifact exceeds the configured byte ceiling",
            Self::SizeComputationOverflow => "artifact size computation overflowed",
        }
    }
}

/// Opaque, content-free resource-policy failure.
///
/// The error retains only categories and byte counts. It never retains
/// artifact, payload, signature, carrier, key, or malformed trailing bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactResourceError {
    kind: ArtifactResourceErrorKind,
    artifact_form: Option<ArtifactResourceForm>,
    configured_max_artifact_bytes: Option<usize>,
    observed_or_projected_artifact_bytes: Option<usize>,
}

impl ArtifactResourceError {
    const fn new(
        kind: ArtifactResourceErrorKind,
        artifact_form: ArtifactResourceForm,
        configured_max_artifact_bytes: Option<usize>,
        observed_or_projected_artifact_bytes: Option<usize>,
    ) -> Self {
        Self {
            kind,
            artifact_form: Some(artifact_form),
            configured_max_artifact_bytes,
            observed_or_projected_artifact_bytes,
        }
    }

    /// Return the stable resource failure category.
    #[must_use]
    pub const fn kind(&self) -> ArtifactResourceErrorKind {
        self.kind
    }

    /// Return the encoded artifact form associated with this failure.
    ///
    /// The initial byte-oriented failures always return `Some`. The optional
    /// shape leaves room for a future resource category unrelated to one
    /// encoded form.
    #[must_use]
    pub const fn artifact_form(&self) -> Option<ArtifactResourceForm> {
        self.artifact_form
    }

    /// Return the configured complete-artifact byte ceiling, when finite.
    #[must_use]
    pub const fn configured_max_artifact_bytes(&self) -> Option<usize> {
        self.configured_max_artifact_bytes
    }

    /// Return an exact observed or projected artifact size, when known.
    ///
    /// Exact input and output rejections report their byte count. A
    /// conclusive lower-bound output rejection returns `None`: it proves
    /// that the output cannot fit without claiming its final exact size.
    /// Representational overflow also returns `None`.
    #[must_use]
    pub const fn observed_or_projected_artifact_bytes(&self) -> Option<usize> {
        self.observed_or_projected_artifact_bytes
    }
}

impl fmt::Debug for ArtifactResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactResourceError")
            .field("kind", &self.kind)
            .field("artifact_form", &self.artifact_form)
            .field(
                "configured_max_artifact_bytes",
                &self.configured_max_artifact_bytes,
            )
            .field(
                "observed_or_projected_artifact_bytes",
                &self.observed_or_projected_artifact_bytes,
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ArtifactResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} resource check failed",
            self.artifact_form
                .map_or("artifact", ArtifactResourceForm::description),
            self.kind.description()
        )?;
        if let Some(maximum) = self.configured_max_artifact_bytes {
            write!(formatter, " (configured maximum: {maximum} bytes")?;
            if let Some(observed) = self.observed_or_projected_artifact_bytes {
                write!(formatter, ", observed or projected: {observed} bytes")?;
            }
            formatter.write_str(")")?;
        }
        Ok(())
    }
}

impl core::error::Error for ArtifactResourceError {}

/// Result layer used by opt-in artifact resource checks.
pub type ArtifactResourceResult<T> = Result<T, ArtifactResourceError>;

/// Opaque, forward-compatible artifact resource policy.
///
/// The first policy dimension is a maximum complete encoded artifact size.
/// Fields remain private so later releases can add separately configured
/// dimensions without changing operation signatures.
///
/// New dimensions remain disabled in [`Self::default`] in compatible releases
/// until you explicitly enable them. Enabling a new dimension by default is a
/// behavioral breaking change. Dimension-specific builders preserve every other
/// setting, while [`Self::unbounded`] disables every optional dimension known to
/// this crate version.
///
/// This type deliberately does not implement `Copy`:
///
/// ```compile_fail
/// use yaml_sigil_traits::v1alpha1::ArtifactResourceLimits;
///
/// fn require_copy<T: Copy>() {}
/// require_copy::<ArtifactResourceLimits>();
/// ```
///
/// Its fields are not directly constructible:
///
/// ```compile_fail
/// use yaml_sigil_traits::v1alpha1::ArtifactResourceLimits;
///
/// let _ = ArtifactResourceLimits {
///     max_artifact_bytes: None,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactResourceLimits {
    max_artifact_bytes: Option<NonZeroUsize>,
}

impl ArtifactResourceLimits {
    /// Disable every optional resource dimension known to this crate version.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_artifact_bytes: None,
        }
    }

    /// Return the configured complete-artifact byte ceiling.
    #[must_use]
    pub const fn max_artifact_bytes(&self) -> Option<NonZeroUsize> {
        self.max_artifact_bytes
    }

    /// Replace the complete-artifact byte ceiling.
    ///
    /// Other present or future policy dimensions are preserved.
    #[must_use]
    pub const fn with_max_artifact_bytes(mut self, maximum: NonZeroUsize) -> Self {
        self.max_artifact_bytes = Some(maximum);
        self
    }

    /// Disable only the complete-artifact byte ceiling.
    ///
    /// Other present or future policy dimensions are preserved.
    #[must_use]
    pub const fn without_max_artifact_byte_limit(mut self) -> Self {
        self.max_artifact_bytes = None;
        self
    }

    /// Check the exact byte length of a complete encoded input.
    ///
    /// On success this returns the original slice without copying it.
    pub fn check_input_size<'a>(
        &self,
        form: ArtifactResourceForm,
        artifact: &'a [u8],
    ) -> ArtifactResourceResult<&'a [u8]> {
        match self.max_artifact_bytes {
            Some(maximum) if artifact.len() > maximum.get() => Err(ArtifactResourceError::new(
                ArtifactResourceErrorKind::InputArtifactTooLarge,
                form,
                Some(maximum.get()),
                Some(artifact.len()),
            )),
            _ => Ok(artifact),
        }
    }

    /// Check the exact byte length of a complete encoded output.
    ///
    /// On success this returns `encoded_size`.
    pub fn check_output_size(
        &self,
        form: ArtifactResourceForm,
        encoded_size: usize,
    ) -> ArtifactResourceResult<usize> {
        match self.max_artifact_bytes {
            Some(maximum) if encoded_size > maximum.get() => Err(ArtifactResourceError::new(
                ArtifactResourceErrorKind::OutputArtifactTooLarge,
                form,
                Some(maximum.get()),
                Some(encoded_size),
            )),
            _ => Ok(encoded_size),
        }
    }

    /// Check a conclusive lower bound for a complete encoded output.
    ///
    /// This rejects only when `minimum_encoded_size` already exceeds the
    /// configured ceiling. A successful lower-bound check never replaces the
    /// final [`Self::check_output_size`] call with the exact encoded size.
    pub fn check_output_size_lower_bound(
        &self,
        form: ArtifactResourceForm,
        minimum_encoded_size: usize,
    ) -> ArtifactResourceResult<usize> {
        match self.max_artifact_bytes {
            Some(maximum) if minimum_encoded_size > maximum.get() => {
                Err(ArtifactResourceError::new(
                    ArtifactResourceErrorKind::OutputArtifactTooLarge,
                    form,
                    Some(maximum.get()),
                    None,
                ))
            }
            _ => Ok(minimum_encoded_size),
        }
    }

    /// Construct a resource error for an unrepresentable artifact size.
    #[must_use]
    pub fn size_computation_overflow(&self, form: ArtifactResourceForm) -> ArtifactResourceError {
        ArtifactResourceError::new(
            ArtifactResourceErrorKind::SizeComputationOverflow,
            form,
            self.max_artifact_bytes.map(NonZeroUsize::get),
            None,
        )
    }
}

impl Default for ArtifactResourceLimits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: NonZeroUsize::new(DEFAULT_MAX_ARTIFACT_BYTES),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap())
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn public_resource_types_are_send_and_sync() {
        assert_send_sync::<ArtifactResourceLimits>();
        assert_send_sync::<ArtifactResourceForm>();
        assert_send_sync::<ArtifactResourceErrorKind>();
        assert_send_sync::<ArtifactResourceError>();
    }

    #[test]
    fn default_uses_exported_ceiling() {
        assert_eq!(
            ArtifactResourceLimits::default()
                .max_artifact_bytes()
                .map(NonZeroUsize::get),
            Some(DEFAULT_MAX_ARTIFACT_BYTES)
        );
    }

    #[test]
    fn finite_policy_accepts_boundary_and_rejects_one_over() {
        let limits = finite(3);
        assert_eq!(
            limits
                .check_output_size(ArtifactResourceForm::Yaml, 3)
                .unwrap(),
            3
        );
        let error = limits
            .check_output_size(ArtifactResourceForm::Yaml, 4)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(error.configured_max_artifact_bytes(), Some(3));
        assert_eq!(error.observed_or_projected_artifact_bytes(), Some(4));
    }

    #[test]
    fn one_byte_is_the_smallest_finite_policy() {
        let limits = finite(1);
        assert!(
            limits
                .check_input_size(ArtifactResourceForm::Protobuf, &[0])
                .is_ok()
        );
        assert!(
            limits
                .check_input_size(ArtifactResourceForm::Protobuf, &[0, 1])
                .is_err()
        );
        assert!(NonZeroUsize::new(0).is_none());
    }

    #[test]
    fn builders_replace_and_remove_only_the_byte_limit() {
        let lower = finite(2);
        assert!(
            lower
                .check_output_size(ArtifactResourceForm::Yaml, 3)
                .is_err()
        );
        let limits = lower.with_max_artifact_bytes(NonZeroUsize::new(9).unwrap());
        assert_eq!(limits.max_artifact_bytes().map(NonZeroUsize::get), Some(9));
        assert_eq!(
            limits
                .check_output_size(ArtifactResourceForm::Yaml, 3)
                .unwrap(),
            3
        );
        assert_eq!(
            limits
                .without_max_artifact_byte_limit()
                .max_artifact_bytes(),
            None
        );
        assert!(
            ArtifactResourceLimits::unbounded()
                .check_output_size(ArtifactResourceForm::Protobuf, usize::MAX)
                .is_ok()
        );
    }

    #[test]
    fn input_filter_is_zero_copy_and_reports_exact_size() {
        let bytes = b"same allocation";
        let admitted = ArtifactResourceLimits::unbounded()
            .check_input_size(ArtifactResourceForm::Yaml, bytes)
            .unwrap();
        assert_eq!(admitted.as_ptr(), bytes.as_ptr());
        assert_eq!(admitted.len(), bytes.len());

        let error = finite(bytes.len() - 1)
            .check_input_size(ArtifactResourceForm::Yaml, bytes)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(
            error.observed_or_projected_artifact_bytes(),
            Some(bytes.len())
        );
    }

    #[test]
    fn lower_bound_rejection_does_not_claim_an_exact_size() {
        let limits = finite(4);
        assert_eq!(
            limits
                .check_output_size_lower_bound(ArtifactResourceForm::Yaml, 4)
                .unwrap(),
            4
        );
        let error = limits
            .check_output_size_lower_bound(ArtifactResourceForm::Yaml, 5)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(error.configured_max_artifact_bytes(), Some(4));
        assert_eq!(error.observed_or_projected_artifact_bytes(), None);
    }

    #[test]
    fn overflow_is_reported_even_for_unbounded_policy() {
        let error = ArtifactResourceLimits::unbounded()
            .size_computation_overflow(ArtifactResourceForm::Protobuf);
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::SizeComputationOverflow
        );
        assert_eq!(error.configured_max_artifact_bytes(), None);
        assert_eq!(error.observed_or_projected_artifact_bytes(), None);
    }

    #[test]
    fn errors_are_content_free_and_have_no_source() {
        use core::error::Error as _;

        let secret = "payload-secret-never-retained";
        let error = finite(secret.len() - 1)
            .check_input_size(ArtifactResourceForm::Yaml, secret.as_bytes())
            .unwrap_err();
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains(secret));
        assert!(!display.contains(secret));
        assert!(error.source().is_none());
    }
}

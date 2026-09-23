// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use yaml_sigil_traits::signing::{
    AsyncSigner, OutputForm, SignError, SignOutcome, SignRequest, Signer, SignerCapabilities,
    SigningKey,
};
use yaml_sigil_traits::verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOutcome,
    PreVerifyResponse, PublicKeys, Verifier, VerifierCapabilities, VerifierOptions, VerifierState,
    VerifyResult,
};
use yaml_sigil_traits::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
use yaml_sigil_traits::{transcription, v1alpha1};

struct LocalEd25519SigningKey;
struct LocalP256SigningKey;
#[derive(Debug)]
struct LocalEd25519VerifyingKey;
#[derive(Debug)]
struct LocalP256VerifyingKey;

fn signer_capabilities() -> SignerCapabilities {
    SignerCapabilities {
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        supported_output_forms: &[OutputForm::Yaml],
        supported_algorithms: &[AlgorithmId::Ed25519],
        best_effort_yaml_validation: false,
        implementation_name: "local-test-signer",
        implementation_version: "0",
    }
}

fn verifier_capabilities() -> VerifierCapabilities {
    VerifierCapabilities {
        conformance_profile: AdvertisedConformanceProfile::Permissive,
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policies: vec![
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        ],
        supported_forms: &[ArtifactForm::Yaml],
        supported_algorithms: &[AlgorithmId::Ed25519],
        supports_can_pre_verify: true,
        supports_pre_verify: true,
        implementation_name: "local-test-verifier",
        implementation_version: "0",
    }
}

fn pre_verify_response(form: ArtifactForm) -> PreVerifyResponse {
    PreVerifyResponse {
        outcome: PreVerifyOutcome::Unsigned,
        form,
        unverified_payload_bytes: None,
        unverified_signature: None,
        parser_observations: Vec::new(),
    }
}

struct LocalSigner;

impl Signer for LocalSigner {
    type Ed25519SigningKey = LocalEd25519SigningKey;
    type P256SigningKey = LocalP256SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    fn sign(
        &self,
        _req: &SignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
    ) -> SignOutcome {
        SignOutcome::Signer(SignError::KeyOperationFailure)
    }
}

struct LocalAsyncSigner;

impl AsyncSigner for LocalAsyncSigner {
    type Ed25519SigningKey = LocalEd25519SigningKey;
    type P256SigningKey = LocalP256SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    async fn sign(
        &self,
        _req: &SignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
    ) -> SignOutcome {
        SignOutcome::Signer(SignError::KeyOperationFailure)
    }
}

struct LocalVerifier;

impl Verifier for LocalVerifier {
    type Ed25519VerifyingKey = LocalEd25519VerifyingKey;
    type P256VerifyingKey = LocalP256VerifyingKey;

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }

    fn pre_verify(
        &self,
        _input_bytes: &[u8],
        form: ArtifactForm,
        _allow_unsigned: bool,
        _include_parser_observations: bool,
    ) -> PreVerifyResponse {
        pre_verify_response(form)
    }

    fn verify(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }

    fn verify_with_metadata(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
        _include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }

    fn verify_from_pre_verify(
        &self,
        _pre: &PreVerifyResponse,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }
}

struct LocalAsyncVerifier;

impl AsyncVerifier for LocalAsyncVerifier {
    type Ed25519VerifyingKey = LocalEd25519VerifyingKey;
    type P256VerifyingKey = LocalP256VerifyingKey;

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }

    async fn pre_verify(
        &self,
        _input_bytes: &[u8],
        form: ArtifactForm,
        _allow_unsigned: bool,
        _include_parser_observations: bool,
    ) -> PreVerifyResponse {
        pre_verify_response(form)
    }

    async fn verify(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }

    async fn verify_with_metadata(
        &self,
        _input_bytes: &[u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
        _include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }

    async fn verify_from_pre_verify(
        &self,
        _pre: &PreVerifyResponse,
        _keys: &PublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
        _options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        Err(InvocationError::KeyResolutionFailure)
    }
}

fn assert_copy<T: Copy>() {}

fn assert_send<T: Send>(_: T) {}

// Generic key parameters must not weaken the DTOs' existing copy and
// redacted-debug guarantees or impose key-type trait bounds.
#[test]
fn generic_key_dtos_preserve_copy_and_redacted_debug_without_key_bounds() {
    assert_copy::<SigningKey<'static, LocalEd25519SigningKey, LocalP256SigningKey>>();
    assert_copy::<PublicKeys<'static, LocalEd25519VerifyingKey, LocalP256VerifyingKey>>();

    let key = LocalEd25519SigningKey;
    let signing_key: SigningKey<'_, LocalEd25519SigningKey, LocalP256SigningKey> =
        SigningKey::Ed25519(&key);
    assert_eq!(format!("{signing_key:?}"), "SigningKey::Ed25519(***)");
}

// Explicit associated-key bindings keep the synchronous interfaces usable
// through trait objects after key ownership moves to implementations.
#[test]
fn synchronous_traits_remain_object_safe_with_explicit_key_bindings() {
    let signer: &dyn Signer<Ed25519SigningKey = LocalEd25519SigningKey, P256SigningKey = LocalP256SigningKey> =
        &LocalSigner;
    let verifier: &dyn Verifier<
        Ed25519VerifyingKey = LocalEd25519VerifyingKey,
        P256VerifyingKey = LocalP256VerifyingKey,
    > = &LocalVerifier;

    assert_eq!(
        signer.capabilities().implementation_name,
        "local-test-signer"
    );
    assert_eq!(
        verifier.capabilities().implementation_name,
        "local-test-verifier"
    );
}

// Concrete local key types must preserve the Send contract on futures
// returned by both asynchronous interfaces.
#[test]
fn async_trait_futures_are_send_with_local_key_types() {
    let signing_key = LocalEd25519SigningKey;
    let request = SignRequest {
        payload: b"payload\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::<LocalEd25519SigningKey, LocalP256SigningKey>::Ed25519(&signing_key),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    assert_send(LocalAsyncSigner.sign(&request));

    let verifying_key = LocalEd25519VerifyingKey;
    let keys = PublicKeys::<LocalEd25519VerifyingKey, LocalP256VerifyingKey> {
        ed25519: Some(&verifying_key),
        p256: None,
    };
    assert_send(LocalAsyncVerifier.verify(
        b"artifact",
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    ));
}

struct VersionedSigner;

impl v1alpha1::signing::Signer for VersionedSigner {
    type Ed25519SigningKey = LocalEd25519SigningKey;
    type P256SigningKey = LocalP256SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }

    fn sign(
        &self,
        _req: &SignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
    ) -> v1alpha1::signing::SignOutcome {
        SignOutcome::Signer(SignError::KeyOperationFailure)
    }
}

#[test]
fn signer_implementations_and_borrowed_requests_cross_namespace_paths() {
    let key = LocalEd25519SigningKey;
    let request = v1alpha1::signing::SignRequest {
        payload: b"namespace: v1alpha1\n",
        algorithm: v1alpha1::algorithm::AlgorithmId::Ed25519,
        key: SigningKey::<LocalEd25519SigningKey, LocalP256SigningKey>::Ed25519(&key),
        keyid: None,
        append_missing_final_newline: false,
        output_form: v1alpha1::signing::OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    let default_request: &SignRequest<'_, LocalEd25519SigningKey, LocalP256SigningKey> = &request;
    let versioned_request: &v1alpha1::signing::SignRequest<
        '_,
        LocalEd25519SigningKey,
        LocalP256SigningKey,
    > = default_request;
    let old_implementation: &dyn v1alpha1::signing::Signer<
        Ed25519SigningKey = LocalEd25519SigningKey,
        P256SigningKey = LocalP256SigningKey,
    > = &LocalSigner;
    let new_implementation: &dyn Signer<Ed25519SigningKey = LocalEd25519SigningKey, P256SigningKey = LocalP256SigningKey> =
        &VersionedSigner;
    assert!(matches!(
        old_implementation.sign(default_request),
        SignOutcome::Signer(SignError::KeyOperationFailure)
    ));
    assert!(matches!(
        new_implementation.sign(versioned_request),
        v1alpha1::signing::SignOutcome::Signer(v1alpha1::signing::SignError::KeyOperationFailure)
    ));
    let capabilities: v1alpha1::signing::SignerCapabilities = signer_capabilities();
    assert_eq!(new_implementation.capabilities(), capabilities);
}

#[test]
fn verifier_objects_keys_and_results_cross_namespace_paths() {
    let verifier: &dyn v1alpha1::verification::Verifier<
        Ed25519VerifyingKey = LocalEd25519VerifyingKey,
        P256VerifyingKey = LocalP256VerifyingKey,
    > = &LocalVerifier;
    let key = LocalEd25519VerifyingKey;
    let keys = v1alpha1::verification::PublicKeys {
        ed25519: Some(&key),
        p256: None::<&LocalP256VerifyingKey>,
    };
    let default_keys: PublicKeys<'_, LocalEd25519VerifyingKey, LocalP256VerifyingKey> = keys;
    let versioned_keys: v1alpha1::verification::PublicKeys<
        '_,
        LocalEd25519VerifyingKey,
        LocalP256VerifyingKey,
    > = default_keys;
    let pre: PreVerifyResponse = verifier.pre_verify(b"payload\n", ArtifactForm::Yaml, true, false);
    let versioned_pre: v1alpha1::verification::PreVerifyResponse = pre;
    assert_eq!(
        verifier.verify_from_pre_verify(
            &versioned_pre,
            &versioned_keys,
            v1alpha1::verification::VerifierOptions::default(),
        ),
        Err(v1alpha1::verification::InvocationError::KeyResolutionFailure)
    );
    let policy: v1alpha1::YamlSignatureDocumentUnknownFieldPolicy =
        YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse;
    assert_eq!(
        verifier.capabilities().yaml_signature_unknown_field_policy,
        policy
    );
    assert_eq!(
        verifier.capabilities().protobuf_wire_decode,
        v1alpha1::conformance::ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder
    );
}

struct VersionedTranscriber;

impl v1alpha1::transcription::Transcriber for VersionedTranscriber {
    fn capabilities(&self) -> transcription::TranscriberCapabilities {
        transcription::TranscriberCapabilities {
            supported_forms: &[],
            supported_outer_conformances: &[],
            emits_canonical_yaml_envelope: false,
            implementation_name: "namespace-test-transcriber",
            implementation_version: "0",
        }
    }

    fn compose(&self, _req: &transcription::ComposeRequest<'_>) -> transcription::ComposeOutcome {
        transcription::ComposeOutcome::Invocation(
            transcription::TranscriberInvocationError::InvalidOrUnsupportedForm,
        )
    }

    fn decompose(
        &self,
        _req: &transcription::DecomposeRequest<'_>,
    ) -> transcription::DecomposeResponse {
        transcription::DecomposeResponse::Invocation(
            transcription::TranscriberInvocationError::InvalidOrUnsupportedForm,
        )
    }
}

impl v1alpha1::transcription::AsyncTranscriber for VersionedTranscriber {
    fn capabilities(&self) -> transcription::TranscriberCapabilities {
        transcription::Transcriber::capabilities(self)
    }

    async fn compose(
        &self,
        req: &transcription::ComposeRequest<'_>,
    ) -> transcription::ComposeOutcome {
        transcription::Transcriber::compose(self, req)
    }

    async fn decompose(
        &self,
        req: &transcription::DecomposeRequest<'_>,
    ) -> transcription::DecomposeResponse {
        transcription::Transcriber::decompose(self, req)
    }
}

#[test]
fn transcription_objects_and_owned_dtos_cross_namespace_paths() {
    let versioned = v1alpha1::transcription::AbstractArtifact {
        payload: b"payload\n".to_vec(),
        signature_carrier: Vec::new(),
    };
    let default: transcription::AbstractArtifact = versioned;
    let round_trip: v1alpha1::transcription::AbstractArtifact = default;
    let request = v1alpha1::transcription::ComposeRequest {
        payload: &round_trip.payload,
        signature_carrier: &round_trip.signature_carrier,
        form: transcription::TranscriptionForm::Yaml,
    };
    let transcriber: &dyn transcription::Transcriber = &VersionedTranscriber;
    assert!(matches!(
        transcriber.compose(&request),
        v1alpha1::transcription::ComposeOutcome::Invocation(
            v1alpha1::transcription::TranscriberInvocationError::InvalidOrUnsupportedForm
        )
    ));
}

#[test]
fn versioned_async_traits_preserve_send_futures_and_borrowed_inputs() {
    let key = LocalEd25519SigningKey;
    let request = v1alpha1::signing::SignRequest {
        payload: b"payload\n",
        algorithm: v1alpha1::AlgorithmId::Ed25519,
        key: v1alpha1::signing::SigningKey::<LocalEd25519SigningKey, LocalP256SigningKey>::Ed25519(
            &key,
        ),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    assert_send(v1alpha1::signing::AsyncSigner::sign(
        &LocalAsyncSigner,
        &request,
    ));
    let keys = PublicKeys::<LocalEd25519VerifyingKey, LocalP256VerifyingKey> {
        ed25519: None,
        p256: None,
    };
    assert_send(v1alpha1::verification::AsyncVerifier::verify(
        &LocalAsyncVerifier,
        request.payload,
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    ));
    let compose = transcription::ComposeRequest {
        payload: request.payload,
        signature_carrier: &[],
        form: transcription::TranscriptionForm::Yaml,
    };
    assert_send(transcription::AsyncTranscriber::compose(
        &VersionedTranscriber,
        &compose,
    ));
    let decompose = transcription::DecomposeRequest {
        artifact: request.payload,
        form: transcription::TranscriptionForm::Protobuf,
        outer_conformance: Some(v1alpha1::OuterConformance::Strict),
    };
    assert_send(transcription::AsyncTranscriber::decompose(
        &VersionedTranscriber,
        &decompose,
    ));
}

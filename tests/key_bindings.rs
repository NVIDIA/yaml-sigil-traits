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

#[test]
fn generic_key_dtos_preserve_copy_and_redacted_debug_without_key_bounds() {
    assert_copy::<SigningKey<'static, LocalEd25519SigningKey, LocalP256SigningKey>>();
    assert_copy::<PublicKeys<'static, LocalEd25519VerifyingKey, LocalP256VerifyingKey>>();

    let key = LocalEd25519SigningKey;
    let signing_key: SigningKey<'_, LocalEd25519SigningKey, LocalP256SigningKey> =
        SigningKey::Ed25519(&key);
    assert_eq!(format!("{signing_key:?}"), "SigningKey::Ed25519(***)");
}

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

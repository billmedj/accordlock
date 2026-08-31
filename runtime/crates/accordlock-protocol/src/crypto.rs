use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::OsRng;
use thiserror::Error;

use crate::Digest32;

/// Maximum encoded `COSE_Sign1` size accepted by the local `AccordLock` profile.
pub const MAX_COSE_SIZE_BYTES: usize = 1_048_576;

/// Maximum embedded payload size accepted by the local `AccordLock` profile.
pub const MAX_COSE_PAYLOAD_BYTES: usize = 524_288;

/// Maximum UTF-8 byte length of a COSE key identifier.
pub const MAX_KEY_ID_BYTES: usize = 256;

/// Maximum UTF-8 byte length of the external-AAD domain string.
pub const MAX_DOMAIN_BYTES: usize = 128;

/// Domain separator for the local single-authorization-signer authority profile.
pub const AUTHORIZATION_SIGNER_ROOT_DOMAIN: &[u8] = b"accordlock:v1:authorization-signer-root";

/// Domain separator for the local single-evaluator-verifier authority profile.
pub const EVALUATOR_VERIFIER_ROOT_DOMAIN: &[u8] = b"accordlock:v1:evaluator-verifier-root";

#[derive(Debug)]
pub struct SigningIdentity {
    key_id: String,
    key: SigningKey,
}

impl SigningIdentity {
    #[must_use]
    pub fn generate(key_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::generate(&mut OsRng),
        }
    }

    #[must_use]
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn verifier(&self) -> CoseVerifier {
        CoseVerifier {
            key_id: self.key_id.clone(),
            key: self.key.verifying_key(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CoseVerifier {
    key_id: String,
    key: VerifyingKey,
}

impl CoseVerifier {
    /// Constructs a verifier from a raw Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] if the bytes do not encode a
    /// valid Ed25519 verification key.
    pub fn from_public_key(
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self { key_id, key })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// Commits an authority signer root to one exact Ed25519 key identifier and
/// public key. Components are length framed so no concatenation ambiguity can
/// change the committed identity.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key identifier or public key is outside
/// the accepted COSE/Ed25519 profile.
pub fn authorization_signer_root(
    key_id: &str,
    public_key: [u8; 32],
) -> Result<Digest32, CryptoError> {
    CoseVerifier::from_public_key(key_id, public_key)?;
    let mut commitment =
        Vec::with_capacity(AUTHORIZATION_SIGNER_ROOT_DOMAIN.len() + key_id.len() + 56);
    for component in [
        AUTHORIZATION_SIGNER_ROOT_DOMAIN,
        key_id.as_bytes(),
        public_key.as_slice(),
    ] {
        commitment.extend_from_slice(
            &u64::try_from(component.len())
                .map_err(|_| CryptoError::ProfileLimitExceeded)?
                .to_be_bytes(),
        );
        commitment.extend_from_slice(component);
    }
    Ok(Digest32::sha256(&commitment))
}

/// Commits a local evaluator-verifier authority to one exact Ed25519 key
/// identifier and public key.
///
/// This root is deliberately distinct from [`authorization_signer_root`]. A key cannot
/// be substituted between evaluation verification and authorization signing merely by
/// retaining the same identifier or public bytes.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key identifier or public key is outside
/// the accepted COSE/Ed25519 profile.
pub fn evaluator_verifier_root(
    key_id: &str,
    public_key: [u8; 32],
) -> Result<Digest32, CryptoError> {
    CoseVerifier::from_public_key(key_id, public_key)?;
    let mut commitment =
        Vec::with_capacity(EVALUATOR_VERIFIER_ROOT_DOMAIN.len() + key_id.len() + 56);
    for component in [
        EVALUATOR_VERIFIER_ROOT_DOMAIN,
        key_id.as_bytes(),
        public_key.as_slice(),
    ] {
        commitment.extend_from_slice(
            &u64::try_from(component.len())
                .map_err(|_| CryptoError::ProfileLimitExceeded)?
                .to_be_bytes(),
        );
        commitment.extend_from_slice(component);
    }
    Ok(Digest32::sha256(&commitment))
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("COSE serialization failed: {0}")]
    Cose(String),
    #[error("COSE object is not in the accepted deterministic encoding")]
    NonCanonicalCose,
    #[error("COSE protected headers do not match the AccordLock profile")]
    InvalidProtectedHeaders,
    #[error("COSE unprotected headers are forbidden")]
    UnprotectedHeaders,
    #[error("COSE object has no embedded payload")]
    MissingPayload,
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("invalid COSE key identifier")]
    InvalidKeyId,
    #[error("invalid external-AAD domain")]
    InvalidDomain,
    #[error("COSE object exceeds the accepted profile limits")]
    ProfileLimitExceeded,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
}

fn validate_key_id(key_id: &str) -> Result<(), CryptoError> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || key_id.trim() != key_id
        || key_id.chars().any(char::is_control)
    {
        return Err(CryptoError::InvalidKeyId);
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), CryptoError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
        || domain.trim() != domain
        || domain.chars().any(char::is_control)
    {
        return Err(CryptoError::InvalidDomain);
    }
    Ok(())
}

/// Creates a deterministic COSE Sign1 object with `domain` as external AAD.
///
/// # Errors
///
/// Returns [`CryptoError::Cose`] if the COSE object cannot be serialized.
pub fn sign_cose(
    payload: &[u8],
    domain: &str,
    identity: &SigningIdentity,
) -> Result<Vec<u8>, CryptoError> {
    validate_key_id(&identity.key_id)?;
    validate_domain(domain)?;
    if payload.len() > MAX_COSE_PAYLOAD_BYTES {
        return Err(CryptoError::ProfileLimitExceeded);
    }
    if identity.key.verifying_key().is_weak() {
        return Err(CryptoError::InvalidPublicKey);
    }

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(identity.key_id.as_bytes().to_vec())
        .build();

    let signed = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(domain.as_bytes(), |data| {
            identity.key.sign(data).to_bytes().to_vec()
        })
        .build();

    let encoded = signed
        .to_vec()
        .map_err(|error| CryptoError::Cose(error.to_string()))?;
    if encoded.len() > MAX_COSE_SIZE_BYTES {
        return Err(CryptoError::ProfileLimitExceeded);
    }
    Ok(encoded)
}

/// Verifies the canonical COSE profile, key identity, domain, and signature.
///
/// # Errors
///
/// Returns a [`CryptoError`] for malformed or noncanonical COSE, unexpected
/// headers, a wrong domain or key, a missing payload, or an invalid signature.
pub fn verify_cose(
    encoded: &[u8],
    expected_domain: &str,
    verifier: &CoseVerifier,
) -> Result<Vec<u8>, CryptoError> {
    validate_key_id(&verifier.key_id)?;
    validate_domain(expected_domain)?;
    if encoded.len() > MAX_COSE_SIZE_BYTES {
        return Err(CryptoError::ProfileLimitExceeded);
    }

    let signed =
        CoseSign1::from_slice(encoded).map_err(|error| CryptoError::Cose(error.to_string()))?;

    let canonical = signed
        .clone()
        .to_vec()
        .map_err(|error| CryptoError::Cose(error.to_string()))?;
    if canonical != encoded {
        return Err(CryptoError::NonCanonicalCose);
    }

    let expected_header = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(verifier.key_id.as_bytes().to_vec())
        .build();
    if signed.protected.header != expected_header {
        return Err(CryptoError::InvalidProtectedHeaders);
    }
    let expected_protected = expected_header
        .to_vec()
        .map_err(|error| CryptoError::Cose(error.to_string()))?;
    if signed.protected.original_data.as_deref() != Some(expected_protected.as_slice()) {
        return Err(CryptoError::NonCanonicalCose);
    }
    if !signed.unprotected.is_empty() {
        return Err(CryptoError::UnprotectedHeaders);
    }

    let payload = signed.payload.as_ref().ok_or(CryptoError::MissingPayload)?;
    if payload.len() > MAX_COSE_PAYLOAD_BYTES {
        return Err(CryptoError::ProfileLimitExceeded);
    }

    signed
        .verify_signature(expected_domain.as_bytes(), |signature, data| {
            let parsed =
                Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;
            verifier
                .key
                .verify_strict(data, &parsed)
                .map_err(|_| CryptoError::InvalidSignature)
        })
        .map_err(|_| CryptoError::InvalidSignature)?;

    signed.payload.ok_or(CryptoError::MissingPayload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{Header, ProtectedHeader};
    use proptest::prelude::*;

    #[test]
    fn domain_separation_blocks_cross_route_verification() -> Result<(), Box<dyn std::error::Error>>
    {
        let signer = SigningIdentity::from_seed("test-evaluator", [7; 32]);
        let encoded = sign_cose(b"payload", "accordlock:v1:execution-authorization", &signer)?;
        assert_eq!(
            verify_cose(
                &encoded,
                "accordlock:v1:execution-authorization",
                &signer.verifier()
            )?,
            b"payload"
        );
        assert!(verify_cose(&encoded, "accordlock:v1:emission", &signer.verifier()).is_err());
        Ok(())
    }

    #[test]
    fn wrong_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let signer = SigningIdentity::from_seed("authorization-key", [1; 32]);
        let other = SigningIdentity::from_seed("authorization-key", [2; 32]);
        let encoded = sign_cose(b"payload", "accordlock:v1:execution-authorization", &signer)?;
        assert!(
            verify_cose(
                &encoded,
                "accordlock:v1:execution-authorization",
                &other.verifier()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn noncanonical_protected_header_is_rejected_even_when_signature_is_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let signer = SigningIdentity::from_seed("kid", [3; 32]);
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(b"kid".to_vec())
            .build();

        // Same header map as the profile, but key 4 precedes key 1. The
        // signature is valid over these exact bytes, so only the deterministic
        // protected-header check can reject it.
        let noncanonical_protected = vec![0xa2, 0x04, 0x43, b'k', b'i', b'd', 0x01, 0x27];
        let mut cose = CoseSign1 {
            protected: ProtectedHeader {
                original_data: Some(noncanonical_protected),
                header,
            },
            unprotected: Header::default(),
            payload: Some(b"payload".to_vec()),
            signature: Vec::new(),
        };
        cose.signature = signer
            .key
            .sign(&cose.tbs_data(b"accordlock:v1:test"))
            .to_bytes()
            .to_vec();
        let encoded = cose.to_vec()?;

        assert!(matches!(
            verify_cose(&encoded, "accordlock:v1:test", &signer.verifier()),
            Err(CryptoError::NonCanonicalCose)
        ));
        Ok(())
    }

    #[test]
    fn empty_key_ids_and_oversized_inputs_are_rejected() {
        let empty_kid = SigningIdentity::from_seed("", [4; 32]);
        assert!(matches!(
            sign_cose(b"payload", "accordlock:v1:test", &empty_kid),
            Err(CryptoError::InvalidKeyId)
        ));

        let signer = SigningIdentity::from_seed("kid", [5; 32]);
        let oversized_payload = vec![0_u8; MAX_COSE_PAYLOAD_BYTES + 1];
        assert!(matches!(
            sign_cose(&oversized_payload, "accordlock:v1:test", &signer),
            Err(CryptoError::ProfileLimitExceeded)
        ));
        let oversized_cose = vec![0_u8; MAX_COSE_SIZE_BYTES + 1];
        assert!(matches!(
            verify_cose(&oversized_cose, "accordlock:v1:test", &signer.verifier()),
            Err(CryptoError::ProfileLimitExceeded)
        ));
    }

    #[test]
    fn weak_public_keys_are_rejected_at_registry_construction() {
        let mut identity_encoding = [0_u8; 32];
        identity_encoding[0] = 1;
        assert!(matches!(
            CoseVerifier::from_public_key("weak", identity_encoding),
            Err(CryptoError::InvalidPublicKey)
        ));
    }

    #[test]
    fn authorization_signer_commitment_binds_key_id_and_public_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = SigningIdentity::from_seed("authorization-a", [7; 32]);
        let same_key_other_id = SigningIdentity::from_seed("authorization-b", [7; 32]);
        let other_key = SigningIdentity::from_seed("authorization-a", [8; 32]);

        let root = authorization_signer_root(first.key_id(), first.public_key_bytes())?;
        assert_ne!(
            root,
            authorization_signer_root(
                same_key_other_id.key_id(),
                same_key_other_id.public_key_bytes()
            )?
        );
        assert_ne!(
            root,
            authorization_signer_root(other_key.key_id(), other_key.public_key_bytes())?
        );
        Ok(())
    }

    #[test]
    fn evaluator_commitment_binds_key_id_key_and_purpose() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = SigningIdentity::from_seed("evaluator-a", [9; 32]);
        let same_key_other_id = SigningIdentity::from_seed("evaluator-b", [9; 32]);
        let other_key = SigningIdentity::from_seed("evaluator-a", [10; 32]);

        let root = evaluator_verifier_root(first.key_id(), first.public_key_bytes())?;
        assert_ne!(
            root,
            evaluator_verifier_root(
                same_key_other_id.key_id(),
                same_key_other_id.public_key_bytes()
            )?
        );
        assert_ne!(
            root,
            evaluator_verifier_root(other_key.key_id(), other_key.public_key_bytes())?
        );
        assert_ne!(
            root,
            authorization_signer_root(first.key_id(), first.public_key_bytes())?
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn arbitrary_bounded_cose_input_never_panics(
            encoded in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let verifier = SigningIdentity::from_seed("fuzz-verifier", [6; 32]).verifier();
            drop(verify_cose(&encoded, "accordlock:v1:test", &verifier));
        }
    }
}

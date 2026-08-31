//! `AccordLock` protocol types and cryptographic encodings.

mod canonical;
mod crypto;
mod types;

pub use canonical::{
    AGENT_PROPOSAL_DOMAIN, AUTHORITY_VECTOR_DOMAIN, CanonicalEncode, CanonicalError,
    canonical_hash, evidence_root,
};
pub use crypto::{
    AUTHORIZATION_SIGNER_ROOT_DOMAIN, CoseVerifier, CryptoError, EVALUATOR_VERIFIER_ROOT_DOMAIN,
    MAX_COSE_PAYLOAD_BYTES, MAX_COSE_SIZE_BYTES, MAX_DOMAIN_BYTES, MAX_KEY_ID_BYTES,
    SigningIdentity, authorization_signer_root, evaluator_verifier_root, sign_cose, verify_cose,
};
pub use types::*;

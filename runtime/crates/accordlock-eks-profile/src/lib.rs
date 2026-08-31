#![forbid(unsafe_code)]

//! Canonical, immutable binding for one EKS effect route.
//!
//! [`EksRouteProfile`] closes configuration drift *inside* `AccordLock` by putting
//! the credential broker, native transport, executor, and admission boundary
//! behind one structurally comparable value. It deliberately does not perform
//! DNS resolution, query AWS, validate X.509 syntax, or prove that an external
//! control-plane registry maps identities injectively to a physical cluster.

use std::{fmt, net::SocketAddr, str::FromStr};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ROUTE_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-route-profile\0";
const CA_COMMITMENT_DOMAIN: &[u8] = b"accordlock:v1:eks-ca-trust-set\0";
const PROFILE_SCHEMA_VERSION: u8 = 1;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_KUBERNETES_NAME_BYTES: usize = 253;
const MAX_NAMESPACE_BYTES: usize = 63;
const MAX_CA_CERTIFICATES: usize = 32;
const MAX_CA_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_CREDENTIAL_LIFETIME_SECONDS: i64 = 86_400;
const MAX_CLOCK_UNCERTAINTY_SECONDS: i64 = 300;
const MIN_DELETION_PROPAGATION_SECONDS: i64 = 60;
const MAX_MANAGEMENT_IDENTITY_BYTES: usize = 512;
const CREDENTIAL_LIFECYCLE_SCHEMA_VERSION: u8 = 1;
pub const EKS_CREDENTIAL_LIFECYCLE_POLICY_ID: &str = "eks-credential-lifecycle-v1";
const CREDENTIAL_LIFECYCLE_COMMITMENT_DOMAIN: &[u8] =
    b"accordlock:v1:eks-credential-lifecycle-policy\0";

/// Canonical SHA-256 commitment to one complete credential lifecycle policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EksCredentialLifecycleCommitment([u8; 32]);

impl EksCredentialLifecycleCommitment {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for EksCredentialLifecycleCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EksCredentialLifecycleCommitment([COMMITTED])")
    }
}

/// Rootable credential issue and conservative retirement bounds.
///
/// These values are configuration facts, not caller input. Keeping the whole
/// tuple in the leaf EKS profile lets state and broker compare it without a
/// dependency cycle or a post-restart default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::struct_field_names)]
pub struct EksCredentialLifecyclePolicy {
    requested_expiration_seconds: i64,
    server_lifetime_hard_max_seconds: i64,
    clock_uncertainty_seconds: i64,
    deletion_propagation_hard_max_seconds: i64,
}

impl EksCredentialLifecyclePolicy {
    /// Constructs the complete bounded policy.
    ///
    /// # Errors
    ///
    /// Returns [`EksCredentialLifecyclePolicyError::InvalidBounds`] unless the
    /// requested lifetime is positive, the server maximum contains it, clock
    /// uncertainty is at most five minutes, and deletion propagation is
    /// between one minute and one day.
    pub const fn new(
        requested_expiration_seconds: i64,
        server_lifetime_hard_max_seconds: i64,
        clock_uncertainty_seconds: i64,
        deletion_propagation_hard_max_seconds: i64,
    ) -> Result<Self, EksCredentialLifecyclePolicyError> {
        if requested_expiration_seconds <= 0
            || server_lifetime_hard_max_seconds < requested_expiration_seconds
            || server_lifetime_hard_max_seconds > MAX_CREDENTIAL_LIFETIME_SECONDS
            || clock_uncertainty_seconds < 0
            || clock_uncertainty_seconds > MAX_CLOCK_UNCERTAINTY_SECONDS
            || deletion_propagation_hard_max_seconds < MIN_DELETION_PROPAGATION_SECONDS
            || deletion_propagation_hard_max_seconds > MAX_CREDENTIAL_LIFETIME_SECONDS
        {
            return Err(EksCredentialLifecyclePolicyError::InvalidBounds);
        }
        Ok(Self {
            requested_expiration_seconds,
            server_lifetime_hard_max_seconds,
            clock_uncertainty_seconds,
            deletion_propagation_hard_max_seconds,
        })
    }

    #[must_use]
    pub const fn schema_version(self) -> u8 {
        CREDENTIAL_LIFECYCLE_SCHEMA_VERSION
    }

    #[must_use]
    pub const fn policy_id(self) -> &'static str {
        EKS_CREDENTIAL_LIFECYCLE_POLICY_ID
    }

    #[must_use]
    pub const fn requested_expiration_seconds(self) -> i64 {
        self.requested_expiration_seconds
    }

    #[must_use]
    pub const fn server_lifetime_hard_max_seconds(self) -> i64 {
        self.server_lifetime_hard_max_seconds
    }

    #[must_use]
    pub const fn clock_uncertainty_seconds(self) -> i64 {
        self.clock_uncertainty_seconds
    }

    #[must_use]
    pub const fn deletion_propagation_hard_max_seconds(self) -> i64 {
        self.deletion_propagation_hard_max_seconds
    }

    /// Returns the domain-separated commitment to the schema and every bound.
    #[must_use]
    pub fn commitment(self) -> EksCredentialLifecycleCommitment {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_LIFECYCLE_COMMITMENT_DOMAIN);
        hasher.update(EKS_CREDENTIAL_LIFECYCLE_POLICY_ID.as_bytes());
        hasher.update([0]);
        hasher.update([CREDENTIAL_LIFECYCLE_SCHEMA_VERSION]);
        hasher.update(self.requested_expiration_seconds.to_be_bytes());
        hasher.update(self.server_lifetime_hard_max_seconds.to_be_bytes());
        hasher.update(self.clock_uncertainty_seconds.to_be_bytes());
        hasher.update(self.deletion_propagation_hard_max_seconds.to_be_bytes());
        EksCredentialLifecycleCommitment(hasher.finalize().into())
    }

    /// Computes the latest conservative bearer expiry from an issue start.
    ///
    /// # Errors
    ///
    /// Returns [`EksCredentialLifecyclePolicyError::TimeOverflow`] if the
    /// signed timestamp arithmetic cannot be represented.
    pub fn credential_safe_after(
        self,
        issue_started_unix_s: i64,
    ) -> Result<i64, EksCredentialLifecyclePolicyError> {
        if issue_started_unix_s < 0 {
            return Err(EksCredentialLifecyclePolicyError::InvalidTime);
        }
        issue_started_unix_s
            .checked_add(self.server_lifetime_hard_max_seconds)
            .and_then(|value| value.checked_add(self.clock_uncertainty_seconds))
            .ok_or(EksCredentialLifecyclePolicyError::TimeOverflow)
    }

    /// Computes the conservative retirement instant after observed deletion.
    ///
    /// # Errors
    ///
    /// Returns [`EksCredentialLifecyclePolicyError::TimeOverflow`] if the
    /// signed timestamp arithmetic cannot be represented.
    pub fn deletion_safe_after(
        self,
        deletion_observed_unix_s: i64,
    ) -> Result<i64, EksCredentialLifecyclePolicyError> {
        if deletion_observed_unix_s < 0 {
            return Err(EksCredentialLifecyclePolicyError::InvalidTime);
        }
        deletion_observed_unix_s
            .checked_add(self.deletion_propagation_hard_max_seconds)
            .and_then(|value| value.checked_add(self.clock_uncertainty_seconds))
            .ok_or(EksCredentialLifecyclePolicyError::TimeOverflow)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EksCredentialLifecyclePolicyError {
    #[error("EKS credential lifecycle bounds are invalid")]
    InvalidBounds,
    #[error("EKS credential lifecycle safe-after time overflowed")]
    TimeOverflow,
    #[error("EKS credential lifecycle timestamp is before the Unix epoch")]
    InvalidTime,
}

/// One independently provisioned broker management identity and RBAC root.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EksManagementAuthorityBinding {
    subject: String,
    rbac_commitment: [u8; 32],
}

impl EksManagementAuthorityBinding {
    /// Constructs one exact management identity binding.
    ///
    /// # Errors
    ///
    /// Rejects non-canonical subjects and the zero RBAC commitment.
    pub fn new(
        subject: impl Into<String>,
        rbac_commitment: [u8; 32],
    ) -> Result<Self, EksBrokerManagementBindingsError> {
        let subject = subject.into();
        if subject.is_empty()
            || subject.len() > MAX_MANAGEMENT_IDENTITY_BYTES
            || !subject.is_ascii()
            || subject.trim() != subject
            || subject
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(EksBrokerManagementBindingsError::InvalidSubject);
        }
        if rbac_commitment == [0; 32] {
            return Err(EksBrokerManagementBindingsError::ZeroRbacCommitment);
        }
        Ok(Self {
            subject,
            rbac_commitment,
        })
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub const fn rbac_commitment(&self) -> [u8; 32] {
        self.rbac_commitment
    }
}

impl fmt::Debug for EksManagementAuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksManagementAuthorityBinding")
            .field("subject", &self.subject)
            .field("rbac_commitment", &"[COMMITTED]")
            .finish()
    }
}

/// Exact, pairwise-separated management authorities for the EKS broker.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EksBrokerManagementBindings {
    secret_lifecycle: EksManagementAuthorityBinding,
    service_account_token: EksManagementAuthorityBinding,
    token_review: EksManagementAuthorityBinding,
}

impl EksBrokerManagementBindings {
    /// Constructs the exact three-authority tuple.
    ///
    /// # Errors
    ///
    /// Rejects reuse of a subject or RBAC root between authority families.
    pub fn new(
        secret_lifecycle: EksManagementAuthorityBinding,
        service_account_token: EksManagementAuthorityBinding,
        token_review: EksManagementAuthorityBinding,
    ) -> Result<Self, EksBrokerManagementBindingsError> {
        let subjects = [
            secret_lifecycle.subject(),
            service_account_token.subject(),
            token_review.subject(),
        ];
        if subjects[0] == subjects[1] || subjects[0] == subjects[2] || subjects[1] == subjects[2] {
            return Err(EksBrokerManagementBindingsError::SubjectReused);
        }
        let roots = [
            secret_lifecycle.rbac_commitment(),
            service_account_token.rbac_commitment(),
            token_review.rbac_commitment(),
        ];
        if roots[0] == roots[1] || roots[0] == roots[2] || roots[1] == roots[2] {
            return Err(EksBrokerManagementBindingsError::RbacCommitmentReused);
        }
        Ok(Self {
            secret_lifecycle,
            service_account_token,
            token_review,
        })
    }

    #[must_use]
    pub const fn secret_lifecycle(&self) -> &EksManagementAuthorityBinding {
        &self.secret_lifecycle
    }

    #[must_use]
    pub const fn service_account_token(&self) -> &EksManagementAuthorityBinding {
        &self.service_account_token
    }

    #[must_use]
    pub const fn token_review(&self) -> &EksManagementAuthorityBinding {
        &self.token_review
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EksBrokerManagementBindingsError {
    #[error("EKS broker management subject is not canonical")]
    InvalidSubject,
    #[error("EKS broker management RBAC commitment cannot be zero")]
    ZeroRbacCommitment,
    #[error("EKS broker management subjects must be pairwise distinct")]
    SubjectReused,
    #[error("EKS broker management RBAC commitments must be pairwise distinct")]
    RbacCommitmentReused,
}

/// SHA-256 commitment to the exact, order-independent CA certificate set.
///
/// This type does not claim that the committed bytes are syntactically valid
/// certificates or trusted for a particular server. The TLS constructor must
/// still parse those same bytes and build its root store from them.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaTrustCommitment([u8; 32]);

impl CaTrustCommitment {
    /// Commits to a non-empty set of exact DER certificate byte strings.
    ///
    /// Input order is deliberately irrelevant. Empty, duplicate, or oversized
    /// entries are rejected so equivalent trust sets have exactly one digest.
    ///
    /// # Errors
    ///
    /// Returns [`CaTrustError`] when the set is empty, too large, contains an
    /// invalid-sized entry, or contains the same byte string more than once.
    pub fn from_der_certificates(certificates: &[Vec<u8>]) -> Result<Self, CaTrustError> {
        if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
            return Err(CaTrustError::InvalidCertificateCount);
        }
        if certificates.iter().any(|certificate| {
            certificate.is_empty() || certificate.len() > MAX_CA_CERTIFICATE_BYTES
        }) {
            return Err(CaTrustError::InvalidCertificateSize);
        }

        let mut canonical = certificates.iter().map(Vec::as_slice).collect::<Vec<_>>();
        canonical.sort_unstable();
        if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CaTrustError::DuplicateCertificate);
        }

        let mut hasher = Sha256::new();
        hasher.update(CA_COMMITMENT_DOMAIN);
        update_len(&mut hasher, canonical.len());
        for certificate in canonical {
            update_len(&mut hasher, certificate.len());
            hasher.update(certificate);
        }
        Ok(Self(hasher.finalize().into()))
    }

    /// Reconstructs a persisted SHA-256 CA commitment.
    ///
    /// The all-zero sentinel is never a valid configured commitment. Calling
    /// code remains responsible for loading this value from authenticated
    /// configuration or durable state.
    ///
    /// # Errors
    ///
    /// Returns [`CaTrustError::ZeroCommitment`] for the all-zero sentinel.
    pub fn from_sha256_bytes(bytes: [u8; 32]) -> Result<Self, CaTrustError> {
        if bytes == [0; 32] {
            return Err(CaTrustError::ZeroCommitment);
        }
        Ok(Self(bytes))
    }

    /// Borrows the fixed-size digest for authenticated persistence or compare.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a lowercase hexadecimal representation for explicit audit use.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for CaTrustCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaTrustCommitment([REDACTED])")
    }
}

/// Invalid input to [`CaTrustCommitment`].
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CaTrustError {
    #[error("the CA certificate set must contain between 1 and 32 entries")]
    InvalidCertificateCount,
    #[error("each CA certificate byte string must contain between 1 and 131072 bytes")]
    InvalidCertificateSize,
    #[error("the CA certificate set contains a duplicate byte string")]
    DuplicateCertificate,
    #[error("the all-zero CA commitment sentinel is forbidden")]
    ZeroCommitment,
}

/// One explicit, canonical IP socket target.
///
/// The value cannot contain a hostname, zone identifier, implicit port, or
/// alternate textual IPv6 spelling. DNS resolution is intentionally outside
/// this type: bootstrap must pin the exact address it intends to contact.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PinnedSocketTarget(SocketAddr);

impl PinnedSocketTarget {
    /// Validates an already parsed socket address.
    ///
    /// # Errors
    ///
    /// Rejects unspecified, loopback, multicast, link-local, IPv4 broadcast,
    /// and IPv4-mapped IPv6 destinations.
    pub fn new(address: SocketAddr) -> Result<Self, SocketTargetError> {
        if address.port() == 0 {
            return Err(SocketTargetError::ZeroPort);
        }
        match address {
            SocketAddr::V4(value)
                if value.ip().is_unspecified()
                    || value.ip().is_loopback()
                    || value.ip().is_multicast()
                    || value.ip().is_link_local()
                    || value.ip().is_broadcast() =>
            {
                Err(SocketTargetError::UnsafeAddressClass)
            }
            SocketAddr::V6(value)
                if value.ip().is_unspecified()
                    || value.ip().is_loopback()
                    || value.ip().is_multicast()
                    || value.ip().is_unicast_link_local()
                    || value.ip().to_ipv4_mapped().is_some() =>
            {
                Err(SocketTargetError::UnsafeAddressClass)
            }
            _ => Ok(Self(address)),
        }
    }

    /// Parses only Rust's unique canonical `SocketAddr` spelling.
    ///
    /// In particular, IPv6 must be bracketed, compressed canonically, and have
    /// an explicit decimal port. The function never trims or normalizes input.
    ///
    /// # Errors
    ///
    /// Returns [`SocketTargetError`] for a parse failure, textual alias, or an
    /// unsafe address class.
    pub fn parse_canonical(value: &str) -> Result<Self, SocketTargetError> {
        if value.is_empty() || value.trim() != value || !value.is_ascii() {
            return Err(SocketTargetError::NonCanonicalText);
        }
        let parsed =
            SocketAddr::from_str(value).map_err(|_| SocketTargetError::NonCanonicalText)?;
        if parsed.to_string() != value {
            return Err(SocketTargetError::NonCanonicalText);
        }
        Self::new(parsed)
    }

    /// Returns the exact target by value.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    /// Returns the explicit target port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.0.port()
    }
}

impl fmt::Debug for PinnedSocketTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedSocketTarget([REDACTED])")
    }
}

impl FromStr for PinnedSocketTarget {
    type Err = SocketTargetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_canonical(value)
    }
}

/// Invalid explicit socket destination.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SocketTargetError {
    #[error("the socket target is not in the unique canonical IP:port form")]
    NonCanonicalText,
    #[error("the socket target port cannot be zero")]
    ZeroPort,
    #[error("the socket target belongs to a forbidden address class")]
    UnsafeAddressClass,
}

/// Borrowed constructor material for [`EksRouteProfile`].
///
/// Strings must already be canonical. Construction rejects aliases rather
/// than silently lowercasing, trimming, resolving, or otherwise normalizing.
#[derive(Clone, Copy)]
pub struct EksRouteProfileInput<'a> {
    pub cluster_trust_domain: &'a str,
    pub cluster_identity: &'a str,
    pub api_server_identity: &'a str,
    pub dns_server_name: &'a str,
    pub port: u16,
    pub socket_target: PinnedSocketTarget,
    pub ca_trust_commitment: CaTrustCommitment,
    pub namespace: &'a str,
    pub deployment_name: &'a str,
    pub deployment_uid: &'a str,
    pub attempt_service_account_name: &'a str,
    pub attempt_service_account_uid: &'a str,
    pub token_audience: &'a str,
}

impl fmt::Debug for EksRouteProfileInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksRouteProfileInput")
            .field("route_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Immutable, canonical binding for every route fact used by the EKS slice.
///
/// Fields are private and there is no unchecked deserialization path. Use
/// [`EksRouteProfile::new`] at every trust/bootstrap boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct EksRouteProfile {
    cluster_trust_domain: String,
    cluster_identity: String,
    api_server_identity: String,
    dns_server_name: String,
    port: u16,
    socket_target: PinnedSocketTarget,
    ca_trust_commitment: CaTrustCommitment,
    namespace: String,
    deployment_name: String,
    deployment_uid: String,
    attempt_service_account_name: String,
    attempt_service_account_uid: String,
    token_audience: String,
    commitment: RouteCommitment,
}

impl EksRouteProfile {
    /// Validates and owns one exact EKS route profile.
    ///
    /// # Errors
    ///
    /// Returns [`EksRouteProfileError`] when an identity, DNS name,
    /// Kubernetes name/UID, audience, or endpoint relationship is not in the
    /// required canonical form.
    pub fn new(input: EksRouteProfileInput<'_>) -> Result<Self, EksRouteProfileError> {
        validate_identifier(input.cluster_trust_domain)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidClusterTrustDomain)?;
        validate_identifier(input.cluster_identity)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidClusterIdentity)?;
        validate_api_server_identity(input.api_server_identity)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidApiServerIdentity)?;
        validate_dns_name(input.dns_server_name, true)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidDnsServerName)?;
        if input.port == 0 {
            return Err(EksRouteProfileError::InvalidPort);
        }
        if input.socket_target.port() != input.port {
            return Err(EksRouteProfileError::SocketPortMismatch);
        }
        validate_dns_label(input.namespace, MAX_NAMESPACE_BYTES)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidNamespace)?;
        validate_dns_subdomain(input.deployment_name, MAX_KUBERNETES_NAME_BYTES)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidDeploymentName)?;
        validate_uuid(input.deployment_uid)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidDeploymentUid)?;
        validate_dns_subdomain(
            input.attempt_service_account_name,
            MAX_KUBERNETES_NAME_BYTES,
        )
        .then_some(())
        .ok_or(EksRouteProfileError::InvalidServiceAccountName)?;
        validate_uuid(input.attempt_service_account_uid)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidServiceAccountUid)?;
        validate_identifier(input.token_audience)
            .then_some(())
            .ok_or(EksRouteProfileError::InvalidTokenAudience)?;

        let commitment = route_commitment(&input);
        Ok(Self {
            cluster_trust_domain: input.cluster_trust_domain.to_owned(),
            cluster_identity: input.cluster_identity.to_owned(),
            api_server_identity: input.api_server_identity.to_owned(),
            dns_server_name: input.dns_server_name.to_owned(),
            port: input.port,
            socket_target: input.socket_target,
            ca_trust_commitment: input.ca_trust_commitment,
            namespace: input.namespace.to_owned(),
            deployment_name: input.deployment_name.to_owned(),
            deployment_uid: input.deployment_uid.to_owned(),
            attempt_service_account_name: input.attempt_service_account_name.to_owned(),
            attempt_service_account_uid: input.attempt_service_account_uid.to_owned(),
            token_audience: input.token_audience.to_owned(),
            commitment,
        })
    }

    #[must_use]
    pub fn cluster_trust_domain(&self) -> &str {
        &self.cluster_trust_domain
    }

    #[must_use]
    pub fn cluster_identity(&self) -> &str {
        &self.cluster_identity
    }

    #[must_use]
    pub fn api_server_identity(&self) -> &str {
        &self.api_server_identity
    }

    #[must_use]
    pub fn dns_server_name(&self) -> &str {
        &self.dns_server_name
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn socket_target(&self) -> PinnedSocketTarget {
        self.socket_target
    }

    #[must_use]
    pub const fn ca_trust_commitment(&self) -> CaTrustCommitment {
        self.ca_trust_commitment
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn deployment_name(&self) -> &str {
        &self.deployment_name
    }

    #[must_use]
    pub fn deployment_uid(&self) -> &str {
        &self.deployment_uid
    }

    #[must_use]
    pub fn attempt_service_account_name(&self) -> &str {
        &self.attempt_service_account_name
    }

    #[must_use]
    pub fn attempt_service_account_uid(&self) -> &str {
        &self.attempt_service_account_uid
    }

    #[must_use]
    pub fn token_audience(&self) -> &str {
        &self.token_audience
    }

    /// Returns the versioned, domain-separated commitment to every field.
    #[must_use]
    pub const fn commitment(&self) -> RouteCommitment {
        self.commitment
    }

    /// Structural equality check for live, in-memory enforcement boundaries.
    ///
    /// Prefer this over comparing only SHA-256 commitments when both full
    /// profiles are available.
    #[must_use]
    pub fn exactly_matches(&self, other: &Self) -> bool {
        self.first_mismatch(other).is_none()
    }

    /// Identifies the first structurally different field in schema order.
    #[must_use]
    pub fn first_mismatch(&self, other: &Self) -> Option<RouteField> {
        let comparisons = [
            (
                self.cluster_trust_domain != other.cluster_trust_domain,
                RouteField::ClusterTrustDomain,
            ),
            (
                self.cluster_identity != other.cluster_identity,
                RouteField::ClusterIdentity,
            ),
            (
                self.api_server_identity != other.api_server_identity,
                RouteField::ApiServerIdentity,
            ),
            (
                self.dns_server_name != other.dns_server_name,
                RouteField::DnsServerName,
            ),
            (self.port != other.port, RouteField::Port),
            (
                self.socket_target != other.socket_target,
                RouteField::SocketTarget,
            ),
            (
                self.ca_trust_commitment != other.ca_trust_commitment,
                RouteField::CaTrustCommitment,
            ),
            (self.namespace != other.namespace, RouteField::Namespace),
            (
                self.deployment_name != other.deployment_name,
                RouteField::DeploymentName,
            ),
            (
                self.deployment_uid != other.deployment_uid,
                RouteField::DeploymentUid,
            ),
            (
                self.attempt_service_account_name != other.attempt_service_account_name,
                RouteField::AttemptServiceAccountName,
            ),
            (
                self.attempt_service_account_uid != other.attempt_service_account_uid,
                RouteField::AttemptServiceAccountUid,
            ),
            (
                self.token_audience != other.token_audience,
                RouteField::TokenAudience,
            ),
        ];
        comparisons
            .into_iter()
            .find_map(|(different, field)| different.then_some(field))
    }
}

impl fmt::Debug for EksRouteProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EksRouteProfile")
            .field("schema_version", &PROFILE_SCHEMA_VERSION)
            .field("cluster_trust_domain", &"[REDACTED]")
            .field("cluster_identity", &"[REDACTED]")
            .field("api_server_identity", &"[REDACTED]")
            .field("dns_server_name", &"[REDACTED]")
            .field("socket_target", &"[REDACTED]")
            .field("ca_trust_commitment", &"[REDACTED]")
            .field("kubernetes_scope", &"[REDACTED]")
            .field("attempt_service_account", &"[REDACTED]")
            .field("token_audience", &"[REDACTED]")
            .field("route_commitment", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Versioned SHA-256 commitment to one complete [`EksRouteProfile`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteCommitment([u8; 32]);

impl RouteCommitment {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for RouteCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RouteCommitment([REDACTED])")
    }
}

/// Exact field names used by [`EksRouteProfile::first_mismatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteField {
    ClusterTrustDomain,
    ClusterIdentity,
    ApiServerIdentity,
    DnsServerName,
    Port,
    SocketTarget,
    CaTrustCommitment,
    Namespace,
    DeploymentName,
    DeploymentUid,
    AttemptServiceAccountName,
    AttemptServiceAccountUid,
    TokenAudience,
}

/// Invalid complete route profile.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EksRouteProfileError {
    #[error("cluster trust domain is not a canonical identity")]
    InvalidClusterTrustDomain,
    #[error("cluster identity is not canonical")]
    InvalidClusterIdentity,
    #[error("API-server identity is not canonical")]
    InvalidApiServerIdentity,
    #[error("DNS server name is not a canonical multi-label DNS name")]
    InvalidDnsServerName,
    #[error("API-server port cannot be zero")]
    InvalidPort,
    #[error("profile port differs from the pinned socket target port")]
    SocketPortMismatch,
    #[error("namespace is not a canonical Kubernetes DNS label")]
    InvalidNamespace,
    #[error("Deployment name is not a canonical Kubernetes DNS subdomain")]
    InvalidDeploymentName,
    #[error("Deployment UID is not a lowercase hyphenated UUID")]
    InvalidDeploymentUid,
    #[error("attempt ServiceAccount name is not a canonical Kubernetes DNS subdomain")]
    InvalidServiceAccountName,
    #[error("attempt ServiceAccount UID is not a lowercase hyphenated UUID")]
    InvalidServiceAccountUid,
    #[error("token audience is not a canonical identity")]
    InvalidTokenAudience,
}

fn route_commitment(input: &EksRouteProfileInput<'_>) -> RouteCommitment {
    let mut hasher = Sha256::new();
    hasher.update(ROUTE_COMMITMENT_DOMAIN);
    hasher.update([PROFILE_SCHEMA_VERSION]);
    update_field(&mut hasher, 1, input.cluster_trust_domain.as_bytes());
    update_field(&mut hasher, 2, input.cluster_identity.as_bytes());
    update_field(&mut hasher, 3, input.api_server_identity.as_bytes());
    update_field(&mut hasher, 4, input.dns_server_name.as_bytes());
    update_field(&mut hasher, 5, &input.port.to_be_bytes());
    let mut socket = Vec::with_capacity(19);
    match input.socket_target.socket_addr() {
        SocketAddr::V4(value) => {
            socket.push(4);
            socket.extend_from_slice(&value.ip().octets());
            socket.extend_from_slice(&value.port().to_be_bytes());
        }
        SocketAddr::V6(value) => {
            socket.push(6);
            socket.extend_from_slice(&value.ip().octets());
            socket.extend_from_slice(&value.port().to_be_bytes());
        }
    }
    update_field(&mut hasher, 6, &socket);
    update_field(&mut hasher, 7, input.ca_trust_commitment.as_bytes());
    update_field(&mut hasher, 8, input.namespace.as_bytes());
    update_field(&mut hasher, 9, input.deployment_name.as_bytes());
    update_field(&mut hasher, 10, input.deployment_uid.as_bytes());
    update_field(
        &mut hasher,
        11,
        input.attempt_service_account_name.as_bytes(),
    );
    update_field(
        &mut hasher,
        12,
        input.attempt_service_account_uid.as_bytes(),
    );
    update_field(&mut hasher, 13, input.token_audience.as_bytes());
    RouteCommitment(hasher.finalize().into())
}

fn update_field(hasher: &mut Sha256, tag: u8, value: &[u8]) {
    hasher.update([tag]);
    update_len(hasher, value.len());
    hasher.update(value);
}

fn update_len(hasher: &mut Sha256, length: usize) {
    hasher.update(u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes());
}

fn validate_api_server_identity(value: &str) -> bool {
    if let Some(digest) = value.strip_prefix("sha256:") {
        return digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    }
    validate_identifier(value)
}

fn validate_identifier(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value
            .bytes()
            .any(|byte| matches!(byte, b'%' | b'\\' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    if !validate_scheme(scheme) || remainder.is_empty() {
        return false;
    }
    if let Some(hierarchical) = remainder.strip_prefix("//") {
        return validate_hierarchical_identifier(scheme, hierarchical);
    }
    match scheme {
        "sha256" => remainder.len() == 64 && remainder.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "urn" => validate_colon_tokens(remainder),
        "arn" => validate_eks_arn(remainder),
        _ => validate_token(remainder),
    }
}

fn validate_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'.' | b'-')
        })
}

fn validate_hierarchical_identifier(scheme: &str, value: &str) -> bool {
    let (authority, path) = value
        .split_once('/')
        .map_or((value, ""), |(head, tail)| (head, tail));
    if authority.is_empty() || authority.contains(':') {
        return false;
    }
    let require_multiple_labels = matches!(scheme, "https" | "spiffe");
    if !validate_dns_name(authority, require_multiple_labels) {
        return false;
    }
    path.is_empty()
        || path.split('/').all(|segment| {
            !segment.is_empty() && segment != "." && segment != ".." && validate_token(segment)
        })
}

fn validate_colon_tokens(value: &str) -> bool {
    value
        .split(':')
        .all(|segment| !segment.is_empty() && validate_token(segment))
}

fn validate_eks_arn(value: &str) -> bool {
    let mut fields = value.splitn(5, ':');
    let Some(partition) = fields.next() else {
        return false;
    };
    let Some(service) = fields.next() else {
        return false;
    };
    let Some(region) = fields.next() else {
        return false;
    };
    let Some(account) = fields.next() else {
        return false;
    };
    let Some(resource) = fields.next() else {
        return false;
    };
    validate_token(partition)
        && service == "eks"
        && validate_dns_label(region, 63)
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource
            .strip_prefix("cluster/")
            .is_some_and(validate_token)
}

fn validate_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'.' | b'_' | b'~')
        })
}

fn validate_dns_name(value: &str, require_multiple_labels: bool) -> bool {
    if value.is_empty()
        || value.len() > MAX_DNS_NAME_BYTES
        || value.ends_with('.')
        || value.parse::<std::net::IpAddr>().is_ok()
        || (require_multiple_labels && !value.contains('.'))
    {
        return false;
    }
    value.split('.').all(|label| validate_dns_label(label, 63))
}

fn validate_dns_subdomain(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.ends_with('.')
        && value.split('.').all(|label| validate_dns_label(label, 63))
}

fn validate_dns_label(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
    })
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DEPLOYMENT_UID: &str = "11111111-2222-4333-8444-555555555555";
    const SERVICE_ACCOUNT_UID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const API_IDENTITY: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn ca(seed: u8) -> Result<CaTrustCommitment, CaTrustError> {
        CaTrustCommitment::from_der_certificates(&[vec![0x30, seed, 0x01]])
    }

    fn target_v4(last: u8, port: u16) -> Result<PinnedSocketTarget, SocketTargetError> {
        PinnedSocketTarget::parse_canonical(&format!("10.20.30.{last}:{port}"))
    }

    fn profile() -> Result<EksRouteProfile, Box<dyn std::error::Error>> {
        Ok(EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://trust.example.test/eks/prod-a",
            cluster_identity: "arn:aws:eks:us-east-1:111122223333:cluster/prod-a",
            api_server_identity: API_IDENTITY,
            dns_server_name: "abc.gr7.us-east-1.eks.amazonaws.com",
            port: 443,
            socket_target: target_v4(40, 443)?,
            ca_trust_commitment: ca(1)?,
            namespace: "payments",
            deployment_name: "api",
            deployment_uid: DEPLOYMENT_UID,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: SERVICE_ACCOUNT_UID,
            token_audience: "https://kubernetes.default.svc",
        })?)
    }

    fn management_binding(
        subject: &str,
        seed: u8,
    ) -> Result<EksManagementAuthorityBinding, EksBrokerManagementBindingsError> {
        EksManagementAuthorityBinding::new(subject, [seed; 32])
    }

    #[test]
    fn credential_lifecycle_policy_bounds_and_safe_after_are_total()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = EksCredentialLifecyclePolicy::new(600, 900, 5, 60)?;
        assert_eq!(policy.schema_version(), 1);
        assert_eq!(policy.policy_id(), "eks-credential-lifecycle-v1");
        assert_eq!(policy.credential_safe_after(1_000), Ok(1_905));
        assert_eq!(policy.deletion_safe_after(1_000), Ok(1_065));
        assert_eq!(
            policy.credential_safe_after(-1),
            Err(EksCredentialLifecyclePolicyError::InvalidTime)
        );
        assert_eq!(
            policy.deletion_safe_after(-1),
            Err(EksCredentialLifecyclePolicyError::InvalidTime)
        );
        assert_eq!(
            policy.credential_safe_after(i64::MAX),
            Err(EksCredentialLifecyclePolicyError::TimeOverflow)
        );
        assert_eq!(
            policy.deletion_safe_after(i64::MAX),
            Err(EksCredentialLifecyclePolicyError::TimeOverflow)
        );
        for invalid in [
            (0, 900, 5, 60),
            (901, 900, 5, 60),
            (1, 86_401, 5, 60),
            (1, 900, -1, 60),
            (1, 900, 301, 60),
            (1, 900, 5, 59),
            (1, 900, 5, 86_401),
        ] {
            assert_eq!(
                EksCredentialLifecyclePolicy::new(invalid.0, invalid.1, invalid.2, invalid.3),
                Err(EksCredentialLifecyclePolicyError::InvalidBounds)
            );
        }
        let commitment = policy.commitment();
        assert_ne!(commitment.as_bytes(), &[0; 32]);
        assert_ne!(
            commitment,
            EksCredentialLifecyclePolicy::new(601, 900, 5, 60)?.commitment()
        );
        assert_ne!(
            commitment,
            EksCredentialLifecyclePolicy::new(600, 901, 5, 60)?.commitment()
        );
        assert_ne!(
            commitment,
            EksCredentialLifecyclePolicy::new(600, 900, 6, 60)?.commitment()
        );
        assert_ne!(
            commitment,
            EksCredentialLifecyclePolicy::new(600, 900, 5, 61)?.commitment()
        );
        Ok(())
    }

    #[test]
    fn management_bindings_reject_reuse_and_noncanonical_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = management_binding("spiffe://accordlock/secret", 1)?;
        let token = management_binding("spiffe://accordlock/token", 2)?;
        let review = management_binding("spiffe://accordlock/review", 3)?;
        let bindings =
            EksBrokerManagementBindings::new(secret.clone(), token.clone(), review.clone())?;
        assert_eq!(bindings.secret_lifecycle(), &secret);
        assert_eq!(bindings.service_account_token(), &token);
        assert_eq!(bindings.token_review(), &review);
        assert_eq!(
            EksBrokerManagementBindings::new(secret.clone(), secret.clone(), review.clone()),
            Err(EksBrokerManagementBindingsError::SubjectReused)
        );
        assert_eq!(
            EksBrokerManagementBindings::new(
                secret,
                EksManagementAuthorityBinding::new("spiffe://accordlock/token", [3; 32])?,
                review,
            ),
            Err(EksBrokerManagementBindingsError::RbacCommitmentReused)
        );
        assert_eq!(
            EksManagementAuthorityBinding::new(" bad", [4; 32]),
            Err(EksBrokerManagementBindingsError::InvalidSubject)
        );
        assert_eq!(
            EksManagementAuthorityBinding::new("spiffe://accordlock/other", [0; 32]),
            Err(EksBrokerManagementBindingsError::ZeroRbacCommitment)
        );
        Ok(())
    }

    #[test]
    fn constructs_stable_profile_and_safe_getters() -> Result<(), Box<dyn std::error::Error>> {
        let first = profile()?;
        let second = profile()?;
        assert!(first.exactly_matches(&second));
        assert_eq!(first.first_mismatch(&second), None);
        assert_eq!(first.commitment(), second.commitment());
        assert_eq!(
            first.commitment().to_hex(),
            "6c983e9dcb2456b2d611f94dc45eec0ba0f77975ab7431ebe02fd3fb6ca9bb93"
        );
        assert_eq!(
            first.cluster_identity(),
            "arn:aws:eks:us-east-1:111122223333:cluster/prod-a"
        );
        assert_eq!(
            first.socket_target().socket_addr().to_string(),
            "10.20.30.40:443"
        );
        assert_eq!(first.commitment().to_hex().len(), 64);
        assert_eq!(first.ca_trust_commitment().to_hex().len(), 64);
        Ok(())
    }

    #[test]
    fn debug_redacts_route_and_commitment_material() -> Result<(), Box<dyn std::error::Error>> {
        let route = profile()?;
        let rendered = format!(
            "{route:?} {:?} {:?}",
            route.commitment(),
            route.ca_trust_commitment()
        );
        for forbidden in [
            "trust.example.test",
            "111122223333",
            "10.20.30.40",
            "kubernetes.default.svc",
            &route.commitment().to_hex(),
            &route.ca_trust_commitment().to_hex(),
        ] {
            assert!(!rendered.contains(forbidden));
        }
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn ca_commitment_is_order_independent_but_duplicate_sensitive() -> Result<(), CaTrustError> {
        let left = CaTrustCommitment::from_der_certificates(&[vec![3], vec![1], vec![2]])?;
        let right = CaTrustCommitment::from_der_certificates(&[vec![2], vec![3], vec![1]])?;
        assert_eq!(left, right);
        assert_eq!(
            CaTrustCommitment::from_der_certificates(&[vec![1], vec![1]]),
            Err(CaTrustError::DuplicateCertificate)
        );
        assert_eq!(
            CaTrustCommitment::from_sha256_bytes([0; 32]),
            Err(CaTrustError::ZeroCommitment)
        );
        Ok(())
    }

    #[test]
    fn rejects_socket_aliases_and_unsafe_classes() {
        for value in [
            " 10.20.30.40:443",
            "10.20.30.40:0443",
            "2001:db8::1:443",
            "[2001:0db8:0:0:0:0:0:1]:443",
        ] {
            assert_eq!(
                PinnedSocketTarget::parse_canonical(value),
                Err(SocketTargetError::NonCanonicalText)
            );
        }
        for value in [
            "0.0.0.0:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "[::1]:443",
            "[fe80::1]:443",
            "[::ffff:192.0.2.1]:443",
        ] {
            assert_eq!(
                PinnedSocketTarget::parse_canonical(value),
                Err(SocketTargetError::UnsafeAddressClass)
            );
        }
        assert!(PinnedSocketTarget::parse_canonical("[2001:db8::1]:443").is_ok());
    }

    #[test]
    fn rejects_aliases_in_security_names() -> Result<(), Box<dyn std::error::Error>> {
        let target = target_v4(40, 443)?;
        let trust = ca(1)?;
        let base = |cluster_trust_domain, dns_server_name, namespace, deployment_uid, audience| {
            EksRouteProfile::new(EksRouteProfileInput {
                cluster_trust_domain,
                cluster_identity: "eks://prod-a",
                api_server_identity: API_IDENTITY,
                dns_server_name,
                port: 443,
                socket_target: target,
                ca_trust_commitment: trust,
                namespace,
                deployment_name: "api",
                deployment_uid,
                attempt_service_account_name: "accordlock-attempt",
                attempt_service_account_uid: SERVICE_ACCOUNT_UID,
                token_audience: audience,
            })
        };
        assert_eq!(
            base(
                "SPIFFE://trust.example.test/eks/prod-a",
                "api.example.test",
                "payments",
                DEPLOYMENT_UID,
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidClusterTrustDomain)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/prod-a",
                "Api.Example.Test",
                "payments",
                DEPLOYMENT_UID,
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidDnsServerName)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/prod-a",
                "api.example.test.",
                "payments",
                DEPLOYMENT_UID,
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidDnsServerName)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/../prod-a",
                "api.example.test",
                "payments",
                DEPLOYMENT_UID,
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidClusterTrustDomain)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/prod-a",
                "api.example.test",
                " payments",
                DEPLOYMENT_UID,
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidNamespace)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/prod-a",
                "api.example.test",
                "payments",
                "11111111-2222-4333-8444-55555555555A",
                "https://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidDeploymentUid)
        );
        assert_eq!(
            base(
                "spiffe://trust.example.test/eks/prod-a",
                "api.example.test",
                "payments",
                DEPLOYMENT_UID,
                "HTTPS://kubernetes.default.svc"
            ),
            Err(EksRouteProfileError::InvalidTokenAudience)
        );
        Ok(())
    }

    #[test]
    fn port_must_match_explicit_socket() -> Result<(), Box<dyn std::error::Error>> {
        let result = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: "spiffe://trust.example.test/eks/prod-a",
            cluster_identity: "eks://prod-a",
            api_server_identity: API_IDENTITY,
            dns_server_name: "api.example.test",
            port: 8443,
            socket_target: target_v4(40, 443)?,
            ca_trust_commitment: ca(1)?,
            namespace: "payments",
            deployment_name: "api",
            deployment_uid: DEPLOYMENT_UID,
            attempt_service_account_name: "accordlock-attempt",
            attempt_service_account_uid: SERVICE_ACCOUNT_UID,
            token_audience: "https://kubernetes.default.svc",
        });
        assert_eq!(result, Err(EksRouteProfileError::SocketPortMismatch));
        Ok(())
    }

    #[test]
    // One table deliberately enumerates every schema field. Keeping it in one
    // test makes omissions visible when the profile grows.
    #[allow(clippy::too_many_lines)]
    fn every_route_field_changes_the_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let baseline = profile()?;
        let candidates = [
            make_variant(
                "spiffe://other.example.test/eks/prod-a",
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                "eks://prod-b",
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                "urn:accordlock:api:prod-b",
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                "def.gr7.us-east-1.eks.amazonaws.com",
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                8443,
                target_v4(40, 8443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(41, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(2)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                "orders",
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                "worker",
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                "21111111-2222-4333-8444-555555555555",
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                "accordlock-attempt-b",
                baseline.attempt_service_account_uid(),
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                "baaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                baseline.token_audience(),
            )?,
            make_variant(
                baseline.cluster_trust_domain(),
                baseline.cluster_identity(),
                baseline.api_server_identity(),
                baseline.dns_server_name(),
                443,
                target_v4(40, 443)?,
                ca(1)?,
                baseline.namespace(),
                baseline.deployment_name(),
                baseline.deployment_uid(),
                baseline.attempt_service_account_name(),
                baseline.attempt_service_account_uid(),
                "urn:accordlock:audience:alternate",
            )?,
        ];
        let expected_mismatches = [
            RouteField::ClusterTrustDomain,
            RouteField::ClusterIdentity,
            RouteField::ApiServerIdentity,
            RouteField::DnsServerName,
            RouteField::Port,
            RouteField::SocketTarget,
            RouteField::CaTrustCommitment,
            RouteField::Namespace,
            RouteField::DeploymentName,
            RouteField::DeploymentUid,
            RouteField::AttemptServiceAccountName,
            RouteField::AttemptServiceAccountUid,
            RouteField::TokenAudience,
        ];
        for (candidate, expected_mismatch) in candidates.into_iter().zip(expected_mismatches) {
            assert_ne!(baseline.commitment(), candidate.commitment());
            assert!(!baseline.exactly_matches(&candidate));
            assert_eq!(baseline.first_mismatch(&candidate), Some(expected_mismatch));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn make_variant(
        cluster_trust_domain: &str,
        cluster_identity: &str,
        api_server_identity: &str,
        dns_server_name: &str,
        port: u16,
        socket_target: PinnedSocketTarget,
        ca_trust_commitment: CaTrustCommitment,
        namespace: &str,
        deployment_name: &str,
        deployment_uid: &str,
        attempt_service_account_name: &str,
        attempt_service_account_uid: &str,
        token_audience: &str,
    ) -> Result<EksRouteProfile, EksRouteProfileError> {
        EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain,
            cluster_identity,
            api_server_identity,
            dns_server_name,
            port,
            socket_target,
            ca_trust_commitment,
            namespace,
            deployment_name,
            deployment_uid,
            attempt_service_account_name,
            attempt_service_account_uid,
            token_audience,
        })
    }

    proptest! {
        #[test]
        fn dns_case_and_trailing_dot_aliases_are_never_normalized(
            first in "[a-z]",
            tail in "[a-z0-9]{0,20}",
        ) {
            let label = format!("{first}{tail}");
            let canonical = format!("{label}.example.test");
            let trailing_dot_alias = format!("{canonical}.");
            prop_assert!(validate_dns_name(&canonical, true));
            prop_assert!(!validate_dns_name(&trailing_dot_alias, true));
            prop_assert!(!validate_dns_name(&canonical.to_ascii_uppercase(), true));
        }

        #[test]
        fn changing_any_ca_byte_changes_its_commitment(seed in 1_u8..=254, delta in 1_u8..=255) {
            let other = seed ^ delta;
            prop_assume!(other != seed);
            let left = CaTrustCommitment::from_der_certificates(&[vec![0x30, seed]]);
            let right = CaTrustCommitment::from_der_certificates(&[vec![0x30, other]]);
            prop_assert!(left.is_ok());
            prop_assert!(right.is_ok());
            prop_assert_ne!(left, right);
        }
    }
}

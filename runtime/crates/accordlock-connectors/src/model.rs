use accordlock_protocol::{CompletenessProfile, Digest32, EvidenceKind};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use uuid::Uuid;

/// Maximum UTF-8 length of any untrusted lookup identifier.
pub const MAX_LOOKUP_ID_BYTES: usize = 256;
/// Maximum UTF-8 length accepted for an evidence source URI.
pub const MAX_SOURCE_URI_BYTES: usize = 2_048;
/// Maximum UTF-8 length accepted for a source fact represented as text.
pub const MAX_SOURCE_FIELD_BYTES: usize = 1_024;
/// Hard ceiling for evidence assertion lifetime in this connector profile.
pub const MAX_EVIDENCE_TTL_SECONDS: i64 = 900;
/// Hard ceiling for accepted source observation age.
pub const MAX_SOURCE_AGE_SECONDS: i64 = 600;
/// Hard ceiling for tolerated positive clock skew.
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 60;

/// Public, non-secret identity of one fixed connector source.
///
/// Both digests are commitments produced by trusted bootstrap code. They do
/// not contain credentials: `source_identity_hash` binds the adapter's exact
/// fixed route/configuration and `transport_identity_hash` binds the public
/// identity of the authenticated transport which owns credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorSourceIdentityDescriptor {
    pub kind: EvidenceKind,
    pub endpoint_uri_prefix: String,
    pub source_identity_hash: Digest32,
    pub transport_identity_hash: Digest32,
}

impl ConnectorSourceIdentityDescriptor {
    /// Creates a validated non-secret source identity descriptor.
    ///
    /// # Errors
    ///
    /// Rejects a non-HTTPS endpoint prefix or an empty identity commitment.
    pub fn new(
        kind: EvidenceKind,
        endpoint_uri_prefix: impl Into<String>,
        source_identity_hash: Digest32,
        transport_identity_hash: Digest32,
    ) -> Result<Self, ConnectorError> {
        let endpoint_uri_prefix = endpoint_uri_prefix.into();
        validate_uri_prefix_for_identity(&endpoint_uri_prefix)?;
        if source_identity_hash == Digest32::from_bytes([0; 32])
            || transport_identity_hash == Digest32::from_bytes([0; 32])
        {
            return Err(ConnectorError::InvalidConfiguration(
                "connector source identity commitment",
            ));
        }
        Ok(Self {
            kind,
            endpoint_uri_prefix,
            source_identity_hash,
            transport_identity_hash,
        })
    }
}

macro_rules! lookup_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses one bounded, opaque lookup identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorError::InvalidLookupId`] for an empty,
            /// noncanonical, control-bearing, or overlong identifier.
            pub fn parse(value: impl Into<String>) -> Result<Self, ConnectorError> {
                let value = value.into();
                validate_lookup_id(&value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(de::Error::custom)
            }
        }
    };
}

lookup_id!(ReviewLookupId, "review_lookup_id");
lookup_id!(BuildLookupId, "build_lookup_id");
lookup_id!(ArtifactLookupId, "artifact_lookup_id");
lookup_id!(TargetLookupId, "target_lookup_id");

/// The complete untrusted connector request surface.
///
/// It contains only correlation and lookup identifiers. Security facts cannot
/// be represented in this schema and unknown serialized fields are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLookupRequest {
    pub request_id: Uuid,
    pub review_lookup_id: ReviewLookupId,
    pub build_lookup_id: BuildLookupId,
    pub artifact_lookup_id: ArtifactLookupId,
    pub target_lookup_id: TargetLookupId,
}

impl EvidenceLookupRequest {
    #[must_use]
    pub const fn new(
        request_id: Uuid,
        review_lookup_id: ReviewLookupId,
        build_lookup_id: BuildLookupId,
        artifact_lookup_id: ArtifactLookupId,
        target_lookup_id: TargetLookupId,
    ) -> Self {
        Self {
            request_id,
            review_lookup_id,
            build_lookup_id,
            artifact_lookup_id,
            target_lookup_id,
        }
    }
}

/// Trusted metadata returned by one configured source adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshotMeta {
    pub request_id: Uuid,
    pub lookup_id: String,
    pub evidence_id: Uuid,
    pub source_uri: String,
    pub observed_at: i64,
    /// Monotonic cursor in the configured adapter's source stream.
    pub source_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewSourceSnapshot {
    pub meta: SourceSnapshotMeta,
    pub repository: String,
    pub commit_sha: String,
    pub approved: bool,
    pub review_state_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildSourceSnapshot {
    pub meta: SourceSnapshotMeta,
    pub repository: String,
    pub commit_sha: String,
    pub workflow_ref: String,
    pub run_id: String,
    pub succeeded: bool,
    pub input_manifest_root: Digest32,
    pub completeness_profile: CompletenessProfile,
    pub output_digest: Digest32,
}

/// Artifact facts plus trusted route bindings not copied into the protocol
/// payload. The latter are checked against Review, Build, and Target facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSourceSnapshot {
    pub meta: SourceSnapshotMeta,
    pub source_repository: String,
    pub commit_sha: String,
    pub image_repository: String,
    pub digest: Digest32,
    pub source_run_id: String,
    pub signature_valid: bool,
    pub quarantined: bool,
}

/// Current target facts plus trusted action-route bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSourceSnapshot {
    pub meta: SourceSnapshotMeta,
    pub source_repository: String,
    pub commit_sha: String,
    pub image_repository: String,
    pub desired_image_digest: Digest32,
    pub cluster_identity: String,
    pub namespace: String,
    pub deployment: String,
    pub deployment_uid: String,
    pub resource_version: String,
    pub current_image: Digest32,
    pub projection_hash: Digest32,
}

/// A source error safe to propagate without treating it as evidence.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("trusted source read failed: {code}")]
pub struct SourceReadError {
    code: String,
}

impl SourceReadError {
    /// Creates a bounded diagnostic code. Free-form upstream response bodies
    /// should not be placed here.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::InvalidField`] for an invalid code.
    pub fn new(code: impl Into<String>) -> Result<Self, ConnectorError> {
        let code = code.into();
        validate_text(&code, "source_error_code", 128)?;
        Ok(Self { code })
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

pub trait ReviewSource: Send + Sync {
    /// Returns the intrinsic public identity of this exact source object.
    ///
    /// # Errors
    ///
    /// Returns an error if its fixed bootstrap identity is unavailable.
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError>;

    /// Reads one review snapshot from the fixed authenticated source.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReadError`] when no complete authenticated snapshot can
    /// be obtained for the lookup.
    fn fetch(&self, lookup: &ReviewLookupId) -> Result<ReviewSourceSnapshot, SourceReadError>;
}

pub trait BuildSource: Send + Sync {
    /// Returns the intrinsic public identity of this exact source object.
    ///
    /// # Errors
    ///
    /// Returns an error if its fixed bootstrap identity is unavailable.
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError>;

    /// Reads one build snapshot from the fixed authenticated source.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReadError`] when no complete authenticated snapshot can
    /// be obtained for the lookup.
    fn fetch(&self, lookup: &BuildLookupId) -> Result<BuildSourceSnapshot, SourceReadError>;
}

pub trait ArtifactSource: Send + Sync {
    /// Returns the intrinsic public identity of this exact source object.
    ///
    /// # Errors
    ///
    /// Returns an error if its fixed bootstrap identity is unavailable.
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError>;

    /// Reads one artifact snapshot from the fixed authenticated source.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReadError`] when no complete authenticated snapshot can
    /// be obtained for the lookup.
    fn fetch(&self, lookup: &ArtifactLookupId) -> Result<ArtifactSourceSnapshot, SourceReadError>;
}

pub trait TargetSource: Send + Sync {
    /// Returns the intrinsic public identity of this exact source object.
    ///
    /// # Errors
    ///
    /// Returns an error if its fixed bootstrap identity is unavailable.
    fn identity_descriptor(&self) -> Result<ConnectorSourceIdentityDescriptor, ConnectorError>;

    /// Reads one target snapshot from the fixed authenticated source.
    ///
    /// # Errors
    ///
    /// Returns [`SourceReadError`] when no complete authenticated snapshot can
    /// be obtained for the lookup.
    fn fetch(&self, lookup: &TargetLookupId) -> Result<TargetSourceSnapshot, SourceReadError>;
}

pub trait TrustedClock: Send + Sync {
    /// Returns nonnegative Unix seconds from the fixed trusted clock.
    ///
    /// # Errors
    ///
    /// Returns [`ClockReadError`] when a trustworthy value is unavailable.
    fn unix_seconds(&self) -> Result<i64, ClockReadError>;
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("trusted clock read failed")]
pub struct ClockReadError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityProfile {
    ttl_seconds: i64,
    maximum_source_age_seconds: i64,
    maximum_future_skew_seconds: i64,
    required_completeness_profile: CompletenessProfile,
}

impl ValidityProfile {
    /// Creates a validity profile within hard connector ceilings.
    ///
    /// The TTL must be strictly larger than the maximum accepted source age,
    /// ensuring accepted evidence remains valid at the collection instant.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::InvalidConfiguration`] outside the profile.
    pub fn new(
        ttl_seconds: i64,
        maximum_source_age_seconds: i64,
        maximum_future_skew_seconds: i64,
        required_completeness_profile: CompletenessProfile,
    ) -> Result<Self, ConnectorError> {
        if !(1..=MAX_EVIDENCE_TTL_SECONDS).contains(&ttl_seconds)
            || !(0..=MAX_SOURCE_AGE_SECONDS).contains(&maximum_source_age_seconds)
            || maximum_source_age_seconds >= ttl_seconds
            || !(0..=MAX_FUTURE_SKEW_SECONDS).contains(&maximum_future_skew_seconds)
        {
            return Err(ConnectorError::InvalidConfiguration("validity profile"));
        }
        Ok(Self {
            ttl_seconds,
            maximum_source_age_seconds,
            maximum_future_skew_seconds,
            required_completeness_profile,
        })
    }

    #[must_use]
    pub const fn ttl_seconds(self) -> i64 {
        self.ttl_seconds
    }

    #[must_use]
    pub const fn maximum_source_age_seconds(self) -> i64 {
        self.maximum_source_age_seconds
    }

    #[must_use]
    pub const fn maximum_future_skew_seconds(self) -> i64 {
        self.maximum_future_skew_seconds
    }

    #[must_use]
    pub const fn required_completeness_profile(self) -> CompletenessProfile {
        self.required_completeness_profile
    }
}

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("invalid connector configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid lookup identifier: {0}")]
    InvalidLookupId(&'static str),
    #[error("trusted {kind:?} source failed: {code}")]
    SourceRead { kind: EvidenceKind, code: String },
    #[error("request identifier is nil")]
    NilRequestId,
    #[error("{kind:?} source record is bound to a different request")]
    RequestBindingMismatch { kind: EvidenceKind },
    #[error("{kind:?} source record is bound to a different lookup")]
    LookupBindingMismatch { kind: EvidenceKind },
    #[error("{kind:?} source URI is invalid or outside its configured route")]
    SourceUriMismatch { kind: EvidenceKind },
    #[error("invalid source field: {0}")]
    InvalidField(&'static str),
    #[error("invalid commit SHA in {0}")]
    InvalidCommitSha(&'static str),
    #[error("{kind:?} source evidence is stale")]
    StaleObservation { kind: EvidenceKind },
    #[error("{kind:?} source evidence is from the future")]
    FutureObservation { kind: EvidenceKind },
    #[error("trusted clock moved backwards")]
    ClockRollback,
    #[error("{kind:?} validity calculation overflowed")]
    TimeOverflow { kind: EvidenceKind },
    #[error("build completeness profile is not the configured profile")]
    CompletenessProfileMismatch,
    #[error("source repository routes disagree")]
    RepositoryRouteMismatch,
    #[error("source commit routes disagree")]
    CommitRouteMismatch,
    #[error("build output, artifact digest, and target desired digest disagree")]
    OutputRouteMismatch,
    #[error("artifact source run does not match the selected build")]
    BuildRunRouteMismatch,
    #[error("artifact and target image repositories disagree")]
    TargetRouteMismatch,
    #[error("evidence identifier is nil or duplicated")]
    DuplicateEvidenceId,
    #[error("{kind:?} source sequence moved backwards")]
    SourceRollback { kind: EvidenceKind },
    #[error("{kind:?} source reused a sequence for different facts")]
    SourceEquivocation { kind: EvidenceKind },
    #[error("evidence identifier was reused for a different assertion or request")]
    EvidenceIdReuse,
    #[error("connector checkpoint lock is unavailable")]
    CheckpointUnavailable,
    #[error("canonical evidence encoding failed: {0}")]
    Canonical(String),
    #[error("evidence signing failed: {0}")]
    Crypto(String),
    #[error("connector runtime identity does not match its attester routes")]
    RuntimeIdentityRouteMismatch,
}

fn validate_uri_prefix_for_identity(value: &str) -> Result<(), ConnectorError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_URI_BYTES
        || !value.starts_with("https://")
        || !value.ends_with('/')
        || value.contains(['@', '#', '?'])
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(ConnectorError::InvalidConfiguration(
            "connector source endpoint",
        ));
    }
    let authority = value["https://".len()..]
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.starts_with('.') || authority.ends_with('.') {
        return Err(ConnectorError::InvalidConfiguration(
            "connector source endpoint",
        ));
    }
    Ok(())
}

pub(crate) fn validate_lookup_id(value: &str, label: &'static str) -> Result<(), ConnectorError> {
    if value.is_empty()
        || value.len() > MAX_LOOKUP_ID_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ConnectorError::InvalidLookupId(label));
    }
    Ok(())
}

pub(crate) fn validate_text(
    value: &str,
    label: &'static str,
    maximum: usize,
) -> Result<(), ConnectorError> {
    if value.is_empty()
        || value.len() > maximum.min(MAX_SOURCE_FIELD_BYTES)
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ConnectorError::InvalidField(label));
    }
    Ok(())
}

pub(crate) fn validate_commit_sha(value: &str, label: &'static str) -> Result<(), ConnectorError> {
    let valid_length = value.len() == 40 || value.len() == 64;
    if !valid_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConnectorError::InvalidCommitSha(label));
    }
    Ok(())
}

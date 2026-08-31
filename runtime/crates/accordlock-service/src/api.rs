use core::fmt;

/// Maximum signed proposal envelope accepted by the application boundary.
///
/// The trusted ingress performs its own strict decoding and repeats its own
/// bound. Keeping the same ceiling here prevents needlessly handing oversized
/// input to a TCB adapter.
pub const MAX_SIGNED_SUBMISSION_BYTES: usize = accordlock_ingress::MAX_INGRESS_JSON_BYTES;

/// Maximum signed status-authentication envelope accepted by this layer.
///
/// `accordlock-service` deliberately does not define a production status-signature
/// schema. The installed ingress adapter owns that schema and must bind it to
/// the exact [`StatusLookup`].
pub const MAX_SIGNED_STATUS_BYTES: usize = 16_384;

const MAX_IDENTIFIER_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierViolation {
    Empty,
    TooLong,
    InvalidBoundary,
    InvalidCharacter,
    AmbiguousPathSegment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifierError {
    kind: &'static str,
    violation: IdentifierViolation,
}

impl IdentifierError {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub const fn violation(&self) -> IdentifierViolation {
        self.violation
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} identifier violates {:?}",
            self.kind, self.violation
        )
    }
}

impl std::error::Error for IdentifierError {}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), IdentifierError> {
    let violation = if value.is_empty() {
        Some(IdentifierViolation::Empty)
    } else if value.len() > MAX_IDENTIFIER_BYTES {
        Some(IdentifierViolation::TooLong)
    } else if !value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        Some(IdentifierViolation::InvalidBoundary)
    } else if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Some(IdentifierViolation::InvalidCharacter)
    } else if value.contains("..") {
        Some(IdentifierViolation::AmbiguousPathSegment)
    } else {
        None
    };

    violation.map_or(Ok(()), |violation| Err(IdentifierError { kind, violation }))
}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs a non-authorizing lookup identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] for malformed or ambiguous text.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_identifier($kind, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(RequestId, "request");
identifier_type!(ReceiptId, "receipt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeViolation {
    Empty,
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeError {
    kind: &'static str,
    violation: EnvelopeViolation,
}

impl EnvelopeError {
    #[must_use]
    pub const fn kind(self) -> &'static str {
        self.kind
    }

    #[must_use]
    pub const fn violation(self) -> EnvelopeViolation {
        self.violation
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} envelope violates {:?}",
            self.kind, self.violation
        )
    }
}

impl std::error::Error for EnvelopeError {}

fn validate_envelope(
    kind: &'static str,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<(), EnvelopeError> {
    if bytes.is_empty() {
        Err(EnvelopeError {
            kind,
            violation: EnvelopeViolation::Empty,
        })
    } else if bytes.len() > maximum_bytes {
        Err(EnvelopeError {
            kind,
            violation: EnvelopeViolation::TooLarge,
        })
    } else {
        Ok(())
    }
}

/// Bounded bytes containing one signed `accordlock-ingress` proposal envelope.
///
/// The envelope carries the sole action intent: the signed
/// `AgentProposal`. This layer deliberately exposes no second `SubmitIntent`
/// that could diverge from it.
pub struct SubmissionEnvelope {
    bytes: Vec<u8>,
}

impl SubmissionEnvelope {
    /// Bounds, owns, and preserves the exact signed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] for an empty or oversized envelope. Syntax,
    /// signature, replay, audience, and caller binding remain TCB checks.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, EnvelopeError> {
        let bytes = bytes.into();
        validate_envelope("submission", &bytes, MAX_SIGNED_SUBMISSION_BYTES)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for SubmissionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmissionEnvelope")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Exact, non-authorizing key for one public status projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusLookup {
    receipt_id: ReceiptId,
}

impl StatusLookup {
    #[must_use]
    pub const fn new(receipt_id: ReceiptId) -> Self {
        Self { receipt_id }
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }
}

/// A status lookup plus signed authentication bytes.
///
/// The installed TCB adapter must authenticate the bytes and prove they bind
/// the exact lookup. The lookup alone conveys no read or execution authority.
pub struct StatusEnvelope {
    lookup: StatusLookup,
    authentication_bytes: Vec<u8>,
}

impl StatusEnvelope {
    /// Constructs a bounded status envelope.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] for empty or oversized authentication bytes.
    pub fn from_bytes(
        lookup: StatusLookup,
        authentication_bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, EnvelopeError> {
        let authentication_bytes = authentication_bytes.into();
        validate_envelope(
            "status authentication",
            &authentication_bytes,
            MAX_SIGNED_STATUS_BYTES,
        )?;
        Ok(Self {
            lookup,
            authentication_bytes,
        })
    }

    #[must_use]
    pub const fn lookup(&self) -> &StatusLookup {
        &self.lookup
    }

    #[must_use]
    pub fn authentication_bytes(&self) -> &[u8] {
        &self.authentication_bytes
    }

    pub(crate) fn into_parts(self) -> (StatusLookup, Vec<u8>) {
        (self.lookup, self.authentication_bytes)
    }
}

impl fmt::Debug for StatusEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusEnvelope")
            .field("lookup", &self.lookup)
            .field("authentication_bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionState {
    Denied,
    Authorized,
    DispatchPending,
    AttemptInFlight,
    Succeeded,
    Failed,
    ManualResolutionRequired,
}

impl ActionState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Succeeded | Self::Failed | Self::ManualResolutionRequired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicReasonCode {
    PolicyDenied,
    GrantDenied,
    EvidenceInsufficient,
    AuthorityChanged,
    RequestConflict,
    InternalControlFailure,
    DispatchOutcomeUnknown,
}

/// Status-only acknowledgement. Possession conveys no authority to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionReceipt {
    request_id: RequestId,
    receipt_id: ReceiptId,
    state: ActionState,
    reason: Option<PublicReasonCode>,
}

impl SubmissionReceipt {
    pub(crate) fn from_status(status: &StatusView) -> Self {
        Self {
            request_id: status.request_id.clone(),
            receipt_id: status.receipt_id.clone(),
            state: status.state,
            reason: status.reason,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    #[must_use]
    pub const fn state(&self) -> ActionState {
        self.state
    }

    #[must_use]
    pub const fn reason(&self) -> Option<PublicReasonCode> {
        self.reason
    }

    #[must_use]
    pub fn status_lookup(&self) -> StatusLookup {
        StatusLookup::new(self.receipt_id.clone())
    }
}

/// Read-only projection containing no ingress capability, authorization, credential,
/// dispatch claim, command, signature, `AUTHORIZATION_ID`, or mutation method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusView {
    request_id: RequestId,
    receipt_id: ReceiptId,
    state: ActionState,
    reason: Option<PublicReasonCode>,
}

impl StatusView {
    #[must_use]
    pub const fn new(
        request_id: RequestId,
        receipt_id: ReceiptId,
        state: ActionState,
        reason: Option<PublicReasonCode>,
    ) -> Self {
        Self {
            request_id,
            receipt_id,
            state,
            reason,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    #[must_use]
    pub const fn state(&self) -> ActionState {
        self.state
    }

    #[must_use]
    pub const fn reason(&self) -> Option<PublicReasonCode> {
        self.reason
    }
}

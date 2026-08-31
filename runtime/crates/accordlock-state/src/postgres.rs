use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use accordlock_eks_profile::{
    CaTrustCommitment, EksBrokerManagementBindings, EksCredentialLifecyclePolicy,
    EksManagementAuthorityBinding, EksRouteProfile, EksRouteProfileInput, PinnedSocketTarget,
};
use accordlock_protocol::{
    AuthorityDomainState, AuthorityVector, ConsumptionReceipt, Digest32, canonical_hash,
};
use accordlock_terminal_witness::{
    ActivatedWitnessRegistry, RegisteredWitnessVerifier, WitnessRegistryAuthority, WitnessRole,
    WitnessScope, WitnessVerifierStatus,
};
use postgres::config::{ChannelBinding, Host, SslMode, TargetSessionAttrs};
use postgres::error::SqlState;
use postgres::{Client, Config, GenericClient, IsolationLevel, NoTls, Row, Transaction};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{
    CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer,
    pem::{PemObject as _, SectionKind},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use tokio_postgres_rustls::MakeRustlsConnect;
use uuid::Uuid;

use crate::acquisition::{
    DISPATCH_ACQUISITION_LEASE_SECONDS, DispatchAcquisitionAuthority,
    DispatchAcquisitionDisposition, DispatchAcquisitionOutcome, DispatchAcquisitionReceipt,
    DispatchAcquisitionRecoveryKey, DispatchAcquisitionRequest, DispatchQueueDispositionReason,
    DispatchQueueDispositionReceipt, DispatchRecoveryWork, DispatchWork,
    dispatch_authority_fact_commitment, dispatch_grant_fact_commitment,
    dispatch_outbox_fact_commitment,
};
use crate::broker::{
    AcquiredBrokerOperationRequest, AuthenticatedDispatchCredentialReview, BrokerCleanupRequest,
    BrokerIoAuthority, BrokerJournalCapability, BrokerJournalCapabilityIssuer,
    BrokerJournalOperation, BrokerJournalOutcome, BrokerJournalPhase, BrokerJournalSelector,
    BrokerJournalState, BrokerOperationAudit, BrokerOperationIntent, BrokerOperationReceipt,
    BrokerOperationRequest, BrokerReconciliationAuthority, BrokerReconciliationRequest,
    BrokerReconciliationResult, BrokerSecretObservation, BrokerTokenIssueObservation,
    CredentialReviewIoAuthority, DispatchBrokerRestartContext, DispatchCredentialReviewAudit,
    DispatchCredentialReviewClaims, DispatchCredentialReviewPhase,
    DispatchCredentialReviewRecoveryKey, DispatchRestartDeletionEvidence,
    RejectedDispatchCredentialReview, ReviewedDispatchCredential, StoredBrokerOperation,
    StoredDispatchCredentialReview, broker_result_commitment, pending_broker_reconciliation,
    validate_cleanup_clock,
};
use crate::eks_registry::{
    ActivationKey, CurrentEksAttempt, EksDestinationProfile, EksDestinationRegistryState,
    EksRegistryError, FrozenEksAttempt, PhysicalOwner, RootedEksDestination, derive_attempt_facts,
};
use crate::ingress_replay::{
    IngressNonceConsumption, IngressReplayDecision, IngressReplayScope, IngressReplayState,
    valid_gc_limit, validate_observed_time,
};
use crate::model::{
    AdmissionAuthorization, AdmissionAuthorizationRequest, AdmissionContext, AttemptInFlight,
    ClaimedDispatch, ConsumeKey, ConsumeSuccess, DISPATCH_CLAIM_LEASE_SECONDS,
    DispatchClaimRequest, DispatchClaimToken, DispatchCredentialBinding,
    DispatchRecoveryAcquisition, DispatchSnapshot, GrantRegistration, GrantSnapshot,
    IssuanceSnapshot, IssuedAuthorizationRecord, OutboxEntry, OutboxStatus, PhysicalResourceKey,
    RecoveryNoSendReceipt, RecoveryNoSendRetirementOutcome, RecoveryNoSendRetirementReceipt, Scope,
    StateError, TransactionalState, admission_projection, ensure_monotone_authority,
    is_temporal_rejection_for_sample, validate_admission_provider_commitment,
    validate_authority_vector, validate_consumption, validate_current_grant,
    validate_dispatch_immutable_facts, validate_dispatch_snapshot,
    validate_grant_for_authorization, validate_recovered_consumption,
    validate_revocation_transition,
};
use crate::terminal::{
    StoredSecretDeletionObservation, StoredTerminalRetirement, TerminalDurableInputs,
    TerminalRetirementAudit, TerminalRetirementContext, TerminalRetirementReceipt,
    TerminalRetirementRequest, TerminalRetirementState, TerminalWitnessRegistryReceipt,
    authenticate_terminal_evidence, derive_terminal_context, same_activated_registry,
    validate_terminal_evidence_time,
};

mod control_plane;
mod schema_profile;

const MIGRATION_0001: &str = include_str!("../../../migrations/0001_transactional_state.sql");
const MIGRATION_0002: &str = include_str!("../../../migrations/0002_state_integrity.sql");
const MIGRATION_0003: &str = include_str!("../../../migrations/0003_state_instance.sql");
const MIGRATION_0004: &str = include_str!("../../../migrations/0004_signed_issuance_profile.sql");
const MIGRATION_0005: &str = include_str!("../../../migrations/0005_dispatch_claims.sql");
const MIGRATION_0006: &str =
    include_str!("../../../migrations/0006_physical_resource_reservations.sql");
const MIGRATION_0007: &str = include_str!("../../../migrations/0007_admission_authorizations.sql");
const MIGRATION_0008: &str =
    include_str!("../../../migrations/0008_attempt_credential_binding.sql");
const MIGRATION_0009: &str = include_str!("../../../migrations/0009_broker_operation_journal.sql");
const MIGRATION_0010: &str = include_str!("../../../migrations/0010_ingress_replay.sql");
const MIGRATION_0011: &str = include_str!("../../../migrations/0011_eks_destination_registry.sql");
const MIGRATION_0012: &str = include_str!("../../../migrations/0012_terminal_retirement.sql");
const MIGRATION_0013: &str =
    include_str!("../../../migrations/0013_durable_control_submissions.sql");
const MIGRATION_0014: &str =
    include_str!("../../../migrations/0014_durable_dispatch_acquisitions.sql");
const SERIALIZATION_ATTEMPTS: usize = 4;
const MAX_DISPATCH_ACQUISITION_SCAN: usize = 256;
const DEFAULT_POSTGRES_PORT: u16 = 5432;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_POSTGRES_NAME_BYTES: usize = 63;
const MAX_POSTGRES_PASSWORD_BYTES: usize = 4096;
const MAX_CA_PEM_BYTES: usize = 1024 * 1024;
const MAX_CLIENT_CERTIFICATE_PEM_BYTES: usize = 1024 * 1024;
const MAX_CLIENT_KEY_PEM_BYTES: usize = 256 * 1024;
const TERMINAL_SCHEMA_PROFILE_SHA256: &str =
    "sha256:eca667779e069c93ff1ee2de3b1b57b4d0f2da3ed8508fbf32123ce6cf010725";
const TERMINAL_SCHEMA_PROFILE_SQL: &str = r"
SELECT profile_line
  FROM (
        SELECT format(
                   'constraint|%s|%s|%s|%s|%s', class.relname,
                   con.conname, con.contype::text,
                   con.convalidated::text,
                   pg_get_constraintdef(con.oid, TRUE)
               ) AS profile_line
          FROM pg_constraint AS con
          JOIN pg_class AS class ON class.oid = con.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND (
                class.relname IN (
                    'accordlock_terminal_witness_registries',
                    'accordlock_terminal_witness_registry_entries',
                    'accordlock_terminal_witness_registry_bindings',
                    'accordlock_broker_secret_deletion_observations',
                    'accordlock_terminal_retirements'
                )
                OR con.conname IN (
                    'accordlock_eks_destination_activations_terminal_registry_key',
                    'accordlock_broker_operations_deletion_observation_key',
                    'accordlock_admission_authorizations_terminal_binding_key',
                    'accordlock_dispatch_claims_state_check',
                    'accordlock_dispatch_claims_state_time_check',
                    'accordlock_dispatch_claims_terminalization_id_check',
                    'accordlock_dispatch_claims_terminal_fkey'
                )
           )
        UNION ALL
        SELECT format(
                   'column|%s|%s|%s|%s|%s|%s', class.relname,
                   attribute.attname,
                   format_type(attribute.atttypid, attribute.atttypmod),
                   attribute.attnotnull::text,
                   COALESCE(coll.collname, ''),
                   attribute.attgenerated::text
               ) AS profile_line
          FROM pg_attribute AS attribute
          JOIN pg_class AS class ON class.oid = attribute.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
          LEFT JOIN pg_collation AS coll
            ON coll.oid = attribute.attcollation
         WHERE namespace.nspname = 'public'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND (
                class.relname IN (
                    'accordlock_terminal_witness_registries',
                    'accordlock_terminal_witness_registry_entries',
                    'accordlock_terminal_witness_registry_bindings',
                    'accordlock_broker_secret_deletion_observations',
                    'accordlock_terminal_retirements'
                )
                OR (class.relname = 'accordlock_dispatch_claims'
                    AND attribute.attname = 'terminalization_id')
                OR (class.relname = 'accordlock_broker_operations'
                    AND attribute.attname =
                        'deletion_observation_floor_unix_s')
           )
        UNION ALL
        SELECT format(
                   'index|%s|%s', class.relname,
                   pg_get_indexdef(class.oid)
               ) AS profile_line
          FROM pg_class AS class
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND class.relname =
               'accordlock_dispatch_claims_active_physical_resource_key'
        UNION ALL
        SELECT format(
                   'trigger|%s|%s|%s|%s', relation.relname,
                   trigger.tgname, trigger.tgenabled::text,
                   pg_get_triggerdef(trigger.oid, TRUE)
               ) AS profile_line
          FROM pg_trigger AS trigger
          JOIN pg_class AS relation ON relation.oid = trigger.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND NOT trigger.tgisinternal
           AND trigger.tgname IN (
                'accordlock_terminal_witness_registries_append_only',
                'accordlock_terminal_witness_registry_entries_append_only',
                'accordlock_terminal_witness_registry_bindings_append_only',
                'accordlock_broker_secret_deletion_observations_append_only',
                'accordlock_terminal_retirements_append_only'
           )
        UNION ALL
        SELECT format(
                   'function|%s|%s|%s|%s', proc.proname,
                   proc.provolatile::text, proc.prosecdef::text,
                   proc.prosrc
               ) AS profile_line
          FROM pg_proc AS proc
          JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
         WHERE namespace.nspname = 'public'
           AND proc.proname =
               'accordlock_reject_terminal_history_mutation'
        UNION ALL
        SELECT format(
                   'guard|legacy_physical_constraint|%s',
                   (to_regclass(
                       'public.accordlock_dispatch_claims_physical_resource_key'
                   ) IS NULL)::text
               ) AS profile_line
       ) AS profile
 ORDER BY profile_line
";

const REQUIRED_INTEGRITY_CONSTRAINTS: &[(&str, &str, &str)] = &[
    (
        "accordlock_admission_authorizations_claim_fkey",
        "f",
        "FOREIGN KEY (tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid, credential_token_digest, service_account_uid, credential_id, credential_binding_commitment) REFERENCES accordlock_dispatch_claims(tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid, credential_token_digest, service_account_uid, credential_id, credential_binding_commitment) ON DELETE RESTRICT",
    ),
    (
        "accordlock_admission_authorizations_claim_id_check",
        "c",
        "CHECK (claim_id <> '00000000-0000-0000-0000-000000000000'::uuid)",
    ),
    (
        "accordlock_admission_authorizations_claim_id_key",
        "u",
        "UNIQUE (claim_id)",
    ),
    (
        "accordlock_admission_authorizations_commitments_check",
        "c",
        "CHECK (provider_request_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND old_object_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND new_object_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND executor_identity_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND observer_identity_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND request_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND provider_request_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND old_object_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND new_object_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND executor_identity_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND observer_identity_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND request_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text)",
    ),
    (
        "accordlock_admission_authorizations_cred_commitments_check",
        "c",
        "CHECK (credential_token_digest ~ '^sha256:[0-9a-f]{64}$'::text AND credential_token_digest <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND credential_binding_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND credential_binding_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text)",
    ),
    (
        "accordlock_admission_authorizations_credential_identity_check",
        "c",
        "CHECK (octet_length(service_account_uid) >= 1 AND octet_length(service_account_uid) <= 512 AND service_account_uid = btrim(service_account_uid) AND service_account_uid !~ '[[:cntrl:]]'::text AND credential_id ~ '^AUTHORIZATION_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text AND credential_id <> 'AUTHORIZATION_ID=00000000-0000-0000-0000-000000000000'::text)",
    ),
    (
        "accordlock_admission_authorizations_decision_check",
        "c",
        "CHECK (decision = 'ADMITTED'::text)",
    ),
    (
        "accordlock_admission_authorizations_fence_check",
        "c",
        "CHECK (fence > 0)",
    ),
    (
        "accordlock_admission_authorizations_fence_key",
        "u",
        "UNIQUE (fence)",
    ),
    (
        "accordlock_admission_authorizations_grant_id_check",
        "c",
        "CHECK (grant_id <> '00000000-0000-0000-0000-000000000000'::uuid)",
    ),
    (
        "accordlock_admission_authorizations_physical_identity_check",
        "c",
        "CHECK (octet_length(cluster_identity) >= 1 AND octet_length(cluster_identity) <= 512 AND cluster_identity = btrim(cluster_identity) AND cluster_identity !~ '[[:cntrl:]]'::text AND octet_length(namespace) >= 1 AND octet_length(namespace) <= 253 AND namespace = btrim(namespace) AND namespace !~ '[[:cntrl:]]'::text AND octet_length(deployment_uid) >= 1 AND octet_length(deployment_uid) <= 512 AND deployment_uid = btrim(deployment_uid) AND deployment_uid !~ '[[:cntrl:]]'::text)",
    ),
    (
        "accordlock_admission_authorizations_pkey",
        "p",
        "PRIMARY KEY (admission_uid)",
    ),
    (
        "accordlock_admission_authorizations_provider_request_key",
        "u",
        "UNIQUE (provider_request_commitment)",
    ),
    (
        "accordlock_admission_authorizations_time_check",
        "c",
        "CHECK (authorized_unix_s >= 0 AND dispatch_deadline > authorized_unix_s)",
    ),
    (
        "accordlock_admission_authorizations_transaction_key",
        "u",
        "UNIQUE (tenant, environment, transaction_id)",
    ),
    (
        "accordlock_admission_authorizations_uid_check",
        "c",
        "CHECK (octet_length(admission_uid) >= 1 AND octet_length(admission_uid) <= 128 AND admission_uid ~ '^[A-Za-z0-9._:-]+$'::text)",
    ),
    (
        "accordlock_broker_operations_claim_fkey",
        "f",
        "FOREIGN KEY (tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid) REFERENCES accordlock_dispatch_claims(tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid) ON DELETE RESTRICT",
    ),
    (
        "accordlock_broker_operations_claim_operation_key",
        "u",
        "UNIQUE (claim_id, operation)",
    ),
    (
        "accordlock_broker_operations_commitments_check",
        "c",
        "CHECK (route_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND route_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND request_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND request_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND (provider_evidence_commitment IS NULL OR provider_evidence_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND provider_evidence_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text) AND (token_digest IS NULL OR token_digest ~ '^sha256:[0-9a-f]{64}$'::text AND token_digest <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text) AND (result_commitment IS NULL OR result_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND result_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text) AND (last_reconciliation_evidence_commitment IS NULL OR last_reconciliation_evidence_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND last_reconciliation_evidence_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text))",
    ),
    (
        "accordlock_broker_operations_fence_operation_key",
        "u",
        "UNIQUE (fence, operation)",
    ),
    (
        "accordlock_broker_operations_identity_check",
        "c",
        "CHECK (entry_id <> '00000000-0000-0000-0000-000000000000'::uuid AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid AND fence > 0)",
    ),
    (
        "accordlock_broker_operations_operation_check",
        "c",
        "CHECK (operation = ANY (ARRAY['CREATE_SECRET'::text, 'ISSUE_TOKEN'::text, 'DELETE_SECRET'::text]))",
    ),
    (
        "accordlock_broker_operations_operation_key",
        "u",
        "UNIQUE (tenant, environment, authorization_id, operation)",
    ),
    (
        "accordlock_broker_operations_operation_shape_check",
        "c",
        "CHECK (operation = 'CREATE_SECRET'::text AND credential_lifetime_upper_s IS NULL AND credential_clock_uncertainty_s IS NULL AND credential_safe_after IS NULL OR operation = 'ISSUE_TOKEN'::text AND bound_secret_uid IS NOT NULL AND credential_lifetime_upper_s >= 1 AND credential_lifetime_upper_s <= 86400 AND credential_clock_uncertainty_s >= 0 AND credential_clock_uncertainty_s <= 300 AND (phase = 'INTENT'::text AND credential_safe_after IS NULL OR phase <> 'INTENT'::text AND credential_safe_after IS NOT NULL) OR operation = 'DELETE_SECRET'::text AND bound_secret_uid IS NOT NULL AND credential_lifetime_upper_s IS NULL AND credential_clock_uncertainty_s IS NULL AND credential_safe_after IS NULL)",
    ),
    (
        "accordlock_broker_operations_outcome_check",
        "c",
        "CHECK (outcome IS NULL OR (outcome = ANY (ARRAY['CREATE_MATCHING'::text, 'CREATE_ABSENT'::text, 'CREATE_CONFLICTING'::text, 'TOKEN_ISSUED'::text, 'DELETE_ABSENT'::text, 'DELETE_PRESENT'::text, 'DELETE_CONFLICTING'::text])))",
    ),
    (
        "accordlock_broker_operations_phase_check",
        "c",
        "CHECK (phase = ANY (ARRAY['INTENT'::text, 'IN_FLIGHT'::text, 'UNKNOWN'::text, 'RECONCILE_ONLY'::text, 'COMMITTED'::text, 'TERMINAL'::text]))",
    ),
    (
        "accordlock_broker_operations_physical_identity_check",
        "c",
        "CHECK (octet_length(cluster_identity) >= 1 AND octet_length(cluster_identity) <= 512 AND cluster_identity = btrim(cluster_identity) AND cluster_identity !~ '[[:cntrl:]]'::text AND octet_length(namespace) >= 1 AND octet_length(namespace) <= 253 AND namespace = btrim(namespace) AND namespace !~ '[[:cntrl:]]'::text AND octet_length(deployment_uid) >= 1 AND octet_length(deployment_uid) <= 512 AND deployment_uid = btrim(deployment_uid) AND deployment_uid !~ '[[:cntrl:]]'::text)",
    ),
    (
        "accordlock_broker_operations_pkey",
        "p",
        "PRIMARY KEY (entry_id)",
    ),
    (
        "accordlock_broker_operations_reconciliation_check",
        "c",
        "CHECK (reconciliation_count = 0 AND last_reconciliation_outcome IS NULL AND last_reconciliation_evidence_commitment IS NULL AND last_reconciled_unix_s IS NULL OR reconciliation_count > 0 AND (phase = ANY (ARRAY['RECONCILE_ONLY'::text, 'COMMITTED'::text, 'TERMINAL'::text])) AND last_reconciliation_evidence_commitment IS NOT NULL AND last_reconciled_unix_s IS NOT NULL AND last_reconciled_unix_s >= started_unix_s AND (operation = 'CREATE_SECRET'::text AND last_reconciliation_outcome = 'CREATE_ABSENT'::text OR operation = 'DELETE_SECRET'::text AND last_reconciliation_outcome = 'DELETE_PRESENT'::text))",
    ),
    (
        "accordlock_broker_operations_secret_identity_check",
        "c",
        "CHECK (bound_secret_name = ('accordlock-'::text || replace(transaction_id::text, '-'::text, ''::text)) AND octet_length(bound_secret_name) = 43 AND (bound_secret_uid IS NULL OR octet_length(bound_secret_uid) >= 1 AND octet_length(bound_secret_uid) <= 512 AND bound_secret_uid = btrim(bound_secret_uid) AND bound_secret_uid !~ '[[:cntrl:]]'::text))",
    ),
    (
        "accordlock_broker_operations_state_instance_fkey",
        "f",
        "FOREIGN KEY (state_instance_id) REFERENCES accordlock_state_metadata(state_instance_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_broker_operations_state_result_check",
        "c",
        "CHECK (phase = 'INTENT'::text AND started_unix_s IS NULL AND outcome IS NULL AND provider_evidence_commitment IS NULL AND token_digest IS NULL AND token_expires_at IS NULL AND result_commitment IS NULL OR (phase = ANY (ARRAY['IN_FLIGHT'::text, 'UNKNOWN'::text, 'RECONCILE_ONLY'::text])) AND started_unix_s IS NOT NULL AND outcome IS NULL AND provider_evidence_commitment IS NULL AND token_digest IS NULL AND token_expires_at IS NULL AND result_commitment IS NULL OR phase = 'COMMITTED'::text AND (operation = 'CREATE_SECRET'::text AND outcome = 'CREATE_MATCHING'::text AND bound_secret_uid IS NOT NULL AND token_digest IS NULL AND token_expires_at IS NULL OR operation = 'ISSUE_TOKEN'::text AND outcome = 'TOKEN_ISSUED'::text AND token_digest IS NOT NULL AND token_expires_at IS NOT NULL OR operation = 'DELETE_SECRET'::text AND outcome = 'DELETE_ABSENT'::text AND token_digest IS NULL AND token_expires_at IS NULL) AND started_unix_s IS NOT NULL AND provider_evidence_commitment IS NOT NULL AND result_commitment IS NOT NULL OR phase = 'TERMINAL'::text AND (operation = 'CREATE_SECRET'::text AND outcome = 'CREATE_CONFLICTING'::text OR operation = 'DELETE_SECRET'::text AND outcome = 'DELETE_CONFLICTING'::text) AND started_unix_s IS NOT NULL AND provider_evidence_commitment IS NOT NULL AND token_digest IS NULL AND token_expires_at IS NULL AND result_commitment IS NOT NULL)",
    ),
    (
        "accordlock_broker_operations_time_check",
        "c",
        "CHECK (prepared_unix_s >= 0 AND (started_unix_s IS NULL OR started_unix_s >= prepared_unix_s) AND (credential_safe_after IS NULL OR credential_safe_after > started_unix_s) AND (token_expires_at IS NULL OR token_expires_at > started_unix_s AND token_expires_at <= credential_safe_after))",
    ),
    (
        "accordlock_broker_operations_transaction_operation_key",
        "u",
        "UNIQUE (tenant, environment, transaction_id, operation)",
    ),
    (
        "accordlock_consumptions_full_identity_key",
        "u",
        "UNIQUE (tenant, environment, authorization_id, transaction_id)",
    ),
    (
        "accordlock_consumptions_issued_authorization_fkey",
        "f",
        "FOREIGN KEY (tenant, environment, authorization_id, transaction_id) REFERENCES accordlock_issued_authorizations(tenant, environment, authorization_id, transaction_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_dispatch_claims_admission_binding_key",
        "u",
        "UNIQUE (tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid, credential_token_digest, service_account_uid, credential_id, credential_binding_commitment)",
    ),
    (
        "accordlock_dispatch_claims_broker_binding_key",
        "u",
        "UNIQUE (tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid)",
    ),
    (
        "accordlock_dispatch_claims_claim_id_check",
        "c",
        "CHECK (claim_id <> '00000000-0000-0000-0000-000000000000'::uuid)",
    ),
    (
        "accordlock_dispatch_claims_claim_id_key",
        "u",
        "UNIQUE (claim_id)",
    ),
    (
        "accordlock_dispatch_claims_consumption_fkey",
        "f",
        "FOREIGN KEY (tenant, environment, authorization_id, transaction_id) REFERENCES accordlock_consumptions(tenant, environment, authorization_id, transaction_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_dispatch_claims_credential_commitments_check",
        "c",
        "CHECK (credential_token_digest IS NULL OR credential_token_digest ~ '^sha256:[0-9a-f]{64}$'::text AND credential_token_digest <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text AND credential_binding_commitment ~ '^sha256:[0-9a-f]{64}$'::text AND credential_binding_commitment <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000'::text)",
    ),
    (
        "accordlock_dispatch_claims_credential_identity_check",
        "c",
        "CHECK (service_account_uid IS NULL OR octet_length(service_account_uid) >= 1 AND octet_length(service_account_uid) <= 512 AND service_account_uid = btrim(service_account_uid) AND service_account_uid !~ '[[:cntrl:]]'::text AND credential_id ~ '^AUTHORIZATION_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text AND credential_id <> 'AUTHORIZATION_ID=00000000-0000-0000-0000-000000000000'::text)",
    ),
    (
        "accordlock_dispatch_claims_fence_check",
        "c",
        "CHECK (fence > 0)",
    ),
    (
        "accordlock_dispatch_claims_fence_key",
        "u",
        "UNIQUE (fence)",
    ),
    (
        "accordlock_dispatch_claims_physical_identity_check",
        "c",
        "CHECK (octet_length(cluster_identity) >= 1 AND octet_length(cluster_identity) <= 512 AND cluster_identity = btrim(cluster_identity) AND cluster_identity !~ '[[:cntrl:]]'::text AND octet_length(namespace) >= 1 AND octet_length(namespace) <= 253 AND namespace = btrim(namespace) AND namespace !~ '[[:cntrl:]]'::text AND octet_length(deployment_uid) >= 1 AND octet_length(deployment_uid) <= 512 AND deployment_uid = btrim(deployment_uid) AND deployment_uid !~ '[[:cntrl:]]'::text)",
    ),
    (
        "accordlock_dispatch_claims_pkey",
        "p",
        "PRIMARY KEY (tenant, environment, authorization_id)",
    ),
    (
        "accordlock_dispatch_claims_state_instance_fkey",
        "f",
        "FOREIGN KEY (state_instance_id) REFERENCES accordlock_state_metadata(state_instance_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_dispatch_claims_terminal_fkey",
        "f",
        "FOREIGN KEY (terminalization_id, tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid) REFERENCES accordlock_terminal_retirements(terminalization_id, tenant, environment, authorization_id, transaction_id, claim_id, fence, cluster_identity, namespace, deployment_uid) ON DELETE RESTRICT",
    ),
    (
        "accordlock_dispatch_claims_terminalization_id_check",
        "c",
        "CHECK (terminalization_id IS NULL OR terminalization_id <> '00000000-0000-0000-0000-000000000000'::uuid)",
    ),
    (
        "accordlock_dispatch_claims_time_check",
        "c",
        "CHECK (claimed_unix_s >= 0 AND lease_until > claimed_unix_s)",
    ),
    (
        "accordlock_dispatch_claims_transaction_key",
        "u",
        "UNIQUE (tenant, environment, transaction_id)",
    ),
    (
        "accordlock_dispatch_claims_worker_id_check",
        "c",
        "CHECK (octet_length(worker_id) >= 1 AND octet_length(worker_id) <= 253 AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'::text)",
    ),
    (
        "accordlock_execution_outbox_consumption_fkey",
        "f",
        "FOREIGN KEY (tenant, environment, authorization_id, transaction_id) REFERENCES accordlock_consumptions(tenant, environment, authorization_id, transaction_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_grants_issuance_profile_version_check",
        "c",
        "CHECK (issuance_profile_version = ANY (ARRAY[1, 2]))",
    ),
    (
        "accordlock_grants_scope_key",
        "u",
        "UNIQUE (tenant, environment)",
    ),
    (
        "accordlock_ingress_replay_nonces_key_check",
        "c",
        "CHECK (octet_length(key_id) >= 1 AND octet_length(key_id) <= 256 AND key_id = btrim(key_id) AND key_id !~ '[[:cntrl:]]'::text)",
    ),
    (
        "accordlock_ingress_replay_nonces_nonce_check",
        "c",
        "CHECK (nonce <> '00000000-0000-0000-0000-000000000000'::uuid)",
    ),
    (
        "accordlock_ingress_replay_nonces_pkey",
        "p",
        "PRIMARY KEY (replay_scope, key_id, nonce)",
    ),
    (
        "accordlock_ingress_replay_nonces_scope_fkey",
        "f",
        "FOREIGN KEY (replay_scope, state_instance_id) REFERENCES accordlock_ingress_replay_scopes(replay_scope, state_instance_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_ingress_replay_nonces_time_check",
        "c",
        "CHECK (consumed_unix_s >= 0 AND expires_unix_s > consumed_unix_s)",
    ),
    (
        "accordlock_ingress_replay_scopes_identity_check",
        "c",
        "CHECK (octet_length(replay_scope) >= 1 AND octet_length(replay_scope) <= 4096 AND replay_scope = btrim(replay_scope) AND replay_scope !~ '[[:cntrl:]]'::text)",
    ),
    (
        "accordlock_ingress_replay_scopes_lineage_key",
        "u",
        "UNIQUE (replay_scope, state_instance_id)",
    ),
    (
        "accordlock_ingress_replay_scopes_pkey",
        "p",
        "PRIMARY KEY (replay_scope)",
    ),
    (
        "accordlock_ingress_replay_scopes_state_fkey",
        "f",
        "FOREIGN KEY (state_instance_id) REFERENCES accordlock_state_metadata(state_instance_id) ON DELETE RESTRICT",
    ),
    (
        "accordlock_ingress_replay_scopes_time_check",
        "c",
        "CHECK (observed_unix_s >= 0)",
    ),
    (
        "accordlock_issued_authorizations_full_identity_key",
        "u",
        "UNIQUE (tenant, environment, authorization_id, transaction_id)",
    ),
    (
        "accordlock_issued_authorizations_hash_check",
        "c",
        "CHECK (authorization_hash ~ '^sha256:[0-9a-f]{64}$'::text)",
    ),
    (
        "accordlock_issued_authorizations_issuance_profile_version_check",
        "c",
        "CHECK (issuance_profile_version = ANY (ARRAY[1, 2]))",
    ),
    (
        "accordlock_issued_authorizations_state_time_check",
        "c",
        "CHECK (state = 'ISSUED'::text AND consumed_at IS NULL OR state = 'CONSUMED'::text AND consumed_at IS NOT NULL)",
    ),
    (
        "accordlock_schema_migrations_sha256_check",
        "c",
        "CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
    ),
    (
        "accordlock_state_metadata_instance_id_key",
        "u",
        "UNIQUE (state_instance_id)",
    ),
    (
        "accordlock_state_metadata_singleton_check",
        "c",
        "CHECK (singleton)",
    ),
    (
        "accordlock_state_metadata_singleton_pkey",
        "p",
        "PRIMARY KEY (singleton)",
    ),
];

// SHA-256 is over PostgreSQL's exact `pg_get_constraintdef(oid, TRUE)` output.
// Keeping these separate avoids duplicating very long normalized CHECK text
// while still making any weaker same-name replacement fail schema validation.
const REQUIRED_EKS_INTEGRITY_CONSTRAINTS: &[(&str, &str, &str)] = &[
    (
        "accordlock_eks_destination_activations_commitment_key",
        "u",
        "sha256:314038dca1220e5b2ba84198115d9079b328a3de22718894eda65423d5249bd9",
    ),
    (
        "accordlock_eks_destination_activations_commitments_check",
        "c",
        "sha256:6ec1083cc84e1e92462aec5a5ebe57d2df48b45d6d8fd988eeffa0b58bb632a0",
    ),
    (
        "accordlock_eks_destination_activations_domain_check",
        "c",
        "sha256:c68a4008f7c4cbc8ac3e4e41a4b3f40e21fa8b690bf27bc8048bd384241cd310",
    ),
    (
        "accordlock_eks_destination_activations_domain_key",
        "u",
        "sha256:4a2e73ad07a1ac4ed1f75ce83b5998577f570e8ea9aa90f67de8c3e7b77be7c3",
    ),
    (
        "accordlock_eks_destination_activations_identity_check",
        "c",
        "sha256:652abbc219ebe06614e9df18e0eac13435b9f09221a0c71223841af2a5f44f79",
    ),
    (
        "accordlock_eks_destination_activations_lifecycle_check",
        "c",
        "sha256:79beda23323c3709d6ddf6346a393dca409430a56bbce43585598cf48172f5dc",
    ),
    (
        "accordlock_eks_destination_activations_owner_fkey",
        "f",
        "sha256:42b8b86d4e4aee451e336fe64a38e189fbacaa9677177375cc76207af2957ed8",
    ),
    (
        "accordlock_eks_destination_activations_pkey",
        "p",
        "sha256:47e91439750c29407e3ca275e62039fd7b7741a6431bfb3daa2d4b23b806f960",
    ),
    (
        "accordlock_eks_destination_activations_state_fkey",
        "f",
        "sha256:02c1979f6bd8a02f02b0f96c7b1d379a04c50ae56e4221ac64011d0a48fea07f",
    ),
    (
        "accordlock_eks_destination_activations_terminal_registry_key",
        "u",
        "sha256:01a085a6cdf3f73abe4ae4dd09cb6838d70f596c8b3d584ece81573ea9500588",
    ),
    (
        "accordlock_eks_physical_owners_authority_fkey",
        "f",
        "sha256:f47ac19c4534770b7851cef04590465c76488d350f1f79c5923ea8775dc89899",
    ),
    (
        "accordlock_eks_physical_owners_binding_key",
        "u",
        "sha256:913a0a234b2df155ea0329aefc6fd89c37386668a01e07211f0e1d1f35917ca3",
    ),
    (
        "accordlock_eks_physical_owners_identity_check",
        "c",
        "sha256:fcfb3975a7216e9eaab9923bcc516d525671c2c2b53675ed4f2785e65cb7609a",
    ),
    (
        "accordlock_eks_physical_owners_pkey",
        "p",
        "sha256:dcecf6bbc07ebd3cf5b0d69770ae99e498425bec9f2cfec05382003bc1dd627e",
    ),
    (
        "accordlock_eks_physical_owners_root_check",
        "c",
        "sha256:061ed16c8b2340b76c6862c9f1d4a201af64cf9b7963f6fa63bedf4c67307377",
    ),
    (
        "accordlock_eks_physical_owners_route_key",
        "u",
        "sha256:e72103215d486c4a4183fa6600dbf7061d91c8c54697ff580498c01dd162e5dd",
    ),
    (
        "accordlock_eks_physical_owners_state_fkey",
        "f",
        "sha256:02c1979f6bd8a02f02b0f96c7b1d379a04c50ae56e4221ac64011d0a48fea07f",
    ),
];

/// Rejection returned while constructing the authenticated remote `PostgreSQL`
/// profile.
///
/// The variants deliberately do not embed PEM material, passwords, or parser
/// diagnostics which could copy credential bytes into logs.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TlsPostgresConfigError {
    #[error("PostgreSQL TLS server_name must be one valid DNS name, not an IP address")]
    InvalidServerName,
    #[error("PostgreSQL port must be non-zero")]
    InvalidPort,
    #[error("PostgreSQL database name is empty, too long, or contains control bytes")]
    InvalidDatabaseName,
    #[error("PostgreSQL user name is empty, too long, or contains control bytes")]
    InvalidUserName,
    #[error("PostgreSQL password is empty, too long, or contains a NUL byte")]
    InvalidPassword,
    #[error("PostgreSQL connect timeout must be greater than zero and at most 60 seconds")]
    InvalidConnectTimeout,
    #[error("PostgreSQL CA PEM is empty, too large, malformed, or contains a non-certificate item")]
    InvalidCaPem,
    #[error("PostgreSQL CA PEM contains a certificate rustls cannot use as a trust anchor")]
    InvalidCaCertificate,
    #[error(
        "PostgreSQL client certificate PEM is empty, too large, malformed, or contains a non-certificate item"
    )]
    InvalidClientCertificatePem,
    #[error(
        "PostgreSQL client private-key PEM is empty, too large, malformed, or contains a non-key item"
    )]
    InvalidClientPrivateKeyPem,
    #[error("PostgreSQL client private-key PEM must contain exactly one private key")]
    InvalidClientPrivateKeyCount,
    #[error("PostgreSQL client certificate chain and private key are invalid or do not match")]
    InvalidClientIdentity,
    #[error("the pinned rustls protocol/provider configuration could not be constructed")]
    InvalidTlsProviderConfiguration,
}

struct TlsClientIdentity {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Explicit, authenticated remote-PostgreSQL connection configuration.
///
/// This type intentionally has no connection-string constructor. TLS mode,
/// channel binding, the expected DNS name, and the trust roots are fixed by
/// this profile rather than accepted as `sslmode` or certificate-verification
/// flags from a caller-controlled URL.
pub struct TlsPostgresConfig {
    postgres: Config,
    target_address: Option<IpAddr>,
    port: u16,
    connect_timeout: Duration,
    root_certificates: RootCertStore,
    client_identity: Option<TlsClientIdentity>,
}

impl fmt::Debug for TlsPostgresConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsPostgresConfig")
            .field("server_name", &self.postgres.get_hosts())
            .field("target_address", &self.target_address)
            .field("port", &self.port)
            .field("database", &self.postgres.get_dbname())
            .field("user", &"<redacted>")
            .field("password", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("ca_certificate_count", &self.root_certificates.len())
            .field("client_identity", &self.client_identity.is_some())
            .finish()
    }
}

impl TlsPostgresConfig {
    /// Constructs a strict remote profile with port 5432 and a five-second
    /// socket connect timeout.
    ///
    /// `server_name` is both the `PostgreSQL` host and the DNS identity checked
    /// by rustls. `ca_pem` is the complete explicit trust store for this
    /// connection; platform and `WebPKI` roots are not added implicitly.
    ///
    /// # Errors
    ///
    /// Returns [`TlsPostgresConfigError`] for an invalid DNS name, database or
    /// user name, password, or CA bundle.
    pub fn new(
        server_name: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
        password: impl AsRef<[u8]>,
        ca_pem: impl AsRef<[u8]>,
    ) -> Result<Self, TlsPostgresConfigError> {
        let server_name = server_name.into();
        if server_name.trim() != server_name
            || server_name.parse::<IpAddr>().is_ok()
            || DnsName::try_from(server_name.as_str()).is_err()
        {
            return Err(TlsPostgresConfigError::InvalidServerName);
        }
        let server_name = server_name.to_ascii_lowercase();
        let database = database.into();
        if !valid_postgres_name(&database) {
            return Err(TlsPostgresConfigError::InvalidDatabaseName);
        }
        let user = user.into();
        if !valid_postgres_name(&user) {
            return Err(TlsPostgresConfigError::InvalidUserName);
        }
        let password = password.as_ref();
        if password.is_empty()
            || password.len() > MAX_POSTGRES_PASSWORD_BYTES
            || password.contains(&0)
        {
            return Err(TlsPostgresConfigError::InvalidPassword);
        }
        let root_certificates = parse_ca_certificates(ca_pem.as_ref())?;
        let mut postgres = Config::new();
        postgres
            .host(&server_name)
            .dbname(&database)
            .user(&user)
            .password(password)
            .ssl_mode(SslMode::Require)
            .channel_binding(ChannelBinding::Require)
            .target_session_attrs(TargetSessionAttrs::ReadWrite)
            .application_name("accordlock-state/0.1");
        Ok(Self {
            postgres,
            target_address: None,
            port: DEFAULT_POSTGRES_PORT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            root_certificates,
            client_identity: None,
        })
    }

    /// Pins a network address while retaining `server_name` for SNI and
    /// certificate verification. This avoids replacing authenticated DNS
    /// identity with an IP-address identity.
    #[must_use]
    pub fn with_target_address(mut self, target_address: IpAddr) -> Self {
        self.target_address = Some(target_address);
        self
    }

    /// Overrides the default `PostgreSQL` TCP port.
    ///
    /// # Errors
    ///
    /// Returns [`TlsPostgresConfigError::InvalidPort`] for port zero.
    pub fn with_port(mut self, port: u16) -> Result<Self, TlsPostgresConfigError> {
        if port == 0 {
            return Err(TlsPostgresConfigError::InvalidPort);
        }
        self.port = port;
        Ok(self)
    }

    /// Overrides the socket connect timeout. This is applied to every address
    /// attempted by the `PostgreSQL` client, not to a complete transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TlsPostgresConfigError::InvalidConnectTimeout`] for zero or a
    /// duration above 60 seconds.
    pub fn with_connect_timeout(
        mut self,
        connect_timeout: Duration,
    ) -> Result<Self, TlsPostgresConfigError> {
        if connect_timeout.is_zero() || connect_timeout > MAX_CONNECT_TIMEOUT {
            return Err(TlsPostgresConfigError::InvalidConnectTimeout);
        }
        self.connect_timeout = connect_timeout;
        Ok(self)
    }

    /// Adds a fixed client certificate chain and matching unencrypted private
    /// key. PKCS#1, PKCS#8, and SEC1 key PEM encodings are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`TlsPostgresConfigError`] if either PEM is malformed, contains
    /// the wrong item type, or does not contain exactly the required material.
    /// Key/certificate compatibility is checked by [`TlsPostgresStore::new`].
    pub fn with_client_identity(
        mut self,
        certificate_chain_pem: impl AsRef<[u8]>,
        private_key_pem: impl AsRef<[u8]>,
    ) -> Result<Self, TlsPostgresConfigError> {
        let certificate_chain = parse_client_certificate_chain(certificate_chain_pem.as_ref())?;
        let private_key = parse_client_private_key(private_key_pem.as_ref())?;
        self.client_identity = Some(TlsClientIdentity {
            certificate_chain,
            private_key,
        });
        Ok(self)
    }
}

#[derive(Clone)]
enum PostgresConnectionProfile {
    LocalNoTls(String),
    RemoteTls(Arc<RemoteTlsConnection>),
}

struct RemoteTlsConnection {
    postgres: Config,
    connector: MakeRustlsConnect,
}

/// `PostgreSQL` adapter for the local vertical slice.
///
/// A fresh connection is used per operation so multiple adapter instances and
/// processes rely on `PostgreSQL` row locks and `SERIALIZABLE` isolation rather
/// than an in-process mutex. [`PostgresStore::new`] remains a loopback-only
/// `NoTls` profile. Remote callers must use [`TlsPostgresStore`].
#[derive(Clone)]
pub struct PostgresStore {
    connection_profile: PostgresConnectionProfile,
    broker_capability_issuer: BrokerJournalCapabilityIssuer,
}

/// Authenticated TLS `PostgreSQL` adapter for a remote state database.
///
/// This wrapper has exactly the same transactional and migration behavior as
/// [`PostgresStore`]. TLS authenticates and encrypts each database connection;
/// it does not provide database high availability, secret rotation, or
/// protection from a compromised database administrator or database clock.
#[derive(Clone)]
pub struct TlsPostgresStore {
    inner: PostgresStore,
}

struct LockedDispatchInputs {
    authority: AuthorityVector,
    high_water: i64,
    grant: GrantSnapshot,
    issued: IssuedAuthorizationRecord,
    receipt: ConsumptionReceipt,
    outbox: OutboxEntry,
}

struct LockedControlBrokerTime {
    submission: crate::control::StoredControlSubmission,
    replay_scope: IngressReplayScope,
    ingress_high_water: i64,
    scope_high_water: i64,
}

struct LockedBrokerTimeInputs {
    dispatch: LockedDispatchInputs,
    control: Option<LockedControlBrokerTime>,
}

struct PostgresPostAttemptLineage {
    token: DispatchClaimToken,
    started_at: i64,
    credential: DispatchCredentialBinding,
    time_inputs: LockedBrokerTimeInputs,
}

struct PostgresNoSendLineage {
    acquisition: StoredDispatchAcquisition,
    claim_row: Row,
    lifecycle_policy: accordlock_eks_profile::EksCredentialLifecyclePolicy,
    create: StoredBrokerOperation,
    has_issue: bool,
    review: Option<StoredDispatchCredentialReview>,
    delete: Option<StoredBrokerOperation>,
}

#[derive(Clone, Debug)]
struct StoredDispatchAcquisition {
    token: DispatchClaimToken,
    acquisition_id: Uuid,
    lease_fence: u64,
    worker_id: String,
    acquired_at: i64,
    lease_until: i64,
    dispatch_deadline: i64,
    control_submission_id: Option<Uuid>,
    selection_kind: String,
    claim_state: String,
    attempt_started_at: Option<i64>,
    has_credential: bool,
    terminalization_id: Option<Uuid>,
}

enum DispatchAcquisitionStep {
    Outcome(Box<DispatchAcquisitionOutcome>),
    ExactRecoveryRetry,
    SkippedCandidate(Uuid),
}

impl DispatchAcquisitionStep {
    fn outcome(outcome: DispatchAcquisitionOutcome) -> Self {
        Self::Outcome(Box::new(outcome))
    }
}

/// Decodes a profile-v2 authorization and authenticates every materialized column
/// against its signed JSON. The v13 foreign keys deliberately target these
/// columns, so no loader may treat them as an unauthenticated index.
fn decode_stored_authorization_row(
    row: &Row,
    key: &ConsumeKey,
) -> Result<IssuedAuthorizationRecord, StateError> {
    if row.get::<_, i16>("issuance_profile_version") != 2 {
        return Err(StateError::InvalidRecord(
            "issued authorization uses an unsupported issuance profile".to_owned(),
        ));
    }
    let issued: IssuedAuthorizationRecord = decode_json(row.get("record_json"))?;
    issued.validate()?;
    let stored_transaction_id: Uuid = row.get("transaction_id");
    if stored_transaction_id != key.transaction_id
        || issued.transaction_id != key.transaction_id
        || issued.authorization().authorization_id != key.authorization_id
        || issued.scope() != key.scope
    {
        return Err(StateError::TransactionMismatch);
    }
    let request_id: Option<Uuid> = row.get("request_id");
    let evaluation_nonce: Option<Uuid> = row.get("evaluation_nonce");
    if row.get::<_, Uuid>("grant_id") != issued.authorization().grant_id
        || row.get::<_, String>("authorization_hash") != issued.authorization_hash.to_string()
        || row.get::<_, i64>("consume_before") != issued.authorization().consume_before
        || request_id != Some(issued.authorization().request_id)
        || evaluation_nonce != Some(issued.authorization().evaluation_nonce)
        || canonical_hash(issued.authorization())? != issued.authorization_hash
    {
        return Err(StateError::InvalidRecord(
            "stored authorization columns, JSON, and canonical hash do not agree".to_owned(),
        ));
    }
    Ok(issued)
}

/// Prevents any legacy recovery or dispatch reader from adopting a tuple
/// owned by the v13 control ledger before the combined CONSUME transaction has
/// linked and completed it. This is deliberately called only by read paths;
/// the combined writer validates after inserting the lineage in its one
/// transaction.
fn validate_postgres_control_consumption_lineage_if_owned<C: GenericClient>(
    client: &mut C,
    key: &ConsumeKey,
    issued: &IssuedAuthorizationRecord,
    receipt: &ConsumptionReceipt,
) -> Result<(), StateError> {
    let owners = client.query(
        "SELECT submission_id
           FROM public.accordlock_control_submissions
          WHERE (tenant = $1 AND environment = $2 AND request_id = $5)
             OR evaluation_nonce = $6
          UNION
         SELECT submission_id
           FROM public.accordlock_control_issuances
          WHERE tenant = $1 AND environment = $2
            AND authorization_id = $3 AND transaction_id = $4",
        &[
            &key.scope.tenant,
            &key.scope.environment,
            &key.authorization_id,
            &key.transaction_id,
            &issued.authorization().request_id,
            &issued.authorization().evaluation_nonce,
        ],
    )?;
    if owners.is_empty() {
        return Ok(());
    }
    if owners.len() != 1 {
        return Err(StateError::InvalidRecord(
            "control authorization ownership indexes disagree".to_owned(),
        ));
    }
    let submission_id: Uuid = owners[0].get("submission_id");
    let exact = client.query_opt(
        "SELECT 1
           FROM public.accordlock_control_submissions AS submission
           JOIN public.accordlock_control_issuances AS issuance
             ON issuance.submission_id = submission.submission_id
            AND issuance.tenant = submission.tenant
            AND issuance.environment = submission.environment
            AND issuance.request_id = submission.request_id
            AND issuance.evaluation_nonce = submission.evaluation_nonce
           JOIN public.accordlock_control_consumptions AS consumption
             ON consumption.submission_id = issuance.submission_id
            AND consumption.tenant = issuance.tenant
            AND consumption.environment = issuance.environment
            AND consumption.authorization_id = issuance.authorization_id
            AND consumption.transaction_id = issuance.transaction_id
           JOIN public.accordlock_control_phase_completions AS completion
             ON completion.submission_id = consumption.submission_id
            AND completion.claim_id = consumption.claim_id
            AND completion.phase = 'CONSUME'
            AND completion.completed_at = consumption.linked_at
            AND completion.consumption_artifact_at = consumption.linked_at
            AND completion.consume_authorization_id = consumption.authorization_id
            AND completion.consume_transaction_id = consumption.transaction_id
           JOIN public.accordlock_control_work_queue AS queue
             ON queue.submission_id = submission.submission_id
            AND queue.phase = 'DONE'
            AND queue.state = 'DONE'
            AND queue.active_claim_id IS NULL
           JOIN public.accordlock_control_status AS status
             ON status.submission_id = submission.submission_id
            AND status.receipt_id = submission.receipt_id
            AND status.status = 'DISPATCH_PENDING'
           JOIN public.accordlock_control_events AS event
             ON event.submission_id = status.submission_id
            AND event.revision = status.revision
            AND event.receipt_id = status.receipt_id
            AND event.status = status.status
            AND event.reason_kind IS NOT DISTINCT FROM status.reason_kind
            AND event.reason_code IS NOT DISTINCT FROM status.reason_code
            AND event.observed_at = status.observed_at
          WHERE submission.submission_id = $1
            AND submission.tenant = $2
            AND submission.environment = $3
            AND submission.request_id = $7
            AND submission.evaluation_nonce = $8
            AND issuance.authorization_id = $4
            AND issuance.transaction_id = $5
            AND issuance.authorization_hash = $6
            AND issuance.grant_id = $9
            AND issuance.issuance_profile_version = 2
            AND consumption.linked_at = $10
            AND consumption.dispatch_deadline = $11",
        &[
            &submission_id,
            &key.scope.tenant,
            &key.scope.environment,
            &key.authorization_id,
            &key.transaction_id,
            &issued.authorization_hash.to_string(),
            &issued.authorization().request_id,
            &issued.authorization().evaluation_nonce,
            &issued.authorization().grant_id,
            &receipt.consumed_at,
            &receipt.dispatch_deadline,
        ],
    )?;
    if exact.is_none() {
        return Err(StateError::InvalidRecord(
            "control-owned consumption lacks exact atomic control lineage".to_owned(),
        ));
    }
    Ok(())
}

struct StoredAdmissionAuthorization {
    request: AdmissionAuthorizationRequest,
    grant_id: Uuid,
    authority: AuthorityVector,
    dispatch_deadline: i64,
    authorized_at: i64,
}

struct LockedTerminalInputs {
    context: TerminalRetirementContext,
    claim: DispatchClaimToken,
    registry: ActivatedWitnessRegistry,
    time_inputs: LockedBrokerTimeInputs,
    terminalization_id: Option<Uuid>,
}

enum LockedDispatchValidation {
    Accepted(Box<DispatchSnapshot>),
    TemporalRejection(StateError),
}

impl fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let profile = match &self.connection_profile {
            PostgresConnectionProfile::LocalNoTls(_) => "local-no-tls",
            PostgresConnectionProfile::RemoteTls(_) => "remote-authenticated-tls",
        };
        formatter
            .debug_struct("PostgresStore")
            .field("profile", &profile)
            .field("connection_configuration", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TlsPostgresStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsPostgresStore")
            .field("profile", &"remote-authenticated-tls")
            .field("connection_configuration", &"<redacted>")
            .finish()
    }
}

impl crate::sealed::Sealed for PostgresStore {}
impl crate::sealed::Sealed for TlsPostgresStore {}

impl TlsPostgresStore {
    /// Builds the remote adapter without opening a network connection.
    ///
    /// The resulting `PostgreSQL` configuration always requires TLS, requires
    /// supported channel binding during password authentication, and requires
    /// a read-write server. There is no caller-controlled `sslmode` fallback.
    ///
    /// # Errors
    ///
    /// Returns [`TlsPostgresConfigError`] if the fixed rustls provider cannot
    /// construct its protocol defaults or if an optional client certificate
    /// and private key are invalid or do not match.
    pub fn new(config: TlsPostgresConfig) -> Result<Self, TlsPostgresConfigError> {
        let TlsPostgresConfig {
            mut postgres,
            target_address,
            port,
            connect_timeout,
            root_certificates,
            client_identity,
        } = config;

        let tls_builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsPostgresConfigError::InvalidTlsProviderConfiguration)?
        .with_root_certificates(root_certificates);
        let tls_config = match client_identity {
            Some(identity) => tls_builder
                .with_client_auth_cert(identity.certificate_chain, identity.private_key)
                .map_err(|_| TlsPostgresConfigError::InvalidClientIdentity)?,
            None => tls_builder.with_no_client_auth(),
        };

        postgres.port(port).connect_timeout(connect_timeout);
        if let Some(target_address) = target_address {
            postgres.hostaddr(target_address);
        }

        Ok(Self {
            inner: PostgresStore {
                connection_profile: PostgresConnectionProfile::RemoteTls(Arc::new(
                    RemoteTlsConnection {
                        postgres,
                        connector: MakeRustlsConnect::new(tls_config),
                    },
                )),
                broker_capability_issuer: BrokerJournalCapabilityIssuer::default(),
            },
        })
    }

    /// Returns the durable logical identity of this migrated state lineage.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] under the same conditions as
    /// [`PostgresStore::state_instance_id`].
    pub fn state_instance_id(&self) -> Result<Uuid, StateError> {
        self.inner.state_instance_id()
    }

    /// Verifies the exact migration ledger and integrity constraints.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] under the same conditions as
    /// [`PostgresStore::validate_schema`].
    pub fn validate_schema(&self) -> Result<(), StateError> {
        self.inner.validate_schema()
    }

    /// Applies and verifies the exact `AccordLock` state migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] under the same conditions as
    /// [`PostgresStore::migrate`].
    pub fn migrate(&self) -> Result<(), StateError> {
        self.inner.migrate()
    }
}

impl PostgresStore {
    #[must_use]
    pub fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_profile: PostgresConnectionProfile::LocalNoTls(connection_string.into()),
            broker_capability_issuer: BrokerJournalCapabilityIssuer::default(),
        }
    }

    fn require_broker_capability(
        &self,
        capability: &BrokerJournalCapability,
    ) -> Result<(), StateError> {
        self.broker_capability_issuer
            .validate(capability, self.state_instance_id()?)
    }

    fn connection_config(&self) -> Result<Config, StateError> {
        match &self.connection_profile {
            PostgresConnectionProfile::LocalNoTls(connection_string) => {
                let config = connection_string.parse::<Config>()?;
                if config.get_hosts().is_empty()
                    || !config.get_hosts().iter().all(is_local_host)
                    || !config.get_hostaddrs().iter().all(IpAddr::is_loopback)
                {
                    return Err(StateError::UnsafePostgresConnection);
                }
                Ok(config)
            }
            PostgresConnectionProfile::RemoteTls(remote) => Ok(remote.postgres.clone()),
        }
    }

    fn connect(&self) -> Result<Client, StateError> {
        let mut client = match &self.connection_profile {
            PostgresConnectionProfile::LocalNoTls(_) => self.connection_config()?.connect(NoTls)?,
            PostgresConnectionProfile::RemoteTls(remote) => {
                remote.postgres.connect(remote.connector.clone())?
            }
        };
        client.batch_execute(
            "SET search_path TO pg_catalog, public;
             SELECT pg_catalog.set_config(
                 'accordlock.state_writer_schema', '14', false
             );",
        )?;
        Ok(client)
    }

    /// Returns the durable logical identity of this migrated state lineage.
    ///
    /// Session artifacts bind this value so identifier-only revalidation cannot
    /// silently switch to an unrelated database containing a copied key tuple.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the database is unreachable, unmigrated, or its
    /// singleton metadata row is absent or invalid.
    pub fn state_instance_id(&self) -> Result<Uuid, StateError> {
        let mut client = self.connect()?;
        let rows = client.query(
            "SELECT state_instance_id
               FROM public.accordlock_state_metadata
              WHERE singleton = TRUE",
            &[],
        )?;
        if rows.len() != 1 {
            return Err(StateError::SchemaMismatch(format!(
                "expected one state metadata row, found {}",
                rows.len()
            )));
        }
        let state_instance_id: Uuid = rows[0].get("state_instance_id");
        if state_instance_id.is_nil() {
            return Err(StateError::SchemaMismatch(
                "state instance identifier is nil".to_owned(),
            ));
        }
        Ok(state_instance_id)
    }

    fn expected_migration_versions() -> Vec<(i32, String, String)> {
        [
            (1, "0001_transactional_state", MIGRATION_0001),
            (2, "0002_state_integrity", MIGRATION_0002),
            (3, "0003_state_instance", MIGRATION_0003),
            (4, "0004_signed_issuance_profile", MIGRATION_0004),
            (5, "0005_dispatch_claims", MIGRATION_0005),
            (6, "0006_physical_resource_reservations", MIGRATION_0006),
            (7, "0007_admission_authorizations", MIGRATION_0007),
            (8, "0008_attempt_credential_binding", MIGRATION_0008),
            (9, "0009_broker_operation_journal", MIGRATION_0009),
            (10, "0010_ingress_replay", MIGRATION_0010),
            (11, "0011_eks_destination_registry", MIGRATION_0011),
            (12, "0012_terminal_retirement", MIGRATION_0012),
            (13, "0013_durable_control_submissions", MIGRATION_0013),
            (14, "0014_durable_dispatch_acquisitions", MIGRATION_0014),
        ]
        .iter()
        .map(|(version, name, sql)| (*version, (*name).to_owned(), migration_checksum(sql)))
        .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn validate_eks_registry_schema(transaction: &mut Transaction<'_>) -> Result<(), StateError> {
        let constraints: Vec<(String, String, String)> = transaction
            .query(
                "SELECT conname, contype::text AS constraint_type,
                        pg_get_constraintdef(oid, TRUE) AS definition,
                        convalidated
                   FROM pg_constraint
                  WHERE conrelid IN (
                        'public.accordlock_eks_physical_owners'::regclass,
                        'public.accordlock_eks_destination_activations'::regclass
                  )
                  ORDER BY conname",
                &[],
            )?
            .into_iter()
            .map(|row| {
                if !row.get::<_, bool>("convalidated") {
                    return Err(StateError::SchemaMismatch(
                        "an EKS registry constraint is not validated".to_owned(),
                    ));
                }
                let definition: String = row.get("definition");
                Ok((
                    row.get("conname"),
                    row.get("constraint_type"),
                    migration_checksum(&definition),
                ))
            })
            .collect::<Result<_, _>>()?;
        let expected: Vec<_> = REQUIRED_EKS_INTEGRITY_CONSTRAINTS
            .iter()
            .map(|(name, kind, checksum)| {
                (
                    (*name).to_owned(),
                    (*kind).to_owned(),
                    (*checksum).to_owned(),
                )
            })
            .collect();
        if constraints != expected {
            return Err(StateError::SchemaMismatch(format!(
                "EKS registry constraint profile differs: {constraints:?}"
            )));
        }

        let columns: Vec<(String, String, String, bool, Option<String>)> = transaction
            .query(
                "SELECT class.relname, attribute.attname,
                        format_type(attribute.atttypid, attribute.atttypmod)
                            AS data_type,
                        attribute.attnotnull, coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_class AS class ON class.oid = attribute.attrelid
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = class.relnamespace
                   LEFT JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE namespace.nspname = 'public'
                    AND class.relname = ANY($1)
                    AND attribute.attnum > 0
                    AND NOT attribute.attisdropped
                  ORDER BY class.relname, attribute.attname",
                &[&vec![
                    "accordlock_eks_destination_activations",
                    "accordlock_eks_physical_owners",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("relname"),
                    row.get("attname"),
                    row.get("data_type"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let mut column_profile = String::new();
        for (table, column, data_type, not_null, collation) in &columns {
            for value in [table, column, data_type] {
                column_profile.push_str(value);
                column_profile.push('\0');
            }
            column_profile.push(if *not_null { '1' } else { '0' });
            column_profile.push('\0');
            column_profile.push_str(collation.as_deref().unwrap_or_default());
            column_profile.push('\n');
        }
        let column_profile_checksum = Digest32::sha256(column_profile.as_bytes()).to_string();
        if columns.len() != 55
            || column_profile_checksum
                != "sha256:c8f320441fde80f11d4553028599292f05c576ab95a7a7fbceac57f3ca62bcc0"
        {
            return Err(StateError::SchemaMismatch(format!(
                "EKS registry column profile differs: count={} checksum={column_profile_checksum}",
                columns.len()
            )));
        }

        let index: Vec<String> = transaction
            .query(
                "SELECT indexdef
                   FROM pg_indexes
                  WHERE schemaname = 'public'
                    AND indexname =
                        'accordlock_eks_destination_activations_current_idx'",
                &[],
            )?
            .into_iter()
            .map(|row| row.get("indexdef"))
            .collect();
        if index
            != ["CREATE INDEX accordlock_eks_destination_activations_current_idx ON public.accordlock_eks_destination_activations USING btree (tenant, environment, resource_activation_id, mediation_activation_id)".to_owned()]
        {
            return Err(StateError::SchemaMismatch(format!(
                "EKS registry current index differs: {index:?}"
            )));
        }
        Ok(())
    }

    fn validate_terminal_schema(transaction: &mut Transaction<'_>) -> Result<(), StateError> {
        let lines: Vec<String> = transaction
            .query(TERMINAL_SCHEMA_PROFILE_SQL, &[])?
            .into_iter()
            .map(|row| row.get("profile_line"))
            .collect();
        let checksum = migration_checksum(&lines.join("\n"));
        if checksum != TERMINAL_SCHEMA_PROFILE_SHA256 {
            return Err(StateError::SchemaMismatch(format!(
                "terminal-retirement schema profile differs: {checksum}"
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_schema_transaction(transaction: &mut Transaction<'_>) -> Result<(), StateError> {
        let required_tables_present: bool = transaction
            .query_one(
                "SELECT to_regclass('public.accordlock_schema_migrations') IS NOT NULL
                        AND to_regclass('public.accordlock_state_metadata') IS NOT NULL
                        AND to_regclass('public.accordlock_dispatch_claims') IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_dispatch_acquisitions'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_dispatch_request_identities'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_dispatch_queue_dispositions'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_dispatch_credential_reviews'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_admission_authorizations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_broker_operations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_ingress_replay_scopes'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_ingress_replay_nonces'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_eks_physical_owners'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_eks_destination_activations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_terminal_witness_registries'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_terminal_witness_registry_entries'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_terminal_witness_registry_bindings'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_broker_secret_deletion_observations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_terminal_retirements'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_submissions'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_status'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_events'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_evaluations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_decisions'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_work_claims'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_work_queue'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_work_finalizations'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_issuances'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_consumptions'
                        ) IS NOT NULL
                        AND to_regclass(
                            'public.accordlock_control_phase_completions'
                        ) IS NOT NULL AS present",
                &[],
            )?
            .get("present");
        if !required_tables_present {
            return Err(StateError::SchemaMismatch(
                "one or more required AccordLock state tables are absent".to_owned(),
            ));
        }

        let expected_versions = Self::expected_migration_versions();
        let versions: Vec<(i32, String, Option<String>)> = transaction
            .query(
                "SELECT version, name, sha256
                   FROM public.accordlock_schema_migrations
                  ORDER BY version",
                &[],
            )?
            .into_iter()
            .map(|row| (row.get("version"), row.get("name"), row.get("sha256")))
            .collect();
        let expected_versions_with_checksums: Vec<(i32, String, Option<String>)> =
            expected_versions
                .into_iter()
                .map(|(version, name, checksum)| (version, name, Some(checksum)))
                .collect();
        if versions != expected_versions_with_checksums {
            return Err(StateError::SchemaMismatch(format!(
                "migration ledger differs: {versions:?}"
            )));
        }

        let constraints: Vec<(String, String, String)> = transaction
            .query(
                "SELECT conname,
                        contype::text AS constraint_type,
                        pg_get_constraintdef(oid, TRUE) AS definition
                   FROM pg_constraint
                  WHERE conname = ANY($1)
                    AND connamespace = 'public'::regnamespace
                  ORDER BY conname",
                &[&REQUIRED_INTEGRITY_CONSTRAINTS
                    .iter()
                    .map(|(name, _, _)| *name)
                    .collect::<Vec<_>>()],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("conname"),
                    row.get("constraint_type"),
                    row.get("definition"),
                )
            })
            .collect();
        let expected_constraints: Vec<(String, String, String)> = REQUIRED_INTEGRITY_CONSTRAINTS
            .iter()
            .map(|(name, kind, definition)| {
                (
                    (*name).to_owned(),
                    (*kind).to_owned(),
                    (*definition).to_owned(),
                )
            })
            .collect();
        if constraints != expected_constraints {
            return Err(StateError::SchemaMismatch(format!(
                "integrity constraint definitions differ: {constraints:?}"
            )));
        }
        Self::validate_eks_registry_schema(transaction)?;
        Self::validate_terminal_schema(transaction)?;
        schema_profile::validate_control_schema(transaction)?;
        schema_profile::validate_dispatch_acquisition_schema(transaction)?;

        for (prefix, table) in [
            (
                "accordlock_broker_operations_",
                "accordlock_broker_operations",
            ),
            ("accordlock_dispatch_claims_", "accordlock_dispatch_claims"),
            (
                "accordlock_ingress_replay_nonces_",
                "accordlock_ingress_replay_nonces",
            ),
            (
                "accordlock_ingress_replay_scopes_",
                "accordlock_ingress_replay_scopes",
            ),
            (
                "accordlock_admission_authorizations_",
                "accordlock_admission_authorizations",
            ),
        ] {
            let names: Vec<_> = REQUIRED_INTEGRITY_CONSTRAINTS
                .iter()
                .map(|(name, _, _)| *name)
                .filter(|name| name.starts_with(prefix))
                .collect();
            let attached: i64 = transaction
                .query_one(
                    "SELECT count(*)::bigint AS constraint_count
                       FROM pg_constraint
                      WHERE conname = ANY($1)
                        AND conrelid = to_regclass('public.' || $2)",
                    &[&names, &table],
                )?
                .get("constraint_count");
            if attached
                != i64::try_from(names.len()).map_err(|_| {
                    StateError::SchemaMismatch("constraint count overflowed".to_owned())
                })?
            {
                return Err(StateError::SchemaMismatch(format!(
                    "required constraints are attached to the wrong table: {table}"
                )));
            }
        }

        let admission_text_columns: Vec<(String, bool, String)> = transaction
            .query(
                "SELECT attribute.attname,
                        attribute.attnotnull,
                        coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE attribute.attrelid =
                        'public.accordlock_admission_authorizations'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec![
                    "admission_uid",
                    "cluster_identity",
                    "credential_binding_commitment",
                    "credential_id",
                    "credential_token_digest",
                    "decision",
                    "deployment_uid",
                    "executor_identity_commitment",
                    "namespace",
                    "new_object_commitment",
                    "observer_identity_commitment",
                    "old_object_commitment",
                    "provider_request_commitment",
                    "request_commitment",
                    "service_account_uid",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let expected_admission_text_columns = vec![
            ("admission_uid".to_owned(), true, "C".to_owned()),
            ("cluster_identity".to_owned(), true, "C".to_owned()),
            (
                "credential_binding_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("credential_id".to_owned(), true, "C".to_owned()),
            ("credential_token_digest".to_owned(), true, "C".to_owned()),
            ("decision".to_owned(), true, "C".to_owned()),
            ("deployment_uid".to_owned(), true, "C".to_owned()),
            (
                "executor_identity_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("namespace".to_owned(), true, "C".to_owned()),
            ("new_object_commitment".to_owned(), true, "C".to_owned()),
            (
                "observer_identity_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("old_object_commitment".to_owned(), true, "C".to_owned()),
            (
                "provider_request_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("request_commitment".to_owned(), true, "C".to_owned()),
            ("service_account_uid".to_owned(), true, "C".to_owned()),
        ];
        if admission_text_columns != expected_admission_text_columns {
            return Err(StateError::SchemaMismatch(format!(
                "admission text-column profile differs: {admission_text_columns:?}"
            )));
        }

        let broker_text_columns: Vec<(String, bool, String)> = transaction
            .query(
                "SELECT attribute.attname,
                        attribute.attnotnull,
                        coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE attribute.attrelid =
                        'public.accordlock_broker_operations'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec![
                    "bound_secret_name",
                    "bound_secret_uid",
                    "cluster_identity",
                    "deployment_uid",
                    "environment",
                    "last_reconciliation_evidence_commitment",
                    "last_reconciliation_outcome",
                    "namespace",
                    "operation",
                    "outcome",
                    "phase",
                    "provider_evidence_commitment",
                    "request_commitment",
                    "result_commitment",
                    "route_commitment",
                    "tenant",
                    "token_digest",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let expected_broker_text_columns = vec![
            ("bound_secret_name".to_owned(), true, "C".to_owned()),
            ("bound_secret_uid".to_owned(), false, "C".to_owned()),
            ("cluster_identity".to_owned(), true, "C".to_owned()),
            ("deployment_uid".to_owned(), true, "C".to_owned()),
            ("environment".to_owned(), true, "C".to_owned()),
            (
                "last_reconciliation_evidence_commitment".to_owned(),
                false,
                "C".to_owned(),
            ),
            (
                "last_reconciliation_outcome".to_owned(),
                false,
                "C".to_owned(),
            ),
            ("namespace".to_owned(), true, "C".to_owned()),
            ("operation".to_owned(), true, "C".to_owned()),
            ("outcome".to_owned(), false, "C".to_owned()),
            ("phase".to_owned(), true, "C".to_owned()),
            (
                "provider_evidence_commitment".to_owned(),
                false,
                "C".to_owned(),
            ),
            ("request_commitment".to_owned(), true, "C".to_owned()),
            ("result_commitment".to_owned(), false, "C".to_owned()),
            ("route_commitment".to_owned(), true, "C".to_owned()),
            ("tenant".to_owned(), true, "C".to_owned()),
            ("token_digest".to_owned(), false, "C".to_owned()),
        ];
        if broker_text_columns != expected_broker_text_columns {
            return Err(StateError::SchemaMismatch(format!(
                "broker journal text-column profile differs: {broker_text_columns:?}"
            )));
        }
        let broker_reconciliation_columns: Vec<(String, String, bool)> = transaction
            .query(
                "SELECT attribute.attname,
                        format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
                        attribute.attnotnull
                   FROM pg_attribute AS attribute
                  WHERE attribute.attrelid =
                        'public.accordlock_broker_operations'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec!["last_reconciled_unix_s", "reconciliation_count"]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("data_type"),
                    row.get("attnotnull"),
                )
            })
            .collect();
        if broker_reconciliation_columns
            != vec![
                (
                    "last_reconciled_unix_s".to_owned(),
                    "bigint".to_owned(),
                    false,
                ),
                ("reconciliation_count".to_owned(), "bigint".to_owned(), true),
            ]
        {
            return Err(StateError::SchemaMismatch(format!(
                "broker reconciliation column profile differs: {broker_reconciliation_columns:?}"
            )));
        }

        let physical_columns: Vec<(String, bool, String)> = transaction
            .query(
                "SELECT attribute.attname,
                        attribute.attnotnull,
                        coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE attribute.attrelid =
                        'public.accordlock_dispatch_claims'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec![
                    "cluster_identity",
                    "credential_binding_commitment",
                    "credential_id",
                    "credential_token_digest",
                    "deployment_uid",
                    "namespace",
                    "service_account_uid",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let expected_physical_columns = vec![
            ("cluster_identity".to_owned(), true, "C".to_owned()),
            (
                "credential_binding_commitment".to_owned(),
                false,
                "C".to_owned(),
            ),
            ("credential_id".to_owned(), false, "C".to_owned()),
            ("credential_token_digest".to_owned(), false, "C".to_owned()),
            ("deployment_uid".to_owned(), true, "C".to_owned()),
            ("namespace".to_owned(), true, "C".to_owned()),
            ("service_account_uid".to_owned(), false, "C".to_owned()),
        ];
        if physical_columns != expected_physical_columns {
            return Err(StateError::SchemaMismatch(format!(
                "physical-resource claim columns differ: {physical_columns:?}"
            )));
        }

        let ingress_columns: Vec<(String, String, String, bool)> = transaction
            .query(
                "SELECT class.relname, attribute.attname,
                        format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
                        attribute.attnotnull
                   FROM pg_attribute AS attribute
                   JOIN pg_class AS class ON class.oid = attribute.attrelid
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = class.relnamespace
                  WHERE namespace.nspname = 'public'
                    AND class.relname = ANY($1)
                    AND attribute.attnum > 0
                    AND NOT attribute.attisdropped
                  ORDER BY class.relname, attribute.attname",
                &[&vec![
                    "accordlock_ingress_replay_nonces",
                    "accordlock_ingress_replay_scopes",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("relname"),
                    row.get("attname"),
                    row.get("data_type"),
                    row.get("attnotnull"),
                )
            })
            .collect();
        if ingress_columns
            != vec![
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "consumed_unix_s".to_owned(),
                    "bigint".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "created_at".to_owned(),
                    "timestamp with time zone".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "expires_unix_s".to_owned(),
                    "bigint".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "key_id".to_owned(),
                    "text".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "nonce".to_owned(),
                    "uuid".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "replay_scope".to_owned(),
                    "text".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "state_instance_id".to_owned(),
                    "uuid".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "updated_at".to_owned(),
                    "timestamp with time zone".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "created_at".to_owned(),
                    "timestamp with time zone".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "observed_unix_s".to_owned(),
                    "bigint".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "replay_scope".to_owned(),
                    "text".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "state_instance_id".to_owned(),
                    "uuid".to_owned(),
                    true,
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "updated_at".to_owned(),
                    "timestamp with time zone".to_owned(),
                    true,
                ),
            ]
        {
            return Err(StateError::SchemaMismatch(format!(
                "ingress replay column profile differs: {ingress_columns:?}"
            )));
        }

        let ingress_text_columns: Vec<(String, String, bool, String)> = transaction
            .query(
                "SELECT class.relname, attribute.attname,
                        attribute.attnotnull, coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_class AS class ON class.oid = attribute.attrelid
                   JOIN pg_namespace AS namespace
                     ON namespace.oid = class.relnamespace
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE namespace.nspname = 'public'
                    AND (
                        class.relname = 'accordlock_ingress_replay_scopes'
                        AND attribute.attname = 'replay_scope'
                     OR class.relname = 'accordlock_ingress_replay_nonces'
                        AND attribute.attname = ANY($1)
                    )
                    AND NOT attribute.attisdropped
                  ORDER BY class.relname, attribute.attname",
                &[&vec!["key_id", "replay_scope"]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("relname"),
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        if ingress_text_columns
            != vec![
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "key_id".to_owned(),
                    true,
                    "C".to_owned(),
                ),
                (
                    "accordlock_ingress_replay_nonces".to_owned(),
                    "replay_scope".to_owned(),
                    true,
                    "C".to_owned(),
                ),
                (
                    "accordlock_ingress_replay_scopes".to_owned(),
                    "replay_scope".to_owned(),
                    true,
                    "C".to_owned(),
                ),
            ]
        {
            return Err(StateError::SchemaMismatch(format!(
                "ingress replay text-column profile differs: {ingress_text_columns:?}"
            )));
        }

        let ingress_expiry_index: Vec<String> = transaction
            .query(
                "SELECT indexdef
                   FROM pg_indexes
                  WHERE schemaname = 'public'
                    AND indexname = 'accordlock_ingress_replay_nonces_expiry_idx'",
                &[],
            )?
            .into_iter()
            .map(|row| row.get("indexdef"))
            .collect();
        if ingress_expiry_index
            != ["CREATE INDEX accordlock_ingress_replay_nonces_expiry_idx ON public.accordlock_ingress_replay_nonces USING btree (replay_scope, expires_unix_s, key_id, nonce)".to_owned()]
        {
            return Err(StateError::SchemaMismatch(format!(
                "ingress replay expiry index differs: {ingress_expiry_index:?}"
            )));
        }

        let fence_profile = transaction.query(
            "SELECT attribute.attidentity::text AS identity_kind,
                    sequence.seqincrement, sequence.seqmin, sequence.seqstart,
                    sequence.seqmax, sequence.seqcycle
               FROM pg_attribute AS attribute
               JOIN pg_sequence AS sequence
                 ON sequence.seqrelid =
                    pg_get_serial_sequence(
                        'public.accordlock_dispatch_claims', 'fence'
                    )::regclass
              WHERE attribute.attrelid =
                    'public.accordlock_dispatch_claims'::regclass
                AND attribute.attname = 'fence'
                AND NOT attribute.attisdropped",
            &[],
        )?;
        if fence_profile.len() != 1
            || fence_profile[0].get::<_, String>("identity_kind") != "a"
            || fence_profile[0].get::<_, i64>("seqincrement") != 1
            || fence_profile[0].get::<_, i64>("seqmin") != 1
            || fence_profile[0].get::<_, i64>("seqstart") != 1
            || fence_profile[0].get::<_, i64>("seqmax") != i64::MAX
            || fence_profile[0].get::<_, bool>("seqcycle")
        {
            return Err(StateError::SchemaMismatch(
                "dispatch fence is not a non-cycling GENERATED ALWAYS global identity".to_owned(),
            ));
        }
        let fence_runtime = transaction.query_one(
            "SELECT sequence.last_value, sequence.is_called,
                    (SELECT max(fence)
                       FROM public.accordlock_dispatch_claims) AS max_fence
               FROM public.accordlock_dispatch_claims_fence_seq AS sequence",
            &[],
        )?;
        let last_value: i64 = fence_runtime.get("last_value");
        let is_called: bool = fence_runtime.get("is_called");
        let max_fence: Option<i64> = fence_runtime.get("max_fence");
        if last_value < 1 || max_fence.is_some_and(|maximum| !is_called || last_value < maximum) {
            return Err(StateError::SchemaMismatch(
                "dispatch fence sequence is behind durable claim state".to_owned(),
            ));
        }

        let metadata_rows = transaction.query(
            "SELECT state_instance_id
               FROM public.accordlock_state_metadata
              WHERE singleton = TRUE",
            &[],
        )?;
        if metadata_rows.len() != 1
            || metadata_rows[0]
                .get::<_, Uuid>("state_instance_id")
                .is_nil()
        {
            return Err(StateError::SchemaMismatch(format!(
                "expected one non-nil state metadata row, found {}",
                metadata_rows.len()
            )));
        }
        Ok(())
    }

    /// Validates the installed schema without applying migrations or changing
    /// durable data.
    ///
    /// The check runs in a `PostgreSQL` read-only transaction and verifies the
    /// exact migration ledger and checksums, required integrity constraints,
    /// constraint attachment, security-critical column profile, global
    /// non-cycling fence sequence, and singleton state identity.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::SchemaMismatch`] for a missing or drifted schema,
    /// or [`StateError::Database`] when `PostgreSQL` cannot complete the read.
    pub fn validate_schema(&self) -> Result<(), StateError> {
        let mut client = self.connect()?;
        let mut transaction = client.build_transaction().read_only(true).start()?;
        Self::validate_schema_transaction(&mut transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// Applies the idempotent local schema migration.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if the database cannot be reached or the migration
    /// cannot be applied.
    #[allow(clippy::too_many_lines)]
    pub fn migrate(&self) -> Result<(), StateError> {
        let mut client = self.connect()?;
        let mut transaction = client.transaction()?;
        transaction.batch_execute("SELECT pg_advisory_xact_lock(6001412934996)")?;
        let mut applied_v14 = false;

        let ledger_exists: bool = transaction
            .query_one(
                "SELECT to_regclass('public.accordlock_schema_migrations') IS NOT NULL AS present",
                &[],
            )?
            .get("present");
        if ledger_exists {
            let installed: Vec<(i32, String)> = transaction
                .query(
                    "SELECT version, name
                       FROM public.accordlock_schema_migrations
                      ORDER BY version",
                    &[],
                )?
                .into_iter()
                .map(|row| (row.get("version"), row.get("name")))
                .collect();
            match installed.as_slice() {
                [(1, first), (2, second)]
                    if first == "0001_transactional_state" && second == "0002_state_integrity" =>
                {
                    transaction.batch_execute(MIGRATION_0003)?;
                    transaction.batch_execute(MIGRATION_0004)?;
                    transaction.batch_execute(MIGRATION_0005)?;
                    transaction.batch_execute(MIGRATION_0006)?;
                    transaction.batch_execute(MIGRATION_0007)?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [(1, first), (2, second), (3, third)]
                    if first == "0001_transactional_state"
                        && second == "0002_state_integrity"
                        && third == "0003_state_instance" =>
                {
                    // Older adapters left the checksum column NOT NULL after
                    // v3 verification. v4 must first insert its ledger row
                    // with a temporary NULL, which is filled and made NOT
                    // NULL again below in this same transaction.
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0004)?;
                    transaction.batch_execute(MIGRATION_0005)?;
                    transaction.batch_execute(MIGRATION_0006)?;
                    transaction.batch_execute(MIGRATION_0007)?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [(1, first), (2, second), (3, third), (4, fourth)]
                    if first == "0001_transactional_state"
                        && second == "0002_state_integrity"
                        && third == "0003_state_instance"
                        && fourth == "0004_signed_issuance_profile" =>
                {
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0005)?;
                    transaction.batch_execute(MIGRATION_0006)?;
                    transaction.batch_execute(MIGRATION_0007)?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [(1, first), (2, second), (3, third), (4, fourth), (5, fifth)]
                    if first == "0001_transactional_state"
                        && second == "0002_state_integrity"
                        && third == "0003_state_instance"
                        && fourth == "0004_signed_issuance_profile"
                        && fifth == "0005_dispatch_claims" =>
                {
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0006)?;
                    transaction.batch_execute(MIGRATION_0007)?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations" =>
                {
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0007)?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations" =>
                {
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0008)?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding" =>
                {
                    transaction.batch_execute(
                        "ALTER TABLE public.accordlock_schema_migrations
                             ALTER COLUMN sha256 DROP NOT NULL",
                    )?;
                    transaction.batch_execute(MIGRATION_0009)?;
                }
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal" => {}
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                    (10, tenth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal"
                    && tenth == "0010_ingress_replay" => {}
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                    (10, tenth),
                    (11, eleventh),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal"
                    && tenth == "0010_ingress_replay"
                    && eleventh == "0011_eks_destination_registry" => {}
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                    (10, tenth),
                    (11, eleventh),
                    (12, twelfth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal"
                    && tenth == "0010_ingress_replay"
                    && eleventh == "0011_eks_destination_registry"
                    && twelfth == "0012_terminal_retirement" => {}
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                    (10, tenth),
                    (11, eleventh),
                    (12, twelfth),
                    (13, thirteenth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal"
                    && tenth == "0010_ingress_replay"
                    && eleventh == "0011_eks_destination_registry"
                    && twelfth == "0012_terminal_retirement"
                    && thirteenth == "0013_durable_control_submissions" => {}
                [
                    (1, first),
                    (2, second),
                    (3, third),
                    (4, fourth),
                    (5, fifth),
                    (6, sixth),
                    (7, seventh),
                    (8, eighth),
                    (9, ninth),
                    (10, tenth),
                    (11, eleventh),
                    (12, twelfth),
                    (13, thirteenth),
                    (14, fourteenth),
                ] if first == "0001_transactional_state"
                    && second == "0002_state_integrity"
                    && third == "0003_state_instance"
                    && fourth == "0004_signed_issuance_profile"
                    && fifth == "0005_dispatch_claims"
                    && sixth == "0006_physical_resource_reservations"
                    && seventh == "0007_admission_authorizations"
                    && eighth == "0008_attempt_credential_binding"
                    && ninth == "0009_broker_operation_journal"
                    && tenth == "0010_ingress_replay"
                    && eleventh == "0011_eks_destination_registry"
                    && twelfth == "0012_terminal_retirement"
                    && thirteenth == "0013_durable_control_submissions"
                    && fourteenth == "0014_durable_dispatch_acquisitions" => {}
                _ => {
                    return Err(StateError::SchemaMismatch(format!(
                        "unexpected installed migration set: {installed:?}"
                    )));
                }
            }
            if installed.last().is_some_and(|(version, _)| *version < 10) {
                transaction.batch_execute(
                    "ALTER TABLE public.accordlock_schema_migrations
                         ALTER COLUMN sha256 DROP NOT NULL",
                )?;
                transaction.batch_execute(MIGRATION_0010)?;
            }
            if installed.last().is_some_and(|(version, _)| *version < 11) {
                transaction.batch_execute(
                    "ALTER TABLE public.accordlock_schema_migrations
                         ALTER COLUMN sha256 DROP NOT NULL",
                )?;
                transaction.batch_execute(MIGRATION_0011)?;
            }
            if installed.last().is_some_and(|(version, _)| *version < 12) {
                transaction.batch_execute(
                    "ALTER TABLE public.accordlock_schema_migrations
                         ALTER COLUMN sha256 DROP NOT NULL",
                )?;
                transaction.batch_execute(MIGRATION_0012)?;
            }
            if installed.last().is_some_and(|(version, _)| *version < 13) {
                transaction.batch_execute(
                    "ALTER TABLE public.accordlock_schema_migrations
                         ALTER COLUMN sha256 DROP NOT NULL",
                )?;
                transaction.batch_execute(MIGRATION_0013)?;
            }
            if installed.last().is_some_and(|(version, _)| *version < 14) {
                transaction.batch_execute(
                    "ALTER TABLE public.accordlock_schema_migrations
                         ALTER COLUMN sha256 DROP NOT NULL",
                )?;
                transaction.batch_execute(MIGRATION_0014)?;
                applied_v14 = true;
            }
        } else {
            transaction.batch_execute(MIGRATION_0001)?;
            transaction.batch_execute(MIGRATION_0002)?;
            transaction.batch_execute(MIGRATION_0003)?;
            transaction.batch_execute(MIGRATION_0004)?;
            transaction.batch_execute(MIGRATION_0005)?;
            transaction.batch_execute(MIGRATION_0006)?;
            transaction.batch_execute(MIGRATION_0007)?;
            transaction.batch_execute(MIGRATION_0008)?;
            transaction.batch_execute(MIGRATION_0009)?;
            transaction.batch_execute(MIGRATION_0010)?;
            transaction.batch_execute(MIGRATION_0011)?;
            transaction.batch_execute(MIGRATION_0012)?;
            transaction.batch_execute(MIGRATION_0013)?;
            transaction.batch_execute(MIGRATION_0014)?;
            applied_v14 = true;
        }

        if applied_v14 {
            Self::validate_migrated_dispatch_sources(&mut transaction)?;
        }

        let expected_versions = Self::expected_migration_versions();
        let recorded_versions: Vec<(i32, String, Option<String>)> = transaction
            .query(
                "SELECT version, name, sha256
                   FROM public.accordlock_schema_migrations
                  ORDER BY version",
                &[],
            )?
            .into_iter()
            .map(|row| (row.get("version"), row.get("name"), row.get("sha256")))
            .collect();
        if recorded_versions.len() != expected_versions.len() {
            return Err(StateError::SchemaMismatch(format!(
                "migration ledger differs: {recorded_versions:?}"
            )));
        }
        for ((version, name, recorded_sha256), expected) in
            recorded_versions.iter().zip(&expected_versions)
        {
            if *version != expected.0 || name != &expected.1 {
                return Err(StateError::SchemaMismatch(format!(
                    "migration ledger differs: {recorded_versions:?}"
                )));
            }
            if let Some(recorded_sha256) = recorded_sha256 {
                if recorded_sha256 != &expected.2 {
                    return Err(StateError::SchemaMismatch(format!(
                        "migration checksum differs at version {version}"
                    )));
                }
            } else {
                transaction.execute(
                    "UPDATE public.accordlock_schema_migrations
                        SET sha256 = $3
                      WHERE version = $1 AND name = $2 AND sha256 IS NULL",
                    &[version, name, &expected.2],
                )?;
            }
        }
        transaction.batch_execute(
            "ALTER TABLE public.accordlock_schema_migrations
                 ALTER COLUMN sha256 SET NOT NULL",
        )?;

        let versions: Vec<(i32, String, String)> = transaction
            .query(
                "SELECT version, name, sha256
                   FROM public.accordlock_schema_migrations
                  ORDER BY version",
                &[],
            )?
            .into_iter()
            .map(|row| (row.get("version"), row.get("name"), row.get("sha256")))
            .collect();
        if versions != expected_versions {
            return Err(StateError::SchemaMismatch(format!(
                "migration ledger differs: {versions:?}"
            )));
        }

        let constraints: Vec<(String, String, String)> = transaction
            .query(
                "SELECT conname,
                        contype::text AS constraint_type,
                        pg_get_constraintdef(oid, TRUE) AS definition
                   FROM pg_constraint
                  WHERE conname = ANY($1)
                    AND connamespace = 'public'::regnamespace
                  ORDER BY conname",
                &[&REQUIRED_INTEGRITY_CONSTRAINTS
                    .iter()
                    .map(|(name, _, _)| *name)
                    .collect::<Vec<_>>()],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("conname"),
                    row.get("constraint_type"),
                    row.get("definition"),
                )
            })
            .collect();
        let expected_constraints: Vec<(String, String, String)> = REQUIRED_INTEGRITY_CONSTRAINTS
            .iter()
            .map(|(name, kind, definition)| {
                (
                    (*name).to_owned(),
                    (*kind).to_owned(),
                    (*definition).to_owned(),
                )
            })
            .collect();
        if constraints != expected_constraints {
            return Err(StateError::SchemaMismatch(format!(
                "integrity constraint definitions differ: {constraints:?}"
            )));
        }
        let claim_constraint_names: Vec<_> = REQUIRED_INTEGRITY_CONSTRAINTS
            .iter()
            .map(|(name, _, _)| *name)
            .filter(|name| name.starts_with("accordlock_dispatch_claims_"))
            .collect();
        let claim_constraint_count: i64 = transaction
            .query_one(
                "SELECT count(*)::bigint AS constraint_count
                   FROM pg_constraint
                  WHERE conname = ANY($1)
                    AND conrelid = 'public.accordlock_dispatch_claims'::regclass",
                &[&claim_constraint_names],
            )?
            .get("constraint_count");
        if claim_constraint_count
            != i64::try_from(claim_constraint_names.len()).map_err(|_| {
                StateError::SchemaMismatch("claim constraint count overflowed".to_owned())
            })?
        {
            return Err(StateError::SchemaMismatch(
                "dispatch-claim constraints are attached to the wrong table".to_owned(),
            ));
        }

        let admission_constraint_names: Vec<_> = REQUIRED_INTEGRITY_CONSTRAINTS
            .iter()
            .map(|(name, _, _)| *name)
            .filter(|name| name.starts_with("accordlock_admission_authorizations_"))
            .collect();
        let admission_constraint_count: i64 = transaction
            .query_one(
                "SELECT count(*)::bigint AS constraint_count
                   FROM pg_constraint
                  WHERE conname = ANY($1)
                    AND conrelid =
                        'public.accordlock_admission_authorizations'::regclass",
                &[&admission_constraint_names],
            )?
            .get("constraint_count");
        if admission_constraint_count
            != i64::try_from(admission_constraint_names.len()).map_err(|_| {
                StateError::SchemaMismatch("admission constraint count overflowed".to_owned())
            })?
        {
            return Err(StateError::SchemaMismatch(
                "admission constraints are attached to the wrong table".to_owned(),
            ));
        }

        let admission_text_columns: Vec<(String, bool, String)> = transaction
            .query(
                "SELECT attribute.attname,
                        attribute.attnotnull,
                        coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE attribute.attrelid =
                        'public.accordlock_admission_authorizations'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec![
                    "admission_uid",
                    "cluster_identity",
                    "credential_binding_commitment",
                    "credential_id",
                    "credential_token_digest",
                    "decision",
                    "deployment_uid",
                    "executor_identity_commitment",
                    "namespace",
                    "new_object_commitment",
                    "observer_identity_commitment",
                    "old_object_commitment",
                    "provider_request_commitment",
                    "request_commitment",
                    "service_account_uid",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let expected_admission_text_columns = vec![
            ("admission_uid".to_owned(), true, "C".to_owned()),
            ("cluster_identity".to_owned(), true, "C".to_owned()),
            (
                "credential_binding_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("credential_id".to_owned(), true, "C".to_owned()),
            ("credential_token_digest".to_owned(), true, "C".to_owned()),
            ("decision".to_owned(), true, "C".to_owned()),
            ("deployment_uid".to_owned(), true, "C".to_owned()),
            (
                "executor_identity_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("namespace".to_owned(), true, "C".to_owned()),
            ("new_object_commitment".to_owned(), true, "C".to_owned()),
            (
                "observer_identity_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("old_object_commitment".to_owned(), true, "C".to_owned()),
            (
                "provider_request_commitment".to_owned(),
                true,
                "C".to_owned(),
            ),
            ("request_commitment".to_owned(), true, "C".to_owned()),
            ("service_account_uid".to_owned(), true, "C".to_owned()),
        ];
        if admission_text_columns != expected_admission_text_columns {
            return Err(StateError::SchemaMismatch(format!(
                "admission text-column profile differs: {admission_text_columns:?}"
            )));
        }

        let physical_columns: Vec<(String, bool, String)> = transaction
            .query(
                "SELECT attribute.attname,
                        attribute.attnotnull,
                        coll.collname
                   FROM pg_attribute AS attribute
                   JOIN pg_collation AS coll
                     ON coll.oid = attribute.attcollation
                  WHERE attribute.attrelid =
                        'public.accordlock_dispatch_claims'::regclass
                    AND attribute.attname = ANY($1)
                    AND NOT attribute.attisdropped
                  ORDER BY attribute.attname",
                &[&vec![
                    "cluster_identity",
                    "credential_binding_commitment",
                    "credential_id",
                    "credential_token_digest",
                    "deployment_uid",
                    "namespace",
                    "service_account_uid",
                ]],
            )?
            .into_iter()
            .map(|row| {
                (
                    row.get("attname"),
                    row.get("attnotnull"),
                    row.get("collname"),
                )
            })
            .collect();
        let expected_physical_columns = vec![
            ("cluster_identity".to_owned(), true, "C".to_owned()),
            (
                "credential_binding_commitment".to_owned(),
                false,
                "C".to_owned(),
            ),
            ("credential_id".to_owned(), false, "C".to_owned()),
            ("credential_token_digest".to_owned(), false, "C".to_owned()),
            ("deployment_uid".to_owned(), true, "C".to_owned()),
            ("namespace".to_owned(), true, "C".to_owned()),
            ("service_account_uid".to_owned(), false, "C".to_owned()),
        ];
        if physical_columns != expected_physical_columns {
            return Err(StateError::SchemaMismatch(format!(
                "physical-resource claim columns differ: {physical_columns:?}"
            )));
        }

        let fence_profile = transaction.query(
            "SELECT attribute.attidentity::text AS identity_kind,
                    sequence.seqincrement, sequence.seqmin, sequence.seqstart,
                    sequence.seqmax, sequence.seqcycle
               FROM pg_attribute AS attribute
               JOIN pg_sequence AS sequence
                 ON sequence.seqrelid =
                    pg_get_serial_sequence(
                        'public.accordlock_dispatch_claims', 'fence'
                    )::regclass
              WHERE attribute.attrelid =
                    'public.accordlock_dispatch_claims'::regclass
                AND attribute.attname = 'fence'
                AND NOT attribute.attisdropped",
            &[],
        )?;
        if fence_profile.len() != 1
            || fence_profile[0].get::<_, String>("identity_kind") != "a"
            || fence_profile[0].get::<_, i64>("seqincrement") != 1
            || fence_profile[0].get::<_, i64>("seqmin") != 1
            || fence_profile[0].get::<_, i64>("seqstart") != 1
            || fence_profile[0].get::<_, i64>("seqmax") != i64::MAX
            || fence_profile[0].get::<_, bool>("seqcycle")
        {
            return Err(StateError::SchemaMismatch(
                "dispatch fence is not a non-cycling GENERATED ALWAYS global identity".to_owned(),
            ));
        }
        let fence_runtime = transaction.query_one(
            "SELECT sequence.last_value, sequence.is_called,
                    (SELECT max(fence)
                       FROM public.accordlock_dispatch_claims) AS max_fence
               FROM public.accordlock_dispatch_claims_fence_seq AS sequence",
            &[],
        )?;
        let last_value: i64 = fence_runtime.get("last_value");
        let is_called: bool = fence_runtime.get("is_called");
        let max_fence: Option<i64> = fence_runtime.get("max_fence");
        if last_value < 1 || max_fence.is_some_and(|maximum| !is_called || last_value < maximum) {
            return Err(StateError::SchemaMismatch(
                "dispatch fence sequence is behind durable claim state".to_owned(),
            ));
        }

        let metadata_rows = transaction.query(
            "SELECT state_instance_id
               FROM public.accordlock_state_metadata
              WHERE singleton = TRUE",
            &[],
        )?;
        if metadata_rows.len() != 1
            || metadata_rows[0]
                .get::<_, Uuid>("state_instance_id")
                .is_nil()
        {
            return Err(StateError::SchemaMismatch(format!(
                "expected one non-nil state metadata row, found {}",
                metadata_rows.len()
            )));
        }
        Self::validate_schema_transaction(&mut transaction)?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_migrated_dispatch_sources(
        transaction: &mut Transaction<'_>,
    ) -> Result<(), StateError> {
        const PAGE_SIZE: i64 = 128;
        let mut after_submission_id = Uuid::nil();
        loop {
            let rows = transaction.query(
                "SELECT submission_id,tenant,environment,authorization_id,transaction_id
                   FROM public.accordlock_control_consumptions
                  WHERE submission_id > $1
                  ORDER BY submission_id
                  LIMIT $2",
                &[&after_submission_id, &PAGE_SIZE],
            )?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let submission_id: Uuid = row.get("submission_id");
                let key = ConsumeKey {
                    scope: Scope {
                        tenant: row.get("tenant"),
                        environment: row.get("environment"),
                    },
                    authorization_id: row.get("authorization_id"),
                    transaction_id: row.get("transaction_id"),
                };
                key.validate()?;
                let stored = control_plane::load_submission_for_update(transaction, submission_id)?;
                control_plane::validate_migrated_dispatch_source(transaction, &stored, &key)?;
                after_submission_id = submission_id;
            }
            if rows.len() < usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX) {
                break;
            }
        }
        Ok(())
    }

    fn lock_or_create_ingress_scope(
        transaction: &mut Transaction<'_>,
        scope: &IngressReplayScope,
    ) -> Result<(Uuid, i64), StateError> {
        transaction.execute(
            "INSERT INTO public.accordlock_ingress_replay_scopes
                        (replay_scope, state_instance_id, observed_unix_s)
                 SELECT $1, state_instance_id, 0
                   FROM public.accordlock_state_metadata
                  WHERE singleton = TRUE
                 ON CONFLICT DO NOTHING",
            &[&scope.as_str()],
        )?;
        Self::lock_ingress_scope(transaction, scope)
    }

    fn lock_ingress_scope(
        transaction: &mut Transaction<'_>,
        scope: &IngressReplayScope,
    ) -> Result<(Uuid, i64), StateError> {
        let row = transaction
            .query_opt(
                "SELECT replay.state_instance_id AS stored_state_instance_id,
                        replay.observed_unix_s,
                        metadata.state_instance_id AS expected_state_instance_id
                   FROM public.accordlock_ingress_replay_scopes AS replay
                  CROSS JOIN public.accordlock_state_metadata AS metadata
                  WHERE replay.replay_scope = $1
                    AND metadata.singleton = TRUE
                  FOR UPDATE OF replay",
                &[&scope.as_str()],
            )?
            .ok_or_else(|| {
                StateError::InvalidRecord(
                    "ingress replay scope is not initialized or its lineage is absent".to_owned(),
                )
            })?;
        let stored_state_instance_id: Uuid = row.get("stored_state_instance_id");
        let expected_state_instance_id: Uuid = row.get("expected_state_instance_id");
        if stored_state_instance_id.is_nil()
            || expected_state_instance_id.is_nil()
            || stored_state_instance_id != expected_state_instance_id
        {
            return Err(StateError::InvalidRecord(
                "ingress replay scope belongs to another state lineage".to_owned(),
            ));
        }
        Ok((stored_state_instance_id, row.get("observed_unix_s")))
    }

    fn advance_ingress_high_water(
        transaction: &mut Transaction<'_>,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
        high_water: i64,
    ) -> Result<(), StateError> {
        if observed_unix_s < high_water {
            return Err(StateError::ClockRollback {
                observed: observed_unix_s,
                high_water,
            });
        }
        let updated = transaction.execute(
            "UPDATE public.accordlock_ingress_replay_scopes
                SET observed_unix_s = $2,
                    updated_at = clock_timestamp()
              WHERE replay_scope = $1
                AND observed_unix_s = $3",
            &[&scope.as_str(), &observed_unix_s, &high_water],
        )?;
        if updated != 1 {
            return Err(StateError::RetryableConflict);
        }
        Ok(())
    }

    fn commit_ingress_transaction(transaction: Transaction<'_>) -> Result<(), StateError> {
        match transaction.commit() {
            Ok(()) => Ok(()),
            Err(error) if is_retryable(&error) => Err(StateError::Database(error)),
            Err(_) => Err(StateError::IngressReplayOutcomeUnknown),
        }
    }

    fn observe_ingress_time_once(
        &self,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
    ) -> Result<(), StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (_, high_water) = Self::lock_or_create_ingress_scope(&mut transaction, scope)?;
        Self::advance_ingress_high_water(&mut transaction, scope, observed_unix_s, high_water)?;
        Self::commit_ingress_transaction(transaction)
    }

    fn consume_ingress_nonce_once(
        &self,
        request: &IngressNonceConsumption,
    ) -> Result<IngressReplayDecision, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (state_instance_id, high_water) =
            Self::lock_or_create_ingress_scope(&mut transaction, request.scope())?;
        Self::advance_ingress_high_water(
            &mut transaction,
            request.scope(),
            request.observed_unix_s(),
            high_water,
        )?;
        let consumed = transaction
            .query_opt(
                "INSERT INTO public.accordlock_ingress_replay_nonces
                            (replay_scope, state_instance_id, key_id, nonce,
                             expires_unix_s, consumed_unix_s)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (replay_scope, key_id, nonce) DO UPDATE
                       SET state_instance_id = EXCLUDED.state_instance_id,
                           expires_unix_s = EXCLUDED.expires_unix_s,
                           consumed_unix_s = EXCLUDED.consumed_unix_s,
                           updated_at = clock_timestamp()
                      WHERE accordlock_ingress_replay_nonces.expires_unix_s
                            <= EXCLUDED.consumed_unix_s
                        AND NOT EXISTS (
                            SELECT 1
                              FROM public.accordlock_control_submissions AS control
                             WHERE control.replay_scope =
                                   accordlock_ingress_replay_nonces.replay_scope
                               AND control.key_id =
                                   accordlock_ingress_replay_nonces.key_id
                               AND control.nonce =
                                   accordlock_ingress_replay_nonces.nonce
                        )
                      RETURNING nonce",
                &[
                    &request.scope().as_str(),
                    &state_instance_id,
                    &request.key_id(),
                    &request.nonce(),
                    &request.expires_unix_s(),
                    &request.observed_unix_s(),
                ],
            )?
            .is_some();
        Self::commit_ingress_transaction(transaction)?;
        Ok(if consumed {
            IngressReplayDecision::Consumed
        } else {
            IngressReplayDecision::AlreadyUsed
        })
    }

    fn prune_expired_ingress_nonces_once(
        &self,
        scope: &IngressReplayScope,
        limit: u32,
    ) -> Result<u32, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (_, high_water) = Self::lock_ingress_scope(&mut transaction, scope)?;
        let limit = i64::from(limit);
        let deleted = transaction.execute(
            "WITH candidates AS (
                 SELECT nonce.replay_scope, nonce.key_id, nonce.nonce
                   FROM public.accordlock_ingress_replay_nonces AS nonce
                   WHERE nonce.replay_scope = $1
                     AND nonce.expires_unix_s <= $2
                     AND NOT EXISTS (
                         SELECT 1
                           FROM public.accordlock_control_submissions AS control
                          WHERE control.replay_scope = nonce.replay_scope
                            AND control.key_id = nonce.key_id
                            AND control.nonce = nonce.nonce
                     )
                   ORDER BY nonce.expires_unix_s, nonce.key_id, nonce.nonce
                  FOR UPDATE OF nonce SKIP LOCKED
                  LIMIT $3
             )
             DELETE FROM public.accordlock_ingress_replay_nonces AS nonce
              USING candidates
              WHERE nonce.replay_scope = candidates.replay_scope
                AND nonce.key_id = candidates.key_id
                AND nonce.nonce = candidates.nonce",
            &[&scope.as_str(), &high_water, &limit],
        )?;
        Self::commit_ingress_transaction(transaction)?;
        u32::try_from(deleted).map_err(|_| {
            StateError::InvalidRecord("ingress replay GC result cannot be represented".to_owned())
        })
    }

    fn serializable(client: &mut Client) -> Result<Transaction<'_>, StateError> {
        client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(StateError::Database)
    }

    #[allow(clippy::too_many_lines)]
    fn consume_once(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;

        let authority_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&key.scope.tenant, &key.scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let authority: AuthorityVector = decode_json(authority_row.get("authority_json"))?;

        transaction.execute(
            "INSERT INTO accordlock_time_high_water
                        (tenant, environment, observed_unix_s)
                 VALUES ($1, $2, 0)
                 ON CONFLICT (tenant, environment) DO NOTHING",
            &[&key.scope.tenant, &key.scope.environment],
        )?;
        let high_water: i64 = transaction
            .query_one(
                "SELECT observed_unix_s
                   FROM accordlock_time_high_water
                  WHERE tenant = $1 AND environment = $2
                  FOR UPDATE",
                &[&key.scope.tenant, &key.scope.environment],
            )?
            .get("observed_unix_s");

        let authorization_row = transaction
            .query_opt(
                "SELECT transaction_id, grant_id, record_json, authorization_hash,
                        consume_before, state, issuance_profile_version,
                        request_id, evaluation_nonce
                   FROM accordlock_issued_authorizations
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                  FOR UPDATE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )?
            .ok_or(StateError::AuthorizationNotFound)?;
        let issued = decode_stored_authorization_row(&authorization_row, key)?;
        let state: String = authorization_row.get("state");
        if state == "CONSUMED" {
            return Err(StateError::AlreadyConsumed);
        }
        if state != "ISSUED" {
            return Err(StateError::InvalidRecord(format!(
                "unsupported issued-authorization state {state}"
            )));
        }
        let owned_by_control_submission = transaction
            .query_opt(
                "SELECT submission_id
                   FROM public.accordlock_control_submissions
                  WHERE (tenant = $1 AND environment = $2 AND request_id = $3)
                     OR evaluation_nonce = $4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &issued.authorization().request_id,
                    &issued.authorization().evaluation_nonce,
                ],
            )?
            .is_some();
        let linked_to_control_issuance = transaction
            .query_opt(
                "SELECT submission_id
                   FROM public.accordlock_control_issuances
                  WHERE tenant = $1 AND environment = $2
                    AND authorization_id = $3 AND transaction_id = $4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?
            .is_some();
        if owned_by_control_submission || linked_to_control_issuance {
            return Err(StateError::ControlWorkMismatch);
        }

        let grant_row = transaction
            .query_opt(
                "SELECT registration_json, uses, maximum_uses, not_before,
                        expires_at, revoked, issuance_profile_version
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                  FOR UPDATE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &issued.authorization().grant_id,
                ],
            )?
            .ok_or(StateError::GrantNotFound)?;
        let uses_i64: i64 = grant_row.get("uses");
        let uses = u32::try_from(uses_i64).map_err(|_| {
            StateError::InvalidRecord("stored grant use count does not fit u32".to_owned())
        })?;
        let grant = GrantSnapshot {
            registration: decode_json(grant_row.get("registration_json"))?,
            uses,
            revoked: grant_row.get("revoked"),
        };
        let maximum_uses: i64 = grant_row.get("maximum_uses");
        let not_before: i64 = grant_row.get("not_before");
        let expires_at: i64 = grant_row.get("expires_at");
        if grant_row.get::<_, i16>("issuance_profile_version") != 2
            || maximum_uses != i64::from(grant.registration.grant.maximum_uses)
            || not_before != grant.registration.grant.not_before
            || expires_at != grant.registration.grant.expires_at
        {
            return Err(StateError::InvalidRecord(
                "stored grant columns and registration JSON do not agree".to_owned(),
            ));
        }

        // Read trusted database time only after every state row needed for the
        // decision is locked. A transaction waiting on another consumer must
        // not validate an authorization using a timestamp sampled before that wait.
        let observed_time: i64 = transaction
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint AS now_unix_s",
                &[],
            )?
            .get("now_unix_s");

        let dispatch_deadline = match validate_consumption(
            &authority,
            &grant,
            &issued,
            observed_time,
            Some(high_water),
        ) {
            Ok(deadline) => deadline,
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                Self::update_dispatch_high_water(&mut transaction, &key.scope, observed_time)?;
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let receipt = ConsumptionReceipt {
            schema_version: issued.authorization().schema_version,
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
            consumed_at: observed_time,
            dispatch_deadline,
            authority,
            authorization_hash: issued.authorization_hash,
        };
        let outbox = OutboxEntry {
            scope: key.scope.clone(),
            transaction_id: issued.transaction_id,
            authorization_id: issued.authorization().authorization_id,
            dispatch_deadline,
            status: OutboxStatus::PendingWitness,
            receipt: receipt.clone(),
        };
        let receipt_json = encode_json(&receipt)?;
        let outbox_json = encode_json(&outbox)?;

        let updated_grants = transaction
            .execute(
                "UPDATE accordlock_grants
                SET uses = uses + 1, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                AND revoked = FALSE AND uses < maximum_uses",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &issued.authorization().grant_id,
                ],
            )
            .map_err(StateError::from)?;
        if updated_grants != 1 {
            return Err(StateError::GrantExhausted);
        }
        let updated_authorizations = transaction
            .execute(
                "UPDATE accordlock_issued_authorizations
                SET state = 'CONSUMED', consumed_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND transaction_id = $4 AND state = 'ISSUED'",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )
            .map_err(StateError::from)?;
        if updated_authorizations != 1 {
            return Err(StateError::AlreadyConsumed);
        }
        transaction.execute(
            "UPDATE accordlock_time_high_water
                SET observed_unix_s = $3, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2",
            &[&key.scope.tenant, &key.scope.environment, &observed_time],
        )?;
        transaction.execute(
            "INSERT INTO accordlock_consumptions
                        (tenant, environment, authorization_id, transaction_id, receipt_json,
                         consumed_unix_s, dispatch_deadline)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &receipt_json,
                &observed_time,
                &dispatch_deadline,
            ],
        )?;
        transaction.execute(
            "INSERT INTO accordlock_execution_outbox
                        (tenant, environment, authorization_id, transaction_id,
                         dispatch_deadline, status, entry_json)
                 VALUES ($1, $2, $3, $4, $5, 'PENDING_WITNESS', $6)",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &dispatch_deadline,
                &outbox_json,
            ],
        )?;
        transaction.commit()?;
        Ok(ConsumeSuccess::new(receipt, outbox, issued))
    }

    #[allow(clippy::too_many_lines)]
    fn lock_dispatch_inputs(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<LockedDispatchInputs, StateError> {
        let authority = Self::lock_dispatch_authority(transaction, key)?;
        let high_water_row = transaction.query_opt(
            "SELECT observed_unix_s
                   FROM accordlock_time_high_water
                  WHERE tenant = $1 AND environment = $2
                  FOR UPDATE",
            &[&key.scope.tenant, &key.scope.environment],
        )?;
        let high_water: i64 = if let Some(row) = high_water_row {
            row.get("observed_unix_s")
        } else {
            // An unconsumed authorization legitimately has no trusted-time high-water row yet.
            // Preserve the normal authority -> HWM -> authorization lock order when the row
            // exists, but distinguish that state from a corrupt consumed record here.
            let authorization_state_row = transaction.query_opt(
                "SELECT transaction_id, state
                   FROM accordlock_issued_authorizations
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )?;
            let authorization_state_row =
                authorization_state_row.ok_or(StateError::AuthorizationNotFound)?;
            if authorization_state_row.get::<_, Uuid>("transaction_id") != key.transaction_id {
                return Err(StateError::TransactionMismatch);
            }
            let authorization_state: String = authorization_state_row.get("state");
            if authorization_state == "ISSUED" {
                return Err(StateError::GrantNotConsumed);
            }
            return Err(StateError::InvalidRecord(
                "consumed authorization has no durable trusted-time high-water row".to_owned(),
            ));
        };
        Self::lock_dispatch_inputs_after_high_water(transaction, key, authority, high_water)
    }

    fn lock_dispatch_authority(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<AuthorityVector, StateError> {
        Self::decode_locked_dispatch_authority(Self::lock_dispatch_authority_value(
            transaction,
            key,
        )?)
    }

    fn lock_dispatch_authority_value(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<Option<Value>, StateError> {
        Ok(transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&key.scope.tenant, &key.scope.environment],
            )?
            .map(|row| row.get("authority_json")))
    }

    fn decode_locked_dispatch_authority(
        authority: Option<Value>,
    ) -> Result<AuthorityVector, StateError> {
        authority
            .map(decode_json)
            .transpose()?
            .ok_or(StateError::AuthorityNotInitialized)
    }

    #[allow(clippy::too_many_lines)]
    fn lock_dispatch_inputs_after_high_water(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        authority: AuthorityVector,
        high_water: i64,
    ) -> Result<LockedDispatchInputs, StateError> {
        let authorization_row = transaction
            .query_opt(
                "SELECT transaction_id, grant_id, record_json, authorization_hash,
                        consume_before, state, issuance_profile_version,
                        request_id, evaluation_nonce
                   FROM accordlock_issued_authorizations
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )?
            .ok_or(StateError::AuthorizationNotFound)?;
        let issued = decode_stored_authorization_row(&authorization_row, key)?;
        let authorization_state: String = authorization_row.get("state");
        if authorization_state == "ISSUED" {
            return Err(StateError::GrantNotConsumed);
        }
        if authorization_state != "CONSUMED" {
            return Err(StateError::InvalidRecord(format!(
                "unsupported issued-authorization state {authorization_state}"
            )));
        }
        let grant_row = transaction
            .query_opt(
                "SELECT registration_json, uses, maximum_uses, not_before,
                        expires_at, revoked, issuance_profile_version
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &issued.authorization().grant_id,
                ],
            )?
            .ok_or(StateError::GrantNotFound)?;
        let uses_i64: i64 = grant_row.get("uses");
        let grant = GrantSnapshot {
            registration: decode_json(grant_row.get("registration_json"))?,
            uses: u32::try_from(uses_i64).map_err(|_| {
                StateError::InvalidRecord("stored grant use count does not fit u32".to_owned())
            })?,
            revoked: grant_row.get("revoked"),
        };
        if grant_row.get::<_, i16>("issuance_profile_version") != 2
            || grant_row.get::<_, i64>("maximum_uses")
                != i64::from(grant.registration.grant.maximum_uses)
            || grant_row.get::<_, i64>("not_before") != grant.registration.grant.not_before
            || grant_row.get::<_, i64>("expires_at") != grant.registration.grant.expires_at
        {
            return Err(StateError::InvalidRecord(
                "stored grant columns and registration JSON do not agree".to_owned(),
            ));
        }

        let consumption_row = transaction
            .query_opt(
                "SELECT receipt_json, consumed_unix_s, dispatch_deadline
                   FROM accordlock_consumptions
                  WHERE tenant = $1 AND environment = $2
                    AND authorization_id = $3 AND transaction_id = $4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?
            .ok_or(StateError::ConsumptionNotFound)?;
        let receipt: ConsumptionReceipt = decode_json(consumption_row.get("receipt_json"))?;
        if consumption_row.get::<_, i64>("consumed_unix_s") != receipt.consumed_at
            || consumption_row.get::<_, i64>("dispatch_deadline") != receipt.dispatch_deadline
        {
            return Err(StateError::InvalidRecord(
                "stored consumption columns and receipt JSON do not agree".to_owned(),
            ));
        }

        let outbox_row = transaction
            .query_opt(
                "SELECT entry_json, dispatch_deadline, status
                   FROM accordlock_execution_outbox
                  WHERE tenant = $1 AND environment = $2
                    AND authorization_id = $3 AND transaction_id = $4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?
            .ok_or(StateError::ConsumptionNotFound)?;
        let outbox: OutboxEntry = decode_json(outbox_row.get("entry_json"))?;
        if outbox_row.get::<_, i64>("dispatch_deadline") != outbox.dispatch_deadline
            || outbox_row.get::<_, String>("status") != "PENDING_WITNESS"
        {
            return Err(StateError::InvalidRecord(
                "stored outbox columns and entry JSON do not agree".to_owned(),
            ));
        }
        validate_postgres_control_consumption_lineage_if_owned(
            transaction,
            key,
            &issued,
            &receipt,
        )?;

        Ok(LockedDispatchInputs {
            authority,
            high_water,
            grant,
            issued,
            receipt,
            outbox,
        })
    }

    fn lock_v14_dispatch_inputs(
        transaction: &mut Transaction<'_>,
        stored: &crate::control::StoredControlSubmission,
        key: &ConsumeKey,
    ) -> Result<(IngressReplayScope, i64, i64, LockedDispatchInputs), StateError> {
        // Do not compose the legacy dispatch and control HWM helpers: their
        // independent lock orders invert one another. Every v14 transaction
        // already owns exactly one submission root, then follows the global
        // authority -> ingress HWM -> scope HWM -> immutable-input order.
        let authority = Self::lock_dispatch_authority(transaction, key)?;
        let replay_scope = IngressReplayScope::new(&stored.replay_scope)?;
        let (ingress_state_instance, ingress_high_water) =
            Self::lock_or_create_ingress_scope(transaction, &replay_scope)?;
        if ingress_state_instance != stored.state_instance_id {
            return Err(StateError::ControlWorkMismatch);
        }
        let scope_high_water = Self::lock_or_create_high_water(transaction, &stored.scope())?;
        let inputs = Self::lock_dispatch_inputs_after_high_water(
            transaction,
            key,
            authority,
            scope_high_water,
        )?;
        Ok((replay_scope, ingress_high_water, scope_high_water, inputs))
    }

    /// Authenticates immutable consumed-dispatch facts against their original
    /// authorization authority without consulting the current authority or either
    /// trusted-time high-water mark. This is suitable only for frozen audit,
    /// reconciliation, and cleanup paths that cannot mint productive
    /// authority.
    fn lock_frozen_dispatch_inputs(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<LockedDispatchInputs, StateError> {
        let authorization_row = transaction
            .query_opt(
                "SELECT transaction_id, grant_id, record_json, authorization_hash,
                        consume_before, state, issuance_profile_version,
                        request_id, evaluation_nonce
                   FROM accordlock_issued_authorizations
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )?
            .ok_or(StateError::AuthorizationNotFound)?;
        let issued = decode_stored_authorization_row(&authorization_row, key)?;
        if authorization_row.get::<_, String>("state") != "CONSUMED" {
            return Err(StateError::GrantNotConsumed);
        }
        let original_authority = issued.authorization().authority.clone();
        let inputs =
            Self::lock_dispatch_inputs_after_high_water(transaction, key, original_authority, 0)?;
        validate_recovered_consumption(key, &inputs.issued, &inputs.receipt, &inputs.outbox)?;
        Ok(inputs)
    }

    /// Locks the trusted-time roots for a broker operation's immutable origin.
    /// Control-owned origins use the v14 dual-HWM order; strict legacy origins
    /// retain the scope-only profile.
    fn lock_broker_time_inputs(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        origin_acquisition_id: Uuid,
        origin_lease_fence: u64,
    ) -> Result<LockedBrokerTimeInputs, StateError> {
        let state_instance_id = Self::locked_state_instance(transaction)?;
        let origin = Self::dispatch_acquisition_row(transaction, origin_acquisition_id)?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if origin.acquisition_id != origin_acquisition_id
            || origin.lease_fence != origin_lease_fence
            || origin.token.key() != key
            || origin.token.state_instance_id() != state_instance_id
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        if let Some(submission_id) = origin.control_submission_id {
            if !matches!(
                origin.selection_kind.as_str(),
                "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
            ) {
                return Err(StateError::BrokerOperationMismatch);
            }
            let submission = control_plane::load_submission_for_update(transaction, submission_id)?;
            if submission.submission_id != submission_id
                || submission.scope() != key.scope
                || submission.state_instance_id != state_instance_id
                || Self::control_submission_for_dispatch(transaction, key)? != Some(submission_id)
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            control_plane::validate_dispatch_pending_lineage(transaction, &submission, key)?;
            let (replay_scope, ingress_high_water, scope_high_water, dispatch) =
                Self::lock_v14_dispatch_inputs(transaction, &submission, key)?;
            Ok(LockedBrokerTimeInputs {
                dispatch,
                control: Some(LockedControlBrokerTime {
                    submission,
                    replay_scope,
                    ingress_high_water,
                    scope_high_water,
                }),
            })
        } else {
            if origin.selection_kind != "LEGACY_BOOTSTRAP"
                || Self::control_submission_for_dispatch(transaction, key)?.is_some()
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            Ok(LockedBrokerTimeInputs {
                dispatch: Self::lock_dispatch_inputs(transaction, key)?,
                control: None,
            })
        }
    }

    fn validate_and_advance_broker_time(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        locked: &LockedBrokerTimeInputs,
        observed_at: i64,
    ) -> Result<(), StateError> {
        let high_water = Self::broker_time_high_water(locked);
        validate_cleanup_clock(&key.scope, Some(high_water), observed_at)?;
        if let Some(control) = &locked.control {
            control_plane::advance_control_high_water(
                transaction,
                &control.submission,
                &control.replay_scope,
                control.ingress_high_water,
                observed_at,
            )
        } else {
            Self::update_dispatch_high_water(transaction, &key.scope, observed_at)
        }
    }

    fn broker_time_high_water(locked: &LockedBrokerTimeInputs) -> i64 {
        locked
            .control
            .as_ref()
            .map_or(locked.dispatch.high_water, |control| {
                control
                    .ingress_high_water
                    .max(control.scope_high_water)
                    .max(locked.dispatch.high_water)
            })
    }

    fn sample_trusted_time(transaction: &mut Transaction<'_>) -> Result<i64, StateError> {
        // Trusted time is deliberately sampled only after every security row
        // and exact claim identity, where applicable, are locked.
        Ok(transaction
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint AS now_unix_s",
                &[],
            )?
            .get("now_unix_s"))
    }

    fn lock_or_create_high_water(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
    ) -> Result<i64, StateError> {
        transaction.execute(
            "INSERT INTO accordlock_time_high_water
                        (tenant, environment, observed_unix_s)
                 VALUES ($1, $2, 0)
                 ON CONFLICT (tenant, environment) DO NOTHING",
            &[&scope.tenant, &scope.environment],
        )?;
        Ok(transaction
            .query_one(
                "SELECT observed_unix_s
                   FROM accordlock_time_high_water
                  WHERE tenant = $1 AND environment = $2
                  FOR UPDATE",
                &[&scope.tenant, &scope.environment],
            )
            .map_err(StateError::from)?
            .get("observed_unix_s"))
    }

    fn validate_locked_dispatch(
        key: &ConsumeKey,
        inputs: &LockedDispatchInputs,
        observed_time: i64,
    ) -> Result<DispatchSnapshot, StateError> {
        validate_dispatch_snapshot(
            key,
            &inputs.authority,
            &inputs.grant,
            &inputs.issued,
            &inputs.receipt,
            &inputs.outbox,
            observed_time,
            Some(inputs.high_water),
        )
    }

    fn update_dispatch_high_water(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
        observed_time: i64,
    ) -> Result<(), StateError> {
        let updated = transaction.execute(
            "UPDATE accordlock_time_high_water
                SET observed_unix_s = $3, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2",
            &[&scope.tenant, &scope.environment, &observed_time],
        )?;
        if updated != 1 {
            return Err(StateError::InvalidRecord(
                "dispatch snapshot has no exact trusted-time high-water row".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_locked_dispatch_with_high_water(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        inputs: &LockedDispatchInputs,
    ) -> Result<LockedDispatchValidation, StateError> {
        let observed_time = Self::sample_trusted_time(transaction)?;
        let validation = Self::validate_locked_dispatch(key, inputs, observed_time);
        match validation {
            Ok(snapshot) => {
                Self::update_dispatch_high_water(transaction, &key.scope, observed_time)?;
                Ok(LockedDispatchValidation::Accepted(Box::new(snapshot)))
            }
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                Self::update_dispatch_high_water(transaction, &key.scope, observed_time)?;
                Ok(LockedDispatchValidation::TemporalRejection(error))
            }
            Err(error) => Err(error),
        }
    }

    fn dispatch_snapshot_once(&self, key: &ConsumeKey) -> Result<DispatchSnapshot, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, key)?;
        let snapshot =
            match Self::validate_locked_dispatch_with_high_water(&mut transaction, key, &inputs)? {
                LockedDispatchValidation::Accepted(snapshot) => *snapshot,
                LockedDispatchValidation::TemporalRejection(error) => {
                    transaction.commit()?;
                    return Err(error);
                }
            };
        transaction.commit()?;
        Ok(snapshot)
    }

    fn locked_state_instance(transaction: &mut Transaction<'_>) -> Result<Uuid, StateError> {
        let rows = transaction
            .query(
                "SELECT state_instance_id
               FROM accordlock_state_metadata
              WHERE singleton = TRUE
              FOR SHARE",
                &[],
            )
            .map_err(StateError::from)?;
        if rows.len() != 1 {
            return Err(StateError::SchemaMismatch(format!(
                "expected one state metadata row, found {}",
                rows.len()
            )));
        }
        let state_instance_id: Uuid = rows[0].get("state_instance_id");
        if state_instance_id.is_nil() {
            return Err(StateError::SchemaMismatch(
                "state instance identifier is nil".to_owned(),
            ));
        }
        Ok(state_instance_id)
    }

    fn dispatch_claim_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<Option<Row>, StateError> {
        Ok(transaction.query_opt(
            "SELECT transaction_id, claim_id, worker_id, fence,
                    cluster_identity, namespace, deployment_uid,
                    state_instance_id, claimed_unix_s, lease_until,
                    state, attempt_started_at, credential_token_digest,
                    service_account_uid, credential_id,
                    credential_not_before, credential_expires_at,
                    credential_binding_commitment, terminalization_id,
                    attempt_acquisition_id, attempt_lease_fence,
                    attempt_acquired_unix_s, attempt_lease_until,
                    acquisition_binding_version, credential_review_id,
                    recovery_safe_after_unix_s, recovery_retired_unix_s
               FROM accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
              FOR UPDATE",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )?)
    }

    fn dispatch_claim_row_unlocked(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<Option<Row>, StateError> {
        Ok(transaction.query_opt(
            "SELECT transaction_id, claim_id, worker_id, fence,
                    cluster_identity, namespace, deployment_uid,
                    state_instance_id, claimed_unix_s, lease_until,
                    state, attempt_started_at, credential_token_digest,
                    service_account_uid, credential_id,
                    credential_not_before, credential_expires_at,
                    credential_binding_commitment, terminalization_id,
                    attempt_acquisition_id, attempt_lease_fence,
                    attempt_acquired_unix_s, attempt_lease_until,
                    acquisition_binding_version, credential_review_id,
                    recovery_safe_after_unix_s, recovery_retired_unix_s
               FROM accordlock_dispatch_claims
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )?)
    }

    fn classify_existing_claim(request: &DispatchClaimRequest, row: &Row) -> StateError {
        if row.get::<_, Uuid>("transaction_id") == request.key.transaction_id
            && row.get::<_, Uuid>("claim_id") == request.claim_id
            && row.get::<_, String>("worker_id") == request.worker_id
        {
            StateError::DispatchClaimOutcomeUnknown
        } else {
            StateError::DispatchAlreadyClaimed
        }
    }

    fn token_from_claim_row(
        key: &ConsumeKey,
        row: &Row,
    ) -> Result<(DispatchClaimToken, String), StateError> {
        if row.get::<_, Uuid>("transaction_id") != key.transaction_id {
            return Err(StateError::TransactionMismatch);
        }
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| {
            StateError::InvalidRecord("stored dispatch fence is not a positive u64".to_owned())
        })?;
        if fence == 0 {
            return Err(StateError::InvalidRecord(
                "stored dispatch fence is zero".to_owned(),
            ));
        }
        let token = DispatchClaimToken::new(
            key.clone(),
            PhysicalResourceKey::new(
                row.get("cluster_identity"),
                row.get("namespace"),
                row.get("deployment_uid"),
            )?,
            row.get("claim_id"),
            row.get("worker_id"),
            fence,
            row.get("claimed_unix_s"),
            row.get("lease_until"),
            row.get("state_instance_id"),
        );
        Ok((token, row.get("state")))
    }

    fn require_exact_claim(
        transaction: &mut Transaction<'_>,
        token: &DispatchClaimToken,
        state_instance_id: Uuid,
    ) -> Result<String, StateError> {
        if token.state_instance_id() != state_instance_id {
            return Err(StateError::DispatchClaimMismatch);
        }
        let row = Self::dispatch_claim_row(transaction, token.key())?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (stored, state) = Self::token_from_claim_row(token.key(), &row)?;
        if stored != *token {
            return Err(StateError::DispatchClaimMismatch);
        }
        Ok(state)
    }

    fn stored_dispatch_acquisition(row: &Row) -> Result<StoredDispatchAcquisition, StateError> {
        let key = ConsumeKey {
            scope: Scope {
                tenant: row.get("tenant"),
                environment: row.get("environment"),
            },
            transaction_id: row.get("transaction_id"),
            authorization_id: row.get("authorization_id"),
        };
        key.validate()?;
        let acquisition_id: Uuid = row.get("acquisition_id");
        let worker_id: String = row.get("acquisition_worker_id");
        DispatchAcquisitionRequest::new(worker_id.clone(), acquisition_id)?;
        let claim_fence_i64: i64 = row.get("claim_fence");
        let lease_fence_i64: i64 = row.get("lease_fence");
        let claim_fence = u64::try_from(claim_fence_i64).map_err(|_| {
            StateError::InvalidRecord("stored claim fence is not a positive u64".to_owned())
        })?;
        let lease_fence = u64::try_from(lease_fence_i64).map_err(|_| {
            StateError::InvalidRecord("stored acquisition fence is not a positive u64".to_owned())
        })?;
        if claim_fence == 0 || lease_fence == 0 {
            return Err(StateError::InvalidRecord(
                "stored dispatch acquisition has a zero fence".to_owned(),
            ));
        }
        let state_instance_id: Uuid = row.get("state_instance_id");
        let control_submission_id: Option<Uuid> = row.get("control_submission_id");
        let selection_kind: String = row.get("selection_kind");
        let acquired_at: i64 = row.get("acquired_unix_s");
        let lease_until: i64 = row.get("acquisition_lease_until");
        let dispatch_deadline: i64 = row.get("dispatch_deadline");
        if state_instance_id.is_nil()
            || matches!(
                selection_kind.as_str(),
                "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
            ) != control_submission_id.is_some()
            || !matches!(
                selection_kind.as_str(),
                "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13" | "LEGACY_BOOTSTRAP"
            )
            || acquired_at < 0
            || lease_until <= acquired_at
            || lease_until > dispatch_deadline
            || lease_until.checked_sub(acquired_at).is_none_or(|duration| {
                duration <= 0
                    || selection_kind == "CONTROL_QUEUE"
                        && duration > DISPATCH_ACQUISITION_LEASE_SECONDS
            })
        {
            return Err(StateError::InvalidRecord(
                "stored dispatch acquisition is malformed".to_owned(),
            ));
        }
        let token = DispatchClaimToken::new(
            key,
            PhysicalResourceKey::new(
                row.get("cluster_identity"),
                row.get("namespace"),
                row.get("deployment_uid"),
            )?,
            row.get("claim_id"),
            row.get("claim_worker_id"),
            claim_fence,
            row.get("claimed_unix_s"),
            row.get("claim_lease_until"),
            state_instance_id,
        );
        Ok(StoredDispatchAcquisition {
            token,
            acquisition_id,
            lease_fence,
            worker_id,
            acquired_at,
            lease_until,
            dispatch_deadline,
            control_submission_id,
            selection_kind,
            claim_state: row.get("claim_state"),
            attempt_started_at: row.get("attempt_started_at"),
            has_credential: row.get("has_credential"),
            terminalization_id: row.get("terminalization_id"),
        })
    }

    fn dispatch_acquisition_row<C: GenericClient>(
        client: &mut C,
        acquisition_id: Uuid,
    ) -> Result<Option<StoredDispatchAcquisition>, StateError> {
        client
            .query_opt(
                "SELECT acquisition.acquisition_id, acquisition.tenant,
                        acquisition.environment, acquisition.authorization_id,
                        acquisition.transaction_id, acquisition.claim_id,
                        acquisition.claim_fence, acquisition.state_instance_id,
                        acquisition.control_submission_id,
                        acquisition.selection_kind,
                        acquisition.worker_id AS acquisition_worker_id,
                        acquisition.lease_fence,
                        acquisition.acquired_unix_s,
                        acquisition.lease_until AS acquisition_lease_until,
                        acquisition.dispatch_deadline,
                        claim.worker_id AS claim_worker_id,
                        claim.claimed_unix_s,
                        claim.lease_until AS claim_lease_until,
                        claim.cluster_identity, claim.namespace,
                        claim.deployment_uid, claim.state AS claim_state,
                        claim.attempt_started_at,
                        (claim.credential_token_digest IS NOT NULL
                         OR claim.service_account_uid IS NOT NULL
                         OR claim.credential_id IS NOT NULL
                         OR claim.credential_binding_commitment IS NOT NULL)
                            AS has_credential,
                        claim.terminalization_id
                   FROM public.accordlock_dispatch_acquisitions AS acquisition
                   JOIN public.accordlock_dispatch_claims AS claim
                     ON claim.tenant = acquisition.tenant
                    AND claim.environment = acquisition.environment
                    AND claim.authorization_id = acquisition.authorization_id
                    AND claim.transaction_id = acquisition.transaction_id
                    AND claim.claim_id = acquisition.claim_id
                    AND claim.fence = acquisition.claim_fence
                    AND claim.state_instance_id = acquisition.state_instance_id
                  WHERE acquisition.acquisition_id = $1",
                &[&acquisition_id],
            )?
            .map(|row| Self::stored_dispatch_acquisition(&row))
            .transpose()
    }

    fn latest_dispatch_acquisition(
        transaction: &mut Transaction<'_>,
        token: &DispatchClaimToken,
    ) -> Result<StoredDispatchAcquisition, StateError> {
        transaction
            .query_opt(
                "SELECT acquisition.acquisition_id, acquisition.tenant,
                        acquisition.environment, acquisition.authorization_id,
                        acquisition.transaction_id, acquisition.claim_id,
                        acquisition.claim_fence, acquisition.state_instance_id,
                        acquisition.control_submission_id,
                        acquisition.selection_kind,
                        acquisition.worker_id AS acquisition_worker_id,
                        acquisition.lease_fence,
                        acquisition.acquired_unix_s,
                        acquisition.lease_until AS acquisition_lease_until,
                        acquisition.dispatch_deadline,
                        claim.worker_id AS claim_worker_id,
                        claim.claimed_unix_s,
                        claim.lease_until AS claim_lease_until,
                        claim.cluster_identity, claim.namespace,
                        claim.deployment_uid, claim.state AS claim_state,
                        claim.attempt_started_at,
                        (claim.credential_token_digest IS NOT NULL
                         OR claim.service_account_uid IS NOT NULL
                         OR claim.credential_id IS NOT NULL
                         OR claim.credential_binding_commitment IS NOT NULL)
                            AS has_credential,
                        claim.terminalization_id
                   FROM public.accordlock_dispatch_acquisitions AS acquisition
                   JOIN public.accordlock_dispatch_claims AS claim
                     ON claim.tenant = acquisition.tenant
                    AND claim.environment = acquisition.environment
                    AND claim.authorization_id = acquisition.authorization_id
                    AND claim.transaction_id = acquisition.transaction_id
                    AND claim.claim_id = acquisition.claim_id
                    AND claim.fence = acquisition.claim_fence
                    AND claim.state_instance_id = acquisition.state_instance_id
                  WHERE acquisition.tenant = $1
                    AND acquisition.environment = $2
                    AND acquisition.authorization_id = $3
                    AND acquisition.transaction_id = $4
                    AND acquisition.claim_id = $5
                    AND acquisition.claim_fence = $6
                    AND acquisition.state_instance_id = $7
                  ORDER BY acquisition.lease_fence DESC
                  LIMIT 1
                  FOR SHARE OF acquisition",
                &[
                    &token.key().scope.tenant,
                    &token.key().scope.environment,
                    &token.key().authorization_id,
                    &token.key().transaction_id,
                    &token.claim_id(),
                    &i64::try_from(token.fence()).map_err(|_| {
                        StateError::InvalidRecord(
                            "dispatch claim fence does not fit PostgreSQL BIGINT".to_owned(),
                        )
                    })?,
                    &token.state_instance_id(),
                ],
            )?
            .map(|row| Self::stored_dispatch_acquisition(&row))
            .transpose()?
            .ok_or(StateError::DispatchAcquisitionMismatch)
    }

    /// Reject every control-owned stable token before a legacy productive
    /// endpoint takes authority or high-water locks. The control-consumption
    /// link and acquisition history are immutable; authorization is still
    /// repeated under the normal locks before any mutation.
    fn require_legacy_bootstrap_preflight<C: GenericClient>(
        client: &mut C,
        token: &DispatchClaimToken,
    ) -> Result<(), StateError> {
        if Self::control_submission_for_dispatch(client, token.key())?.is_some() {
            return Err(StateError::DispatchAcquisitionRequired);
        }
        let fence = i64::try_from(token.fence()).map_err(|_| {
            StateError::InvalidRecord(
                "dispatch claim fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let row = client
            .query_opt(
                "SELECT acquisition_id, selection_kind, control_submission_id
                   FROM public.accordlock_dispatch_acquisitions
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4 AND claim_id=$5
                    AND claim_fence=$6 AND state_instance_id=$7
                  ORDER BY lease_fence DESC
                  LIMIT 1",
                &[
                    &token.key().scope.tenant,
                    &token.key().scope.environment,
                    &token.key().authorization_id,
                    &token.key().transaction_id,
                    &token.claim_id(),
                    &fence,
                    &token.state_instance_id(),
                ],
            )?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if row.get::<_, Uuid>("acquisition_id") != token.claim_id()
            || row.get::<_, String>("selection_kind") != "LEGACY_BOOTSTRAP"
            || row
                .get::<_, Option<Uuid>>("control_submission_id")
                .is_some()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Ok(())
    }

    fn dispatch_acquisition_receipt(
        acquisition: &StoredDispatchAcquisition,
        disposition: DispatchAcquisitionDisposition,
    ) -> DispatchAcquisitionReceipt {
        DispatchAcquisitionReceipt::new(
            acquisition.acquisition_id,
            acquisition.lease_fence,
            acquisition.worker_id.clone(),
            acquisition.token.claim_id(),
            acquisition.token.fence(),
            acquisition.acquired_at,
            acquisition.lease_until,
            disposition,
        )
    }

    fn dispatch_acquisition_authority(
        acquisition: &StoredDispatchAcquisition,
    ) -> DispatchAcquisitionAuthority {
        DispatchAcquisitionAuthority::new(
            acquisition.token.clone(),
            acquisition.acquisition_id,
            acquisition.lease_fence,
            acquisition.worker_id.clone(),
            acquisition.acquired_at,
            acquisition.lease_until,
            acquisition.dispatch_deadline,
            acquisition.control_submission_id,
        )
    }

    fn dispatch_recovery_acquisition(
        acquisition: &StoredDispatchAcquisition,
    ) -> Result<DispatchRecoveryAcquisition, StateError> {
        Ok(DispatchRecoveryAcquisition::new(
            acquisition.acquisition_id,
            acquisition.lease_fence,
            acquisition.worker_id.clone(),
            acquisition.acquired_at,
            acquisition.lease_until,
            acquisition.dispatch_deadline,
            acquisition
                .control_submission_id
                .ok_or(StateError::DispatchAcquisitionMismatch)?,
        ))
    }

    fn dispatch_acquisition_artifact_disposition(
        transaction: &mut Transaction<'_>,
        acquisition: &StoredDispatchAcquisition,
    ) -> Result<Option<DispatchAcquisitionDisposition>, StateError> {
        if acquisition.claim_state == "TERMINAL" || acquisition.terminalization_id.is_some() {
            return Ok(Some(DispatchAcquisitionDisposition::Terminal));
        }
        if acquisition.claim_state == "RECOVERY_RETIRED" {
            return Ok(Some(DispatchAcquisitionDisposition::RecoveryRetired));
        }
        if acquisition.claim_state == "RECOVERY_NO_SEND" {
            return Ok(Some(DispatchAcquisitionDisposition::RecoveryNoSend));
        }
        if acquisition.claim_state == "ATTEMPT_IN_FLIGHT"
            || acquisition.attempt_started_at.is_some()
            || acquisition.has_credential
        {
            return Ok(Some(DispatchAcquisitionDisposition::AttemptInFlight));
        }
        if acquisition.claim_state != "CLAIMED" {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let fence = i64::try_from(acquisition.token.fence()).map_err(|_| {
            StateError::InvalidRecord("claim fence does not fit PostgreSQL BIGINT".to_owned())
        })?;
        let key = acquisition.token.key();
        let row = transaction.query_one(
            "SELECT EXISTS (
                        SELECT 1 FROM public.accordlock_broker_operations
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                    ) AS has_broker,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_admission_authorizations
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                    ) AS has_admission,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_dispatch_credential_reviews
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4 AND acquisition_id=$8
                    ) AS has_review,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_terminal_retirements
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                           AND state_instance_id=$7
                    ) AS has_terminal",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
                &acquisition.token.claim_id(),
                &fence,
                &acquisition.token.state_instance_id(),
                &acquisition.acquisition_id,
            ],
        )?;
        if row.get("has_terminal") {
            Ok(Some(DispatchAcquisitionDisposition::Terminal))
        } else if row.get("has_broker") || row.get("has_review") {
            Ok(Some(DispatchAcquisitionDisposition::BrokerArtifactPresent))
        } else if row.get("has_admission") {
            Ok(Some(
                DispatchAcquisitionDisposition::AdmissionArtifactPresent,
            ))
        } else {
            Ok(None)
        }
    }

    fn control_submission_for_dispatch<C: GenericClient>(
        client: &mut C,
        key: &ConsumeKey,
    ) -> Result<Option<Uuid>, StateError> {
        let rows = client.query(
            "SELECT submission_id
               FROM public.accordlock_control_consumptions
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4",
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )?;
        if rows.len() > 1 {
            return Err(StateError::ControlWorkMismatch);
        }
        Ok(rows.first().map(|row| row.get("submission_id")))
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_locked_dispatch_with_dual_high_water(
        transaction: &mut Transaction<'_>,
        stored: &crate::control::StoredControlSubmission,
        replay_scope: &IngressReplayScope,
        ingress_high_water: i64,
        scope_high_water: i64,
        key: &ConsumeKey,
        inputs: &LockedDispatchInputs,
        observed_at: i64,
    ) -> Result<LockedDispatchValidation, StateError> {
        if stored.state_instance_id.is_nil()
            || stored.submission_id.is_nil()
            || stored.scope() != key.scope
            || inputs.receipt.consumed_at < stored.accepted_at
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let high_water = ingress_high_water
            .max(scope_high_water)
            .max(inputs.high_water)
            .max(stored.accepted_at)
            .max(inputs.receipt.consumed_at);
        let validation = validate_dispatch_snapshot(
            key,
            &inputs.authority,
            &inputs.grant,
            &inputs.issued,
            &inputs.receipt,
            &inputs.outbox,
            observed_at,
            Some(high_water),
        );
        match validation {
            Ok(snapshot) => {
                control_plane::advance_control_high_water(
                    transaction,
                    stored,
                    replay_scope,
                    ingress_high_water,
                    observed_at,
                )?;
                Ok(LockedDispatchValidation::Accepted(Box::new(snapshot)))
            }
            Err(error) if is_temporal_rejection_for_sample(&error, observed_at) => {
                control_plane::advance_control_high_water(
                    transaction,
                    stored,
                    replay_scope,
                    ingress_high_water,
                    observed_at,
                )?;
                Ok(LockedDispatchValidation::TemporalRejection(error))
            }
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_dispatch_request_identity(
        transaction: &mut Transaction<'_>,
        dispatch_request_id: Uuid,
        worker_id: &str,
    ) -> Result<Option<String>, StateError> {
        transaction.execute(
            "INSERT INTO public.accordlock_dispatch_request_identities
                        (dispatch_request_id, worker_id)
                 VALUES ($1,$2)
             ON CONFLICT (dispatch_request_id) DO NOTHING",
            &[&dispatch_request_id, &worker_id],
        )?;
        let row = transaction
            .query_opt(
                "SELECT request_kind, worker_id
                   FROM public.accordlock_dispatch_request_identities
                  WHERE dispatch_request_id=$1
                  FOR UPDATE",
                &[&dispatch_request_id],
            )?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if row.get::<_, String>("worker_id") != worker_id {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Ok(row.get("request_kind"))
    }

    fn bind_dispatch_request_identity(
        transaction: &mut Transaction<'_>,
        dispatch_request_id: Uuid,
        worker_id: &str,
        request_kind: &str,
    ) -> Result<(), StateError> {
        transaction.execute(
            "UPDATE public.accordlock_dispatch_request_identities
                SET request_kind=$3,bound_at=clock_timestamp()
              WHERE dispatch_request_id=$1 AND worker_id=$2
                AND request_kind IS NULL",
            &[&dispatch_request_id, &worker_id, &request_kind],
        )?;
        let row = transaction
            .query_opt(
                "SELECT request_kind, worker_id
                   FROM public.accordlock_dispatch_request_identities
                  WHERE dispatch_request_id=$1
                  FOR UPDATE",
                &[&dispatch_request_id],
            )?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if row.get::<_, Option<String>>("request_kind").as_deref() != Some(request_kind)
            || row.get::<_, String>("worker_id") != worker_id
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Ok(())
    }

    fn stored_dispatch_queue_disposition(
        row: &Row,
    ) -> Result<DispatchQueueDispositionReceipt, StateError> {
        fn digest(row: &Row, column: &str) -> Result<Digest32, StateError> {
            row.get::<_, String>(column)
                .parse::<Digest32>()
                .map_err(|_| {
                    StateError::InvalidRecord(format!(
                        "stored dispatch disposition {column} is not canonical"
                    ))
                })
        }
        fn positive_optional(value: Option<i64>) -> Result<Option<u64>, StateError> {
            value
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        StateError::InvalidRecord(
                            "stored dispatch disposition fence is invalid".to_owned(),
                        )
                    })
                })
                .transpose()
        }

        let reason = match row.get::<_, String>("reason").as_str() {
            "AUTHORITY_CHANGED" => DispatchQueueDispositionReason::AuthorityChanged,
            "GRANT_REVOKED" => DispatchQueueDispositionReason::GrantRevoked,
            "DISPATCH_DEADLINE_EXPIRED" => DispatchQueueDispositionReason::DispatchDeadlineExpired,
            _ => {
                return Err(StateError::InvalidRecord(
                    "stored dispatch disposition reason is unsupported".to_owned(),
                ));
            }
        };
        let receipt = DispatchQueueDispositionReceipt::new(
            row.get("dispatch_request_id"),
            row.get("worker_id"),
            row.get("control_submission_id"),
            ConsumeKey {
                scope: Scope {
                    tenant: row.get("tenant"),
                    environment: row.get("environment"),
                },
                authorization_id: row.get("authorization_id"),
                transaction_id: row.get("transaction_id"),
            },
            row.get("state_instance_id"),
            row.get("claim_id"),
            positive_optional(row.get("claim_fence"))?,
            row.get("acquisition_id"),
            positive_optional(row.get("lease_fence"))?,
            reason,
            row.get("observed_unix_s"),
            row.get("dispatch_deadline"),
            digest(row, "authorization_commitment")?,
            digest(row, "grant_commitment")?,
            digest(row, "outbox_commitment")?,
            digest(row, "expected_authority_commitment")?,
            digest(row, "current_authority_commitment")?,
        )?;
        if receipt.disposition_commitment() != digest(row, "disposition_commitment")? {
            return Err(StateError::InvalidRecord(
                "stored dispatch disposition commitment differs".to_owned(),
            ));
        }
        Ok(receipt)
    }

    fn dispatch_queue_disposition<C: GenericClient>(
        client: &mut C,
        dispatch_request_id: Option<Uuid>,
        control_submission_id: Option<Uuid>,
    ) -> Result<Option<DispatchQueueDispositionReceipt>, StateError> {
        client
            .query_opt(
                "SELECT dispatch_request_id, worker_id, control_submission_id,
                        tenant, environment, authorization_id, transaction_id,
                        state_instance_id, claim_id, claim_fence,
                        acquisition_id, lease_fence, reason, observed_unix_s,
                        dispatch_deadline, authorization_commitment, grant_commitment,
                        outbox_commitment, expected_authority_commitment,
                        current_authority_commitment, disposition_commitment
                   FROM public.accordlock_dispatch_queue_dispositions
                  WHERE ($1::uuid IS NOT NULL AND dispatch_request_id=$1)
                     OR ($2::uuid IS NOT NULL AND control_submission_id=$2)",
                &[&dispatch_request_id, &control_submission_id],
            )?
            .map(|row| Self::stored_dispatch_queue_disposition(&row))
            .transpose()
    }

    fn insert_dispatch_queue_disposition(
        transaction: &mut Transaction<'_>,
        receipt: &DispatchQueueDispositionReceipt,
    ) -> Result<(), StateError> {
        receipt.validate()?;
        Self::bind_dispatch_request_identity(
            transaction,
            receipt.dispatch_request_id(),
            receipt.worker_id(),
            "DISPOSITION",
        )?;
        let claim_fence = receipt
            .claim_fence()
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StateError::DispatchAcquisitionMismatch)?;
        let lease_fence = receipt
            .lease_fence()
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StateError::DispatchAcquisitionMismatch)?;
        let reason = match receipt.reason() {
            DispatchQueueDispositionReason::AuthorityChanged => "AUTHORITY_CHANGED",
            DispatchQueueDispositionReason::GrantRevoked => "GRANT_REVOKED",
            DispatchQueueDispositionReason::DispatchDeadlineExpired => "DISPATCH_DEADLINE_EXPIRED",
        };
        transaction.execute(
            "INSERT INTO public.accordlock_dispatch_queue_dispositions
                        (dispatch_request_id, worker_id, control_submission_id,
                         tenant, environment, authorization_id, transaction_id,
                         state_instance_id, claim_id, claim_fence,
                         acquisition_id, lease_fence, reason, observed_unix_s,
                         dispatch_deadline, authorization_commitment, grant_commitment,
                         outbox_commitment, expected_authority_commitment,
                         current_authority_commitment, disposition_commitment)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                         $15,$16,$17,$18,$19,$20,$21)",
            &[
                &receipt.dispatch_request_id(),
                &receipt.worker_id(),
                &receipt.control_submission_id(),
                &receipt.key().scope.tenant,
                &receipt.key().scope.environment,
                &receipt.key().authorization_id,
                &receipt.key().transaction_id,
                &receipt.state_instance_id(),
                &receipt.claim_id(),
                &claim_fence,
                &receipt.acquisition_id(),
                &lease_fence,
                &reason,
                &receipt.observed_at(),
                &receipt.dispatch_deadline(),
                &receipt.authorization_commitment().to_string(),
                &receipt.grant_commitment().to_string(),
                &receipt.outbox_commitment().to_string(),
                &receipt.expected_authority_commitment().to_string(),
                &receipt.current_authority_commitment().to_string(),
                &receipt.disposition_commitment().to_string(),
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_dispatch_acquisition(
        transaction: &mut Transaction<'_>,
        token: DispatchClaimToken,
        acquisition_id: Uuid,
        control_submission_id: Option<Uuid>,
        selection_kind: &str,
        worker_id: String,
        acquired_at: i64,
        lease_until: i64,
        dispatch_deadline: i64,
    ) -> Result<StoredDispatchAcquisition, StateError> {
        if (selection_kind == "CONTROL_QUEUE") == (acquisition_id == token.claim_id()) {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        Self::bind_dispatch_request_identity(
            transaction,
            acquisition_id,
            &worker_id,
            "ACQUISITION",
        )?;
        let claim_fence = i64::try_from(token.fence()).map_err(|_| {
            StateError::InvalidRecord(
                "dispatch claim fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let row = transaction
            .query_one(
                "INSERT INTO public.accordlock_dispatch_acquisitions
                            (acquisition_id, tenant, environment, authorization_id,
                             transaction_id, claim_id, claim_fence,
                             state_instance_id, control_submission_id,
                             selection_kind, worker_id, acquired_unix_s,
                             lease_until, dispatch_deadline)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                  RETURNING lease_fence",
                &[
                    &acquisition_id,
                    &token.key().scope.tenant,
                    &token.key().scope.environment,
                    &token.key().authorization_id,
                    &token.key().transaction_id,
                    &token.claim_id(),
                    &claim_fence,
                    &token.state_instance_id(),
                    &control_submission_id,
                    &selection_kind,
                    &worker_id,
                    &acquired_at,
                    &lease_until,
                    &dispatch_deadline,
                ],
            )
            .map_err(|error| {
                if error.code().is_some_and(|code| code.code() == "2200H") {
                    StateError::DispatchAcquisitionFenceExhausted
                } else {
                    StateError::Database(error)
                }
            })?;
        let lease_fence_i64: i64 = row.get("lease_fence");
        let lease_fence = u64::try_from(lease_fence_i64)
            .map_err(|_| StateError::DispatchAcquisitionFenceExhausted)?;
        if lease_fence == 0 {
            return Err(StateError::DispatchAcquisitionFenceExhausted);
        }
        Ok(StoredDispatchAcquisition {
            token,
            acquisition_id,
            lease_fence,
            worker_id,
            acquired_at,
            lease_until,
            dispatch_deadline,
            control_submission_id,
            selection_kind: selection_kind.to_owned(),
            claim_state: "CLAIMED".to_owned(),
            attempt_started_at: None,
            has_credential: false,
            terminalization_id: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn lock_post_attempt_lineage(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        allow_terminal: bool,
    ) -> Result<PostgresPostAttemptLineage, StateError> {
        let state_instance_id = Self::locked_state_instance(transaction)?;
        let preflight = Self::dispatch_claim_row_unlocked(transaction, key)?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (preflight_token, preflight_state) = Self::token_from_claim_row(key, &preflight)?;
        if preflight_token.state_instance_id() != state_instance_id
            || (preflight_state != "ATTEMPT_IN_FLIGHT"
                && !(allow_terminal && preflight_state == "TERMINAL"))
        {
            return Err(StateError::AdmissionClaimNotInFlight);
        }
        let acquisition_id = preflight
            .get::<_, Option<Uuid>>("attempt_acquisition_id")
            .ok_or_else(|| {
                StateError::InvalidRecord(
                    "post-attempt claim has no acquisition identifier".to_owned(),
                )
            })?;
        let lease_fence_i64 = preflight
            .get::<_, Option<i64>>("attempt_lease_fence")
            .ok_or_else(|| {
                StateError::InvalidRecord("post-attempt claim has no acquisition fence".to_owned())
            })?;
        let lease_fence = u64::try_from(lease_fence_i64).map_err(|_| {
            StateError::InvalidRecord("post-attempt acquisition fence is invalid".to_owned())
        })?;
        if acquisition_id.is_nil() || lease_fence == 0 {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let time_inputs =
            Self::lock_broker_time_inputs(transaction, key, acquisition_id, lease_fence)?;
        let acquisition = Self::dispatch_acquisition_row(transaction, acquisition_id)?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let row =
            Self::dispatch_claim_row(transaction, key)?.ok_or(StateError::DispatchClaimNotFound)?;
        let (token, state) = Self::token_from_claim_row(key, &row)?;
        if token != preflight_token
            || state != preflight_state
            || (state != "ATTEMPT_IN_FLIGHT" && !(allow_terminal && state == "TERMINAL"))
        {
            return Err(StateError::AdmissionClaimNotInFlight);
        }
        let started_at = row
            .get::<_, Option<i64>>("attempt_started_at")
            .ok_or_else(|| {
                StateError::InvalidRecord("post-attempt claim has no durable start time".to_owned())
            })?;
        let stored_acquisition_id = row
            .get::<_, Option<Uuid>>("attempt_acquisition_id")
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let stored_lease_fence_i64 = row
            .get::<_, Option<i64>>("attempt_lease_fence")
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let stored_lease_fence = u64::try_from(stored_lease_fence_i64)
            .map_err(|_| StateError::DispatchAcquisitionMismatch)?;
        let stored_acquired_at = row
            .get::<_, Option<i64>>("attempt_acquired_unix_s")
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let stored_lease_until = row
            .get::<_, Option<i64>>("attempt_lease_until")
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let binding_version = row
            .get::<_, Option<i16>>("acquisition_binding_version")
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let credential_review_id = row.get::<_, Option<Uuid>>("credential_review_id");
        if acquisition.token != token
            || acquisition.acquisition_id != stored_acquisition_id
            || acquisition.lease_fence != stored_lease_fence
            || acquisition.acquired_at != stored_acquired_at
            || acquisition.lease_until != stored_lease_until
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let authority = Self::dispatch_acquisition_authority(&acquisition);
        let token_digest = Self::canonical_digest_from_row(&row, "credential_token_digest")?;
        let service_account_uid: String = row.get("service_account_uid");
        let credential_id: String = row.get("credential_id");
        let not_before: i64 = row.get("credential_not_before");
        let expires_at: i64 = row.get("credential_expires_at");
        let durable_commitment =
            Self::canonical_digest_from_row(&row, "credential_binding_commitment")?;

        let credential = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => {
                if binding_version != 2 || acquisition.control_submission_id.is_none() {
                    return Err(StateError::DispatchCredentialReviewMismatch);
                }
                let review_id = credential_review_id
                    .filter(|review_id| !review_id.is_nil())
                    .ok_or(StateError::DispatchCredentialReviewMismatch)?;
                let review_row = Self::dispatch_credential_review_row(transaction, key, false)?
                    .ok_or(StateError::DispatchCredentialReviewNotFound)?;
                let review = Self::stored_dispatch_credential_review(&review_row, &acquisition)?;
                if review.review_id != review_id
                    || review.phase != DispatchCredentialReviewPhase::Authenticated
                {
                    return Err(StateError::DispatchCredentialReviewMismatch);
                }
                Self::validate_postgres_credential_review_frozen_lineage(transaction, &review)?;
                let reviewed = review.reviewed_credential()?;
                if reviewed.binding.token_digest() != token_digest
                    || reviewed.binding.service_account_uid() != service_account_uid
                    || reviewed.binding.credential_id() != credential_id
                    || reviewed.binding.not_before() != not_before
                    || reviewed.binding.expires_at() != expires_at
                    || reviewed.binding.commitment() != durable_commitment
                {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                reviewed.binding
            }
            "CONTROL_BOOTSTRAP_V13" if binding_version == 1 => {
                if acquisition.control_submission_id.is_none()
                    || credential_review_id.is_some()
                    || acquisition.acquisition_id != token.claim_id()
                    || acquisition.lease_fence != token.fence()
                    || acquisition.worker_id != token.worker_id()
                    || acquisition.acquired_at != token.claimed_at()
                    || acquisition.lease_until != token.lease_until()
                {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                let credential = token.bind_authenticated_credential(
                    *token_digest.as_bytes(),
                    service_account_uid,
                    credential_id,
                    not_before,
                    expires_at,
                )?;
                if credential.commitment() != durable_commitment {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                Self::validate_postgres_optional_bootstrap_attempt_broker_lineage(
                    transaction,
                    &authority,
                    &credential,
                )?;
                credential
            }
            "LEGACY_BOOTSTRAP" if binding_version == 1 => {
                if acquisition.control_submission_id.is_some()
                    || credential_review_id.is_some()
                    || acquisition.acquisition_id != token.claim_id()
                    || acquisition.lease_fence != token.fence()
                    || acquisition.worker_id != token.worker_id()
                    || acquisition.acquired_at != token.claimed_at()
                    || acquisition.lease_until != token.lease_until()
                {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                let credential = token.bind_authenticated_credential(
                    *token_digest.as_bytes(),
                    service_account_uid,
                    credential_id,
                    not_before,
                    expires_at,
                )?;
                if credential.commitment() != durable_commitment {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                credential
            }
            "LEGACY_BOOTSTRAP" if binding_version == 2 => {
                // The acquisition lease fence is a distinct monotone domain;
                // the exact durable attempt tuple was already checked above.
                if credential_review_id.is_some()
                    || acquisition.control_submission_id.is_some()
                    || acquisition.acquisition_id != token.claim_id()
                    || acquisition.worker_id != token.worker_id()
                    || acquisition.acquired_at != token.claimed_at()
                    || acquisition.lease_until != token.lease_until()
                {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                let credential = DispatchCredentialBinding::new_for_acquisition(
                    &authority,
                    token_digest,
                    service_account_uid,
                    credential_id,
                    not_before,
                    expires_at,
                )?;
                if credential.commitment() != durable_commitment {
                    return Err(StateError::AdmissionCredentialMismatch);
                }
                credential
            }
            _ => return Err(StateError::AdmissionCredentialMismatch),
        };
        Ok(PostgresPostAttemptLineage {
            token,
            started_at,
            credential,
            time_inputs,
        })
    }

    fn validate_post_attempt_snapshot(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        lineage: &PostgresPostAttemptLineage,
    ) -> Result<LockedDispatchValidation, StateError> {
        if let Some(control) = &lineage.time_inputs.control {
            let observed_at = Self::sample_trusted_time(transaction)?;
            Self::validate_locked_dispatch_with_dual_high_water(
                transaction,
                &control.submission,
                &control.replay_scope,
                control.ingress_high_water,
                control.scope_high_water,
                key,
                &lineage.time_inputs.dispatch,
                observed_at,
            )
        } else {
            Self::validate_locked_dispatch_with_high_water(
                transaction,
                key,
                &lineage.time_inputs.dispatch,
            )
        }
    }

    fn admission_authorization_row(
        transaction: &mut Transaction<'_>,
        admission_uid: &str,
        lock: bool,
    ) -> Result<Option<Row>, StateError> {
        let base = "SELECT admission_uid, tenant, environment, transaction_id,
                           authorization_id, claim_id, fence, cluster_identity, namespace,
                           deployment_uid, credential_token_digest,
                           service_account_uid, credential_id,
                           credential_binding_commitment,
                           provider_request_commitment,
                           old_object_commitment, new_object_commitment,
                           executor_identity_commitment,
                           observer_identity_commitment, request_commitment,
                           grant_id, authorized_authority_json,
                           dispatch_deadline, authorized_unix_s, decision
                      FROM accordlock_admission_authorizations
                     WHERE admission_uid = $1";
        if lock {
            Ok(transaction.query_opt(&format!("{base} FOR UPDATE"), &[&admission_uid])?)
        } else {
            Ok(transaction.query_opt(base, &[&admission_uid])?)
        }
    }

    fn canonical_digest_from_row(row: &Row, column: &str) -> Result<Digest32, StateError> {
        let stored: String = row.get(column);
        let digest = Digest32::from_str(&stored).map_err(|error| {
            StateError::InvalidRecord(format!("stored {column} is invalid: {error}"))
        })?;
        if stored != digest.to_string() {
            return Err(StateError::InvalidRecord(format!(
                "stored {column} is not canonical"
            )));
        }
        Ok(digest)
    }

    fn stored_admission_from_row(row: &Row) -> Result<StoredAdmissionAuthorization, StateError> {
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| {
            StateError::InvalidRecord("stored admission fence is not a positive u64".to_owned())
        })?;
        let request = AdmissionAuthorizationRequest::new(
            ConsumeKey {
                scope: Scope::new(
                    row.get::<_, String>("tenant"),
                    row.get::<_, String>("environment"),
                )?,
                transaction_id: row.get("transaction_id"),
                authorization_id: row.get("authorization_id"),
            },
            row.get("claim_id"),
            fence,
            PhysicalResourceKey::new(
                row.get("cluster_identity"),
                row.get("namespace"),
                row.get("deployment_uid"),
            )?,
            Self::canonical_digest_from_row(row, "credential_token_digest")?,
            row.get("service_account_uid"),
            row.get("credential_id"),
            Self::canonical_digest_from_row(row, "credential_binding_commitment")?,
            row.get("admission_uid"),
            Self::canonical_digest_from_row(row, "provider_request_commitment")?,
            Self::canonical_digest_from_row(row, "old_object_commitment")?,
            Self::canonical_digest_from_row(row, "new_object_commitment")?,
            Self::canonical_digest_from_row(row, "executor_identity_commitment")?,
            Self::canonical_digest_from_row(row, "observer_identity_commitment")?,
        )?;
        if request.commitment()? != Self::canonical_digest_from_row(row, "request_commitment")? {
            return Err(StateError::InvalidRecord(
                "stored admission request commitment does not match its tuple".to_owned(),
            ));
        }
        let grant_id: Uuid = row.get("grant_id");
        let authority: AuthorityVector = decode_json(row.get("authorized_authority_json"))?;
        let dispatch_deadline: i64 = row.get("dispatch_deadline");
        let authorized_at: i64 = row.get("authorized_unix_s");
        if grant_id.is_nil()
            || row.get::<_, String>("decision") != "ADMITTED"
            || authorized_at < 0
            || authorized_at >= dispatch_deadline
        {
            return Err(StateError::InvalidRecord(
                "stored admission audit columns are invalid".to_owned(),
            ));
        }
        Ok(StoredAdmissionAuthorization {
            request,
            grant_id,
            authority,
            dispatch_deadline,
            authorized_at,
        })
    }

    fn classify_admission_collision(
        transaction: &mut Transaction<'_>,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<Option<StateError>, StateError> {
        let fence_i64 = i64::try_from(request.fence()).map_err(|_| {
            StateError::InvalidRecord("admission fence does not fit PostgreSQL BIGINT".to_owned())
        })?;
        let provider_request = request.provider_request_commitment().to_string();
        let rows = transaction
            .query(
                "SELECT tenant, environment, transaction_id, claim_id, fence,
                    provider_request_commitment
               FROM accordlock_admission_authorizations
              WHERE (tenant = $1 AND environment = $2 AND transaction_id = $3)
                 OR claim_id = $4 OR fence = $5
                 OR provider_request_commitment = $6",
                &[
                    &request.scope().tenant,
                    &request.scope().environment,
                    &request.transaction_id(),
                    &request.claim_id(),
                    &fence_i64,
                    &provider_request,
                ],
            )
            .map_err(StateError::from)?;
        if rows.iter().any(|row| {
            (row.get::<_, String>("tenant") == request.scope().tenant
                && row.get::<_, String>("environment") == request.scope().environment
                && row.get::<_, Uuid>("transaction_id") == request.transaction_id())
                || row.get::<_, Uuid>("claim_id") == request.claim_id()
                || row.get::<_, i64>("fence") == fence_i64
        }) {
            return Ok(Some(StateError::AdmissionAlreadyAuthorized));
        }
        if rows
            .iter()
            .any(|row| row.get::<_, String>("provider_request_commitment") == provider_request)
        {
            return Ok(Some(StateError::AdmissionProviderRequestReplay));
        }
        Ok(None)
    }

    #[allow(clippy::too_many_lines)]
    fn admission_context_once(&self, key: &ConsumeKey) -> Result<AdmissionContext, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;

        let lineage = Self::lock_post_attempt_lineage(&mut transaction, key, false)?;
        let snapshot = match Self::validate_post_attempt_snapshot(&mut transaction, key, &lineage)?
        {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit()?;
                return Err(error);
            }
        };
        let physical_resource =
            PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        if physical_resource != *lineage.token.physical_resource() {
            return Err(StateError::AdmissionClaimMismatch);
        }
        if lineage.started_at < 0 || lineage.started_at > snapshot.checked_at() {
            return Err(StateError::InvalidRecord(
                "dispatch attempt start time is outside the current interval".to_owned(),
            ));
        }
        let (operation_hash, provider_request_commitment) =
            admission_projection(snapshot.issued())?;
        let context = AdmissionContext::new(
            key.clone(),
            lineage.token.claim_id(),
            lineage.token.fence(),
            physical_resource,
            lineage.credential.token_digest(),
            lineage.credential.service_account_uid().to_owned(),
            lineage.credential.credential_id().to_owned(),
            lineage.credential.not_before(),
            lineage.credential.expires_at(),
            lineage.credential.commitment(),
            snapshot.issued().authorization().template.clone(),
            snapshot.issued().authorization().template_hash,
            operation_hash,
            provider_request_commitment,
            lineage.started_at,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
            snapshot.authority().clone(),
        );
        transaction.commit()?;
        Ok(context)
    }

    #[allow(clippy::too_many_lines)]
    fn authorize_admission_once(
        &self,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<AdmissionAuthorization, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;

        let preflight_admission =
            Self::admission_authorization_row(&mut transaction, request.admission_uid(), false)?
                .map(|row| Self::stored_admission_from_row(&row))
                .transpose()?;
        if preflight_admission
            .as_ref()
            .is_some_and(|stored| stored.request != *request)
        {
            return Err(StateError::AdmissionUidMismatch);
        }
        if preflight_admission.is_none()
            && let Some(error) = Self::classify_admission_collision(&mut transaction, request)?
        {
            return Err(error);
        }

        let lineage = Self::lock_post_attempt_lineage(&mut transaction, request.key(), false)?;
        if lineage.token.claim_id() != request.claim_id()
            || lineage.token.fence() != request.fence()
            || lineage.token.physical_resource() != request.physical_resource()
        {
            return Err(StateError::AdmissionClaimMismatch);
        }
        if lineage.credential.token_digest() != request.credential_token_digest()
            || lineage.credential.service_account_uid() != request.service_account_uid()
            || lineage.credential.credential_id() != request.credential_id()
            || lineage.credential.commitment() != request.credential_binding_commitment()
        {
            return Err(StateError::AdmissionCredentialMismatch);
        }
        validate_admission_provider_commitment(request, &lineage.time_inputs.dispatch.issued)?;
        let snapshot = match Self::validate_post_attempt_snapshot(
            &mut transaction,
            request.key(),
            &lineage,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit()?;
                return Err(error);
            }
        };
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *request.physical_resource()
        {
            return Err(StateError::AdmissionClaimMismatch);
        }

        let locked_admission =
            Self::admission_authorization_row(&mut transaction, request.admission_uid(), true)?
                .map(|row| Self::stored_admission_from_row(&row))
                .transpose()?;
        if let Some(stored) = locked_admission {
            if stored.request != *request {
                return Err(StateError::AdmissionUidMismatch);
            }
            if stored.grant_id != snapshot.issued().authorization().grant_id
                || stored.authority != *snapshot.authority()
                || stored.dispatch_deadline != snapshot.receipt().dispatch_deadline
            {
                return Err(StateError::InvalidRecord(
                    "stored admission audit lineage does not match current dispatch state"
                        .to_owned(),
                ));
            }
            let checked_at = snapshot.checked_at();
            transaction
                .commit()
                .map_err(|_| StateError::AdmissionOutcomeUnknown)?;
            return Ok(AdmissionAuthorization::new(
                request.clone(),
                stored.authorized_at,
                checked_at,
                true,
            ));
        }
        if preflight_admission.is_some() {
            return Err(StateError::InvalidRecord(
                "durable admission authorization disappeared during revalidation".to_owned(),
            ));
        }
        if let Some(error) = Self::classify_admission_collision(&mut transaction, request)? {
            return Err(error);
        }

        let fence_i64 = i64::try_from(request.fence()).map_err(|_| {
            StateError::InvalidRecord("admission fence does not fit PostgreSQL BIGINT".to_owned())
        })?;
        let request_commitment = request.commitment()?.to_string();
        let authority_json = encode_json(snapshot.authority())?;
        let inserted = transaction.execute(
            "INSERT INTO accordlock_admission_authorizations
                        (admission_uid, tenant, environment, transaction_id,
                         authorization_id, claim_id, fence, cluster_identity, namespace,
                         deployment_uid, credential_token_digest,
                         service_account_uid, credential_id,
                         credential_binding_commitment,
                         provider_request_commitment,
                         old_object_commitment, new_object_commitment,
                         executor_identity_commitment,
                         observer_identity_commitment, request_commitment,
                         grant_id, authorized_authority_json,
                         dispatch_deadline, authorized_unix_s, decision)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, $15, $16, $17, $18,
                         $19, $20, $21, $22, $23, $24, 'ADMITTED')",
            &[
                &request.admission_uid(),
                &request.scope().tenant,
                &request.scope().environment,
                &request.transaction_id(),
                &request.authorization_id(),
                &request.claim_id(),
                &fence_i64,
                &request.physical_resource().cluster_identity(),
                &request.physical_resource().namespace(),
                &request.physical_resource().deployment_uid(),
                &request.credential_token_digest().to_string(),
                &request.service_account_uid(),
                &request.credential_id(),
                &request.credential_binding_commitment().to_string(),
                &request.provider_request_commitment().to_string(),
                &request.old_object_commitment().to_string(),
                &request.new_object_commitment().to_string(),
                &request.executor_identity_commitment().to_string(),
                &request.observer_identity_commitment().to_string(),
                &request_commitment,
                &snapshot.issued().authorization().grant_id,
                &authority_json,
                &snapshot.receipt().dispatch_deadline,
                &snapshot.checked_at(),
            ],
        )?;
        if inserted != 1 {
            return Err(StateError::AdmissionOutcomeUnknown);
        }
        let authorized_at = snapshot.checked_at();
        transaction
            .commit()
            .map_err(|_| StateError::AdmissionOutcomeUnknown)?;
        Ok(AdmissionAuthorization::new(
            request.clone(),
            authorized_at,
            authorized_at,
            false,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn claim_dispatch_once(
        &self,
        request: &DispatchClaimRequest,
    ) -> Result<ClaimedDispatch, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        if Self::control_submission_for_dispatch(&mut transaction, &request.key)?.is_some() {
            return Err(StateError::DispatchAcquisitionRequired);
        }
        // The request identity is the first mutable root in every claim
        // transaction. Direct SQL child triggers take the same identity first,
        // so an application writer can never hold a claim/HWM while waiting on
        // the identity owned by a trigger writer.
        let request_kind = Self::reserve_dispatch_request_identity(
            &mut transaction,
            request.claim_id,
            &request.worker_id,
        )?;
        if let Some(kind) = request_kind {
            if kind == "ACQUISITION"
                && let Some(row) =
                    Self::dispatch_claim_row_unlocked(&mut transaction, &request.key)?
            {
                return Err(Self::classify_existing_claim(request, &row));
            }
            return Err(StateError::DispatchAlreadyClaimed);
        }
        if let Some(row) = Self::dispatch_claim_row_unlocked(&mut transaction, &request.key)? {
            return Err(Self::classify_existing_claim(request, &row));
        }
        let inputs = Self::lock_dispatch_inputs(&mut transaction, &request.key)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;

        if let Some(row) = Self::dispatch_claim_row(&mut transaction, &request.key)? {
            return Err(Self::classify_existing_claim(request, &row));
        }
        if transaction
            .query_opt(
                "SELECT claim_id
                   FROM accordlock_dispatch_claims
                  WHERE claim_id = $1
                  FOR SHARE",
                &[&request.claim_id],
            )
            .map_err(StateError::from)?
            .is_some()
        {
            return Err(StateError::DispatchAlreadyClaimed);
        }

        let snapshot = match Self::validate_locked_dispatch_with_high_water(
            &mut transaction,
            &request.key,
            &inputs,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                // An unbound request identity is never durable. The deferred
                // one-of guard would reject COMMIT as well; roll back the whole
                // attempt so the same id can be retried.
                transaction.rollback()?;
                return Err(error);
            }
        };
        let physical_resource =
            PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        let control_submission_id = None;
        let lease_cap = snapshot
            .checked_at()
            .checked_add(DISPATCH_CLAIM_LEASE_SECONDS)
            .ok_or(StateError::DeadlineOverflow)?;
        let lease_until = lease_cap.min(snapshot.receipt().dispatch_deadline);
        if lease_until <= snapshot.checked_at() {
            transaction.rollback()?;
            return Err(StateError::DispatchDeadlineExpired {
                observed: snapshot.checked_at(),
                dispatch_deadline: snapshot.receipt().dispatch_deadline,
            });
        }
        let row = transaction
            .query_one(
                "INSERT INTO accordlock_dispatch_claims
                        (tenant, environment, authorization_id, transaction_id, claim_id,
                         worker_id, state_instance_id, claimed_unix_s,
                         lease_until, state, cluster_identity, namespace,
                         deployment_uid)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'CLAIMED',
                         $10, $11, $12)
              RETURNING fence",
                &[
                    &request.key.scope.tenant,
                    &request.key.scope.environment,
                    &request.key.authorization_id,
                    &request.key.transaction_id,
                    &request.claim_id,
                    &request.worker_id,
                    &state_instance_id,
                    &snapshot.checked_at(),
                    &lease_until,
                    &physical_resource.cluster_identity(),
                    &physical_resource.namespace(),
                    &physical_resource.deployment_uid(),
                ],
            )
            .map_err(|error| {
                if error.code().is_some_and(|code| code.code() == "2200H") {
                    StateError::DispatchFenceExhausted
                } else if error
                    .as_db_error()
                    .and_then(|db_error| db_error.constraint())
                    == Some("accordlock_dispatch_claims_active_physical_resource_key")
                {
                    StateError::PhysicalResourceAlreadyReserved
                } else {
                    StateError::Database(error)
                }
            })?;
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| StateError::DispatchFenceExhausted)?;
        if fence == 0 {
            return Err(StateError::DispatchFenceExhausted);
        }
        let token = DispatchClaimToken::new(
            request.key.clone(),
            physical_resource,
            request.claim_id,
            request.worker_id.clone(),
            fence,
            snapshot.checked_at(),
            lease_until,
            state_instance_id,
        );
        let selection_kind = "LEGACY_BOOTSTRAP";
        Self::insert_dispatch_acquisition(
            &mut transaction,
            token.clone(),
            request.claim_id,
            control_submission_id,
            selection_kind,
            request.worker_id.clone(),
            snapshot.checked_at(),
            lease_until,
            snapshot.receipt().dispatch_deadline,
        )?;
        transaction
            .commit()
            .map_err(|_| StateError::DispatchClaimOutcomeUnknown)?;
        Ok(ClaimedDispatch::new(snapshot, token))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_productive_candidate(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
        excluded_submissions: &[Uuid],
    ) -> Result<Option<Row>, StateError> {
        Ok(transaction.query_opt(
            "SELECT submission.submission_id, consumption.tenant,
                    consumption.environment, consumption.authorization_id,
                    consumption.transaction_id, consumption.linked_at
               FROM public.accordlock_control_submissions AS submission
               JOIN public.accordlock_control_consumptions AS consumption
                 ON consumption.submission_id = submission.submission_id
               JOIN public.accordlock_execution_outbox AS outbox
                 ON outbox.tenant = consumption.tenant
                AND outbox.environment = consumption.environment
                AND outbox.authorization_id = consumption.authorization_id
                AND outbox.transaction_id = consumption.transaction_id
                AND outbox.dispatch_deadline = consumption.dispatch_deadline
               JOIN public.accordlock_issued_authorizations AS issued
                 ON issued.tenant = consumption.tenant
                AND issued.environment = consumption.environment
                AND issued.authorization_id = consumption.authorization_id
                AND issued.transaction_id = consumption.transaction_id
               LEFT JOIN public.accordlock_dispatch_claims AS claim
                 ON claim.tenant = consumption.tenant
                AND claim.environment = consumption.environment
                AND claim.authorization_id = consumption.authorization_id
                AND claim.transaction_id = consumption.transaction_id
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope = submission.replay_scope
                AND ingress.state_instance_id = submission.state_instance_id
               JOIN public.accordlock_time_high_water AS scope_hwm
                 ON scope_hwm.tenant = consumption.tenant
                AND scope_hwm.environment = consumption.environment
              WHERE outbox.status = 'PENDING_WITNESS'
                AND consumption.tenant = $1
                AND consumption.environment = $2
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_queue_dispositions AS disposition
                     WHERE disposition.control_submission_id = submission.submission_id
                )
                AND (
                    claim.claim_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                          FROM public.accordlock_dispatch_claims AS reserved
                          WHERE reserved.state IN (
                              'CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND'
                          )
                           AND reserved.cluster_identity = issued.record_json #>>
                               '{signed_authorization,authorization,template,cluster_identity}'
                           AND reserved.namespace = issued.record_json #>>
                               '{signed_authorization,authorization,template,namespace}'
                           AND reserved.deployment_uid = issued.record_json #>>
                               '{signed_authorization,authorization,template,deployment_uid}'
                    )
                    OR claim.claim_id IS NOT NULL
                    AND claim.state = 'CLAIMED'
                    AND claim.attempt_started_at IS NULL
                    AND claim.credential_token_digest IS NULL
                    AND claim.service_account_uid IS NULL
                    AND claim.credential_id IS NULL
                    AND claim.credential_not_before IS NULL
                    AND claim.credential_expires_at IS NULL
                    AND claim.credential_binding_commitment IS NULL
                    AND claim.terminalization_id IS NULL
                    AND COALESCE((
                        SELECT latest.lease_until <= GREATEST(
                                   floor(extract(
                                       epoch FROM clock_timestamp()
                                   ))::bigint,
                                   ingress.observed_unix_s,
                                   scope_hwm.observed_unix_s,
                                   submission.accepted_at,
                                   latest.acquired_unix_s
                               )
                          FROM public.accordlock_dispatch_acquisitions AS latest
                         WHERE latest.tenant = claim.tenant
                           AND latest.environment = claim.environment
                           AND latest.authorization_id = claim.authorization_id
                           AND latest.transaction_id = claim.transaction_id
                           AND latest.claim_id = claim.claim_id
                           AND latest.claim_fence = claim.fence
                           AND latest.state_instance_id = claim.state_instance_id
                         ORDER BY latest.lease_fence DESC
                         LIMIT 1
                    ), TRUE)
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_broker_operations AS broker
                         WHERE broker.tenant = claim.tenant
                           AND broker.environment = claim.environment
                           AND broker.authorization_id = claim.authorization_id
                           AND broker.transaction_id = claim.transaction_id
                           AND broker.claim_id = claim.claim_id
                           AND broker.fence = claim.fence
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_admission_authorizations AS admission
                         WHERE admission.tenant = claim.tenant
                           AND admission.environment = claim.environment
                           AND admission.authorization_id = claim.authorization_id
                           AND admission.transaction_id = claim.transaction_id
                           AND admission.claim_id = claim.claim_id
                           AND admission.fence = claim.fence
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_terminal_retirements AS terminal
                         WHERE terminal.tenant = claim.tenant
                           AND terminal.environment = claim.environment
                           AND terminal.authorization_id = claim.authorization_id
                           AND terminal.transaction_id = claim.transaction_id
                           AND terminal.claim_id = claim.claim_id
                           AND terminal.fence = claim.fence
                           AND terminal.state_instance_id = claim.state_instance_id
                    )
                )
                AND NOT (submission.submission_id = ANY($3::uuid[]))
              ORDER BY consumption.linked_at, submission.submission_id
              LIMIT 1",
            &[&scope.tenant, &scope.environment, &excluded_submissions],
        )?)
    }

    #[allow(clippy::too_many_lines)]
    fn claim_next_dispatch_once(
        &self,
        scope: &Scope,
        request: &DispatchAcquisitionRequest,
        excluded_submissions: &[Uuid],
    ) -> Result<DispatchAcquisitionStep, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;

        // Reserve and lock the global request identity before reading a child
        // or locking any submission/authority/HWM/claim root. New NoWork/skip
        // paths roll this unbound row back; successful paths bind it exactly
        // once to ACQUISITION or DISPOSITION before COMMIT.
        let request_kind = Self::reserve_dispatch_request_identity(
            &mut transaction,
            request.acquisition_id(),
            request.worker_id(),
        )?;
        if request_kind
            .as_deref()
            .is_some_and(|kind| !matches!(kind, "ACQUISITION" | "DISPOSITION"))
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        // Idempotency/collision is resolved before trusted time or either HWM
        // can be sampled or changed. A bootstrap acquisition is deliberately
        // not recoverable through the server-selected worker API.
        if let Some(disposition) = Self::dispatch_queue_disposition(
            &mut transaction,
            Some(request.acquisition_id()),
            None,
        )? {
            if request_kind.as_deref() != Some("DISPOSITION") {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            if disposition.worker_id() != request.worker_id() || disposition.key().scope != *scope {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let state_instance_id = Self::locked_state_instance(&mut transaction)?;
            if disposition.state_instance_id() != state_instance_id {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let stored = control_plane::load_submission_for_update(
                &mut transaction,
                disposition.control_submission_id(),
            )?;
            if stored.scope() != *scope {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            control_plane::validate_dispatch_pending_lineage(
                &mut transaction,
                &stored,
                disposition.key(),
            )?;
            transaction.commit()?;
            return Ok(DispatchAcquisitionStep::outcome(
                DispatchAcquisitionOutcome::Disposed(disposition),
            ));
        }
        if request_kind.as_deref() == Some("DISPOSITION") {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if let Some(existing) =
            Self::dispatch_acquisition_row(&mut transaction, request.acquisition_id())?
        {
            if request_kind.as_deref() != Some("ACQUISITION") {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            if existing.worker_id != request.worker_id()
                || existing.selection_kind != "CONTROL_QUEUE"
                || existing.control_submission_id.is_none()
                || existing.token.key().scope != *scope
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let submission_id = existing
                .control_submission_id
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            let state_instance_id = Self::locked_state_instance(&mut transaction)?;
            if state_instance_id != existing.token.state_instance_id() {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let stored =
                control_plane::load_submission_for_update(&mut transaction, submission_id)?;
            if stored.submission_id != submission_id
                || stored.scope() != existing.token.key().scope
                || stored.state_instance_id != existing.token.state_instance_id()
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            control_plane::validate_dispatch_pending_lineage(
                &mut transaction,
                &stored,
                existing.token.key(),
            )?;

            let queue_disposition =
                Self::dispatch_queue_disposition(&mut transaction, None, Some(submission_id))?;
            if let Some(disposition) = &queue_disposition
                && (disposition.key() != existing.token.key()
                    || disposition.state_instance_id() != existing.token.state_instance_id())
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }

            let claim_row = Self::dispatch_claim_row(&mut transaction, existing.token.key())?
                .ok_or(StateError::DispatchClaimNotFound)?;
            let (claim_token, _) = Self::token_from_claim_row(existing.token.key(), &claim_row)?;
            if claim_token != existing.token {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let latest = Self::latest_dispatch_acquisition(&mut transaction, &existing.token)?;
            if latest.acquisition_id != existing.acquisition_id {
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::outcome(
                    DispatchAcquisitionOutcome::Inert(Self::dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::Superseded,
                    )),
                ));
            }
            if queue_disposition.is_some() {
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::outcome(
                    DispatchAcquisitionOutcome::Quarantined(Self::dispatch_acquisition_receipt(
                        &existing,
                        DispatchAcquisitionDisposition::QueueDisposed,
                    )),
                ));
            }
            if let Some(disposition) =
                Self::dispatch_acquisition_artifact_disposition(&mut transaction, &latest)?
            {
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::outcome(
                    DispatchAcquisitionOutcome::Quarantined(Self::dispatch_acquisition_receipt(
                        &latest,
                        disposition,
                    )),
                ));
            }
            if latest.control_submission_id != Some(submission_id) {
                return Err(StateError::DispatchAcquisitionMismatch);
            }

            // Historical receipts above are byte-inert after the immutable
            // v13 lineage is authenticated. For the latest artifact-free
            // lease, lock the authority row before both HWMs to preserve the
            // global order, but deliberately defer decoding/currentness until
            // we know this lease is still live.
            let locked_authority =
                Self::lock_dispatch_authority_value(&mut transaction, existing.token.key())?;
            let replay_scope = IngressReplayScope::new(&stored.replay_scope)?;
            let (ingress_state_instance, ingress_high_water) =
                Self::lock_or_create_ingress_scope(&mut transaction, &replay_scope)?;
            if ingress_state_instance != stored.state_instance_id {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let scope_high_water =
                Self::lock_or_create_high_water(&mut transaction, &stored.scope())?;
            let durable_high_water = ingress_high_water
                .max(scope_high_water)
                .max(stored.accepted_at)
                .max(latest.acquired_at);
            if durable_high_water >= latest.lease_until {
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::outcome(
                    DispatchAcquisitionOutcome::Inert(Self::dispatch_acquisition_receipt(
                        &latest,
                        DispatchAcquisitionDisposition::Expired,
                    )),
                ));
            }
            let expiry_observed_at = Self::sample_trusted_time(&mut transaction)?;
            if expiry_observed_at < durable_high_water {
                return Err(StateError::ClockRollback {
                    observed: expiry_observed_at,
                    high_water: durable_high_water,
                });
            }
            if expiry_observed_at >= latest.lease_until {
                control_plane::advance_control_high_water(
                    &mut transaction,
                    &stored,
                    &replay_scope,
                    ingress_high_water,
                    expiry_observed_at,
                )?;
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::outcome(
                    DispatchAcquisitionOutcome::Inert(Self::dispatch_acquisition_receipt(
                        &latest,
                        DispatchAcquisitionDisposition::Expired,
                    )),
                ));
            }

            let authority = Self::decode_locked_dispatch_authority(locked_authority)?;
            let inputs = Self::lock_dispatch_inputs_after_high_water(
                &mut transaction,
                existing.token.key(),
                authority,
                scope_high_water,
            )?;
            if latest.dispatch_deadline != inputs.outbox.dispatch_deadline {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let observed_at = Self::sample_trusted_time(&mut transaction)?;
            if observed_at >= latest.lease_until {
                // Crossed the integer-second boundary while locking immutable
                // currentness inputs. Persist that trusted observation in both
                // HWMs before retrying, so a later raw-clock rollback cannot
                // resurrect the lease. The fresh transaction then derives the
                // inert Expired receipt without depending on current inputs.
                control_plane::advance_control_high_water(
                    &mut transaction,
                    &stored,
                    &replay_scope,
                    ingress_high_water,
                    observed_at,
                )?;
                transaction.commit()?;
                return Ok(DispatchAcquisitionStep::ExactRecoveryRetry);
            }
            let validation = Self::validate_locked_dispatch_with_dual_high_water(
                &mut transaction,
                &stored,
                &replay_scope,
                ingress_high_water,
                scope_high_water,
                existing.token.key(),
                &inputs,
                observed_at,
            )?;
            let snapshot = match validation {
                LockedDispatchValidation::Accepted(snapshot) => *snapshot,
                LockedDispatchValidation::TemporalRejection(error) => {
                    transaction.commit()?;
                    return Err(error);
                }
            };
            if snapshot.receipt().dispatch_deadline != latest.dispatch_deadline
                || PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
                    != *latest.token.physical_resource()
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let authority = Self::dispatch_acquisition_authority(&latest);
            transaction.commit()?;
            return Ok(DispatchAcquisitionStep::outcome(
                DispatchAcquisitionOutcome::Recovered(DispatchWork::new(snapshot, authority)),
            ));
        }
        if request_kind.is_some() {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let productive_candidate =
            Self::dispatch_productive_candidate(&mut transaction, scope, excluded_submissions)?;

        // Recovery and productive/disposition candidates share one global
        // durable FIFO order. These first reads intentionally take no row
        // lock; after comparing their stable (linked_at, submission_id) keys,
        // only the winning submission root is locked and fully revalidated.
        let recovery_candidate = transaction.query_opt(
            "SELECT submission.submission_id, consumption.tenant,
                    consumption.environment, consumption.authorization_id,
                    consumption.transaction_id, latest.acquisition_id,
                    consumption.linked_at,
                    ingress.observed_unix_s AS ingress_high_water,
                    scope_hwm.observed_unix_s AS scope_high_water
               FROM public.accordlock_control_submissions AS submission
               JOIN public.accordlock_control_consumptions AS consumption
                 ON consumption.submission_id = submission.submission_id
               JOIN public.accordlock_execution_outbox AS outbox
                 ON outbox.tenant = consumption.tenant
                AND outbox.environment = consumption.environment
                AND outbox.authorization_id = consumption.authorization_id
                AND outbox.transaction_id = consumption.transaction_id
                AND outbox.dispatch_deadline = consumption.dispatch_deadline
               JOIN public.accordlock_dispatch_claims AS claim
                 ON claim.tenant = consumption.tenant
                AND claim.environment = consumption.environment
                AND claim.authorization_id = consumption.authorization_id
                AND claim.transaction_id = consumption.transaction_id
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope = submission.replay_scope
                AND ingress.state_instance_id = submission.state_instance_id
               JOIN public.accordlock_time_high_water AS scope_hwm
                 ON scope_hwm.tenant = consumption.tenant
                AND scope_hwm.environment = consumption.environment
               JOIN LATERAL (
                    SELECT acquisition.acquisition_id,
                           acquisition.selection_kind,
                           acquisition.control_submission_id
                      FROM public.accordlock_dispatch_acquisitions AS acquisition
                     WHERE acquisition.tenant = claim.tenant
                       AND acquisition.environment = claim.environment
                       AND acquisition.authorization_id = claim.authorization_id
                       AND acquisition.transaction_id = claim.transaction_id
                       AND acquisition.claim_id = claim.claim_id
                       AND acquisition.claim_fence = claim.fence
                       AND acquisition.state_instance_id = claim.state_instance_id
                     ORDER BY acquisition.lease_fence DESC
                     LIMIT 1
               ) AS latest ON TRUE
              WHERE outbox.status = 'PENDING_WITNESS'
                AND consumption.tenant = $1
                AND consumption.environment = $2
                AND latest.control_submission_id = submission.submission_id
                AND latest.selection_kind IN (
                    'CONTROL_QUEUE', 'CONTROL_BOOTSTRAP_V13'
                )
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_queue_dispositions AS disposition
                     WHERE disposition.control_submission_id = submission.submission_id
                )
                AND (
                    claim.state = 'CLAIMED'
                    AND (
                        EXISTS (
                            SELECT 1
                              FROM public.accordlock_broker_operations AS broker
                             WHERE broker.tenant = claim.tenant
                               AND broker.environment = claim.environment
                               AND broker.authorization_id = claim.authorization_id
                               AND broker.transaction_id = claim.transaction_id
                               AND broker.claim_id = claim.claim_id
                               AND broker.fence = claim.fence
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM public.accordlock_dispatch_credential_reviews AS review
                             WHERE review.tenant = claim.tenant
                               AND review.environment = claim.environment
                               AND review.authorization_id = claim.authorization_id
                               AND review.transaction_id = claim.transaction_id
                               AND review.acquisition_id = latest.acquisition_id
                        )
                    )
                    OR claim.state = 'ATTEMPT_IN_FLIGHT'
                    AND NOT EXISTS (
                        SELECT 1
                          FROM public.accordlock_broker_operations AS delete_op
                          JOIN public.accordlock_broker_secret_deletion_observations AS deletion
                            ON deletion.entry_id = delete_op.entry_id
                           AND deletion.tenant = delete_op.tenant
                           AND deletion.environment = delete_op.environment
                           AND deletion.authorization_id = delete_op.authorization_id
                           AND deletion.transaction_id = delete_op.transaction_id
                         WHERE delete_op.tenant = claim.tenant
                           AND delete_op.environment = claim.environment
                           AND delete_op.authorization_id = claim.authorization_id
                           AND delete_op.transaction_id = claim.transaction_id
                           AND delete_op.claim_id = claim.claim_id
                           AND delete_op.fence = claim.fence
                           AND delete_op.origin_acquisition_id = latest.acquisition_id
                           AND delete_op.operation = 'DELETE_SECRET'
                           AND delete_op.phase = 'COMMITTED'
                           AND delete_op.outcome = 'DELETE_ABSENT'
                    )
                    AND NOT EXISTS (
                        SELECT 1
                          FROM public.accordlock_broker_operations AS delete_conflict
                         WHERE delete_conflict.tenant = claim.tenant
                           AND delete_conflict.environment = claim.environment
                           AND delete_conflict.authorization_id = claim.authorization_id
                           AND delete_conflict.transaction_id = claim.transaction_id
                           AND delete_conflict.claim_id = claim.claim_id
                           AND delete_conflict.fence = claim.fence
                           AND delete_conflict.origin_acquisition_id = latest.acquisition_id
                           AND delete_conflict.operation = 'DELETE_SECRET'
                           AND delete_conflict.phase = 'TERMINAL'
                           AND delete_conflict.outcome = 'DELETE_CONFLICTING'
                    )
                    OR claim.state = 'RECOVERY_NO_SEND'
                    AND (
                        claim.recovery_safe_after_unix_s IS NOT NULL
                        AND claim.recovery_safe_after_unix_s <= GREATEST(
                            floor(extract(epoch FROM clock_timestamp()))::bigint,
                            ingress.observed_unix_s,
                            scope_hwm.observed_unix_s
                        )
                        OR claim.recovery_safe_after_unix_s IS NULL
                        AND NOT EXISTS (
                            SELECT 1
                              FROM public.accordlock_broker_operations AS conflict
                             WHERE conflict.tenant = claim.tenant
                               AND conflict.environment = claim.environment
                               AND conflict.authorization_id = claim.authorization_id
                               AND conflict.transaction_id = claim.transaction_id
                               AND conflict.claim_id = claim.claim_id
                               AND conflict.fence = claim.fence
                               AND conflict.origin_acquisition_id = latest.acquisition_id
                               AND conflict.phase = 'TERMINAL'
                               AND (
                                   conflict.operation = 'CREATE_SECRET'
                                   AND conflict.outcome = 'CREATE_CONFLICTING'
                                   OR conflict.operation = 'DELETE_SECRET'
                                   AND conflict.outcome = 'DELETE_CONFLICTING'
                               )
                        )
                    )
                )
                AND NOT (submission.submission_id = ANY($3::uuid[]))
              ORDER BY consumption.linked_at, submission.submission_id
              LIMIT 1",
            &[&scope.tenant, &scope.environment, &excluded_submissions],
        )?;
        let recovery_precedes = recovery_candidate.as_ref().is_some_and(|recovery| {
            productive_candidate.as_ref().is_none_or(|productive| {
                (
                    recovery.get::<_, i64>("linked_at"),
                    recovery.get::<_, Uuid>("submission_id"),
                ) <= (
                    productive.get::<_, i64>("linked_at"),
                    productive.get::<_, Uuid>("submission_id"),
                )
            })
        });
        if let Some(candidate) = recovery_candidate.filter(|_| recovery_precedes) {
            let submission_id: Uuid = candidate.get("submission_id");
            let key = ConsumeKey {
                scope: Scope {
                    tenant: candidate.get("tenant"),
                    environment: candidate.get("environment"),
                },
                transaction_id: candidate.get("transaction_id"),
                authorization_id: candidate.get("authorization_id"),
            };
            key.validate()?;
            let stored =
                control_plane::load_submission_for_update(&mut transaction, submission_id)?;
            if stored.submission_id != submission_id
                || stored.scope() != key.scope
                || stored.state_instance_id != state_instance_id
            {
                return Err(StateError::ControlWorkMismatch);
            }
            control_plane::validate_dispatch_pending_lineage(&mut transaction, &stored, &key)?;
            let claim_row = Self::dispatch_claim_row(&mut transaction, &key)?
                .ok_or(StateError::DispatchClaimNotFound)?;
            let (token, _) = Self::token_from_claim_row(&key, &claim_row)?;
            let latest = Self::latest_dispatch_acquisition(&mut transaction, &token)?;
            if latest.acquisition_id != candidate.get::<_, Uuid>("acquisition_id")
                || latest.control_submission_id != Some(submission_id)
                || !matches!(
                    latest.selection_kind.as_str(),
                    "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
                )
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            let disposition =
                Self::dispatch_acquisition_artifact_disposition(&mut transaction, &latest)?
                    .filter(|disposition| {
                        matches!(
                            disposition,
                            DispatchAcquisitionDisposition::BrokerArtifactPresent
                                | DispatchAcquisitionDisposition::RecoveryNoSend
                                | DispatchAcquisitionDisposition::AttemptInFlight
                        )
                    })
                    .ok_or(StateError::DispatchAcquisitionMismatch)?;
            let recovery_key = DispatchAcquisitionRecoveryKey::from_durable_acquisition(
                &key.scope,
                &latest.worker_id,
                latest.acquisition_id,
            )?;
            let actionable = match disposition {
                DispatchAcquisitionDisposition::BrokerArtifactPresent => true,
                DispatchAcquisitionDisposition::AttemptInFlight => {
                    Self::exact_broker_delete_absence(&mut transaction, &latest)?.is_none()
                        && !Self::exact_broker_delete_terminal_conflict(&mut transaction, &latest)?
                }
                DispatchAcquisitionDisposition::RecoveryNoSend => {
                    let lineage = Self::lock_postgres_no_send_lineage(
                        &mut transaction,
                        &recovery_key,
                        state_instance_id,
                    )?;
                    if let Some(absent_at) =
                        Self::exact_broker_delete_absence(&mut transaction, &latest)?
                    {
                        let propagation_safe_after = absent_at
                            .checked_add(
                                lineage
                                    .lifecycle_policy
                                    .deletion_propagation_hard_max_seconds(),
                            )
                            .and_then(|value| {
                                value.checked_add(
                                    lineage.lifecycle_policy.clock_uncertainty_seconds(),
                                )
                            })
                            .ok_or(StateError::DeadlineOverflow)?;
                        let safe_after = lineage
                            .claim_row
                            .get::<_, Option<i64>>("recovery_safe_after_unix_s")
                            .unwrap_or(propagation_safe_after);
                        let observed_at = Self::sample_trusted_time(&mut transaction)?;
                        let durable_high_water = candidate
                            .get::<_, i64>("ingress_high_water")
                            .max(candidate.get::<_, i64>("scope_high_water"));
                        observed_at.max(durable_high_water) >= safe_after
                    } else {
                        !(lineage.create.phase == BrokerJournalPhase::Terminal
                            && lineage.create.outcome
                                == Some(BrokerJournalOutcome::CreateConflicting)
                            || lineage.delete.as_ref().is_some_and(|delete| {
                                delete.phase == BrokerJournalPhase::Terminal
                                    && delete.outcome
                                        == Some(BrokerJournalOutcome::DeleteConflicting)
                            }))
                    }
                }
                _ => false,
            };
            if !actionable {
                transaction.rollback()?;
                return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
            }
            transaction.rollback()?;
            return Ok(DispatchAcquisitionStep::outcome(
                DispatchAcquisitionOutcome::RecoveryRequired(DispatchRecoveryWork::new(
                    recovery_key,
                    disposition,
                )),
            ));
        }

        // Re-read the productive winner in the same serializable snapshot.
        // The submission root is acquired exactly once below by
        // load_submission_for_update, after the global class comparison.
        let candidate = transaction.query_opt(
            "SELECT submission.submission_id, consumption.tenant,
                    consumption.environment, consumption.authorization_id,
                    consumption.transaction_id
               FROM public.accordlock_control_submissions AS submission
               JOIN public.accordlock_control_consumptions AS consumption
                 ON consumption.submission_id = submission.submission_id
               JOIN public.accordlock_execution_outbox AS outbox
                 ON outbox.tenant = consumption.tenant
                AND outbox.environment = consumption.environment
                AND outbox.authorization_id = consumption.authorization_id
                AND outbox.transaction_id = consumption.transaction_id
                AND outbox.dispatch_deadline = consumption.dispatch_deadline
               JOIN public.accordlock_issued_authorizations AS issued
                 ON issued.tenant = consumption.tenant
                AND issued.environment = consumption.environment
                AND issued.authorization_id = consumption.authorization_id
                AND issued.transaction_id = consumption.transaction_id
               LEFT JOIN public.accordlock_dispatch_claims AS claim
                 ON claim.tenant = consumption.tenant
                AND claim.environment = consumption.environment
                AND claim.authorization_id = consumption.authorization_id
                AND claim.transaction_id = consumption.transaction_id
               JOIN public.accordlock_ingress_replay_scopes AS ingress
                 ON ingress.replay_scope = submission.replay_scope
                AND ingress.state_instance_id = submission.state_instance_id
               JOIN public.accordlock_time_high_water AS scope_hwm
                 ON scope_hwm.tenant = consumption.tenant
                AND scope_hwm.environment = consumption.environment
              WHERE outbox.status = 'PENDING_WITNESS'
                AND consumption.tenant = $1
                AND consumption.environment = $2
                AND NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_queue_dispositions AS disposition
                     WHERE disposition.control_submission_id = submission.submission_id
                )
                AND (
                    claim.claim_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1
                          FROM public.accordlock_dispatch_claims AS reserved
                          WHERE reserved.state IN (
                              'CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND'
                          )
                           AND reserved.cluster_identity = issued.record_json #>>
                               '{signed_authorization,authorization,template,cluster_identity}'
                           AND reserved.namespace = issued.record_json #>>
                               '{signed_authorization,authorization,template,namespace}'
                           AND reserved.deployment_uid = issued.record_json #>>
                               '{signed_authorization,authorization,template,deployment_uid}'
                    )
                    OR claim.claim_id IS NOT NULL
                    AND claim.state = 'CLAIMED'
                    AND claim.attempt_started_at IS NULL
                    AND claim.credential_token_digest IS NULL
                    AND claim.service_account_uid IS NULL
                    AND claim.credential_id IS NULL
                    AND claim.credential_not_before IS NULL
                    AND claim.credential_expires_at IS NULL
                    AND claim.credential_binding_commitment IS NULL
                    AND claim.terminalization_id IS NULL
                    AND COALESCE((
                        SELECT latest.lease_until <= GREATEST(
                                   floor(extract(
                                       epoch FROM clock_timestamp()
                                   ))::bigint,
                                   ingress.observed_unix_s,
                                   scope_hwm.observed_unix_s,
                                   submission.accepted_at,
                                   latest.acquired_unix_s
                               )
                          FROM public.accordlock_dispatch_acquisitions AS latest
                         WHERE latest.tenant = claim.tenant
                           AND latest.environment = claim.environment
                           AND latest.authorization_id = claim.authorization_id
                           AND latest.transaction_id = claim.transaction_id
                           AND latest.claim_id = claim.claim_id
                           AND latest.claim_fence = claim.fence
                           AND latest.state_instance_id = claim.state_instance_id
                         ORDER BY latest.lease_fence DESC
                         LIMIT 1
                    ), TRUE)
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_broker_operations AS broker
                         WHERE broker.tenant = claim.tenant
                           AND broker.environment = claim.environment
                           AND broker.authorization_id = claim.authorization_id
                           AND broker.transaction_id = claim.transaction_id
                           AND broker.claim_id = claim.claim_id
                           AND broker.fence = claim.fence
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_admission_authorizations AS admission
                         WHERE admission.tenant = claim.tenant
                           AND admission.environment = claim.environment
                           AND admission.authorization_id = claim.authorization_id
                           AND admission.transaction_id = claim.transaction_id
                           AND admission.claim_id = claim.claim_id
                           AND admission.fence = claim.fence
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM public.accordlock_terminal_retirements AS terminal
                         WHERE terminal.tenant = claim.tenant
                           AND terminal.environment = claim.environment
                           AND terminal.authorization_id = claim.authorization_id
                           AND terminal.transaction_id = claim.transaction_id
                           AND terminal.claim_id = claim.claim_id
                           AND terminal.fence = claim.fence
                           AND terminal.state_instance_id = claim.state_instance_id
                    )
                )
                AND NOT (submission.submission_id = ANY($3::uuid[]))
              ORDER BY consumption.linked_at, submission.submission_id
              LIMIT 1",
            &[&scope.tenant, &scope.environment, &excluded_submissions],
        )?;
        let Some(candidate) = candidate else {
            transaction.rollback()?;
            return Ok(DispatchAcquisitionStep::outcome(
                DispatchAcquisitionOutcome::NoWork,
            ));
        };
        // The second read deliberately does not use SKIP LOCKED: it must name
        // the same globally ordered productive winner that participated in the
        // recovery-vs-productive comparison above.  Keep this identity check as
        // a fail-closed guard against future query drift or lock-clause changes.
        if productive_candidate
            .as_ref()
            .map(|row| row.get::<_, Uuid>("submission_id"))
            != Some(candidate.get::<_, Uuid>("submission_id"))
        {
            transaction.rollback()?;
            return Ok(DispatchAcquisitionStep::ExactRecoveryRetry);
        }
        let submission_id: Uuid = candidate.get("submission_id");
        let key = ConsumeKey {
            scope: Scope {
                tenant: candidate.get("tenant"),
                environment: candidate.get("environment"),
            },
            transaction_id: candidate.get("transaction_id"),
            authorization_id: candidate.get("authorization_id"),
        };
        key.validate()?;
        let stored = control_plane::load_submission_for_update(&mut transaction, submission_id)?;
        if stored.submission_id != submission_id || stored.scope() != key.scope {
            return Err(StateError::ControlWorkMismatch);
        }
        control_plane::validate_dispatch_pending_lineage(&mut transaction, &stored, &key)?;
        if Self::dispatch_queue_disposition(&mut transaction, None, Some(submission_id))?.is_some()
        {
            transaction.rollback()?;
            return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
        }
        let (replay_scope, ingress_high_water, scope_high_water, inputs) =
            Self::lock_v14_dispatch_inputs(&mut transaction, &stored, &key)?;
        if stored.state_instance_id != state_instance_id
            || Self::control_submission_for_dispatch(&mut transaction, &key)? != Some(submission_id)
        {
            return Err(StateError::ControlWorkMismatch);
        }

        let claim_row = Self::dispatch_claim_row(&mut transaction, &key)?;
        let prior = if let Some(claim_row) = claim_row {
            let (token, state) = Self::token_from_claim_row(&key, &claim_row)?;
            if state != "CLAIMED" {
                transaction.rollback()?;
                return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
            }
            let latest = Self::latest_dispatch_acquisition(&mut transaction, &token)?;
            if latest.control_submission_id != Some(submission_id)
                || !matches!(
                    latest.selection_kind.as_str(),
                    "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
                )
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            if Self::dispatch_acquisition_artifact_disposition(&mut transaction, &latest)?.is_some()
            {
                transaction.rollback()?;
                return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
            }
            Some(latest)
        } else {
            let physical_resource =
                PhysicalResourceKey::from_authorization(inputs.issued.authorization())?;
            if transaction
                .query_opt(
                    "SELECT 1 FROM public.accordlock_dispatch_claims
                      WHERE cluster_identity=$1 AND namespace=$2
                        AND deployment_uid=$3
                        AND state IN (
                            'CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND'
                        )
                      FOR SHARE",
                    &[
                        &physical_resource.cluster_identity(),
                        &physical_resource.namespace(),
                        &physical_resource.deployment_uid(),
                    ],
                )?
                .is_some()
            {
                transaction.rollback()?;
                return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
            }
            None
        };

        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        let dual_high_water = ingress_high_water
            .max(scope_high_water)
            .max(inputs.high_water)
            .max(stored.accepted_at)
            .max(inputs.receipt.consumed_at);
        if observed_at < dual_high_water {
            return Err(StateError::ClockRollback {
                observed: observed_at,
                high_water: dual_high_water,
            });
        }
        validate_dispatch_immutable_facts(
            &key,
            &inputs.grant,
            &inputs.issued,
            &inputs.receipt,
            &inputs.outbox,
        )?;
        if prior
            .as_ref()
            .is_some_and(|latest| observed_at < latest.lease_until)
        {
            transaction.rollback()?;
            return Ok(DispatchAcquisitionStep::SkippedCandidate(submission_id));
        }
        let disposition_reason = if observed_at >= inputs.outbox.dispatch_deadline {
            Some(DispatchQueueDispositionReason::DispatchDeadlineExpired)
        } else if inputs.authority != inputs.issued.authorization().authority {
            Some(DispatchQueueDispositionReason::AuthorityChanged)
        } else if inputs.grant.revoked {
            Some(DispatchQueueDispositionReason::GrantRevoked)
        } else {
            None
        };
        if let Some(reason) = disposition_reason {
            let (claim_id, claim_fence, acquisition_id, lease_fence) =
                prior.as_ref().map_or((None, None, None, None), |latest| {
                    (
                        Some(latest.token.claim_id()),
                        Some(latest.token.fence()),
                        Some(latest.acquisition_id),
                        Some(latest.lease_fence),
                    )
                });
            let disposition = DispatchQueueDispositionReceipt::new(
                request.acquisition_id(),
                request.worker_id().to_owned(),
                submission_id,
                key.clone(),
                state_instance_id,
                claim_id,
                claim_fence,
                acquisition_id,
                lease_fence,
                reason,
                observed_at,
                inputs.outbox.dispatch_deadline,
                inputs.issued.authorization_hash,
                dispatch_grant_fact_commitment(&inputs.grant)?,
                dispatch_outbox_fact_commitment(&inputs.outbox)?,
                dispatch_authority_fact_commitment(&inputs.issued.authorization().authority)?,
                dispatch_authority_fact_commitment(&inputs.authority)?,
            )?;
            control_plane::advance_control_high_water(
                &mut transaction,
                &stored,
                &replay_scope,
                ingress_high_water,
                observed_at,
            )?;
            Self::insert_dispatch_queue_disposition(&mut transaction, &disposition)?;
            if let Some(latest) = prior.as_ref() {
                let disposed = transaction.execute(
                    "UPDATE public.accordlock_dispatch_claims
                        SET state='DISPOSED'
                      WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                        AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                        AND state_instance_id=$7 AND state='CLAIMED'",
                    &[
                        &key.scope.tenant,
                        &key.scope.environment,
                        &key.authorization_id,
                        &key.transaction_id,
                        &latest.token.claim_id(),
                        &i64::try_from(latest.token.fence()).map_err(|_| {
                            StateError::InvalidRecord(
                                "dispatch claim fence does not fit PostgreSQL BIGINT".to_owned(),
                            )
                        })?,
                        &state_instance_id,
                    ],
                )?;
                if disposed != 1 {
                    return Err(StateError::DispatchAcquisitionMismatch);
                }
            }
            transaction.commit()?;
            return Ok(DispatchAcquisitionStep::outcome(
                DispatchAcquisitionOutcome::Disposed(disposition),
            ));
        }
        let validation = Self::validate_locked_dispatch_with_dual_high_water(
            &mut transaction,
            &stored,
            &replay_scope,
            ingress_high_water,
            scope_high_water,
            &key,
            &inputs,
            observed_at,
        )?;
        let snapshot = match validation {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.rollback()?;
                return Err(error);
            }
        };
        let lease_until = observed_at
            .checked_add(DISPATCH_ACQUISITION_LEASE_SECONDS)
            .ok_or(StateError::DeadlineOverflow)?
            .min(snapshot.receipt().dispatch_deadline);
        if lease_until <= observed_at {
            transaction.rollback()?;
            return Err(StateError::DispatchDeadlineExpired {
                observed: observed_at,
                dispatch_deadline: snapshot.receipt().dispatch_deadline,
            });
        }

        let token = if let Some(prior) = prior {
            prior.token
        } else {
            let physical_resource =
                PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
            let mut claim_id = Uuid::new_v4();
            while claim_id == request.acquisition_id() {
                claim_id = Uuid::new_v4();
            }
            let row = transaction
                .query_one(
                    "INSERT INTO public.accordlock_dispatch_claims
                                (tenant, environment, authorization_id, transaction_id,
                                 claim_id, worker_id, state_instance_id,
                                 claimed_unix_s, lease_until, state,
                                 cluster_identity, namespace, deployment_uid)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'CLAIMED',$10,$11,$12)
                      RETURNING fence",
                    &[
                        &key.scope.tenant,
                        &key.scope.environment,
                        &key.authorization_id,
                        &key.transaction_id,
                        &claim_id,
                        &request.worker_id(),
                        &state_instance_id,
                        &observed_at,
                        &lease_until,
                        &physical_resource.cluster_identity(),
                        &physical_resource.namespace(),
                        &physical_resource.deployment_uid(),
                    ],
                )
                .map_err(|error| {
                    if error.code().is_some_and(|code| code.code() == "2200H") {
                        StateError::DispatchFenceExhausted
                    } else if error
                        .as_db_error()
                        .and_then(|db_error| db_error.constraint())
                        == Some("accordlock_dispatch_claims_active_physical_resource_key")
                    {
                        StateError::PhysicalResourceAlreadyReserved
                    } else {
                        StateError::Database(error)
                    }
                })?;
            let fence_i64: i64 = row.get("fence");
            let fence = u64::try_from(fence_i64).map_err(|_| StateError::DispatchFenceExhausted)?;
            if fence == 0 {
                return Err(StateError::DispatchFenceExhausted);
            }
            DispatchClaimToken::new(
                key.clone(),
                physical_resource,
                claim_id,
                request.worker_id().to_owned(),
                fence,
                observed_at,
                lease_until,
                state_instance_id,
            )
        };
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let acquisition = Self::insert_dispatch_acquisition(
            &mut transaction,
            token,
            request.acquisition_id(),
            Some(submission_id),
            "CONTROL_QUEUE",
            request.worker_id().to_owned(),
            observed_at,
            lease_until,
            snapshot.receipt().dispatch_deadline,
        )?;
        let authority = Self::dispatch_acquisition_authority(&acquisition);
        transaction.commit()?;
        Ok(DispatchAcquisitionStep::outcome(
            DispatchAcquisitionOutcome::Acquired(DispatchWork::new(snapshot, authority)),
        ))
    }

    fn classify_claim_collision(
        &self,
        request: &DispatchClaimRequest,
    ) -> Result<ClaimedDispatch, StateError> {
        let mut client = self
            .connect()
            .map_err(|_| StateError::DispatchClaimOutcomeUnknown)?;
        let existing = client
            .query_opt(
                "SELECT transaction_id, claim_id, worker_id
                   FROM accordlock_dispatch_claims
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
                &[
                    &request.key.scope.tenant,
                    &request.key.scope.environment,
                    &request.key.authorization_id,
                ],
            )
            .map_err(|_| StateError::DispatchClaimOutcomeUnknown)?;
        if let Some(existing) = existing {
            return Err(Self::classify_existing_claim(request, &existing));
        }
        let claim_id_exists = client
            .query_opt(
                "SELECT claim_id FROM accordlock_dispatch_claims WHERE claim_id = $1",
                &[&request.claim_id],
            )
            .map_err(|_| StateError::DispatchClaimOutcomeUnknown)?
            .is_some();
        if claim_id_exists {
            Err(StateError::DispatchAlreadyClaimed)
        } else {
            Err(StateError::DispatchClaimOutcomeUnknown)
        }
    }

    fn revalidate_dispatch_claim_once(
        &self,
        token: &DispatchClaimToken,
    ) -> Result<DispatchSnapshot, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let preflight = Self::dispatch_claim_row_unlocked(&mut transaction, token.key())?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (preflight_token, preflight_state) =
            Self::token_from_claim_row(token.key(), &preflight)?;
        if preflight_token != *token {
            return Err(StateError::DispatchClaimMismatch);
        }
        if preflight_state == "ATTEMPT_IN_FLIGHT" {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        Self::require_legacy_bootstrap_preflight(&mut transaction, token)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, token.key())?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let state = Self::require_exact_claim(&mut transaction, token, state_instance_id)?;
        if state == "ATTEMPT_IN_FLIGHT" {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        if state != "CLAIMED" {
            return Err(StateError::InvalidRecord(format!(
                "unsupported dispatch-claim state {state}"
            )));
        }
        let acquisition = Self::latest_dispatch_acquisition(&mut transaction, token)?;
        if acquisition.acquisition_id != token.claim_id()
            || acquisition.control_submission_id.is_some()
            || acquisition.selection_kind != "LEGACY_BOOTSTRAP"
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let snapshot = match Self::validate_locked_dispatch_with_high_water(
            &mut transaction,
            token.key(),
            &inputs,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit()?;
                return Err(error);
            }
        };
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if snapshot.checked_at() >= acquisition.lease_until {
            transaction.commit()?;
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: acquisition.lease_until,
            });
        }
        transaction.commit()?;
        Ok(snapshot)
    }

    #[allow(clippy::too_many_lines)]
    fn mark_attempt_in_flight_once(
        &self,
        token: &DispatchClaimToken,
        credential: DispatchCredentialBinding,
    ) -> Result<AttemptInFlight, StateError> {
        if !credential.matches_token(token) {
            return Err(StateError::DispatchClaimMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let preflight = Self::dispatch_claim_row_unlocked(&mut transaction, token.key())?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (preflight_token, preflight_state) =
            Self::token_from_claim_row(token.key(), &preflight)?;
        if preflight_token != *token {
            return Err(StateError::DispatchClaimMismatch);
        }
        if preflight_state == "ATTEMPT_IN_FLIGHT" {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        Self::require_legacy_bootstrap_preflight(&mut transaction, token)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, token.key())?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let state = Self::require_exact_claim(&mut transaction, token, state_instance_id)?;
        if state == "ATTEMPT_IN_FLIGHT" {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        if state != "CLAIMED" {
            return Err(StateError::InvalidRecord(format!(
                "unsupported dispatch-claim state {state}"
            )));
        }
        let acquisition = Self::latest_dispatch_acquisition(&mut transaction, token)?;
        if acquisition.acquisition_id != token.claim_id()
            || acquisition.control_submission_id.is_some()
            || acquisition.selection_kind != "LEGACY_BOOTSTRAP"
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let authority = Self::dispatch_acquisition_authority(&acquisition);
        let credential = credential.into_v2(&authority)?;
        let snapshot = match Self::validate_locked_dispatch_with_high_water(
            &mut transaction,
            token.key(),
            &inputs,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit()?;
                return Err(error);
            }
        };
        if PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
            != *token.physical_resource()
        {
            return Err(StateError::DispatchClaimMismatch);
        }
        if snapshot.checked_at() >= acquisition.lease_until {
            transaction.commit()?;
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: acquisition.lease_until,
            });
        }
        if credential.not_before() > snapshot.checked_at()
            || credential.expires_at() <= snapshot.checked_at()
        {
            transaction.commit()?;
            return Err(StateError::DispatchCredentialExpired);
        }
        let credential_token_digest = credential.token_digest().to_string();
        let credential_binding_commitment = credential.commitment().to_string();
        let acquisition_lease_fence = i64::try_from(acquisition.lease_fence).map_err(|_| {
            StateError::InvalidRecord(
                "dispatch acquisition fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let updated = transaction.execute(
            "UPDATE accordlock_dispatch_claims
                SET state = 'ATTEMPT_IN_FLIGHT',
                    attempt_started_at = $5,
                    credential_token_digest = $6,
                    service_account_uid = $7,
                    credential_id = $8,
                    credential_not_before = $9,
                    credential_expires_at = $10,
                    credential_binding_commitment = $11,
                    attempt_acquisition_id = $12,
                    attempt_lease_fence = $13,
                    attempt_acquired_unix_s = $14,
                    attempt_lease_until = $15,
                    acquisition_binding_version = 2,
                    updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND claim_id = $4 AND state = 'CLAIMED'",
            &[
                &token.key().scope.tenant,
                &token.key().scope.environment,
                &token.key().authorization_id,
                &token.claim_id(),
                &snapshot.checked_at(),
                &credential_token_digest,
                &credential.service_account_uid(),
                &credential.credential_id(),
                &credential.not_before(),
                &credential.expires_at(),
                &credential_binding_commitment,
                &acquisition.acquisition_id,
                &acquisition_lease_fence,
                &acquisition.acquired_at,
                &acquisition.lease_until,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        transaction
            .commit()
            .map_err(|_| StateError::DispatchAttemptOutcomeUnknown)?;
        let started_at = snapshot.checked_at();
        Ok(AttemptInFlight::new(snapshot, authority, started_at))
    }

    fn broker_operation_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
        lock: bool,
    ) -> Result<Option<Row>, StateError> {
        let suffix = if lock { " FOR UPDATE" } else { "" };
        let sql = format!(
            "SELECT entry_id, tenant, environment, authorization_id, transaction_id,
                    claim_id, fence, state_instance_id, origin_acquisition_id,
                    origin_lease_fence, acquisition_binding_version, cluster_identity,
                    namespace, deployment_uid, route_commitment,
                    bound_secret_name, bound_secret_uid, operation, phase,
                    prepared_unix_s, started_unix_s,
                    credential_lifetime_upper_s,
                    credential_clock_uncertainty_s, credential_safe_after,
                    reconciliation_count, last_reconciliation_outcome,
                    last_reconciliation_evidence_commitment,
                    last_reconciled_unix_s, outcome,
                    provider_evidence_commitment, token_digest,
                    token_expires_at, request_commitment, result_commitment
               FROM accordlock_broker_operations
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND operation = $4{suffix}"
        );
        Ok(transaction.query_opt(
            &sql,
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &operation.database_name(),
            ],
        )?)
    }

    fn optional_digest(row: &Row, column: &str) -> Result<Option<Digest32>, StateError> {
        row.get::<_, Option<String>>(column)
            .map(|value| {
                Digest32::from_str(&value).map_err(|error| {
                    StateError::InvalidRecord(format!(
                        "stored broker digest {column} is not canonical: {error}"
                    ))
                })
            })
            .transpose()
    }

    fn stored_broker_operation(row: &Row) -> Result<StoredBrokerOperation, StateError> {
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| {
            StateError::InvalidRecord("stored broker fence is not a positive u64".to_owned())
        })?;
        let operation = BrokerJournalOperation::from_database(row.get("operation"))?;
        let origin_lease_fence_i64: i64 = row.get("origin_lease_fence");
        let origin_lease_fence = u64::try_from(origin_lease_fence_i64).map_err(|_| {
            StateError::InvalidRecord(
                "stored broker acquisition fence is not a positive u64".to_owned(),
            )
        })?;
        let lifetime: Option<i64> = row.get("credential_lifetime_upper_s");
        let uncertainty: Option<i64> = row.get("credential_clock_uncertainty_s");
        let credential_policy = match (lifetime, uncertainty) {
            (Some(lifetime), Some(uncertainty)) => Some(
                crate::broker::BrokerCredentialSafetyPolicy::new(lifetime, uncertainty)?,
            ),
            (None, None) => None,
            _ => {
                return Err(StateError::InvalidRecord(
                    "stored broker credential policy is partial".to_owned(),
                ));
            }
        };
        let route_commitment =
            Digest32::from_str(row.get("route_commitment")).map_err(|error| {
                StateError::InvalidRecord(format!(
                    "stored broker route commitment is not canonical: {error}"
                ))
            })?;
        let request_commitment =
            Digest32::from_str(row.get("request_commitment")).map_err(|error| {
                StateError::InvalidRecord(format!(
                    "stored broker request commitment is not canonical: {error}"
                ))
            })?;
        let outcome = row
            .get::<_, Option<String>>("outcome")
            .as_deref()
            .map(BrokerJournalOutcome::from_database)
            .transpose()?;
        let reconciliation_count_i64: i64 = row.get("reconciliation_count");
        let reconciliation_count = u64::try_from(reconciliation_count_i64).map_err(|_| {
            StateError::InvalidRecord("stored broker reconciliation count is negative".to_owned())
        })?;
        let last_reconciliation_outcome = row
            .get::<_, Option<String>>("last_reconciliation_outcome")
            .as_deref()
            .map(BrokerJournalOutcome::from_database)
            .transpose()?;
        let stored = StoredBrokerOperation {
            entry_id: row.get("entry_id"),
            key: ConsumeKey {
                scope: Scope {
                    tenant: row.get("tenant"),
                    environment: row.get("environment"),
                },
                transaction_id: row.get("transaction_id"),
                authorization_id: row.get("authorization_id"),
            },
            claim_id: row.get("claim_id"),
            fence,
            state_instance_id: row.get("state_instance_id"),
            origin_acquisition_id: row.get("origin_acquisition_id"),
            origin_lease_fence,
            acquisition_binding_version: row.get("acquisition_binding_version"),
            physical_resource: PhysicalResourceKey::new(
                row.get("cluster_identity"),
                row.get("namespace"),
                row.get("deployment_uid"),
            )?,
            route_commitment,
            bound_secret_name: row.get("bound_secret_name"),
            bound_secret_uid: row.get("bound_secret_uid"),
            operation,
            phase: BrokerJournalPhase::from_database(row.get("phase"))?,
            prepared_at: row.get("prepared_unix_s"),
            started_at: row.get("started_unix_s"),
            credential_policy,
            credential_safe_after: row.get("credential_safe_after"),
            reconciliation_count,
            last_reconciliation_outcome,
            last_reconciliation_evidence_commitment: Self::optional_digest(
                row,
                "last_reconciliation_evidence_commitment",
            )?,
            last_reconciled_at: row.get("last_reconciled_unix_s"),
            outcome,
            provider_evidence_commitment: Self::optional_digest(
                row,
                "provider_evidence_commitment",
            )?,
            token_digest: Self::optional_digest(row, "token_digest")?,
            token_expires_at: row.get("token_expires_at"),
            request_commitment,
            result_commitment: Self::optional_digest(row, "result_commitment")?,
        };
        stored.validate()?;
        Ok(stored)
    }

    fn secret_deletion_observation_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        lock: bool,
    ) -> Result<Option<Row>, StateError> {
        let suffix = if lock { " FOR SHARE" } else { "" };
        let sql = format!(
            "SELECT entry_id, tenant, environment, authorization_id, transaction_id,
                    claim_id, fence, state_instance_id, cluster_identity,
                    namespace, deployment_uid, route_commitment,
                    bound_secret_name, bound_secret_uid,
                    journal_request_commitment, journal_result_commitment,
                    provider_evidence_commitment,
                    reconciliation_floor_unix_s, observed_unix_s
               FROM accordlock_broker_secret_deletion_observations
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3{suffix}"
        );
        Ok(transaction.query_opt(
            &sql,
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )?)
    }

    fn stored_secret_deletion_observation(
        row: &Row,
    ) -> Result<StoredSecretDeletionObservation, StateError> {
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| {
            StateError::InvalidRecord(
                "stored Secret-deletion observation fence is invalid".to_owned(),
            )
        })?;
        let stored = StoredSecretDeletionObservation {
            entry_id: row.get("entry_id"),
            key: ConsumeKey {
                scope: Scope::new(
                    row.get::<_, String>("tenant"),
                    row.get::<_, String>("environment"),
                )?,
                transaction_id: row.get("transaction_id"),
                authorization_id: row.get("authorization_id"),
            },
            claim_id: row.get("claim_id"),
            fence,
            state_instance_id: row.get("state_instance_id"),
            physical_resource: PhysicalResourceKey::new(
                row.get("cluster_identity"),
                row.get("namespace"),
                row.get("deployment_uid"),
            )?,
            route_commitment: Self::canonical_digest_from_row(row, "route_commitment")?,
            bound_secret_name: row.get("bound_secret_name"),
            bound_secret_uid: row.get("bound_secret_uid"),
            journal_request_commitment: Self::canonical_digest_from_row(
                row,
                "journal_request_commitment",
            )?,
            journal_result_commitment: Self::canonical_digest_from_row(
                row,
                "journal_result_commitment",
            )?,
            provider_evidence_commitment: Self::canonical_digest_from_row(
                row,
                "provider_evidence_commitment",
            )?,
            reconciliation_floor_at: row.get("reconciliation_floor_unix_s"),
            observed_at: row.get("observed_unix_s"),
        };
        if stored.entry_id.is_nil()
            || stored.claim_id.is_nil()
            || stored.fence == 0
            || stored.state_instance_id.is_nil()
            || stored.reconciliation_floor_at <= 0
            || stored.observed_at < stored.reconciliation_floor_at
        {
            return Err(StateError::InvalidRecord(
                "stored Secret-deletion observation identity or time is invalid".to_owned(),
            ));
        }
        Ok(stored)
    }

    fn exact_broker_delete_absence(
        transaction: &mut Transaction<'_>,
        acquisition: &StoredDispatchAcquisition,
    ) -> Result<Option<i64>, StateError> {
        let key = acquisition.token.key();
        let Some(delete_row) = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        else {
            return Ok(None);
        };
        let delete = Self::stored_broker_operation(&delete_row)?;
        if delete.phase != BrokerJournalPhase::Committed
            || delete.outcome != Some(BrokerJournalOutcome::DeleteAbsent)
        {
            return Ok(None);
        }
        let create_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let versions_match = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => {
                create.acquisition_binding_version == 2 && delete.acquisition_binding_version == 2
            }
            "CONTROL_BOOTSTRAP_V13" => {
                create.acquisition_binding_version == 1
                    && matches!(delete.acquisition_binding_version, 1 | 2)
            }
            _ => false,
        };
        if !versions_match
            || create.key != *key
            || create.claim_id != acquisition.token.claim_id()
            || create.fence != acquisition.token.fence()
            || create.state_instance_id != acquisition.token.state_instance_id()
            || create.origin_acquisition_id != acquisition.acquisition_id
            || create.origin_lease_fence != acquisition.lease_fence
            || create.physical_resource != *acquisition.token.physical_resource()
            || delete.key != create.key
            || delete.claim_id != create.claim_id
            || delete.fence != create.fence
            || delete.state_instance_id != create.state_instance_id
            || delete.origin_acquisition_id != create.origin_acquisition_id
            || delete.origin_lease_fence != create.origin_lease_fence
            || delete.physical_resource != create.physical_resource
            || delete.route_commitment != create.route_commitment
            || delete.bound_secret_uid != create.bound_secret_uid
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let deletion_row = Self::secret_deletion_observation_row(transaction, key, true)?
            .ok_or(StateError::BrokerOperationMismatch)?;
        let deletion = Self::stored_secret_deletion_observation(&deletion_row)?;
        if deletion
            != StoredSecretDeletionObservation::from_committed_delete(
                &delete,
                deletion.observed_at,
            )?
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        Ok(Some(deletion.observed_at))
    }

    fn exact_broker_delete_terminal_conflict(
        transaction: &mut Transaction<'_>,
        acquisition: &StoredDispatchAcquisition,
    ) -> Result<bool, StateError> {
        let key = acquisition.token.key();
        let Some(delete_row) = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        else {
            return Ok(false);
        };
        let delete = Self::stored_broker_operation(&delete_row)?;
        if delete.phase != BrokerJournalPhase::Terminal
            || delete.outcome != Some(BrokerJournalOutcome::DeleteConflicting)
        {
            return Ok(false);
        }
        let create_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let versions_match = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => {
                create.acquisition_binding_version == 2 && delete.acquisition_binding_version == 2
            }
            "CONTROL_BOOTSTRAP_V13" => {
                create.acquisition_binding_version == 1
                    && matches!(delete.acquisition_binding_version, 1 | 2)
            }
            _ => false,
        };
        if !versions_match
            || create.key != *key
            || create.claim_id != acquisition.token.claim_id()
            || create.fence != acquisition.token.fence()
            || create.state_instance_id != acquisition.token.state_instance_id()
            || create.origin_acquisition_id != acquisition.acquisition_id
            || create.origin_lease_fence != acquisition.lease_fence
            || create.physical_resource != *acquisition.token.physical_resource()
            || delete.key != create.key
            || delete.claim_id != create.claim_id
            || delete.fence != create.fence
            || delete.state_instance_id != create.state_instance_id
            || delete.origin_acquisition_id != create.origin_acquisition_id
            || delete.origin_lease_fence != create.origin_lease_fence
            || delete.physical_resource != create.physical_resource
            || delete.route_commitment != create.route_commitment
            || delete.bound_secret_uid != create.bound_secret_uid
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        Ok(true)
    }

    fn insert_broker_intent(
        transaction: &mut Transaction<'_>,
        stored: &StoredBrokerOperation,
    ) -> Result<(), StateError> {
        let fence = i64::try_from(stored.fence).map_err(|_| {
            StateError::InvalidRecord("broker fence does not fit PostgreSQL BIGINT".to_owned())
        })?;
        let origin_lease_fence = i64::try_from(stored.origin_lease_fence).map_err(|_| {
            StateError::InvalidRecord(
                "broker acquisition fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let lifetime = stored
            .credential_policy
            .map(crate::broker::BrokerCredentialSafetyPolicy::lifetime_upper_bound_seconds);
        let uncertainty = stored
            .credential_policy
            .map(crate::broker::BrokerCredentialSafetyPolicy::clock_uncertainty_seconds);
        let inserted = transaction.execute(
            "INSERT INTO accordlock_broker_operations
                        (entry_id, tenant, environment, authorization_id, transaction_id,
                         claim_id, fence, state_instance_id, origin_acquisition_id,
                         origin_lease_fence, acquisition_binding_version, cluster_identity,
                         namespace, deployment_uid, route_commitment,
                         bound_secret_name, bound_secret_uid, operation, phase,
                         prepared_unix_s, credential_lifetime_upper_s,
                         credential_clock_uncertainty_s, request_commitment)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, $15, $16, $17, $18,
                         'INTENT', $19, $20, $21, $22)",
            &[
                &stored.entry_id,
                &stored.key.scope.tenant,
                &stored.key.scope.environment,
                &stored.key.authorization_id,
                &stored.key.transaction_id,
                &stored.claim_id,
                &fence,
                &stored.state_instance_id,
                &stored.origin_acquisition_id,
                &origin_lease_fence,
                &stored.acquisition_binding_version,
                &stored.physical_resource.cluster_identity(),
                &stored.physical_resource.namespace(),
                &stored.physical_resource.deployment_uid(),
                &stored.route_commitment.to_string(),
                &stored.bound_secret_name,
                &stored.bound_secret_uid,
                &stored.operation.database_name(),
                &stored.prepared_at,
                &lifetime,
                &uncertainty,
                &stored.request_commitment.to_string(),
            ],
        )?;
        if inserted != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        Ok(())
    }

    fn require_broker_claim_lineage(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        expected: Option<&DispatchClaimToken>,
        state_instance_id: Uuid,
    ) -> Result<DispatchClaimToken, StateError> {
        let row =
            Self::dispatch_claim_row(transaction, key)?.ok_or(StateError::DispatchClaimNotFound)?;
        let (token, state) = Self::token_from_claim_row(key, &row)?;
        if token.state_instance_id() != state_instance_id
            || expected.is_some_and(|value| value != &token)
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        if expected.is_some() && state != "CLAIMED" {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        Ok(token)
    }

    fn matching_create_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        route_commitment: Digest32,
    ) -> Result<StoredBrokerOperation, StateError> {
        let row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let create = Self::stored_broker_operation(&row)?;
        if create.phase != BrokerJournalPhase::Committed
            || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
            || create.route_commitment != route_commitment
            || create.bound_secret_uid.is_none()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        Ok(create)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_broker_operation_once(
        &self,
        request: &BrokerOperationRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        let token = request.token();
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let preflight = Self::dispatch_claim_row_unlocked(&mut transaction, token.key())?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (preflight_token, preflight_state) =
            Self::token_from_claim_row(token.key(), &preflight)?;
        if preflight_token != *token {
            return Err(StateError::BrokerOperationMismatch);
        }
        if preflight_state != "CLAIMED" {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        Self::require_legacy_bootstrap_preflight(&mut transaction, token)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, token.key())?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        Self::require_broker_claim_lineage(
            &mut transaction,
            token.key(),
            Some(token),
            state_instance_id,
        )?;
        let acquisition = Self::latest_dispatch_acquisition(&mut transaction, token)?;
        if acquisition.acquisition_id != token.claim_id()
            || acquisition.control_submission_id.is_some()
            || acquisition.selection_kind != "LEGACY_BOOTSTRAP"
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let snapshot = match Self::validate_locked_dispatch_with_high_water(
            &mut transaction,
            token.key(),
            &inputs,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit()?;
                return Err(error);
            }
        };
        if snapshot.checked_at() >= token.lease_until() {
            transaction.commit()?;
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: token.lease_until(),
            });
        }
        let bound_secret_uid = if request.operation() == BrokerJournalOperation::IssueToken {
            Self::matching_create_row(&mut transaction, token.key(), request.route_commitment())?
                .bound_secret_uid
        } else {
            None
        };
        let existing =
            Self::broker_operation_row(&mut transaction, token.key(), request.operation(), true)?
                .map(|row| Self::stored_broker_operation(&row))
                .transpose()?;
        let candidate = StoredBrokerOperation::new_intent(
            existing
                .as_ref()
                .map_or_else(Uuid::new_v4, |stored| stored.entry_id),
            token.key().clone(),
            token.claim_id(),
            token.fence(),
            token.state_instance_id(),
            acquisition.acquisition_id,
            acquisition.lease_fence,
            token.physical_resource().clone(),
            request.route_commitment(),
            bound_secret_uid,
            request.operation(),
            snapshot.checked_at(),
            request.credential_policy(),
        )?;
        if let Some(existing) = existing {
            if !existing.same_request_material(&candidate) {
                return Err(StateError::BrokerOperationMismatch);
            }
            if existing.phase != BrokerJournalPhase::Intent {
                return Err(StateError::BrokerOperationOutcomeUnknown);
            }
            transaction.commit()?;
            return Ok(BrokerOperationIntent::new(existing));
        }
        Self::insert_broker_intent(&mut transaction, &candidate)?;
        transaction.commit()?;
        Ok(BrokerOperationIntent::new(candidate))
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_broker_cleanup_once(
        &self,
        request: &BrokerCleanupRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;

        // CREATE origin fields and acquisition links are immutable. Resolve
        // them without row locks, then take metadata and the optional control
        // submission root before authority/HWM/claim/broker locks. The DELETE
        // insert trigger takes that same root; taking it here prevents a
        // claim -> submission inversion with exact acquisition recovery.
        let preflight_create = Self::broker_operation_row(
            &mut transaction,
            request.key(),
            BrokerJournalOperation::CreateSecret,
            false,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?
        .ok_or(StateError::BrokerOperationNotFound)?;
        if preflight_create.phase != BrokerJournalPhase::Committed
            || preflight_create.outcome != Some(BrokerJournalOutcome::CreateMatching)
            || preflight_create.route_commitment != request.route_commitment()
            || preflight_create.bound_secret_uid.is_none()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let origin = Self::dispatch_acquisition_row(
            &mut transaction,
            preflight_create.origin_acquisition_id,
        )?
        .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if origin.acquisition_id != preflight_create.origin_acquisition_id
            || origin.lease_fence != preflight_create.origin_lease_fence
            || origin.token.key() != request.key()
            || origin.token.claim_id() != preflight_create.claim_id
            || origin.token.fence() != preflight_create.fence
            || origin.token.state_instance_id() != preflight_create.state_instance_id
            || origin.token.physical_resource() != &preflight_create.physical_resource
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let time_inputs = Self::lock_broker_time_inputs(
            &mut transaction,
            request.key(),
            preflight_create.origin_acquisition_id,
            preflight_create.origin_lease_fence,
        )?;
        let state_instance_id = origin.token.state_instance_id();
        let token = Self::require_broker_claim_lineage(
            &mut transaction,
            request.key(),
            None,
            state_instance_id,
        )?;
        let create =
            Self::matching_create_row(&mut transaction, request.key(), request.route_commitment())?;
        if create.entry_id != preflight_create.entry_id
            || create.origin_acquisition_id != origin.acquisition_id
            || create.origin_lease_fence != origin.lease_fence
            || token != origin.token
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        Self::validate_and_advance_broker_time(
            &mut transaction,
            request.key(),
            &time_inputs,
            observed_at,
        )?;
        let existing = Self::broker_operation_row(
            &mut transaction,
            request.key(),
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?;
        if let Some(existing) = &existing
            && existing.acquisition_binding_version == 1
        {
            if origin.selection_kind != "CONTROL_BOOTSTRAP_V13"
                || origin.acquisition_id != origin.token.claim_id()
                || origin.lease_fence != origin.token.fence()
                || create.acquisition_binding_version != 1
                || existing.phase != BrokerJournalPhase::Intent
                || existing.key != *request.key()
                || existing.claim_id != token.claim_id()
                || existing.fence != token.fence()
                || existing.state_instance_id != token.state_instance_id()
                || existing.origin_acquisition_id != create.origin_acquisition_id
                || existing.origin_lease_fence != create.origin_lease_fence
                || existing.physical_resource != *token.physical_resource()
                || existing.route_commitment != request.route_commitment()
                || existing.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            transaction.commit()?;
            return Ok(BrokerOperationIntent::new(existing.clone()));
        }
        let candidate = StoredBrokerOperation::new_intent(
            existing
                .as_ref()
                .map_or_else(Uuid::new_v4, |stored| stored.entry_id),
            request.key().clone(),
            token.claim_id(),
            token.fence(),
            token.state_instance_id(),
            create.origin_acquisition_id,
            create.origin_lease_fence,
            token.physical_resource().clone(),
            request.route_commitment(),
            create.bound_secret_uid,
            BrokerJournalOperation::DeleteSecret,
            observed_at,
            None,
        )?;
        if let Some(existing) = existing {
            if !existing.same_request_material(&candidate) {
                return Err(StateError::BrokerOperationMismatch);
            }
            if existing.phase != BrokerJournalPhase::Intent {
                return Err(StateError::BrokerOperationOutcomeUnknown);
            }
            transaction.commit()?;
            return Ok(BrokerOperationIntent::new(existing));
        }
        Self::insert_broker_intent(&mut transaction, &candidate)?;
        transaction.commit()?;
        Ok(BrokerOperationIntent::new(candidate))
    }

    #[allow(clippy::too_many_lines)]
    fn begin_broker_io_once(
        &self,
        expected: &StoredBrokerOperation,
    ) -> Result<BrokerIoAuthority, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        if expected.operation != BrokerJournalOperation::DeleteSecret
            && Self::control_submission_for_dispatch(&mut transaction, &expected.key)?.is_some()
        {
            return Err(StateError::DispatchAcquisitionRequired);
        }
        let cleanup_time_inputs = if expected.operation == BrokerJournalOperation::DeleteSecret {
            Some(Self::lock_broker_time_inputs(
                &mut transaction,
                &expected.key,
                expected.origin_acquisition_id,
                expected.origin_lease_fence,
            )?)
        } else {
            None
        };
        let legacy_inputs = if cleanup_time_inputs.is_none() {
            Some(Self::lock_dispatch_inputs(&mut transaction, &expected.key)?)
        } else {
            None
        };
        let inputs = cleanup_time_inputs
            .as_ref()
            .map(|locked| &locked.dispatch)
            .or(legacy_inputs.as_ref())
            .ok_or(StateError::BrokerOperationMismatch)?;
        let state_instance_id = if cleanup_time_inputs.is_some() {
            expected.state_instance_id
        } else {
            Self::locked_state_instance(&mut transaction)?
        };
        let token = Self::require_broker_claim_lineage(
            &mut transaction,
            &expected.key,
            None,
            state_instance_id,
        )?;
        if token.claim_id() != expected.claim_id
            || token.fence() != expected.fence
            || token.physical_resource() != &expected.physical_resource
            || token.state_instance_id() != expected.state_instance_id
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        if expected.operation != BrokerJournalOperation::DeleteSecret
            && token
                != Self::require_broker_claim_lineage(
                    &mut transaction,
                    &expected.key,
                    Some(&token),
                    state_instance_id,
                )?
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let observed_at = if expected.operation == BrokerJournalOperation::DeleteSecret {
            let observed_at = Self::sample_trusted_time(&mut transaction)?;
            Self::validate_and_advance_broker_time(
                &mut transaction,
                &expected.key,
                cleanup_time_inputs
                    .as_ref()
                    .ok_or(StateError::BrokerOperationMismatch)?,
                observed_at,
            )?;
            observed_at
        } else {
            let snapshot = match Self::validate_locked_dispatch_with_high_water(
                &mut transaction,
                &expected.key,
                inputs,
            )? {
                LockedDispatchValidation::Accepted(snapshot) => *snapshot,
                LockedDispatchValidation::TemporalRejection(error) => {
                    transaction.commit()?;
                    return Err(error);
                }
            };
            if snapshot.checked_at() >= token.lease_until() {
                transaction.commit()?;
                return Err(StateError::DispatchClaimLeaseExpired {
                    observed: snapshot.checked_at(),
                    lease_until: token.lease_until(),
                });
            }
            snapshot.checked_at()
        };
        let row =
            Self::broker_operation_row(&mut transaction, &expected.key, expected.operation, true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let stored = Self::stored_broker_operation(&row)?;
        if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
            return Err(StateError::BrokerOperationMismatch);
        }
        if stored.phase != BrokerJournalPhase::Intent {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let safe_after = stored
            .credential_policy
            .map(|policy| policy.safe_after(observed_at))
            .transpose()?;
        let updated = transaction.execute(
            "UPDATE accordlock_broker_operations
                SET phase = 'IN_FLIGHT', started_unix_s = $5,
                    credential_safe_after = $6,
                    updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND operation = $4 AND phase = 'INTENT'",
            &[
                &expected.key.scope.tenant,
                &expected.key.scope.environment,
                &expected.key.authorization_id,
                &expected.operation.database_name(),
                &observed_at,
                &safe_after,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        transaction
            .commit()
            .map_err(|_| StateError::BrokerOperationOutcomeUnknown)?;
        let mut in_flight = stored;
        in_flight.phase = BrokerJournalPhase::InFlight;
        in_flight.started_at = Some(observed_at);
        in_flight.credential_safe_after = safe_after;
        in_flight.validate()?;
        Ok(BrokerIoAuthority::new(in_flight))
    }

    fn broker_secret_result(
        expected: &StoredBrokerOperation,
        observation: &BrokerSecretObservation,
        direct_create: bool,
    ) -> Result<
        (
            BrokerJournalPhase,
            BrokerJournalOutcome,
            Option<String>,
            Digest32,
            Digest32,
        ),
        StateError,
    > {
        let evidence = observation.evidence_commitment();
        let (phase, outcome, uid) = match (expected.operation, observation) {
            (
                BrokerJournalOperation::CreateSecret,
                BrokerSecretObservation::Matching { secret_uid, .. },
            ) => (
                BrokerJournalPhase::Committed,
                BrokerJournalOutcome::CreateMatching,
                Some(secret_uid.clone()),
            ),
            (BrokerJournalOperation::CreateSecret, BrokerSecretObservation::Conflicting { .. })
                if !direct_create =>
            {
                (
                    BrokerJournalPhase::Terminal,
                    BrokerJournalOutcome::CreateConflicting,
                    None,
                )
            }
            (BrokerJournalOperation::DeleteSecret, BrokerSecretObservation::Absent { .. })
                if !direct_create =>
            {
                (
                    BrokerJournalPhase::Committed,
                    BrokerJournalOutcome::DeleteAbsent,
                    expected.bound_secret_uid.clone(),
                )
            }
            (
                BrokerJournalOperation::DeleteSecret,
                BrokerSecretObservation::Matching { .. }
                | BrokerSecretObservation::Conflicting { .. },
            ) if !direct_create => (
                BrokerJournalPhase::Terminal,
                BrokerJournalOutcome::DeleteConflicting,
                expected.bound_secret_uid.clone(),
            ),
            _ => return Err(StateError::BrokerOperationMismatch),
        };
        let result = broker_result_commitment(
            expected.request_commitment,
            outcome,
            uid.as_deref(),
            evidence,
            None,
            None,
        )?;
        Ok((phase, outcome, uid, evidence, result))
    }

    #[allow(clippy::too_many_lines)]
    fn commit_broker_secret_once(
        &self,
        expected: &StoredBrokerOperation,
        observation: &BrokerSecretObservation,
        direct_create: bool,
    ) -> Result<BrokerOperationReceipt, StateError> {
        let (phase, outcome, uid, evidence, result) =
            Self::broker_secret_result(expected, observation, direct_create)?;
        let is_final_delete = expected.operation == BrokerJournalOperation::DeleteSecret
            && phase == BrokerJournalPhase::Committed
            && outcome == BrokerJournalOutcome::DeleteAbsent;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        // Preserve the global lock order used by cleanup and terminalization:
        // dispatch lineage/high-water precedes the broker journal row.
        let deletion_clock = if is_final_delete {
            let locked = Self::lock_broker_time_inputs(
                &mut transaction,
                &expected.key,
                expected.origin_acquisition_id,
                expected.origin_lease_fence,
            )?;
            Some((locked, Self::sample_trusted_time(&mut transaction)?))
        } else {
            None
        };
        let row =
            Self::broker_operation_row(&mut transaction, &expected.key, expected.operation, true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let stored = Self::stored_broker_operation(&row)?;
        if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
            return Err(StateError::BrokerOperationMismatch);
        }
        if !direct_create && stored.reconciliation_count != expected.reconciliation_count {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        if stored.phase
            != if direct_create {
                BrokerJournalPhase::InFlight
            } else {
                BrokerJournalPhase::ReconcileOnly
            }
        {
            if stored.result_commitment == Some(result) {
                if is_final_delete {
                    let deletion_row = Self::secret_deletion_observation_row(
                        &mut transaction,
                        &expected.key,
                        true,
                    )?
                    .ok_or(StateError::BrokerOperationOutcomeUnknown)?;
                    let deletion = Self::stored_secret_deletion_observation(&deletion_row)?;
                    let exact = StoredSecretDeletionObservation::from_committed_delete(
                        &stored,
                        deletion.observed_at,
                    )?;
                    if deletion != exact {
                        return Err(StateError::BrokerOperationOutcomeUnknown);
                    }
                }
                transaction.commit()?;
                return Ok(BrokerOperationReceipt::new(stored.audit(), true));
            }
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let deletion_observed_at = if let Some((locked, observed_at)) = deletion_clock {
            Self::validate_and_advance_broker_time(
                &mut transaction,
                &expected.key,
                &locked,
                observed_at,
            )?;
            Some(observed_at)
        } else {
            None
        };
        let updated = transaction.execute(
            "UPDATE accordlock_broker_operations
                SET phase = $5, bound_secret_uid = $6, outcome = $7,
                    provider_evidence_commitment = $8,
                    result_commitment = $9, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND operation = $4 AND entry_id = $10 AND phase = $11",
            &[
                &expected.key.scope.tenant,
                &expected.key.scope.environment,
                &expected.key.authorization_id,
                &expected.operation.database_name(),
                &phase.database_name(),
                &uid,
                &outcome.database_name(),
                &evidence.to_string(),
                &result.to_string(),
                &expected.entry_id,
                &stored.phase.database_name(),
            ],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let mut committed = stored;
        committed.phase = phase;
        committed.bound_secret_uid = uid;
        committed.outcome = Some(outcome);
        committed.provider_evidence_commitment = Some(evidence);
        committed.result_commitment = Some(result);
        committed.validate()?;
        if let Some(observed_at) = deletion_observed_at {
            let deletion =
                StoredSecretDeletionObservation::from_committed_delete(&committed, observed_at)?;
            let fence = i64::try_from(deletion.fence).map_err(|_| {
                StateError::InvalidRecord(
                    "Secret-deletion observation fence does not fit BIGINT".to_owned(),
                )
            })?;
            let inserted = transaction.execute(
                "INSERT INTO accordlock_broker_secret_deletion_observations
                        (entry_id, tenant, environment, authorization_id, transaction_id,
                         claim_id, fence, state_instance_id,
                         cluster_identity, namespace, deployment_uid,
                         route_commitment, bound_secret_name,
                         bound_secret_uid, operation, phase,
                         started_unix_s, reconciliation_floor_unix_s,
                         outcome, journal_request_commitment,
                         journal_result_commitment,
                         provider_evidence_commitment, observed_unix_s)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, 'DELETE_SECRET', 'COMMITTED',
                         $15, $16, 'DELETE_ABSENT', $17, $18, $19, $20)",
                &[
                    &deletion.entry_id,
                    &deletion.key.scope.tenant,
                    &deletion.key.scope.environment,
                    &deletion.key.authorization_id,
                    &deletion.key.transaction_id,
                    &deletion.claim_id,
                    &fence,
                    &deletion.state_instance_id,
                    &deletion.physical_resource.cluster_identity(),
                    &deletion.physical_resource.namespace(),
                    &deletion.physical_resource.deployment_uid(),
                    &deletion.route_commitment.to_string(),
                    &deletion.bound_secret_name,
                    &deletion.bound_secret_uid,
                    &committed.started_at,
                    &deletion.reconciliation_floor_at,
                    &deletion.journal_request_commitment.to_string(),
                    &deletion.journal_result_commitment.to_string(),
                    &deletion.provider_evidence_commitment.to_string(),
                    &deletion.observed_at,
                ],
            )?;
            if inserted != 1 {
                return Err(StateError::BrokerOperationOutcomeUnknown);
            }
        }
        transaction.commit()?;
        Ok(BrokerOperationReceipt::new(committed.audit(), false))
    }

    fn commit_broker_token_once(
        &self,
        expected: &StoredBrokerOperation,
        observation: &BrokerTokenIssueObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        if expected.operation != BrokerJournalOperation::IssueToken {
            return Err(StateError::BrokerOperationMismatch);
        }
        let result = broker_result_commitment(
            expected.request_commitment,
            BrokerJournalOutcome::TokenIssued,
            expected.bound_secret_uid.as_deref(),
            observation.evidence_commitment(),
            Some(observation.token_digest()),
            Some(observation.expires_at()),
        )?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let row =
            Self::broker_operation_row(&mut transaction, &expected.key, expected.operation, true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let stored = Self::stored_broker_operation(&row)?;
        if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
            return Err(StateError::BrokerOperationMismatch);
        }
        if stored.phase != BrokerJournalPhase::InFlight {
            if stored.result_commitment == Some(result) {
                transaction.commit()?;
                return Ok(BrokerOperationReceipt::new(stored.audit(), true));
            }
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let started_at = stored
            .started_at
            .ok_or(StateError::BrokerOperationMismatch)?;
        let safe_after = stored
            .credential_safe_after
            .ok_or(StateError::BrokerOperationMismatch)?;
        if observation.expires_at() <= started_at || observation.expires_at() > safe_after {
            return Err(StateError::BrokerOperationMismatch);
        }
        let updated = transaction.execute(
            "UPDATE accordlock_broker_operations
                SET phase = 'COMMITTED', outcome = 'TOKEN_ISSUED',
                    provider_evidence_commitment = $5, token_digest = $6,
                    token_expires_at = $7, result_commitment = $8,
                    updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3
                AND operation = $4 AND entry_id = $9
                AND phase = 'IN_FLIGHT'",
            &[
                &expected.key.scope.tenant,
                &expected.key.scope.environment,
                &expected.key.authorization_id,
                &expected.operation.database_name(),
                &observation.evidence_commitment().to_string(),
                &observation.token_digest().to_string(),
                &observation.expires_at(),
                &result.to_string(),
                &expected.entry_id,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        transaction.commit()?;
        let mut committed = stored;
        committed.phase = BrokerJournalPhase::Committed;
        committed.outcome = Some(BrokerJournalOutcome::TokenIssued);
        committed.provider_evidence_commitment = Some(observation.evidence_commitment());
        committed.token_digest = Some(observation.token_digest());
        committed.token_expires_at = Some(observation.expires_at());
        committed.result_commitment = Some(result);
        committed.validate()?;
        Ok(BrokerOperationReceipt::new(committed.audit(), false))
    }

    fn mark_broker_unknown_once(
        &self,
        expected: &StoredBrokerOperation,
    ) -> Result<BrokerOperationAudit, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let row =
            Self::broker_operation_row(&mut transaction, &expected.key, expected.operation, true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let mut stored = Self::stored_broker_operation(&row)?;
        if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
            return Err(StateError::BrokerOperationMismatch);
        }
        if stored.phase == BrokerJournalPhase::Unknown {
            transaction.commit()?;
            return Ok(stored.audit());
        }
        if stored.phase != BrokerJournalPhase::InFlight {
            return Err(StateError::BrokerOperationInvalidTransition);
        }
        let updated = transaction.execute(
            "UPDATE accordlock_broker_operations
                SET phase = 'UNKNOWN', updated_at = clock_timestamp()
              WHERE entry_id = $1 AND phase = 'IN_FLIGHT'",
            &[&expected.entry_id],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        transaction.commit()?;
        stored.phase = BrokerJournalPhase::Unknown;
        stored.validate()?;
        Ok(stored.audit())
    }

    fn begin_broker_reconciliation_once(
        &self,
        request: &BrokerReconciliationRequest,
    ) -> Result<BrokerReconciliationAuthority, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let preflight = Self::broker_operation_row(
            &mut transaction,
            request.key(),
            request.operation(),
            false,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?
        .ok_or(StateError::BrokerOperationNotFound)?;
        if preflight.route_commitment != request.route_commitment() {
            return Err(StateError::BrokerOperationMismatch);
        }
        let time_inputs = Self::lock_broker_time_inputs(
            &mut transaction,
            request.key(),
            preflight.origin_acquisition_id,
            preflight.origin_lease_fence,
        )?;
        let state_instance_id = preflight.state_instance_id;
        let token = Self::require_broker_claim_lineage(
            &mut transaction,
            request.key(),
            None,
            state_instance_id,
        )?;
        let row =
            Self::broker_operation_row(&mut transaction, request.key(), request.operation(), true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let mut stored = Self::stored_broker_operation(&row)?;
        if stored != preflight
            || stored.route_commitment != request.route_commitment()
            || token.claim_id() != stored.claim_id
            || token.fence() != stored.fence
            || token.physical_resource() != &stored.physical_resource
            || token.state_instance_id() != stored.state_instance_id
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        Self::validate_and_advance_broker_time(
            &mut transaction,
            request.key(),
            &time_inputs,
            observed_at,
        )?;
        match stored.phase {
            BrokerJournalPhase::Intent => {
                if stored.operation != BrokerJournalOperation::CreateSecret {
                    return Err(StateError::BrokerOperationInvalidTransition);
                }
                let updated = transaction.execute(
                    "UPDATE accordlock_broker_operations
                        SET phase = 'RECONCILE_ONLY', started_unix_s = $2,
                            updated_at = clock_timestamp()
                      WHERE entry_id = $1 AND phase = 'INTENT'
                        AND started_unix_s IS NULL",
                    &[&stored.entry_id, &observed_at],
                )?;
                if updated != 1 {
                    return Err(StateError::BrokerOperationOutcomeUnknown);
                }
                stored.started_at = Some(observed_at);
                stored.phase = BrokerJournalPhase::ReconcileOnly;
            }
            BrokerJournalPhase::InFlight | BrokerJournalPhase::Unknown => {
                let updated = transaction.execute(
                    "UPDATE accordlock_broker_operations
                        SET phase = 'RECONCILE_ONLY',
                            updated_at = clock_timestamp()
                      WHERE entry_id = $1 AND phase = $2",
                    &[&stored.entry_id, &stored.phase.database_name()],
                )?;
                if updated != 1 {
                    return Err(StateError::BrokerOperationOutcomeUnknown);
                }
                stored.phase = BrokerJournalPhase::ReconcileOnly;
            }
            BrokerJournalPhase::ReconcileOnly => {}
            _ => return Err(StateError::BrokerOperationInvalidTransition),
        }
        transaction.commit()?;
        stored.validate()?;
        Ok(BrokerReconciliationAuthority::new(stored))
    }

    fn commit_pending_broker_reconciliation_once(
        &self,
        expected: &StoredBrokerOperation,
        outcome: BrokerJournalOutcome,
        evidence: Digest32,
    ) -> Result<BrokerReconciliationResult, StateError> {
        let next_count = expected
            .reconciliation_count
            .checked_add(1)
            .ok_or(StateError::BrokerOperationOutcomeUnknown)?;
        let expected_count_i64 = i64::try_from(expected.reconciliation_count)
            .map_err(|_| StateError::BrokerOperationOutcomeUnknown)?;
        let next_count_i64 =
            i64::try_from(next_count).map_err(|_| StateError::BrokerOperationOutcomeUnknown)?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let time_inputs = Self::lock_broker_time_inputs(
            &mut transaction,
            &expected.key,
            expected.origin_acquisition_id,
            expected.origin_lease_fence,
        )?;
        let state_instance_id = expected.state_instance_id;
        let token = Self::require_broker_claim_lineage(
            &mut transaction,
            &expected.key,
            None,
            state_instance_id,
        )?;
        if token.claim_id() != expected.claim_id
            || token.fence() != expected.fence
            || token.physical_resource() != &expected.physical_resource
            || token.state_instance_id() != expected.state_instance_id
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let row =
            Self::broker_operation_row(&mut transaction, &expected.key, expected.operation, true)?
                .ok_or(StateError::BrokerOperationNotFound)?;
        let mut stored = Self::stored_broker_operation(&row)?;
        if !stored.matches_intent(expected) || !stored.same_request_material(expected) {
            return Err(StateError::BrokerOperationMismatch);
        }
        if stored.phase != BrokerJournalPhase::ReconcileOnly
            || stored.reconciliation_count != expected.reconciliation_count
        {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        Self::validate_and_advance_broker_time(
            &mut transaction,
            &expected.key,
            &time_inputs,
            observed_at,
        )?;
        let updated = transaction.execute(
            "UPDATE accordlock_broker_operations
                SET reconciliation_count = $2,
                    last_reconciliation_outcome = $3,
                    last_reconciliation_evidence_commitment = $4,
                    last_reconciled_unix_s = $5,
                    updated_at = clock_timestamp()
              WHERE entry_id = $1 AND phase = 'RECONCILE_ONLY'
                AND reconciliation_count = $6",
            &[
                &expected.entry_id,
                &next_count_i64,
                &outcome.database_name(),
                &evidence.to_string(),
                &observed_at,
                &expected_count_i64,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        transaction.commit()?;
        stored.reconciliation_count = next_count;
        stored.last_reconciliation_outcome = Some(outcome);
        stored.last_reconciliation_evidence_commitment = Some(evidence);
        stored.last_reconciled_at = Some(observed_at);
        stored.validate()?;
        Ok(BrokerReconciliationResult::Pending(
            BrokerReconciliationAuthority::new(stored),
        ))
    }

    fn commit_broker_reconciliation_once(
        &self,
        expected: &StoredBrokerOperation,
        observation: &BrokerSecretObservation,
    ) -> Result<BrokerReconciliationResult, StateError> {
        if let Some((outcome, evidence)) = pending_broker_reconciliation(expected, observation) {
            self.commit_pending_broker_reconciliation_once(expected, outcome, evidence)
        } else {
            self.commit_broker_secret_once(expected, observation, false)
                .map(BrokerReconciliationResult::Completed)
        }
    }

    fn load_stored_broker_operation(
        &self,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
    ) -> Result<StoredBrokerOperation, StateError> {
        let mut client = self.connect()?;
        let mut transaction = client.build_transaction().read_only(true).start()?;
        let row = Self::broker_operation_row(&mut transaction, key, operation, false)?
            .ok_or(StateError::BrokerOperationNotFound)?;
        let stored = Self::stored_broker_operation(&row)?;
        transaction.commit()?;
        Ok(stored)
    }

    fn registry_authority_domain(
        row: &Row,
        root_column: &str,
        epoch_column: &str,
        activation_column: &str,
    ) -> Result<AuthorityDomainState, EksRegistryError> {
        let epoch: i64 = row.get(epoch_column);
        let epoch = u64::try_from(epoch).map_err(|_| {
            StateError::InvalidRecord(format!(
                "stored EKS authority epoch {epoch_column} is negative"
            ))
        })?;
        let activation_id: Uuid = row.get(activation_column);
        if activation_id.is_nil() {
            return Err(StateError::InvalidRecord(format!(
                "stored EKS authority activation {activation_column} is nil"
            ))
            .into());
        }
        Ok(AuthorityDomainState {
            root: Self::canonical_digest_from_row(row, root_column)?,
            epoch,
            activation_id,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn registry_destination_from_row(
        row: &Row,
        expected_scope: &Scope,
    ) -> Result<RootedEksDestination, EksRegistryError> {
        let scope = Scope::new(
            row.get::<_, String>("tenant"),
            row.get::<_, String>("environment"),
        )?;
        if &scope != expected_scope {
            return Err(EksRegistryError::ActivationConflict);
        }
        let port_i32: i32 = row.get("api_server_port");
        let port = u16::try_from(port_i32).map_err(|_| {
            StateError::InvalidRecord("stored EKS API-server port is invalid".to_owned())
        })?;
        let socket_text: String = row.get("socket_target");
        let socket_target = PinnedSocketTarget::parse_canonical(&socket_text).map_err(|error| {
            StateError::InvalidRecord(format!("stored EKS socket target is invalid: {error}"))
        })?;
        let ca_digest = Self::canonical_digest_from_row(row, "ca_trust_commitment")?;
        let ca_trust_commitment = CaTrustCommitment::from_sha256_bytes(*ca_digest.as_bytes())
            .map_err(|error| {
                StateError::InvalidRecord(format!("stored EKS CA commitment is invalid: {error}"))
            })?;

        let cluster_trust_domain: String = row.get("cluster_trust_domain");
        let cluster_identity: String = row.get("cluster_identity");
        let api_server_identity: String = row.get("api_server_identity");
        let dns_server_name: String = row.get("dns_server_name");
        let namespace: String = row.get("namespace");
        let deployment_name: String = row.get("deployment_name");
        let deployment_uid: String = row.get("deployment_uid");
        let attempt_service_account_name: String = row.get("attempt_service_account_name");
        let attempt_service_account_uid: String = row.get("attempt_service_account_uid");
        let token_audience: String = row.get("token_audience");
        let route = EksRouteProfile::new(EksRouteProfileInput {
            cluster_trust_domain: &cluster_trust_domain,
            cluster_identity: &cluster_identity,
            api_server_identity: &api_server_identity,
            dns_server_name: &dns_server_name,
            port,
            socket_target,
            ca_trust_commitment,
            namespace: &namespace,
            deployment_name: &deployment_name,
            deployment_uid: &deployment_uid,
            attempt_service_account_name: &attempt_service_account_name,
            attempt_service_account_uid: &attempt_service_account_uid,
            token_audience: &token_audience,
        })
        .map_err(|error| {
            StateError::InvalidRecord(format!("stored EKS route profile is invalid: {error}"))
        })?;
        let route_commitment = Digest32::from_bytes(*route.commitment().as_bytes()).to_string();
        if row.get::<_, String>("route_commitment") != route_commitment {
            return Err(StateError::InvalidRecord(
                "stored EKS route commitment does not match its fields".to_owned(),
            )
            .into());
        }

        let lifecycle_version: i16 = row.get("credential_lifecycle_schema_version");
        let lifecycle = EksCredentialLifecyclePolicy::new(
            row.get("requested_expiration_seconds"),
            row.get("server_lifetime_hard_max_seconds"),
            row.get("clock_uncertainty_seconds"),
            row.get("deletion_propagation_hard_max_seconds"),
        )
        .map_err(|error| {
            StateError::InvalidRecord(format!(
                "stored EKS credential lifecycle policy is invalid: {error}"
            ))
        })?;
        let lifecycle_commitment =
            Digest32::from_bytes(*lifecycle.commitment().as_bytes()).to_string();
        if lifecycle_version != i16::from(lifecycle.schema_version())
            || row.get::<_, String>("credential_lifecycle_policy_id") != lifecycle.policy_id()
            || row.get::<_, String>("credential_lifecycle_commitment") != lifecycle_commitment
        {
            return Err(StateError::InvalidRecord(
                "stored EKS credential lifecycle commitment does not match its fields".to_owned(),
            )
            .into());
        }

        let management_binding =
            |subject_column: &str,
             commitment_column: &str|
             -> Result<EksManagementAuthorityBinding, EksRegistryError> {
                let commitment = Self::canonical_digest_from_row(row, commitment_column)?;
                EksManagementAuthorityBinding::new(
                    row.get::<_, String>(subject_column),
                    *commitment.as_bytes(),
                )
                .map_err(|error| {
                    StateError::InvalidRecord(format!(
                        "stored EKS management authority binding is invalid: {error}"
                    ))
                    .into()
                })
            };
        let management = EksBrokerManagementBindings::new(
            management_binding(
                "secret_lifecycle_subject",
                "secret_lifecycle_rbac_commitment",
            )?,
            management_binding(
                "service_account_token_subject",
                "service_account_token_rbac_commitment",
            )?,
            management_binding("token_review_subject", "token_review_rbac_commitment")?,
        )
        .map_err(|error| {
            StateError::InvalidRecord(format!(
                "stored EKS management authority tuple is invalid: {error}"
            ))
        })?;
        let effective_rbac = Self::canonical_digest_from_row(row, "effective_rbac_commitment")?;
        let terminal =
            Self::canonical_digest_from_row(row, "terminal_witness_registry_commitment")?;
        let profile = EksDestinationProfile::new(
            route,
            *effective_rbac.as_bytes(),
            *terminal.as_bytes(),
            lifecycle,
            management,
        )?;
        if row.get::<_, String>("token_subject") != profile.token_subject() {
            return Err(StateError::InvalidRecord(
                "stored EKS token subject does not match the route".to_owned(),
            )
            .into());
        }

        let destination = RootedEksDestination {
            profile,
            resource_authority: Self::registry_authority_domain(
                row,
                "resource_root",
                "resource_epoch",
                "resource_activation_id",
            )?,
            mediation_authority: Self::registry_authority_domain(
                row,
                "mediation_root",
                "mediation_epoch",
                "mediation_activation_id",
            )?,
            activation_commitment: Self::canonical_digest_from_row(row, "activation_commitment")?,
        };
        destination.validate(expected_scope)?;
        Ok(destination)
    }

    fn registry_owner_from_row(row: &Row) -> Result<PhysicalOwner, EksRegistryError> {
        let ca = Self::canonical_digest_from_row(row, "ca_trust_commitment")?;
        Ok(PhysicalOwner {
            scope: Scope::new(
                row.get::<_, String>("tenant"),
                row.get::<_, String>("environment"),
            )?,
            cluster_identity: row.get("cluster_identity"),
            cluster_trust_domain: row.get("cluster_trust_domain"),
            physical_key: crate::eks_registry::PhysicalOwnershipKey {
                api_server_identity: row.get("api_server_identity"),
                namespace: row.get("namespace"),
                deployment_uid: row.get("deployment_uid"),
            },
            route_key: crate::eks_registry::PinnedRouteOwnershipKey {
                socket_target: row.get("socket_target"),
                ca_trust_commitment: ca,
                namespace: row.get("namespace"),
                deployment_uid: row.get("deployment_uid"),
            },
            first_resource_authority: Self::registry_authority_domain(
                row,
                "first_resource_root",
                "first_resource_epoch",
                "first_resource_activation_id",
            )?,
        })
    }

    fn registry_owner_row(
        transaction: &mut Transaction<'_>,
        owner: &PhysicalOwner,
        require_first_activation: bool,
    ) -> Result<Row, EksRegistryError> {
        let rows = transaction
            .query(
                "SELECT api_server_identity, namespace, deployment_uid,
                    tenant, environment, cluster_identity,
                    cluster_trust_domain, socket_target, ca_trust_commitment,
                    first_resource_root, first_resource_epoch,
                    first_resource_activation_id
               FROM accordlock_eks_physical_owners
              WHERE (api_server_identity = $1 AND namespace = $2
                     AND deployment_uid = $3)
                 OR (socket_target = $4 AND ca_trust_commitment = $5
                     AND namespace = $2 AND deployment_uid = $3)
              FOR SHARE",
                &[
                    &owner.physical_key.api_server_identity,
                    &owner.physical_key.namespace,
                    &owner.physical_key.deployment_uid,
                    &owner.route_key.socket_target,
                    &owner.route_key.ca_trust_commitment.to_string(),
                ],
            )
            .map_err(StateError::from)?;
        if rows.len() != 1 {
            return Err(if rows.is_empty() {
                EksRegistryError::NotFound
            } else {
                EksRegistryError::PhysicalAliasConflict
            });
        }
        let row = rows.into_iter().next().ok_or(EksRegistryError::NotFound)?;
        let stored = Self::registry_owner_from_row(&row)?;
        if !stored.same_immutable_ownership(owner) {
            return Err(EksRegistryError::PhysicalAliasConflict);
        }
        let first_activation_exists: bool = !require_first_activation
            || transaction
                .query_one(
                    "SELECT EXISTS (
                        SELECT 1
                          FROM accordlock_eks_destination_activations
                         WHERE tenant = $1 AND environment = $2
                           AND api_server_identity = $3 AND namespace = $4
                           AND deployment_uid = $5
                           AND resource_root = $6 AND resource_epoch = $7
                           AND resource_activation_id = $8
                    ) AS present",
                    &[
                        &stored.scope.tenant,
                        &stored.scope.environment,
                        &stored.physical_key.api_server_identity,
                        &stored.physical_key.namespace,
                        &stored.physical_key.deployment_uid,
                        &stored.first_resource_authority.root.to_string(),
                        &i64::try_from(stored.first_resource_authority.epoch).map_err(|_| {
                            StateError::InvalidRecord(
                                "stored first EKS resource epoch does not fit BIGINT".to_owned(),
                            )
                        })?,
                        &stored.first_resource_authority.activation_id,
                    ],
                )
                .map_err(StateError::from)?
                .get("present");
        if !first_activation_exists {
            return Err(EksRegistryError::ActivationConflict);
        }
        Ok(row)
    }

    const fn registry_activation_select() -> &'static str {
        "SELECT tenant, environment, state_instance_id,
                resource_root, resource_epoch, resource_activation_id,
                mediation_root, mediation_epoch, mediation_activation_id,
                activation_commitment, route_commitment,
                cluster_trust_domain, cluster_identity, api_server_identity,
                dns_server_name, api_server_port, socket_target,
                ca_trust_commitment, namespace, deployment_name,
                deployment_uid, attempt_service_account_name,
                attempt_service_account_uid, token_subject, token_audience,
                effective_rbac_commitment,
                terminal_witness_registry_commitment,
                credential_lifecycle_schema_version,
                credential_lifecycle_policy_id,
                credential_lifecycle_commitment,
                requested_expiration_seconds,
                server_lifetime_hard_max_seconds, clock_uncertainty_seconds,
                deletion_propagation_hard_max_seconds,
                secret_lifecycle_subject,
                secret_lifecycle_rbac_commitment,
                service_account_token_subject,
                service_account_token_rbac_commitment,
                token_review_subject, token_review_rbac_commitment
           FROM accordlock_eks_destination_activations
          WHERE tenant = $1 AND environment = $2
            AND resource_activation_id = $3
            AND mediation_activation_id = $4"
    }

    fn registry_destination_for_authority(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
        authority: &AuthorityVector,
    ) -> Result<RootedEksDestination, EksRegistryError> {
        let query = format!("{} FOR SHARE", Self::registry_activation_select());
        let rows = transaction
            .query(
                &query,
                &[
                    &scope.tenant,
                    &scope.environment,
                    &authority.resource.activation_id,
                    &authority.mediation.activation_id,
                ],
            )
            .map_err(StateError::from)?;
        if rows.len() != 1 {
            return Err(if rows.is_empty() {
                EksRegistryError::NotFound
            } else {
                EksRegistryError::Ambiguous
            });
        }
        let destination = Self::registry_destination_from_row(&rows[0], scope)?;
        if !destination.matches_authority(authority) {
            return Err(EksRegistryError::AuthorityRootMismatch);
        }
        let owner = destination.physical_owner(scope);
        Self::registry_owner_row(transaction, &owner, true)?;
        Ok(destination)
    }

    /// Loads the exact historical activation committed by the signed authorization.
    /// Frozen cleanup/recovery must not consult the current physical-owner
    /// projection: an authority rotation may legitimately replace that
    /// projection after CREATE while the old Secret still needs reconciliation
    /// or deletion.
    fn registry_frozen_destination_for_authority(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
        authority: &AuthorityVector,
    ) -> Result<RootedEksDestination, EksRegistryError> {
        let query = format!("{} FOR SHARE", Self::registry_activation_select());
        let rows = transaction
            .query(
                &query,
                &[
                    &scope.tenant,
                    &scope.environment,
                    &authority.resource.activation_id,
                    &authority.mediation.activation_id,
                ],
            )
            .map_err(StateError::from)?;
        if rows.len() != 1 {
            return Err(if rows.is_empty() {
                EksRegistryError::NotFound
            } else {
                EksRegistryError::Ambiguous
            });
        }
        let destination = Self::registry_destination_from_row(&rows[0], scope)?;
        if !destination.matches_authority(authority) {
            return Err(EksRegistryError::AuthorityRootMismatch);
        }
        Ok(destination)
    }

    #[allow(clippy::too_many_lines)]
    fn activate_eks_destination_once(
        &self,
        scope: &Scope,
        profile: &EksDestinationProfile,
    ) -> Result<(), EksRegistryError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let authority_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )
            .map_err(StateError::from)?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let active: AuthorityVector = decode_json(authority_row.get("authority_json"))?;
        let destination = RootedEksDestination::activate(scope, profile, &active)?;
        let owner = destination.physical_owner(scope);
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let resource_epoch = i64::try_from(destination.resource_authority.epoch)
            .map_err(|_| EksRegistryError::InvalidProfile)?;
        let mediation_epoch = i64::try_from(destination.mediation_authority.epoch)
            .map_err(|_| EksRegistryError::InvalidProfile)?;
        transaction
            .execute(
                "INSERT INTO accordlock_eks_physical_owners
                        (api_server_identity, namespace, deployment_uid,
                         tenant, environment, cluster_identity,
                         cluster_trust_domain, socket_target,
                         ca_trust_commitment, first_resource_root,
                         first_resource_epoch, first_resource_activation_id,
                         state_instance_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13)
                 ON CONFLICT DO NOTHING",
                &[
                    &owner.physical_key.api_server_identity,
                    &owner.physical_key.namespace,
                    &owner.physical_key.deployment_uid,
                    &owner.scope.tenant,
                    &owner.scope.environment,
                    &owner.cluster_identity,
                    &owner.cluster_trust_domain,
                    &owner.route_key.socket_target,
                    &owner.route_key.ca_trust_commitment.to_string(),
                    &owner.first_resource_authority.root.to_string(),
                    &resource_epoch,
                    &owner.first_resource_authority.activation_id,
                    &state_instance_id,
                ],
            )
            .map_err(StateError::from)?;
        Self::registry_owner_row(&mut transaction, &owner, false)?;

        let route = profile.route();
        let lifecycle = profile.credential_lifecycle_policy();
        let management = profile.broker_management_bindings();
        let port = i32::from(route.port());
        let lifecycle_version = i16::from(lifecycle.schema_version());
        let lifecycle_commitment =
            Digest32::from_bytes(*lifecycle.commitment().as_bytes()).to_string();
        let secret_rbac =
            Digest32::from_bytes(management.secret_lifecycle().rbac_commitment()).to_string();
        let token_rbac =
            Digest32::from_bytes(management.service_account_token().rbac_commitment()).to_string();
        let review_rbac =
            Digest32::from_bytes(management.token_review().rbac_commitment()).to_string();
        transaction
            .execute(
                "INSERT INTO accordlock_eks_destination_activations
                        (tenant, environment, state_instance_id,
                         resource_root, resource_epoch, resource_activation_id,
                         mediation_root, mediation_epoch, mediation_activation_id,
                         activation_commitment, route_commitment,
                         cluster_trust_domain, cluster_identity,
                         api_server_identity, dns_server_name, api_server_port,
                         socket_target, ca_trust_commitment, namespace,
                         deployment_name, deployment_uid,
                         attempt_service_account_name,
                         attempt_service_account_uid, token_subject,
                         token_audience, effective_rbac_commitment,
                         terminal_witness_registry_commitment,
                         credential_lifecycle_schema_version,
                         credential_lifecycle_policy_id,
                         credential_lifecycle_commitment,
                         requested_expiration_seconds,
                         server_lifetime_hard_max_seconds,
                         clock_uncertainty_seconds,
                         deletion_propagation_hard_max_seconds,
                         secret_lifecycle_subject,
                         secret_lifecycle_rbac_commitment,
                         service_account_token_subject,
                         service_account_token_rbac_commitment,
                         token_review_subject, token_review_rbac_commitment)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, $15, $16, $17, $18, $19,
                         $20, $21, $22, $23, $24, $25, $26, $27, $28,
                         $29, $30, $31, $32, $33, $34, $35, $36, $37,
                         $38, $39, $40)
                 ON CONFLICT DO NOTHING",
                &[
                    &scope.tenant,
                    &scope.environment,
                    &state_instance_id,
                    &destination.resource_authority.root.to_string(),
                    &resource_epoch,
                    &destination.resource_authority.activation_id,
                    &destination.mediation_authority.root.to_string(),
                    &mediation_epoch,
                    &destination.mediation_authority.activation_id,
                    &destination.activation_commitment.to_string(),
                    &Digest32::from_bytes(*route.commitment().as_bytes()).to_string(),
                    &route.cluster_trust_domain(),
                    &route.cluster_identity(),
                    &route.api_server_identity(),
                    &route.dns_server_name(),
                    &port,
                    &route.socket_target().socket_addr().to_string(),
                    &Digest32::from_bytes(*route.ca_trust_commitment().as_bytes()).to_string(),
                    &route.namespace(),
                    &route.deployment_name(),
                    &route.deployment_uid(),
                    &route.attempt_service_account_name(),
                    &route.attempt_service_account_uid(),
                    &profile.token_subject(),
                    &route.token_audience(),
                    &profile.effective_rbac_commitment().to_string(),
                    &profile.terminal_witness_registry_commitment().to_string(),
                    &lifecycle_version,
                    &lifecycle.policy_id(),
                    &lifecycle_commitment,
                    &lifecycle.requested_expiration_seconds(),
                    &lifecycle.server_lifetime_hard_max_seconds(),
                    &lifecycle.clock_uncertainty_seconds(),
                    &lifecycle.deletion_propagation_hard_max_seconds(),
                    &management.secret_lifecycle().subject(),
                    &secret_rbac,
                    &management.service_account_token().subject(),
                    &token_rbac,
                    &management.token_review().subject(),
                    &review_rbac,
                ],
            )
            .map_err(StateError::from)?;
        let stored = Self::registry_destination_for_authority(&mut transaction, scope, &active)?;
        if stored != destination {
            return Err(EksRegistryError::ActivationConflict);
        }
        transaction.commit().map_err(StateError::from)?;
        Ok(())
    }

    fn registry_key_for_transaction(
        transaction: &mut Transaction<'_>,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<ConsumeKey, EksRegistryError> {
        let rows = transaction
            .query(
                "SELECT authorization_id
               FROM accordlock_issued_authorizations
              WHERE tenant = $1 AND environment = $2 AND transaction_id = $3
              FOR SHARE",
                &[&scope.tenant, &scope.environment, &transaction_id],
            )
            .map_err(StateError::from)?;
        if rows.len() != 1 {
            return Err(if rows.is_empty() {
                EksRegistryError::NotFound
            } else {
                EksRegistryError::Ambiguous
            });
        }
        Ok(ConsumeKey {
            scope: scope.clone(),
            transaction_id,
            authorization_id: rows[0].get("authorization_id"),
        })
    }

    fn registry_claim_for_attempt(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        physical: &PhysicalResourceKey,
        state_instance_id: Uuid,
    ) -> Result<(DispatchClaimToken, String), EksRegistryError> {
        let row = Self::dispatch_claim_row(transaction, key)?
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let (claim, state) = Self::token_from_claim_row(key, &row)?;
        if claim.state_instance_id() != state_instance_id || claim.physical_resource() != physical {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok((claim, state))
    }

    /// Gates the deprecated transaction-keyed EKS loaders before they take
    /// authority or high-water locks.  Productive control ownership is only
    /// available through the acquisition-aware loaders; this compatibility
    /// surface is strict non-control `LEGACY_BOOTSTRAP`.
    fn registry_legacy_bootstrap_preflight(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<DispatchClaimToken, EksRegistryError> {
        let row = Self::dispatch_claim_row_unlocked(transaction, key)?
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let (claim, _) = Self::token_from_claim_row(key, &row)?;
        Self::require_legacy_bootstrap_preflight(transaction, &claim)?;
        Ok(claim)
    }

    fn registry_preflight_current_claim(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<PhysicalResourceKey, EksRegistryError> {
        let authorization_row = transaction
            .query_opt(
                "SELECT transaction_id, grant_id, record_json, authorization_hash,
                        consume_before, state, issuance_profile_version,
                        request_id, evaluation_nonce
                   FROM accordlock_issued_authorizations
                  WHERE tenant = $1 AND environment = $2 AND authorization_id = $3",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                ],
            )
            .map_err(StateError::from)?
            .ok_or(StateError::AuthorizationNotFound)?;
        let issued = decode_stored_authorization_row(&authorization_row, key)?;
        if authorization_row.get::<_, String>("state") != "CONSUMED" {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let physical = PhysicalResourceKey::from_authorization(issued.authorization())?;
        let state_instance_id = Self::locked_state_instance(transaction)?;
        let row = Self::dispatch_claim_row_unlocked(transaction, key)?
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let (claim, state) = Self::token_from_claim_row(key, &row)?;
        Self::require_legacy_bootstrap_preflight(transaction, &claim)?;
        if claim.state_instance_id() != state_instance_id
            || claim.physical_resource() != &physical
            || !matches!(state.as_str(), "CLAIMED" | "ATTEMPT_IN_FLIGHT")
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok(physical)
    }

    fn registry_frozen_lineage(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        claim: &DispatchClaimToken,
        destination: &RootedEksDestination,
    ) -> Result<(), EksRegistryError> {
        let create_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let route = Digest32::from_bytes(*destination.profile.route().commitment().as_bytes());
        if create.key != *key
            || create.claim_id != claim.claim_id()
            || create.fence != claim.fence()
            || create.state_instance_id != claim.state_instance_id()
            || create.physical_resource != *claim.physical_resource()
            || create.route_commitment != route
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        if create.phase == BrokerJournalPhase::ReconcileOnly {
            return Ok(());
        }
        if create.phase != BrokerJournalPhase::Committed
            || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
            || create.bound_secret_uid.is_none()
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let delete_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let delete = Self::stored_broker_operation(&delete_row)?;
        if delete.key != *key
            || delete.claim_id != create.claim_id
            || delete.fence != create.fence
            || delete.state_instance_id != create.state_instance_id
            || delete.physical_resource != create.physical_resource
            || delete.route_commitment != create.route_commitment
            || delete.bound_secret_name != create.bound_secret_name
            || delete.bound_secret_uid != create.bound_secret_uid
            || !matches!(
                delete.phase,
                BrokerJournalPhase::InFlight
                    | BrokerJournalPhase::Unknown
                    | BrokerJournalPhase::ReconcileOnly
                    | BrokerJournalPhase::Committed
                    | BrokerJournalPhase::Terminal
            )
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn terminal_registry_from_state(
        transaction: &mut Transaction<'_>,
        registry_commitment: Digest32,
    ) -> Result<Option<(ActivatedWitnessRegistry, Scope, String, Uuid)>, StateError> {
        let header = transaction.query_opt(
            "SELECT registry_commitment, tenant, environment,
                    cluster_identity, material_root, registry_epoch,
                    registry_activation_id, entry_count, state_instance_id
               FROM accordlock_terminal_witness_registries
              WHERE registry_commitment = $1
              FOR SHARE",
            &[&registry_commitment.to_string()],
        )?;
        let Some(header) = header else {
            return Ok(None);
        };
        if Self::canonical_digest_from_row(&header, "registry_commitment")? != registry_commitment {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        let scope = Scope::new(
            header.get::<_, String>("tenant"),
            header.get::<_, String>("environment"),
        )?;
        let cluster_identity: String = header.get("cluster_identity");
        let state_instance_id: Uuid = header.get("state_instance_id");
        let epoch_i64: i64 = header.get("registry_epoch");
        let epoch =
            u64::try_from(epoch_i64).map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
        let authority = WitnessRegistryAuthority::new(
            Self::canonical_digest_from_row(&header, "material_root")?,
            epoch,
            header.get("registry_activation_id"),
        )
        .map_err(|error| StateError::TerminalEvidenceInvalid(error.to_string()))?;
        let entry_count_i16: i16 = header.get("entry_count");
        let entry_count = usize::try_from(entry_count_i16)
            .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
        let rows = transaction.query(
            "SELECT ordinal, tenant, environment, cluster_identity, role,
                    observer_identity, key_id, public_key, not_before,
                    valid_until, accepted_through, authority_version,
                    authorizing_root, status
               FROM accordlock_terminal_witness_registry_entries
              WHERE registry_commitment = $1
              ORDER BY ordinal
              FOR SHARE",
            &[&registry_commitment.to_string()],
        )?;
        if rows.len() != entry_count {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        let entries = rows
            .iter()
            .enumerate()
            .map(|(ordinal, row)| {
                let stored_ordinal: i16 = row.get("ordinal");
                if usize::try_from(stored_ordinal).ok() != Some(ordinal)
                    || row.get::<_, String>("tenant") != scope.tenant
                    || row.get::<_, String>("environment") != scope.environment
                    || row.get::<_, String>("cluster_identity") != cluster_identity
                {
                    return Err(StateError::TerminalWitnessRegistryMismatch);
                }
                let role = match row.get::<_, String>("role").as_str() {
                    "EXACT_EFFECT" => WitnessRole::ExactEffect,
                    "CREDENTIAL_RETIREMENT" => WitnessRole::CredentialRetirement,
                    _ => return Err(StateError::TerminalWitnessRegistryMismatch),
                };
                let status = match row.get::<_, String>("status").as_str() {
                    "ACTIVE" => WitnessVerifierStatus::Active,
                    "RETIRED" => WitnessVerifierStatus::Retired,
                    "REVOKED" => WitnessVerifierStatus::Revoked,
                    _ => return Err(StateError::TerminalWitnessRegistryMismatch),
                };
                let public_key: Vec<u8> = row.get("public_key");
                let public_key: [u8; 32] = public_key
                    .try_into()
                    .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
                let authority_version_i64: i64 = row.get("authority_version");
                let authority_version = u64::try_from(authority_version_i64)
                    .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
                RegisteredWitnessVerifier::new(
                    WitnessScope::new(scope.tenant.clone(), scope.environment.clone())
                        .map_err(|error| StateError::TerminalEvidenceInvalid(error.to_string()))?,
                    cluster_identity.clone(),
                    role,
                    row.get::<_, String>("observer_identity"),
                    row.get::<_, String>("key_id"),
                    public_key,
                    row.get("not_before"),
                    row.get("valid_until"),
                    row.get("accepted_through"),
                    authority_version,
                    Self::canonical_digest_from_row(row, "authorizing_root")?,
                    status,
                )
                .map_err(|error| StateError::TerminalEvidenceInvalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let registry = ActivatedWitnessRegistry::new(authority, entries)
            .map_err(|error| StateError::TerminalEvidenceInvalid(error.to_string()))?;
        if registry.commitment() != registry_commitment || state_instance_id.is_nil() {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        Ok(Some((registry, scope, cluster_identity, state_instance_id)))
    }

    #[allow(clippy::too_many_lines)]
    fn register_terminal_registry_once(
        &self,
        scope: &Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry: &ActivatedWitnessRegistry,
    ) -> Result<TerminalWitnessRegistryReceipt, StateError> {
        let first = registry
            .entries()
            .first()
            .ok_or(StateError::TerminalWitnessRegistryMismatch)?;
        let cluster_identity = first.cluster_identity();
        if registry.entries().iter().any(|entry| {
            entry.scope().tenant() != scope.tenant
                || entry.scope().environment() != scope.environment
                || entry.cluster_identity() != cluster_identity
        }) {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let destination_query = format!("{} FOR SHARE", Self::registry_activation_select());
        let destination_rows = transaction.query(
            &destination_query,
            &[
                &scope.tenant,
                &scope.environment,
                &resource_activation_id,
                &mediation_activation_id,
            ],
        )?;
        if destination_rows.len() != 1 {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        let destination = Self::registry_destination_from_row(&destination_rows[0], scope)
            .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;
        if destination_rows[0].get::<_, Uuid>("state_instance_id") != state_instance_id
            || destination.profile.route().cluster_identity() != cluster_identity
            || destination.profile.terminal_witness_registry_commitment() != registry.commitment()
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        let activation_commitment = destination.activation_commitment.to_string();
        let binding = transaction.query_opt(
            "SELECT registry_commitment, state_instance_id
               FROM accordlock_terminal_witness_registry_bindings
              WHERE tenant = $1 AND environment = $2
                AND resource_activation_id = $3
                AND mediation_activation_id = $4
              FOR UPDATE",
            &[
                &scope.tenant,
                &scope.environment,
                &resource_activation_id,
                &mediation_activation_id,
            ],
        )?;
        if let Some(binding) = binding {
            let commitment = Self::canonical_digest_from_row(&binding, "registry_commitment")?;
            let stored = Self::terminal_registry_from_state(&mut transaction, commitment)?
                .ok_or(StateError::TerminalWitnessRegistryNotFound)?;
            if commitment != registry.commitment()
                || binding.get::<_, Uuid>("state_instance_id") != state_instance_id
                || stored.1 != *scope
                || stored.2 != cluster_identity
                || stored.3 != state_instance_id
                || !same_activated_registry(&stored.0, registry)
            {
                return Err(StateError::TerminalWitnessRegistryMismatch);
            }
            transaction.commit()?;
            return Ok(TerminalWitnessRegistryReceipt::new(
                scope.clone(),
                resource_activation_id,
                mediation_activation_id,
                commitment,
                true,
            ));
        }

        if let Some(stored) =
            Self::terminal_registry_from_state(&mut transaction, registry.commitment())?
        {
            if stored.1 != *scope
                || stored.2 != cluster_identity
                || stored.3 != state_instance_id
                || !same_activated_registry(&stored.0, registry)
            {
                return Err(StateError::TerminalWitnessRegistryMismatch);
            }
        } else {
            let epoch = i64::try_from(registry.authority().epoch())
                .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
            let entry_count = i16::try_from(registry.len())
                .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
            transaction.execute(
                "INSERT INTO accordlock_terminal_witness_registries
                        (registry_commitment, tenant, environment,
                         cluster_identity, material_root, registry_epoch,
                         registry_activation_id, entry_count,
                         state_instance_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &registry.commitment().to_string(),
                    &scope.tenant,
                    &scope.environment,
                    &cluster_identity,
                    &registry.material_root().to_string(),
                    &epoch,
                    &registry.authority().activation_id(),
                    &entry_count,
                    &state_instance_id,
                ],
            )?;
            for (ordinal, entry) in registry.entries().iter().enumerate() {
                let ordinal = i16::try_from(ordinal)
                    .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
                let authority_version = i64::try_from(entry.authority_version())
                    .map_err(|_| StateError::TerminalWitnessRegistryMismatch)?;
                let role = match entry.role() {
                    WitnessRole::ExactEffect => "EXACT_EFFECT",
                    WitnessRole::CredentialRetirement => "CREDENTIAL_RETIREMENT",
                };
                let status = match entry.status() {
                    WitnessVerifierStatus::Active => "ACTIVE",
                    WitnessVerifierStatus::Retired => "RETIRED",
                    WitnessVerifierStatus::Revoked => "REVOKED",
                };
                transaction.execute(
                    "INSERT INTO accordlock_terminal_witness_registry_entries
                            (registry_commitment, ordinal, tenant, environment,
                             cluster_identity, role, observer_identity, key_id,
                             public_key, not_before, valid_until,
                             accepted_through, authority_version,
                             authorizing_root, status)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                             $11, $12, $13, $14, $15)",
                    &[
                        &registry.commitment().to_string(),
                        &ordinal,
                        &scope.tenant,
                        &scope.environment,
                        &cluster_identity,
                        &role,
                        &entry.observer_identity(),
                        &entry.key_id(),
                        &&entry.public_key()[..],
                        &entry.not_before(),
                        &entry.valid_until(),
                        &entry.accepted_through(),
                        &authority_version,
                        &entry.authorizing_root().to_string(),
                        &status,
                    ],
                )?;
            }
        }
        transaction.execute(
            "INSERT INTO accordlock_terminal_witness_registry_bindings
                    (tenant, environment, resource_activation_id,
                     mediation_activation_id,
                     destination_activation_commitment, cluster_identity,
                     registry_commitment, state_instance_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &scope.tenant,
                &scope.environment,
                &resource_activation_id,
                &mediation_activation_id,
                &activation_commitment,
                &cluster_identity,
                &registry.commitment().to_string(),
                &state_instance_id,
            ],
        )?;
        transaction.commit()?;
        Ok(TerminalWitnessRegistryReceipt::new(
            scope.clone(),
            resource_activation_id,
            mediation_activation_id,
            registry.commitment(),
            false,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn locked_terminal_inputs(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
    ) -> Result<(LockedTerminalInputs, String), StateError> {
        let lineage =
            Self::lock_post_attempt_lineage(transaction, key, true).map_err(
                |error| match error {
                    error @ StateError::Database(_) => error,
                    _ => StateError::TerminalRetirementLineageUnavailable,
                },
            )?;
        validate_recovered_consumption(
            key,
            &lineage.time_inputs.dispatch.issued,
            &lineage.time_inputs.dispatch.receipt,
            &lineage.time_inputs.dispatch.outbox,
        )?;
        let state_instance_id = lineage.token.state_instance_id();
        let claim_row =
            Self::dispatch_claim_row(transaction, key)?.ok_or(StateError::DispatchClaimNotFound)?;
        let (claim, claim_state) = Self::token_from_claim_row(key, &claim_row)?;
        if claim != lineage.token
            || !matches!(claim_state.as_str(), "ATTEMPT_IN_FLIGHT" | "TERMINAL")
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        let terminalization_id: Option<Uuid> = claim_row.get("terminalization_id");
        if (claim_state == "TERMINAL") != terminalization_id.is_some() {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        if claim.state_instance_id() != state_instance_id
            || PhysicalResourceKey::from_authorization(
                lineage.time_inputs.dispatch.issued.authorization(),
            )? != *claim.physical_resource()
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        let destination = Self::registry_frozen_destination_for_authority(
            transaction,
            &key.scope,
            &lineage
                .time_inputs
                .dispatch
                .issued
                .authorization()
                .authority,
        )
        .map_err(|error| match error {
            EksRegistryError::State(error @ StateError::Database(_)) => error,
            _ => StateError::TerminalRetirementLineageUnavailable,
        })?;
        let facts = derive_attempt_facts(
            &key.scope,
            key.transaction_id,
            key.authorization_id,
            lineage
                .time_inputs
                .dispatch
                .issued
                .authorization()
                .template_hash,
            &lineage.time_inputs.dispatch.issued.authorization().template,
            &destination,
        )
        .map_err(|_| StateError::TerminalRetirementLineageUnavailable)?;
        let activation = ActivationKey {
            scope: key.scope.clone(),
            resource_activation_id: lineage
                .time_inputs
                .dispatch
                .issued
                .authorization()
                .authority
                .resource
                .activation_id,
            mediation_activation_id: lineage
                .time_inputs
                .dispatch
                .issued
                .authorization()
                .authority
                .mediation
                .activation_id,
        };

        let admission_uid_row = transaction
            .query_opt(
                "SELECT admission_uid
                   FROM accordlock_admission_authorizations
                  WHERE tenant = $1 AND environment = $2
                    AND transaction_id = $3
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.transaction_id,
                ],
            )?
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let admission_uid: String = admission_uid_row.get("admission_uid");
        let admission_row = Self::admission_authorization_row(transaction, &admission_uid, true)?
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let admission = Self::stored_admission_from_row(&admission_row)?;

        let create_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let issue_row =
            Self::broker_operation_row(transaction, key, BrokerJournalOperation::IssueToken, true)?
                .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let delete_row = Self::broker_operation_row(
            transaction,
            key,
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let issue = Self::stored_broker_operation(&issue_row)?;
        let delete = Self::stored_broker_operation(&delete_row)?;
        let deletion_row = Self::secret_deletion_observation_row(transaction, key, true)?
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let deletion = Self::stored_secret_deletion_observation(&deletion_row)?;
        if deletion
            != StoredSecretDeletionObservation::from_committed_delete(
                &delete,
                deletion.observed_at,
            )?
        {
            return Err(StateError::TerminalRetirementLineageUnavailable);
        }
        let context = derive_terminal_context(TerminalDurableInputs {
            claim: &claim,
            attempt_started_at: lineage.started_at,
            credential: &lineage.credential,
            activation: &activation,
            facts: &facts,
            admission: &admission.request,
            create: &create,
            issue: &issue,
            delete: &delete,
            deletion: &deletion,
        })?;
        let binding = transaction
            .query_opt(
                "SELECT registry_commitment, state_instance_id
                   FROM accordlock_terminal_witness_registry_bindings
                  WHERE tenant = $1 AND environment = $2
                    AND resource_activation_id = $3
                    AND mediation_activation_id = $4
                  FOR SHARE",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &activation.resource_activation_id,
                    &activation.mediation_activation_id,
                ],
            )?
            .ok_or(StateError::TerminalWitnessRegistryNotFound)?;
        let registry_commitment = Self::canonical_digest_from_row(&binding, "registry_commitment")?;
        let registry_state = Self::terminal_registry_from_state(transaction, registry_commitment)?
            .ok_or(StateError::TerminalWitnessRegistryNotFound)?;
        if registry_commitment != context.registry_commitment()
            || binding.get::<_, Uuid>("state_instance_id") != state_instance_id
            || registry_state.1 != key.scope
            || registry_state.2 != facts.route().cluster_identity()
            || registry_state.3 != state_instance_id
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        Ok((
            LockedTerminalInputs {
                context,
                claim,
                registry: registry_state.0,
                time_inputs: lineage.time_inputs,
                terminalization_id,
            },
            claim_state,
        ))
    }

    fn terminal_retirement_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        lock: bool,
    ) -> Result<Option<Row>, StateError> {
        let suffix = if lock { " FOR UPDATE" } else { "" };
        let sql = format!(
            "SELECT terminalization_id, tenant, environment, authorization_id,
                    transaction_id, claim_id, fence, state_instance_id,
                    cluster_identity, namespace, deployment_uid,
                    resource_activation_id, mediation_activation_id,
                    attempt_binding_commitment, registry_commitment,
                    admission_uid, admission_request_commitment,
                    effect_evidence_id, effect_envelope_commitment,
                    effect_envelope, retirement_evidence_id,
                    retirement_envelope_commitment, retirement_envelope,
                    deletion_journal_entry_id,
                    deletion_observation_commitment, finalized_unix_s,
                    terminal_record_commitment
               FROM accordlock_terminal_retirements
              WHERE tenant = $1 AND environment = $2 AND authorization_id = $3{suffix}"
        );
        Ok(transaction.query_opt(
            &sql,
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
            ],
        )?)
    }

    fn stored_terminal_retirement(row: &Row) -> Result<StoredTerminalRetirement, StateError> {
        let fence_i64: i64 = row.get("fence");
        let fence = u64::try_from(fence_i64).map_err(|_| StateError::TerminalRetirementMismatch)?;
        let stored = StoredTerminalRetirement {
            audit: TerminalRetirementAudit {
                terminalization_id: row.get("terminalization_id"),
                key: ConsumeKey {
                    scope: Scope::new(
                        row.get::<_, String>("tenant"),
                        row.get::<_, String>("environment"),
                    )?,
                    transaction_id: row.get("transaction_id"),
                    authorization_id: row.get("authorization_id"),
                },
                claim_id: row.get("claim_id"),
                fence,
                state_instance_id: row.get("state_instance_id"),
                physical_resource: PhysicalResourceKey::new(
                    row.get("cluster_identity"),
                    row.get("namespace"),
                    row.get("deployment_uid"),
                )?,
                attempt_binding_commitment: Self::canonical_digest_from_row(
                    row,
                    "attempt_binding_commitment",
                )?,
                registry_commitment: Self::canonical_digest_from_row(row, "registry_commitment")?,
                effect_evidence_id: row.get("effect_evidence_id"),
                effect_envelope_commitment: Self::canonical_digest_from_row(
                    row,
                    "effect_envelope_commitment",
                )?,
                retirement_evidence_id: row.get("retirement_evidence_id"),
                retirement_envelope_commitment: Self::canonical_digest_from_row(
                    row,
                    "retirement_envelope_commitment",
                )?,
                deletion_journal_entry_id: row.get("deletion_journal_entry_id"),
                deletion_observation_commitment: Self::canonical_digest_from_row(
                    row,
                    "deletion_observation_commitment",
                )?,
                finalized_at: row.get("finalized_unix_s"),
                terminal_record_commitment: Self::canonical_digest_from_row(
                    row,
                    "terminal_record_commitment",
                )?,
            },
            resource_activation_id: row.get("resource_activation_id"),
            mediation_activation_id: row.get("mediation_activation_id"),
            admission_uid: row.get("admission_uid"),
            admission_request_commitment: Self::canonical_digest_from_row(
                row,
                "admission_request_commitment",
            )?,
            effect_envelope: row.get("effect_envelope"),
            retirement_envelope: row.get("retirement_envelope"),
        };
        stored.validate()?;
        Ok(stored)
    }

    fn terminal_collision_exists(
        transaction: &mut Transaction<'_>,
        request: &TerminalRetirementRequest,
        effect_evidence_id: Uuid,
        retirement_evidence_id: Uuid,
    ) -> Result<bool, StateError> {
        let effect_commitment = Digest32::sha256(request.effect_envelope()).to_string();
        let retirement_commitment = Digest32::sha256(request.retirement_envelope()).to_string();
        Ok(transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM accordlock_terminal_retirements
                     WHERE terminalization_id = $1
                        OR effect_evidence_id = $2
                        OR retirement_evidence_id = $3
                        OR effect_envelope_commitment = $4
                        OR retirement_envelope_commitment = $5
                ) AS present",
                &[
                    &request.terminalization_id(),
                    &effect_evidence_id,
                    &retirement_evidence_id,
                    &effect_commitment,
                    &retirement_commitment,
                ],
            )?
            .get("present"))
    }

    #[allow(clippy::too_many_lines)]
    fn finalize_terminal_retirement_once(
        &self,
        request: &TerminalRetirementRequest,
    ) -> Result<TerminalRetirementReceipt, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (inputs, claim_state) = Self::locked_terminal_inputs(&mut transaction, request.key())?;
        let existing = Self::terminal_retirement_row(&mut transaction, request.key(), true)?;

        if claim_state == "TERMINAL" {
            let row = existing.ok_or(StateError::TerminalRetirementOutcomeUnknown)?;
            let stored = Self::stored_terminal_retirement(&row)?;
            if inputs.terminalization_id != Some(request.terminalization_id())
                || !stored.exact_request(request)
                || !stored.matches_context_and_claim(&inputs.context, &inputs.claim)?
            {
                return Err(StateError::TerminalRetirementMismatch);
            }
            let evidence =
                authenticate_terminal_evidence(&inputs.context, &inputs.registry, request)?;
            // Recovery re-verifies both historical signatures against the
            // exact persisted registry material and the original finalization
            // time; it does not merely trust stored commitments.
            validate_terminal_evidence_time(&evidence, stored.audit.finalized_at())?;
            transaction.commit()?;
            return Ok(TerminalRetirementReceipt::new(stored.audit, true));
        }
        if claim_state != "ATTEMPT_IN_FLIGHT"
            || inputs.terminalization_id.is_some()
            || existing.is_some()
        {
            return Err(StateError::TerminalRetirementMismatch);
        }

        // Authenticate both purpose-separated signatures and every durable
        // binding before sampling trusted time. Invalid cryptography and
        // mismatches are therefore HWM-inert.
        let evidence = authenticate_terminal_evidence(&inputs.context, &inputs.registry, request)?;
        if Self::terminal_collision_exists(
            &mut transaction,
            request,
            evidence.effect.claims().evidence_id(),
            evidence.retirement.claims().evidence_id(),
        )? {
            return Err(StateError::TerminalRetirementMismatch);
        }

        let trusted_now = Self::sample_trusted_time(&mut transaction)?;
        let high_water = Self::broker_time_high_water(&inputs.time_inputs);
        if let Err(error) =
            validate_cleanup_clock(&request.key().scope, Some(high_water), trusted_now)
        {
            if matches!(error, StateError::ClockRollback { .. }) {
                transaction.commit()?;
            }
            return Err(error);
        }
        if let Err(error) = validate_terminal_evidence_time(&evidence, trusted_now) {
            Self::validate_and_advance_broker_time(
                &mut transaction,
                request.key(),
                &inputs.time_inputs,
                trusted_now,
            )?;
            transaction.commit()?;
            return Err(error);
        }
        let stored = StoredTerminalRetirement::new(
            request,
            &inputs.claim,
            &inputs.context,
            &evidence.effect,
            &evidence.retirement,
            trusted_now,
        )?;
        stored.validate()?;
        let fence = i64::try_from(stored.audit.fence())
            .map_err(|_| StateError::TerminalRetirementMismatch)?;
        let inserted = transaction.execute(
            "INSERT INTO accordlock_terminal_retirements
                    (terminalization_id, tenant, environment, authorization_id,
                     transaction_id, claim_id, fence, state_instance_id,
                     cluster_identity, namespace, deployment_uid,
                     resource_activation_id, mediation_activation_id,
                     attempt_binding_commitment, registry_commitment,
                     admission_uid, admission_request_commitment,
                     effect_evidence_id, effect_envelope_commitment,
                     effect_envelope, retirement_evidence_id,
                     retirement_envelope_commitment, retirement_envelope,
                     deletion_journal_entry_id,
                     deletion_observation_commitment, finalized_unix_s,
                     terminal_record_commitment)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16, $17, $18, $19,
                     $20, $21, $22, $23, $24, $25, $26, $27)",
            &[
                &stored.audit.terminalization_id(),
                &stored.audit.key().scope.tenant,
                &stored.audit.key().scope.environment,
                &stored.audit.key().authorization_id,
                &stored.audit.key().transaction_id,
                &stored.audit.claim_id(),
                &fence,
                &stored.audit.state_instance_id(),
                &stored.audit.physical_resource().cluster_identity(),
                &stored.audit.physical_resource().namespace(),
                &stored.audit.physical_resource().deployment_uid(),
                &stored.resource_activation_id,
                &stored.mediation_activation_id,
                &stored.audit.attempt_binding_commitment().to_string(),
                &stored.audit.registry_commitment().to_string(),
                &stored.admission_uid,
                &stored.admission_request_commitment.to_string(),
                &stored.audit.effect_evidence_id(),
                &stored.audit.effect_envelope_commitment().to_string(),
                &stored.effect_envelope,
                &stored.audit.retirement_evidence_id(),
                &stored.audit.retirement_envelope_commitment().to_string(),
                &stored.retirement_envelope,
                &stored.audit.deletion_journal_entry_id(),
                &stored.audit.deletion_observation_commitment().to_string(),
                &stored.audit.finalized_at(),
                &stored.audit.terminal_record_commitment().to_string(),
            ],
        )?;
        if inserted != 1 {
            return Err(StateError::TerminalRetirementOutcomeUnknown);
        }
        let updated = transaction.execute(
            "UPDATE accordlock_dispatch_claims
                SET state = 'TERMINAL', terminalization_id = $1,
                    updated_at = clock_timestamp()
              WHERE tenant = $2 AND environment = $3 AND authorization_id = $4
                AND transaction_id = $5 AND claim_id = $6 AND fence = $7
                AND state_instance_id = $8 AND cluster_identity = $9
                AND namespace = $10 AND deployment_uid = $11
                AND state = 'ATTEMPT_IN_FLIGHT'
                AND terminalization_id IS NULL",
            &[
                &stored.audit.terminalization_id(),
                &stored.audit.key().scope.tenant,
                &stored.audit.key().scope.environment,
                &stored.audit.key().authorization_id,
                &stored.audit.key().transaction_id,
                &stored.audit.claim_id(),
                &fence,
                &stored.audit.state_instance_id(),
                &stored.audit.physical_resource().cluster_identity(),
                &stored.audit.physical_resource().namespace(),
                &stored.audit.physical_resource().deployment_uid(),
            ],
        )?;
        if updated != 1 {
            return Err(StateError::TerminalRetirementOutcomeUnknown);
        }
        Self::validate_and_advance_broker_time(
            &mut transaction,
            request.key(),
            &inputs.time_inputs,
            trusted_now,
        )?;
        transaction.commit()?;
        Ok(TerminalRetirementReceipt::new(stored.audit, false))
    }

    fn terminal_retirement_audit_once(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementAudit, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (inputs, claim_state) = Self::locked_terminal_inputs(&mut transaction, key)?;
        let row = Self::terminal_retirement_row(&mut transaction, key, true)?
            .ok_or(StateError::TerminalRetirementLineageUnavailable)?;
        let stored = Self::stored_terminal_retirement(&row)?;
        if claim_state != "TERMINAL"
            || inputs.terminalization_id != Some(stored.audit.terminalization_id())
            || !stored.matches_context_and_claim(&inputs.context, &inputs.claim)?
        {
            return Err(StateError::TerminalRetirementMismatch);
        }
        let request = TerminalRetirementRequest::new(
            key.clone(),
            stored.audit.terminalization_id(),
            stored.effect_envelope.clone(),
            stored.retirement_envelope.clone(),
        )?;
        let evidence = authenticate_terminal_evidence(&inputs.context, &inputs.registry, &request)?;
        // Audit is an independent historical revalidation: reconstruct every
        // expected binding from durable state, reload the exact v11-rooted
        // registry material, and verify both signatures at finalized_at.
        validate_terminal_evidence_time(&evidence, stored.audit.finalized_at())?;
        transaction.commit()?;
        Ok(stored.audit)
    }

    fn load_current_eks_attempt_once(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let key = Self::registry_key_for_transaction(&mut transaction, scope, transaction_id)?;
        let preflight_physical = Self::registry_preflight_current_claim(&mut transaction, &key)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, &key)?;
        let snapshot = match Self::validate_locked_dispatch_with_high_water(
            &mut transaction,
            &key,
            &inputs,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => {
                transaction.commit().map_err(StateError::from)?;
                return Err(error.into());
            }
        };
        let physical = PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?;
        if physical != preflight_physical {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let (claim, claim_state) =
            Self::registry_claim_for_attempt(&mut transaction, &key, &physical, state_instance_id)?;
        if !matches!(claim_state.as_str(), "CLAIMED" | "ATTEMPT_IN_FLIGHT") {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        if snapshot.checked_at() >= claim.lease_until() {
            let error = StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: claim.lease_until(),
            };
            transaction.commit().map_err(StateError::from)?;
            return Err(error.into());
        }
        let destination = Self::registry_destination_for_authority(
            &mut transaction,
            scope,
            snapshot.authority(),
        )?;
        let facts = derive_attempt_facts(
            scope,
            transaction_id,
            key.authorization_id,
            snapshot.issued().authorization().template_hash,
            &snapshot.issued().authorization().template,
            &destination,
        )?;
        if facts.physical_resource() != claim.physical_resource() {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let current = CurrentEksAttempt::new(
            facts,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
        );
        transaction.commit().map_err(StateError::from)?;
        Ok(current)
    }

    fn load_frozen_eks_attempt_once(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let key = Self::registry_key_for_transaction(&mut transaction, scope, transaction_id)?;
        Self::registry_legacy_bootstrap_preflight(&mut transaction, &key)?;
        let inputs = Self::lock_dispatch_inputs(&mut transaction, &key)?;
        validate_recovered_consumption(&key, &inputs.issued, &inputs.receipt, &inputs.outbox)?;
        let physical = PhysicalResourceKey::from_authorization(inputs.issued.authorization())?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let (claim, _) =
            Self::registry_claim_for_attempt(&mut transaction, &key, &physical, state_instance_id)?;
        let destination = Self::registry_frozen_destination_for_authority(
            &mut transaction,
            scope,
            &inputs.issued.authorization().authority,
        )?;
        Self::registry_frozen_lineage(&mut transaction, &key, &claim, &destination)?;
        let facts = derive_attempt_facts(
            scope,
            transaction_id,
            key.authorization_id,
            inputs.issued.authorization().template_hash,
            &inputs.issued.authorization().template,
            &destination,
        )?;
        transaction.commit().map_err(StateError::from)?;
        Ok(FrozenEksAttempt::new(facts))
    }

    /// Reloads a committed consumption as one database statement and validates
    /// every redundant identity and payload field before returning it.
    fn recover_exact(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        key.validate()?;
        let mut client = self.connect()?;
        let row = client
            .query_opt(
                "SELECT consumption.receipt_json,
                        consumption.consumed_unix_s,
                        consumption.dispatch_deadline AS receipt_deadline,
                        outbox.entry_json,
                        outbox.dispatch_deadline AS outbox_deadline,
                        outbox.status AS outbox_status,
                        issued.record_json,
                        issued.transaction_id,
                        issued.grant_id,
                        issued.authorization_hash,
                        issued.consume_before,
                        issued.issuance_profile_version,
                        issued.request_id,
                        issued.evaluation_nonce,
                        issued.state AS authorization_state
                   FROM accordlock_consumptions AS consumption
                   JOIN accordlock_execution_outbox AS outbox
                     ON outbox.tenant = consumption.tenant
                    AND outbox.environment = consumption.environment
                    AND outbox.authorization_id = consumption.authorization_id
                    AND outbox.transaction_id = consumption.transaction_id
                   JOIN accordlock_issued_authorizations AS issued
                     ON issued.tenant = consumption.tenant
                    AND issued.environment = consumption.environment
                    AND issued.authorization_id = consumption.authorization_id
                    AND issued.transaction_id = consumption.transaction_id
                  WHERE consumption.tenant = $1
                    AND consumption.environment = $2
                    AND consumption.authorization_id = $3
                    AND consumption.transaction_id = $4",
                &[
                    &key.scope.tenant,
                    &key.scope.environment,
                    &key.authorization_id,
                    &key.transaction_id,
                ],
            )?
            .ok_or(StateError::ConsumptionNotFound)?;

        let receipt: ConsumptionReceipt = decode_json(row.get("receipt_json"))?;
        let outbox: OutboxEntry = decode_json(row.get("entry_json"))?;
        let issued = decode_stored_authorization_row(&row, key)?;

        let consumed_unix_s: i64 = row.get("consumed_unix_s");
        let receipt_deadline: i64 = row.get("receipt_deadline");
        let outbox_deadline: i64 = row.get("outbox_deadline");
        let outbox_status: String = row.get("outbox_status");
        let authorization_state: String = row.get("authorization_state");

        if consumed_unix_s != receipt.consumed_at
            || receipt_deadline != receipt.dispatch_deadline
            || outbox_deadline != outbox.dispatch_deadline
            || outbox_status != "PENDING_WITNESS"
            || authorization_state != "CONSUMED"
        {
            return Err(StateError::InvalidRecord(
                "stored consumption, outbox, and authorization columns do not agree with their JSON"
                    .to_owned(),
            ));
        }

        let success = validate_recovered_consumption(key, &issued, &receipt, &outbox)?;
        validate_postgres_control_consumption_lineage_if_owned(
            &mut client,
            key,
            &issued,
            &receipt,
        )?;
        Ok(success)
    }
}

impl PostgresStore {
    #[allow(clippy::too_many_lines, clippy::type_complexity)]
    fn lock_current_control_acquisition(
        transaction: &mut Transaction<'_>,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<
        (
            crate::control::StoredControlSubmission,
            IngressReplayScope,
            i64,
            i64,
            LockedDispatchInputs,
            StoredDispatchAcquisition,
        ),
        StateError,
    > {
        authority.claim().key().validate()?;
        // Global v14 order is metadata -> control-submission root ->
        // authority -> ingress HWM -> scope HWM -> claim/acquisition.  In
        // particular, never acquire metadata after the submission root: the
        // frozen cleanup and terminal paths take metadata first.
        let state_instance_id = Self::locked_state_instance(transaction)?;
        if state_instance_id != authority.claim().state_instance_id() {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let submission_id = authority
            .control_submission_id()
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let stored = control_plane::load_submission_for_update(transaction, submission_id)?;
        if stored.submission_id != submission_id
            || stored.scope() != authority.claim().key().scope
            || stored.state_instance_id != authority.claim().state_instance_id()
        {
            return Err(StateError::ControlWorkMismatch);
        }
        control_plane::validate_dispatch_pending_lineage(
            transaction,
            &stored,
            authority.claim().key(),
        )?;
        if Self::dispatch_queue_disposition(transaction, None, Some(submission_id))?.is_some() {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let (replay_scope, ingress_high_water, scope_high_water, inputs) =
            Self::lock_v14_dispatch_inputs(transaction, &stored, authority.claim().key())?;
        let claim_state =
            Self::require_exact_claim(transaction, authority.claim(), state_instance_id)?;
        if claim_state != "CLAIMED" {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let acquisition = Self::latest_dispatch_acquisition(transaction, authority.claim())?;
        if acquisition.selection_kind != "CONTROL_QUEUE"
            || acquisition.control_submission_id != Some(submission_id)
            || Self::dispatch_acquisition_authority(&acquisition) != *authority
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let artifacts = transaction.query_one(
            "SELECT EXISTS (
                        SELECT 1 FROM public.accordlock_admission_authorizations
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4
                    ) AS has_admission,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_terminal_retirements
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4
                    ) AS has_terminal",
            &[
                &authority.claim().key().scope.tenant,
                &authority.claim().key().scope.environment,
                &authority.claim().key().authorization_id,
                &authority.claim().key().transaction_id,
            ],
        )?;
        if artifacts.get::<_, bool>("has_admission") || artifacts.get::<_, bool>("has_terminal") {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        for operation in [
            BrokerJournalOperation::CreateSecret,
            BrokerJournalOperation::IssueToken,
            BrokerJournalOperation::DeleteSecret,
        ] {
            let Some(row) =
                Self::broker_operation_row(transaction, authority.claim().key(), operation, true)?
            else {
                continue;
            };
            let broker = Self::stored_broker_operation(&row)?;
            if operation == BrokerJournalOperation::DeleteSecret
                || broker.acquisition_binding_version != 2
                || broker.claim_id != authority.claim().claim_id()
                || broker.fence != authority.claim().fence()
                || broker.state_instance_id != authority.claim().state_instance_id()
                || broker.origin_acquisition_id != authority.acquisition_id()
                || broker.origin_lease_fence != authority.lease_fence()
                || broker.physical_resource != *authority.claim().physical_resource()
            {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
        }
        if let Some(row) = transaction.query_opt(
            "SELECT acquisition_id, tenant, environment, authorization_id, transaction_id
               FROM public.accordlock_dispatch_credential_reviews
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
              FOR SHARE",
            &[
                &authority.claim().key().scope.tenant,
                &authority.claim().key().scope.environment,
                &authority.claim().key().authorization_id,
            ],
        )? && (row.get::<_, Uuid>("acquisition_id") != authority.acquisition_id()
            || row.get::<_, Uuid>("transaction_id") != authority.claim().key().transaction_id)
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        Ok((
            stored,
            replay_scope,
            ingress_high_water,
            scope_high_water,
            inputs,
            acquisition,
        ))
    }

    fn validate_current_control_acquisition(
        transaction: &mut Transaction<'_>,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<(DispatchSnapshot, StoredDispatchAcquisition), StateError> {
        let (stored, replay_scope, ingress_high_water, scope_high_water, inputs, acquisition) =
            Self::lock_current_control_acquisition(transaction, authority)?;
        let observed_at = Self::sample_trusted_time(transaction)?;
        let snapshot = match Self::validate_locked_dispatch_with_dual_high_water(
            transaction,
            &stored,
            &replay_scope,
            ingress_high_water,
            scope_high_water,
            authority.claim().key(),
            &inputs,
            observed_at,
        )? {
            LockedDispatchValidation::Accepted(snapshot) => *snapshot,
            LockedDispatchValidation::TemporalRejection(error) => return Err(error),
        };
        if snapshot.receipt().dispatch_deadline != acquisition.dispatch_deadline
            || snapshot.checked_at() < acquisition.acquired_at
            || PhysicalResourceKey::from_authorization(snapshot.issued().authorization())?
                != *authority.claim().physical_resource()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if snapshot.checked_at() >= acquisition.lease_until {
            return Err(StateError::DispatchClaimLeaseExpired {
                observed: snapshot.checked_at(),
                lease_until: acquisition.lease_until,
            });
        }
        Ok((snapshot, acquisition))
    }

    fn revalidate_dispatch_acquisition_once(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<DispatchSnapshot, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (snapshot, _) =
            Self::validate_current_control_acquisition(&mut transaction, authority)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    fn begin_broker_operation_for_acquisition_once(
        &self,
        authority: &DispatchAcquisitionAuthority,
        request: &AcquiredBrokerOperationRequest,
    ) -> Result<BrokerIoAuthority, StateError> {
        authority.claim().key().validate()?;
        if !request.matches_authority(authority) {
            return Err(StateError::BrokerOperationMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (snapshot, acquisition) =
            Self::validate_current_control_acquisition(&mut transaction, authority)?;
        let bound_secret_uid = if request.operation() == BrokerJournalOperation::IssueToken {
            let create = Self::matching_create_row(
                &mut transaction,
                authority.claim().key(),
                request.route_commitment(),
            )?;
            if create.acquisition_binding_version != 2
                || create.origin_acquisition_id != acquisition.acquisition_id
                || create.origin_lease_fence != acquisition.lease_fence
                || create.claim_id != authority.claim().claim_id()
                || create.fence != authority.claim().fence()
                || create.state_instance_id != authority.claim().state_instance_id()
                || create.physical_resource != *authority.claim().physical_resource()
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            Some(
                create
                    .bound_secret_uid
                    .ok_or(StateError::BrokerOperationMismatch)?,
            )
        } else {
            None
        };
        let candidate = StoredBrokerOperation::new_intent(
            Uuid::new_v4(),
            authority.claim().key().clone(),
            authority.claim().claim_id(),
            authority.claim().fence(),
            authority.claim().state_instance_id(),
            acquisition.acquisition_id,
            acquisition.lease_fence,
            authority.claim().physical_resource().clone(),
            request.route_commitment(),
            bound_secret_uid,
            request.operation(),
            snapshot.checked_at(),
            request.credential_policy(),
        )?;
        let stored = if let Some(row) = Self::broker_operation_row(
            &mut transaction,
            authority.claim().key(),
            request.operation(),
            true,
        )? {
            let existing = Self::stored_broker_operation(&row)?;
            if !existing.same_request_material(&candidate) {
                return Err(StateError::BrokerOperationMismatch);
            }
            if existing.phase != BrokerJournalPhase::Intent {
                return Err(StateError::BrokerOperationOutcomeUnknown);
            }
            existing
        } else {
            Self::insert_broker_intent(&mut transaction, &candidate)?;
            candidate
        };
        let safe_after = stored
            .credential_policy
            .map(|policy| policy.safe_after(snapshot.checked_at()))
            .transpose()?;
        let updated = transaction.execute(
            "UPDATE public.accordlock_broker_operations
                SET phase='IN_FLIGHT', started_unix_s=$5,
                    credential_safe_after=$6, updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND operation=$4 AND entry_id=$7 AND phase='INTENT'",
            &[
                &authority.claim().key().scope.tenant,
                &authority.claim().key().scope.environment,
                &authority.claim().key().authorization_id,
                &request.operation().database_name(),
                &snapshot.checked_at(),
                &safe_after,
                &stored.entry_id,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::BrokerOperationOutcomeUnknown);
        }
        transaction
            .commit()
            .map_err(|_| StateError::BrokerOperationOutcomeUnknown)?;
        let mut started = stored;
        started.phase = BrokerJournalPhase::InFlight;
        started.started_at = Some(snapshot.checked_at());
        started.credential_safe_after = safe_after;
        started.validate()?;
        Ok(BrokerIoAuthority::new(started))
    }

    fn load_current_eks_attempt_for_acquisition_once(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (snapshot, _) =
            Self::validate_current_control_acquisition(&mut transaction, authority)?;
        let destination = Self::registry_destination_for_authority(
            &mut transaction,
            &authority.claim().key().scope,
            snapshot.authority(),
        )?;
        let facts = derive_attempt_facts(
            &authority.claim().key().scope,
            authority.claim().key().transaction_id,
            authority.claim().key().authorization_id,
            snapshot.issued().authorization().template_hash,
            &snapshot.issued().authorization().template,
            &destination,
        )?;
        if facts.physical_resource() != authority.claim().physical_resource() {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        let current = CurrentEksAttempt::new(
            facts,
            snapshot.checked_at(),
            snapshot.receipt().dispatch_deadline,
        );
        transaction.commit().map_err(StateError::from)?;
        Ok(current)
    }

    #[allow(clippy::too_many_lines)]
    fn load_frozen_eks_attempt_for_journal_once(
        &self,
        selector: &BrokerJournalSelector,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        selector.key().validate()?;
        if selector.entry_id().is_nil()
            || selector.origin_acquisition_id().is_nil()
            || selector.origin_lease_fence() == 0
            || selector.operation() == BrokerJournalOperation::IssueToken
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }

        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        // Frozen journal order is metadata -> optional control root ->
        // immutable dispatch inputs -> claim/acquisition journal. It never
        // consults current authority, the clock, or either HWM.
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let acquisition =
            Self::dispatch_acquisition_row(&mut transaction, selector.origin_acquisition_id())?
                .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        if acquisition.acquisition_id != selector.origin_acquisition_id()
            || acquisition.lease_fence != selector.origin_lease_fence()
            || acquisition.token.key() != selector.key()
            || acquisition.token.state_instance_id() != state_instance_id
            || !matches!(
                acquisition.claim_state.as_str(),
                "CLAIMED"
                    | "ATTEMPT_IN_FLIGHT"
                    | "RECOVERY_NO_SEND"
                    | "RECOVERY_RETIRED"
                    | "TERMINAL"
            )
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }
        match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13" => {
                let submission_id = acquisition
                    .control_submission_id
                    .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
                let submission =
                    control_plane::load_submission_for_update(&mut transaction, submission_id)?;
                if submission.submission_id != submission_id
                    || submission.scope() != acquisition.token.key().scope
                    || submission.state_instance_id != state_instance_id
                    || Self::control_submission_for_dispatch(
                        &mut transaction,
                        acquisition.token.key(),
                    )? != Some(submission_id)
                {
                    return Err(EksRegistryError::FrozenLineageUnavailable);
                }
                control_plane::validate_dispatch_pending_lineage(
                    &mut transaction,
                    &submission,
                    acquisition.token.key(),
                )?;
            }
            "LEGACY_BOOTSTRAP" if acquisition.control_submission_id.is_none() => {
                if Self::control_submission_for_dispatch(&mut transaction, acquisition.token.key())?
                    .is_some()
                {
                    return Err(EksRegistryError::FrozenLineageUnavailable);
                }
            }
            _ => return Err(EksRegistryError::FrozenLineageUnavailable),
        }

        let inputs = Self::lock_frozen_dispatch_inputs(&mut transaction, acquisition.token.key())?;
        let destination = Self::registry_frozen_destination_for_authority(
            &mut transaction,
            &acquisition.token.key().scope,
            &inputs.issued.authorization().authority,
        )?;
        let facts = derive_attempt_facts(
            &acquisition.token.key().scope,
            acquisition.token.key().transaction_id,
            acquisition.token.key().authorization_id,
            inputs.issued.authorization().template_hash,
            &inputs.issued.authorization().template,
            &destination,
        )?;
        let rooted_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());
        if facts.physical_resource() != acquisition.token.physical_resource() {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }

        let selected_row = Self::broker_operation_row(
            &mut transaction,
            selector.key(),
            selector.operation(),
            true,
        )?
        .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
        let selected = Self::stored_broker_operation(&selected_row)?;
        let valid_binding_version = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => selected.acquisition_binding_version == 2,
            "CONTROL_BOOTSTRAP_V13" => {
                selected.acquisition_binding_version == 1
                    || (selector.operation() == BrokerJournalOperation::DeleteSecret
                        && selected.acquisition_binding_version == 2)
            }
            "LEGACY_BOOTSTRAP" => matches!(selected.acquisition_binding_version, 1 | 2),
            _ => false,
        };
        if selected.entry_id != selector.entry_id()
            || selected.key != *selector.key()
            || selected.operation != selector.operation()
            || selected.request_commitment != selector.request_commitment()
            || selected.origin_acquisition_id != acquisition.acquisition_id
            || selected.origin_lease_fence != acquisition.lease_fence
            || selected.claim_id != acquisition.token.claim_id()
            || selected.fence != acquisition.token.fence()
            || selected.state_instance_id != state_instance_id
            || selected.physical_resource != *acquisition.token.physical_resource()
            || selected.route_commitment != rooted_route
            || !valid_binding_version
            || !matches!(
                selected.phase,
                BrokerJournalPhase::InFlight
                    | BrokerJournalPhase::Unknown
                    | BrokerJournalPhase::ReconcileOnly
                    | BrokerJournalPhase::Committed
                    | BrokerJournalPhase::Terminal
            )
        {
            return Err(EksRegistryError::FrozenLineageUnavailable);
        }

        if selector.operation() == BrokerJournalOperation::DeleteSecret {
            let create_row = Self::broker_operation_row(
                &mut transaction,
                selector.key(),
                BrokerJournalOperation::CreateSecret,
                true,
            )?
            .ok_or(EksRegistryError::FrozenLineageUnavailable)?;
            let create = Self::stored_broker_operation(&create_row)?;
            if create.phase != BrokerJournalPhase::Committed
                || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
                || create.bound_secret_uid.is_none()
                || create.claim_id != selected.claim_id
                || create.fence != selected.fence
                || create.state_instance_id != selected.state_instance_id
                || create.origin_acquisition_id != selected.origin_acquisition_id
                || create.origin_lease_fence != selected.origin_lease_fence
                || create.acquisition_binding_version != selected.acquisition_binding_version
                || create.physical_resource != selected.physical_resource
                || create.route_commitment != rooted_route
                || create.bound_secret_name != selected.bound_secret_name
                || create.bound_secret_uid != selected.bound_secret_uid
            {
                return Err(EksRegistryError::FrozenLineageUnavailable);
            }
        }

        transaction.commit().map_err(StateError::from)?;
        Ok(FrozenEksAttempt::new(facts))
    }

    fn encode_review_lifecycle(policy: EksCredentialLifecyclePolicy) -> Value {
        serde_json::json!({
            "schema_version": policy.schema_version(),
            "policy_id": policy.policy_id(),
            "requested_expiration_seconds": policy.requested_expiration_seconds(),
            "server_lifetime_hard_max_seconds": policy.server_lifetime_hard_max_seconds(),
            "clock_uncertainty_seconds": policy.clock_uncertainty_seconds(),
            "deletion_propagation_hard_max_seconds":
                policy.deletion_propagation_hard_max_seconds(),
        })
    }

    fn decode_review_lifecycle(value: &Value) -> Result<EksCredentialLifecyclePolicy, StateError> {
        let object = value.as_object().ok_or_else(|| {
            StateError::InvalidRecord(
                "stored credential-review lifecycle policy is not an object".to_owned(),
            )
        })?;
        let expected_keys = [
            "clock_uncertainty_seconds",
            "deletion_propagation_hard_max_seconds",
            "policy_id",
            "requested_expiration_seconds",
            "schema_version",
            "server_lifetime_hard_max_seconds",
        ];
        let mut actual_keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        actual_keys.sort_unstable();
        if actual_keys != expected_keys
            || object.get("schema_version").and_then(Value::as_u64) != Some(1)
            || object.get("policy_id").and_then(Value::as_str)
                != Some("eks-credential-lifecycle-v1")
        {
            return Err(StateError::InvalidRecord(
                "stored credential-review lifecycle policy has an invalid shape".to_owned(),
            ));
        }
        let integer = |name: &str| {
            object.get(name).and_then(Value::as_i64).ok_or_else(|| {
                StateError::InvalidRecord(format!(
                    "stored credential-review lifecycle field {name} is invalid"
                ))
            })
        };
        EksCredentialLifecyclePolicy::new(
            integer("requested_expiration_seconds")?,
            integer("server_lifetime_hard_max_seconds")?,
            integer("clock_uncertainty_seconds")?,
            integer("deletion_propagation_hard_max_seconds")?,
        )
        .map_err(|error| {
            StateError::InvalidRecord(format!(
                "stored credential-review lifecycle policy is invalid: {error}"
            ))
        })
    }

    fn dispatch_credential_review_row(
        transaction: &mut Transaction<'_>,
        key: &ConsumeKey,
        lock: bool,
    ) -> Result<Option<Row>, StateError> {
        let suffix = if lock { " FOR UPDATE" } else { " FOR SHARE" };
        let sql = format!(
            "SELECT review_id, acquisition_id, tenant, environment, authorization_id,
                    transaction_id, control_submission_id,
                    create_entry_id, create_request_commitment,
                    create_result_commitment, token_entry_id,
                    token_request_commitment, token_result_commitment,
                    expected_route_commitment, credential_lifetime_upper_s,
                    credential_clock_uncertainty_s, expected_token_digest,
                    expected_token_expires_at, expected_subject,
                    expected_audience, expected_service_account_uid,
                    expected_bound_secret_uid,
                    credential_lifecycle_policy_json,
                    destination_activation_commitment, phase, begun_unix_s,
                    reviewed_unix_s, claims_json,
                    review_evidence_commitment, review_commitment
               FROM public.accordlock_dispatch_credential_reviews
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4{suffix}"
        );
        Ok(transaction.query_opt(
            &sql,
            &[
                &key.scope.tenant,
                &key.scope.environment,
                &key.authorization_id,
                &key.transaction_id,
            ],
        )?)
    }

    fn stored_dispatch_credential_review(
        row: &Row,
        acquisition: &StoredDispatchAcquisition,
    ) -> Result<StoredDispatchCredentialReview, StateError> {
        let key = acquisition.token.key();
        if row.get::<_, String>("tenant") != key.scope.tenant
            || row.get::<_, String>("environment") != key.scope.environment
            || row.get::<_, Uuid>("authorization_id") != key.authorization_id
            || row.get::<_, Uuid>("transaction_id") != key.transaction_id
            || row.get::<_, Uuid>("acquisition_id") != acquisition.acquisition_id
            || row.get::<_, Uuid>("control_submission_id")
                != acquisition
                    .control_submission_id
                    .ok_or(StateError::DispatchCredentialReviewMismatch)?
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let phase = match row.get::<_, String>("phase").as_str() {
            "IN_FLIGHT" => DispatchCredentialReviewPhase::InFlight,
            "AUTHENTICATED" => DispatchCredentialReviewPhase::Authenticated,
            "REJECTED" => DispatchCredentialReviewPhase::Rejected,
            value => {
                return Err(StateError::InvalidRecord(format!(
                    "unsupported credential-review phase {value}"
                )));
            }
        };
        let claims = row
            .get::<_, Option<Value>>("claims_json")
            .map(decode_json::<DispatchCredentialReviewClaims>)
            .transpose()?;
        let digest = |column: &str| Self::canonical_digest_from_row(row, column);
        let optional_digest = |column: &str| Self::optional_digest(row, column);
        let stored = StoredDispatchCredentialReview {
            review_id: row.get("review_id"),
            token: acquisition.token.clone(),
            acquisition_id: acquisition.acquisition_id,
            lease_fence: acquisition.lease_fence,
            acquisition_worker_id: acquisition.worker_id.clone(),
            acquired_at: acquisition.acquired_at,
            lease_until: acquisition.lease_until,
            dispatch_deadline: acquisition.dispatch_deadline,
            control_submission_id: acquisition.control_submission_id,
            create_entry_id: row.get("create_entry_id"),
            create_request_commitment: digest("create_request_commitment")?,
            create_result_commitment: digest("create_result_commitment")?,
            token_entry_id: row.get("token_entry_id"),
            token_request_commitment: digest("token_request_commitment")?,
            token_result_commitment: digest("token_result_commitment")?,
            expected_route_commitment: digest("expected_route_commitment")?,
            token_credential_policy: crate::BrokerCredentialSafetyPolicy::new(
                row.get("credential_lifetime_upper_s"),
                row.get("credential_clock_uncertainty_s"),
            )?,
            expected_token_digest: digest("expected_token_digest")?,
            expected_token_expires_at: row.get("expected_token_expires_at"),
            expected_subject: row.get("expected_subject"),
            expected_audience: row.get("expected_audience"),
            expected_service_account_uid: row.get("expected_service_account_uid"),
            expected_bound_secret_uid: row.get("expected_bound_secret_uid"),
            credential_lifecycle_policy: Self::decode_review_lifecycle(
                &row.get("credential_lifecycle_policy_json"),
            )?,
            destination_activation_commitment: digest("destination_activation_commitment")?,
            phase,
            begun_at: row.get("begun_unix_s"),
            reviewed_at: row.get("reviewed_unix_s"),
            claims,
            review_evidence_commitment: optional_digest("review_evidence_commitment")?,
            review_commitment: optional_digest("review_commitment")?,
        };
        stored.validate()?;
        Ok(stored)
    }

    fn validate_postgres_credential_review_frozen_lineage(
        transaction: &mut Transaction<'_>,
        review: &StoredDispatchCredentialReview,
    ) -> Result<(), StateError> {
        review.validate()?;
        let acquisition = Self::dispatch_acquisition_row(transaction, review.acquisition_id)?
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        if acquisition.token != review.token
            || acquisition.lease_fence != review.lease_fence
            || acquisition.worker_id != review.acquisition_worker_id
            || acquisition.acquired_at != review.acquired_at
            || acquisition.lease_until != review.lease_until
            || acquisition.dispatch_deadline != review.dispatch_deadline
            || acquisition.control_submission_id != review.control_submission_id
            || acquisition.selection_kind != "CONTROL_QUEUE"
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        for (operation, entry_id, request_commitment, result_commitment) in [
            (
                BrokerJournalOperation::CreateSecret,
                review.create_entry_id,
                review.create_request_commitment,
                review.create_result_commitment,
            ),
            (
                BrokerJournalOperation::IssueToken,
                review.token_entry_id,
                review.token_request_commitment,
                review.token_result_commitment,
            ),
        ] {
            let row =
                Self::broker_operation_row(transaction, review.token.key(), operation, false)?
                    .ok_or(StateError::BrokerOperationNotFound)?;
            let broker = Self::stored_broker_operation(&row)?;
            if broker.entry_id != entry_id
                || broker.request_commitment != request_commitment
                || broker.result_commitment != Some(result_commitment)
                || broker.phase != BrokerJournalPhase::Committed
                || broker.origin_acquisition_id != review.acquisition_id
                || broker.origin_lease_fence != review.lease_fence
                || broker.acquisition_binding_version != 2
                || broker.claim_id != review.token.claim_id()
                || broker.fence != review.token.fence()
                || broker.state_instance_id != review.token.state_instance_id()
                || broker.physical_resource != *review.token.physical_resource()
                || broker.route_commitment != review.expected_route_commitment
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            if operation == BrokerJournalOperation::CreateSecret
                && (broker.outcome != Some(BrokerJournalOutcome::CreateMatching)
                    || broker.bound_secret_uid.as_deref()
                        != Some(&review.expected_bound_secret_uid))
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            if operation == BrokerJournalOperation::IssueToken
                && (broker.outcome != Some(BrokerJournalOutcome::TokenIssued)
                    || broker.bound_secret_uid.as_deref()
                        != Some(&review.expected_bound_secret_uid)
                    || broker.token_digest != Some(review.expected_token_digest)
                    || broker.token_expires_at != Some(review.expected_token_expires_at)
                    || broker.credential_policy != Some(review.token_credential_policy))
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
        }
        Ok(())
    }

    fn validate_postgres_optional_bootstrap_attempt_broker_lineage(
        transaction: &mut Transaction<'_>,
        authority: &DispatchAcquisitionAuthority,
        credential: &DispatchCredentialBinding,
    ) -> Result<(), StateError> {
        let create = Self::broker_operation_row(
            transaction,
            authority.claim().key(),
            BrokerJournalOperation::CreateSecret,
            false,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?;
        let issue = Self::broker_operation_row(
            transaction,
            authority.claim().key(),
            BrokerJournalOperation::IssueToken,
            false,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?;
        let (create, issue) = match (create, issue) {
            (None, None) => return Ok(()),
            (Some(create), Some(issue)) => (create, issue),
            _ => return Err(StateError::BrokerOperationMismatch),
        };
        for operation in [&create, &issue] {
            if operation.acquisition_binding_version != 1
                || operation.claim_id != authority.claim().claim_id()
                || operation.fence != authority.claim().fence()
                || operation.state_instance_id != authority.claim().state_instance_id()
                || operation.origin_acquisition_id != authority.acquisition_id()
                || operation.origin_lease_fence != authority.lease_fence()
                || operation.physical_resource != *authority.claim().physical_resource()
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        if create.phase != BrokerJournalPhase::Committed
            || create.outcome != Some(BrokerJournalOutcome::CreateMatching)
            || create.bound_secret_uid.is_none()
            || issue.phase != BrokerJournalPhase::Committed
            || issue.outcome != Some(BrokerJournalOutcome::TokenIssued)
            || issue.route_commitment != create.route_commitment
            || issue.bound_secret_uid != create.bound_secret_uid
            || issue.token_digest != Some(credential.token_digest())
            || issue.token_expires_at != Some(credential.expires_at())
            || issue.credential_policy.is_none()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        Ok(())
    }

    fn insert_dispatch_credential_review(
        transaction: &mut Transaction<'_>,
        review: &StoredDispatchCredentialReview,
    ) -> Result<(), StateError> {
        review.validate()?;
        let lifecycle = Self::encode_review_lifecycle(review.credential_lifecycle_policy);
        let inserted = transaction.execute(
            "INSERT INTO public.accordlock_dispatch_credential_reviews
                        (review_id, acquisition_id, tenant, environment, authorization_id,
                         transaction_id, control_submission_id,
                         create_entry_id, create_request_commitment,
                         create_result_commitment, token_entry_id,
                         token_request_commitment, token_result_commitment,
                         expected_route_commitment, credential_lifetime_upper_s,
                         credential_clock_uncertainty_s, expected_token_digest,
                         expected_token_expires_at, expected_subject,
                         expected_audience, expected_service_account_uid,
                         expected_bound_secret_uid,
                         credential_lifecycle_policy_json,
                         destination_activation_commitment, phase, begun_unix_s)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                         $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)",
            &[
                &review.review_id,
                &review.acquisition_id,
                &review.token.key().scope.tenant,
                &review.token.key().scope.environment,
                &review.token.key().authorization_id,
                &review.token.key().transaction_id,
                &review.control_submission_id,
                &review.create_entry_id,
                &review.create_request_commitment.to_string(),
                &review.create_result_commitment.to_string(),
                &review.token_entry_id,
                &review.token_request_commitment.to_string(),
                &review.token_result_commitment.to_string(),
                &review.expected_route_commitment.to_string(),
                &review
                    .token_credential_policy
                    .lifetime_upper_bound_seconds(),
                &review.token_credential_policy.clock_uncertainty_seconds(),
                &review.expected_token_digest.to_string(),
                &review.expected_token_expires_at,
                &review.expected_subject,
                &review.expected_audience,
                &review.expected_service_account_uid,
                &review.expected_bound_secret_uid,
                &lifecycle,
                &review.destination_activation_commitment.to_string(),
                &review.phase.database_name(),
                &review.begun_at,
            ],
        )?;
        if inserted != 1 {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        Ok(())
    }

    fn update_dispatch_credential_review(
        transaction: &mut Transaction<'_>,
        review: &StoredDispatchCredentialReview,
    ) -> Result<(), StateError> {
        review.validate()?;
        let claims = review.claims.as_ref().map(encode_json).transpose()?;
        let updated = transaction.execute(
            "UPDATE public.accordlock_dispatch_credential_reviews
                SET phase=$2, reviewed_unix_s=$3, claims_json=$4,
                    review_evidence_commitment=$5, review_commitment=$6,
                    updated_at=clock_timestamp()
              WHERE review_id=$1 AND phase='IN_FLIGHT'",
            &[
                &review.review_id,
                &review.phase.database_name(),
                &review.reviewed_at,
                &claims,
                &review
                    .review_evidence_commitment
                    .map(|value| value.to_string()),
                &review.review_commitment.map(|value| value.to_string()),
            ],
        )?;
        if updated != 1 {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn begin_dispatch_credential_review_once(
        &self,
        authority: &DispatchAcquisitionAuthority,
        token_journal: &BrokerJournalSelector,
    ) -> Result<CredentialReviewIoAuthority, StateError> {
        if token_journal.key() != authority.claim().key()
            || token_journal.operation() != BrokerJournalOperation::IssueToken
            || token_journal.origin_acquisition_id() != authority.acquisition_id()
            || token_journal.origin_lease_fence() != authority.lease_fence()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let current = self
            .load_current_eks_attempt_for_acquisition_once(authority)
            .map_err(|error| match error {
                EksRegistryError::State(error) => error,
                other => StateError::InvalidRecord(format!(
                    "current EKS attempt cannot begin credential review: {other}"
                )),
            })?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        if Self::dispatch_credential_review_row(&mut transaction, authority.claim().key(), true)?
            .is_some()
        {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        let (snapshot, acquisition) =
            Self::validate_current_control_acquisition(&mut transaction, authority)?;
        let issue_row = Self::broker_operation_row(
            &mut transaction,
            authority.claim().key(),
            BrokerJournalOperation::IssueToken,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let issue = Self::stored_broker_operation(&issue_row)?;
        if issue.entry_id != token_journal.entry_id()
            || issue.request_commitment != token_journal.request_commitment()
            || issue.phase != BrokerJournalPhase::Committed
            || issue.outcome != Some(BrokerJournalOutcome::TokenIssued)
            || issue.acquisition_binding_version != 2
            || issue.origin_acquisition_id != acquisition.acquisition_id
            || issue.origin_lease_fence != acquisition.lease_fence
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let create = Self::matching_create_row(
            &mut transaction,
            authority.claim().key(),
            issue.route_commitment,
        )?;
        if create.acquisition_binding_version != 2
            || create.origin_acquisition_id != acquisition.acquisition_id
            || create.origin_lease_fence != acquisition.lease_fence
            || create.claim_id != authority.claim().claim_id()
            || create.fence != authority.claim().fence()
            || create.state_instance_id != authority.claim().state_instance_id()
            || create.physical_resource != *authority.claim().physical_resource()
            || issue.claim_id != create.claim_id
            || issue.fence != create.fence
            || issue.state_instance_id != create.state_instance_id
            || issue.physical_resource != create.physical_resource
            || issue.bound_secret_uid != create.bound_secret_uid
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let facts = current.facts();
        if facts.physical_resource() != authority.claim().physical_resource()
            || current.dispatch_deadline() != snapshot.receipt().dispatch_deadline
            || current.checked_at() > snapshot.checked_at()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let expected_bound_secret_uid = issue
            .bound_secret_uid
            .clone()
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        let stored = StoredDispatchCredentialReview {
            review_id: Uuid::new_v4(),
            token: authority.claim().clone(),
            acquisition_id: authority.acquisition_id(),
            lease_fence: authority.lease_fence(),
            acquisition_worker_id: authority.worker_id().to_owned(),
            acquired_at: authority.acquired_at(),
            lease_until: authority.lease_until(),
            dispatch_deadline: authority.dispatch_deadline(),
            control_submission_id: authority.control_submission_id(),
            create_entry_id: create.entry_id,
            create_request_commitment: create.request_commitment,
            create_result_commitment: create
                .result_commitment
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            token_entry_id: issue.entry_id,
            token_request_commitment: issue.request_commitment,
            token_result_commitment: issue
                .result_commitment
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_route_commitment: Digest32::from_bytes(*facts.route().commitment().as_bytes()),
            token_credential_policy: issue
                .credential_policy
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_token_digest: issue
                .token_digest
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_token_expires_at: issue
                .token_expires_at
                .ok_or(StateError::DispatchCredentialReviewMismatch)?,
            expected_subject: facts.token_subject().to_owned(),
            expected_audience: facts.token_audience().to_owned(),
            expected_service_account_uid: facts.service_account_uid().to_owned(),
            expected_bound_secret_uid,
            credential_lifecycle_policy: facts.credential_lifecycle_policy(),
            destination_activation_commitment: facts.activation_commitment(),
            phase: DispatchCredentialReviewPhase::InFlight,
            begun_at: snapshot.checked_at(),
            reviewed_at: None,
            claims: None,
            review_evidence_commitment: None,
            review_commitment: None,
        };
        stored.validate()?;
        Self::insert_dispatch_credential_review(&mut transaction, &stored)?;
        transaction
            .commit()
            .map_err(|_| StateError::DispatchCredentialReviewOutcomeUnknown)?;
        Ok(CredentialReviewIoAuthority::new(stored))
    }

    fn record_authenticated_dispatch_credential_once(
        &self,
        expected: &StoredDispatchCredentialReview,
        observation: AuthenticatedDispatchCredentialReview,
    ) -> Result<ReviewedDispatchCredential, StateError> {
        expected.validate()?;
        let authority = expected.authority();
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (snapshot, acquisition) =
            Self::validate_current_control_acquisition(&mut transaction, &authority)?;
        let row =
            Self::dispatch_credential_review_row(&mut transaction, expected.token.key(), true)?
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let current = Self::stored_dispatch_credential_review(&row, &acquisition)?;
        if &current != expected || current.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &current)?;
        if observation.claims().not_before() > snapshot.checked_at()
            || observation.claims().expires_at() <= snapshot.checked_at()
        {
            return Err(StateError::DispatchCredentialExpired);
        }
        let terminal = current.finish_authenticated(observation, snapshot.checked_at())?;
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &terminal)?;
        let reviewed = terminal.reviewed_credential()?;
        Self::update_dispatch_credential_review(&mut transaction, &terminal)?;
        transaction
            .commit()
            .map_err(|_| StateError::DispatchCredentialReviewOutcomeUnknown)?;
        Ok(reviewed)
    }

    fn record_rejected_dispatch_credential_once(
        &self,
        expected: &StoredDispatchCredentialReview,
        observation: RejectedDispatchCredentialReview,
    ) -> Result<DispatchCredentialReviewAudit, StateError> {
        expected.validate()?;
        let submission_id = expected
            .control_submission_id
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let stored = control_plane::load_submission_for_update(&mut transaction, submission_id)?;
        if stored.submission_id != submission_id
            || stored.scope() != expected.token.key().scope
            || stored.state_instance_id != expected.token.state_instance_id()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        control_plane::validate_dispatch_pending_lineage(
            &mut transaction,
            &stored,
            expected.token.key(),
        )?;
        let (replay_scope, ingress_high_water, scope_high_water, _inputs) =
            Self::lock_v14_dispatch_inputs(&mut transaction, &stored, expected.token.key())?;
        let acquisition =
            Self::dispatch_acquisition_row(&mut transaction, expected.acquisition_id)?
                .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        let row =
            Self::dispatch_credential_review_row(&mut transaction, expected.token.key(), true)?
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let current = Self::stored_dispatch_credential_review(&row, &acquisition)?;
        if &current != expected || current.phase != DispatchCredentialReviewPhase::InFlight {
            return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
        }
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &current)?;
        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        let durable_high_water = ingress_high_water
            .max(scope_high_water)
            .max(stored.accepted_at)
            .max(current.acquired_at);
        if observed_at < durable_high_water {
            return Err(StateError::ClockRollback {
                observed: observed_at,
                high_water: durable_high_water,
            });
        }
        let terminal = current.finish_rejected(observation, observed_at)?;
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &terminal)?;
        control_plane::advance_control_high_water(
            &mut transaction,
            &stored,
            &replay_scope,
            ingress_high_water,
            observed_at,
        )?;
        Self::update_dispatch_credential_review(&mut transaction, &terminal)?;
        transaction
            .commit()
            .map_err(|_| StateError::DispatchCredentialReviewOutcomeUnknown)?;
        Ok(DispatchCredentialReviewAudit::new(terminal))
    }

    fn recover_authenticated_dispatch_credential_once(
        &self,
        key: &DispatchCredentialReviewRecoveryKey,
    ) -> Result<ReviewedDispatchCredential, StateError> {
        key.key().validate()?;
        if key.review_id().is_nil() || key.acquisition_id().is_nil() || key.lease_fence() == 0 {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let acquisition = Self::dispatch_acquisition_row(&mut transaction, key.acquisition_id())?
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let row = Self::dispatch_credential_review_row(&mut transaction, key.key(), false)?
            .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let review = Self::stored_dispatch_credential_review(&row, &acquisition)?;
        if review.review_id != key.review_id()
            || review.acquisition_id != key.acquisition_id()
            || review.lease_fence != key.lease_fence()
            || review.token.key() != key.key()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &review)?;
        let reviewed = review.reviewed_credential()?;
        transaction.commit()?;
        Ok(reviewed)
    }

    fn dispatch_credential_review_audit_once(
        &self,
        acquisition_key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchCredentialReviewAudit, StateError> {
        acquisition_key.scope().validate()?;
        if acquisition_key.acquisition_id().is_nil()
            || !crate::acquisition::valid_worker_id(acquisition_key.worker_id())
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let acquisition =
            Self::dispatch_acquisition_row(&mut transaction, acquisition_key.acquisition_id())?
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        if acquisition.token.key().scope != *acquisition_key.scope()
            || acquisition.worker_id != acquisition_key.worker_id()
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let row =
            Self::dispatch_credential_review_row(&mut transaction, acquisition.token.key(), false)?
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let review = Self::stored_dispatch_credential_review(&row, &acquisition)?;
        if review.acquisition_id != acquisition_key.acquisition_id() {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &review)?;
        transaction.commit()?;
        Ok(DispatchCredentialReviewAudit::new(review))
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_broker_restart_context_once(
        &self,
        acquisition_key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<DispatchBrokerRestartContext, StateError> {
        acquisition_key.scope().validate()?;
        if acquisition_key.acquisition_id().is_nil()
            || !crate::acquisition::valid_worker_id(acquisition_key.worker_id())
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        // Frozen recovery follows metadata -> submission root before every
        // journal/input lock. It never consults current authority or time.
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let acquisition =
            Self::dispatch_acquisition_row(&mut transaction, acquisition_key.acquisition_id())?
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if acquisition.token.key().scope != *acquisition_key.scope()
            || acquisition.worker_id != acquisition_key.worker_id()
            || acquisition.token.state_instance_id() != state_instance_id
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13" => {
                let submission_id = acquisition
                    .control_submission_id
                    .ok_or(StateError::DispatchAcquisitionMismatch)?;
                let stored =
                    control_plane::load_submission_for_update(&mut transaction, submission_id)?;
                if stored.submission_id != submission_id
                    || stored.scope() != acquisition.token.key().scope
                    || stored.state_instance_id != state_instance_id
                {
                    return Err(StateError::DispatchAcquisitionMismatch);
                }
                control_plane::validate_dispatch_pending_lineage(
                    &mut transaction,
                    &stored,
                    acquisition.token.key(),
                )?;
            }
            "LEGACY_BOOTSTRAP" if acquisition.control_submission_id.is_none() => {}
            _ => return Err(StateError::DispatchAcquisitionMismatch),
        }

        let key = acquisition.token.key();
        let inputs = Self::lock_frozen_dispatch_inputs(&mut transaction, key)?;
        let destination = Self::registry_frozen_destination_for_authority(
            &mut transaction,
            &key.scope,
            &inputs.issued.authorization().authority,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        let facts = derive_attempt_facts(
            &key.scope,
            key.transaction_id,
            key.authorization_id,
            inputs.issued.authorization().template_hash,
            &inputs.issued.authorization().template,
            &destination,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        if facts.physical_resource() != acquisition.token.physical_resource() {
            return Err(StateError::BrokerOperationMismatch);
        }
        let rooted_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());

        let create_row = Self::broker_operation_row(
            &mut transaction,
            key,
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let valid_binding_version = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => create.acquisition_binding_version == 2,
            "CONTROL_BOOTSTRAP_V13" => create.acquisition_binding_version == 1,
            "LEGACY_BOOTSTRAP" => matches!(create.acquisition_binding_version, 1 | 2),
            _ => false,
        };
        if create.key != *key
            || create.claim_id != acquisition.token.claim_id()
            || create.fence != acquisition.token.fence()
            || create.state_instance_id != acquisition.token.state_instance_id()
            || create.origin_acquisition_id != acquisition.acquisition_id
            || create.origin_lease_fence != acquisition.lease_fence
            || !valid_binding_version
            || create.physical_resource != *acquisition.token.physical_resource()
            || create.route_commitment != rooted_route
        {
            return Err(StateError::BrokerOperationMismatch);
        }

        let issue_row = Self::broker_operation_row(
            &mut transaction,
            key,
            BrokerJournalOperation::IssueToken,
            true,
        )?;
        if let Some(issue_row) = &issue_row {
            let issue = Self::stored_broker_operation(issue_row)?;
            if issue.key != *key
                || issue.claim_id != create.claim_id
                || issue.fence != create.fence
                || issue.state_instance_id != create.state_instance_id
                || issue.origin_acquisition_id != create.origin_acquisition_id
                || issue.origin_lease_fence != create.origin_lease_fence
                || issue.acquisition_binding_version != create.acquisition_binding_version
                || issue.physical_resource != create.physical_resource
                || issue.route_commitment != rooted_route
                || issue.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }

        let review = Self::dispatch_credential_review_row(&mut transaction, key, false)?
            .map(|row| Self::stored_dispatch_credential_review(&row, &acquisition))
            .transpose()?;
        if let Some(review) = &review {
            if create.acquisition_binding_version != 2
                || review.acquisition_id != acquisition.acquisition_id
            {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, review)?;
        }

        let delete_row = Self::broker_operation_row(
            &mut transaction,
            key,
            BrokerJournalOperation::DeleteSecret,
            true,
        )?;
        if let Some(delete_row) = &delete_row {
            let delete = Self::stored_broker_operation(delete_row)?;
            if delete.claim_id != create.claim_id
                || delete.fence != create.fence
                || delete.state_instance_id != create.state_instance_id
                || delete.origin_acquisition_id != create.origin_acquisition_id
                || delete.origin_lease_fence != create.origin_lease_fence
                || (acquisition.selection_kind == "CONTROL_QUEUE"
                    && delete.acquisition_binding_version != 2)
                || (acquisition.selection_kind == "CONTROL_BOOTSTRAP_V13"
                    && !matches!(delete.acquisition_binding_version, 1 | 2))
                || (acquisition.selection_kind == "LEGACY_BOOTSTRAP"
                    && delete.acquisition_binding_version != create.acquisition_binding_version)
                || delete.physical_resource != create.physical_resource
                || delete.route_commitment != rooted_route
                || delete.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
            if delete.phase == BrokerJournalPhase::Committed
                && delete.outcome == Some(BrokerJournalOutcome::DeleteAbsent)
            {
                let deletion_row =
                    Self::secret_deletion_observation_row(&mut transaction, key, true)?
                        .ok_or(StateError::BrokerOperationMismatch)?;
                let deletion = Self::stored_secret_deletion_observation(&deletion_row)?;
                let exact = StoredSecretDeletionObservation::from_committed_delete(
                    &delete,
                    deletion.observed_at,
                )?;
                if deletion != exact {
                    return Err(StateError::BrokerOperationMismatch);
                }
                let rejected_review = review
                    .as_ref()
                    .filter(|review| review.phase == DispatchCredentialReviewPhase::Rejected)
                    .and_then(|review| {
                        review
                            .reviewed_at
                            .zip(review.review_evidence_commitment)
                            .filter(|(reviewed_at, _)| *reviewed_at >= deletion.observed_at)
                    });
                let evidence = DispatchRestartDeletionEvidence::new(
                    deletion.observed_at,
                    deletion.provider_evidence_commitment,
                    facts.credential_lifecycle_policy(),
                    rejected_review.map(|facts| facts.0),
                    rejected_review.map(|facts| facts.1),
                )?;
                transaction.commit()?;
                return Ok(DispatchBrokerRestartContext::deletion_already_absent(
                    key.clone(),
                    evidence,
                ));
            }
        }
        if acquisition.claim_state == "RECOVERY_NO_SEND"
            && create.phase == BrokerJournalPhase::ReconcileOnly
            && create.outcome.is_none()
            && create.bound_secret_uid.is_none()
            && create.reconciliation_count > 0
            && create.last_reconciliation_outcome == Some(BrokerJournalOutcome::CreateAbsent)
            && create.last_reconciliation_evidence_commitment.is_some()
            && create.last_reconciled_at.is_some()
            && issue_row.is_none()
            && review.is_none()
            && delete_row.is_none()
        {
            transaction.commit()?;
            return Ok(DispatchBrokerRestartContext::creation_already_absent(
                key.clone(),
            ));
        }

        let context = match (create.phase, create.outcome) {
            (BrokerJournalPhase::Committed, Some(BrokerJournalOutcome::CreateMatching)) => {
                DispatchBrokerRestartContext::cleanup_secret(BrokerCleanupRequest::new(
                    key.clone(),
                    *rooted_route.as_bytes(),
                )?)
            }
            (
                BrokerJournalPhase::Intent
                | BrokerJournalPhase::InFlight
                | BrokerJournalPhase::Unknown
                | BrokerJournalPhase::ReconcileOnly,
                None,
            ) => DispatchBrokerRestartContext::reconcile_create(BrokerReconciliationRequest::new(
                key.clone(),
                BrokerJournalOperation::CreateSecret,
                *rooted_route.as_bytes(),
            )?),
            _ => return Err(StateError::BrokerOperationInvalidTransition),
        };
        transaction.commit()?;
        Ok(context)
    }

    #[allow(clippy::too_many_lines)]
    fn lock_postgres_no_send_lineage(
        transaction: &mut Transaction<'_>,
        recovery_key: &DispatchAcquisitionRecoveryKey,
        state_instance_id: Uuid,
    ) -> Result<PostgresNoSendLineage, StateError> {
        recovery_key.scope().validate()?;
        if recovery_key.acquisition_id().is_nil()
            || !crate::acquisition::valid_worker_id(recovery_key.worker_id())
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let selected = Self::dispatch_acquisition_row(transaction, recovery_key.acquisition_id())?
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if selected.token.key().scope != *recovery_key.scope()
            || selected.worker_id != recovery_key.worker_id()
            || selected.token.state_instance_id() != state_instance_id
            || !matches!(
                selected.selection_kind.as_str(),
                "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
            )
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let submission_id = selected
            .control_submission_id
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let submission = control_plane::load_submission_for_update(transaction, submission_id)?;
        if submission.submission_id != submission_id
            || submission.scope() != selected.token.key().scope
            || submission.state_instance_id != state_instance_id
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        control_plane::validate_dispatch_pending_lineage(
            transaction,
            &submission,
            selected.token.key(),
        )?;
        if Self::dispatch_queue_disposition(transaction, None, Some(submission_id))?.is_some() {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let claim_row = Self::dispatch_claim_row(transaction, selected.token.key())?
            .ok_or(StateError::DispatchClaimNotFound)?;
        let (claim, claim_state) = Self::token_from_claim_row(selected.token.key(), &claim_row)?;
        if claim != selected.token
            || !matches!(
                claim_state.as_str(),
                "CLAIMED" | "RECOVERY_NO_SEND" | "RECOVERY_RETIRED"
            )
        {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let latest = Self::latest_dispatch_acquisition(transaction, &claim)?;
        if latest.acquisition_id != selected.acquisition_id
            || latest.lease_fence != selected.lease_fence
            || latest.worker_id != selected.worker_id
            || latest.control_submission_id != Some(submission_id)
            || latest.selection_kind != selected.selection_kind
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if latest.selection_kind == "CONTROL_BOOTSTRAP_V13"
            && (latest.acquisition_id != claim.claim_id()
                || latest.lease_fence != claim.fence()
                || latest.worker_id != claim.worker_id()
                || latest.acquired_at != claim.claimed_at()
                || latest.lease_until != claim.lease_until())
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        if claim_row
            .get::<_, Option<i64>>("attempt_started_at")
            .is_some()
            || claim_row
                .get::<_, Option<String>>("credential_token_digest")
                .is_some()
            || claim_row
                .get::<_, Option<String>>("service_account_uid")
                .is_some()
            || claim_row
                .get::<_, Option<String>>("credential_id")
                .is_some()
            || claim_row
                .get::<_, Option<i64>>("credential_not_before")
                .is_some()
            || claim_row
                .get::<_, Option<i64>>("credential_expires_at")
                .is_some()
            || claim_row
                .get::<_, Option<String>>("credential_binding_commitment")
                .is_some()
            || claim_row
                .get::<_, Option<Uuid>>("attempt_acquisition_id")
                .is_some()
            || claim_row
                .get::<_, Option<i64>>("attempt_lease_fence")
                .is_some()
            || claim_row
                .get::<_, Option<i64>>("attempt_acquired_unix_s")
                .is_some()
            || claim_row
                .get::<_, Option<i64>>("attempt_lease_until")
                .is_some()
            || claim_row
                .get::<_, Option<i16>>("acquisition_binding_version")
                .is_some()
            || claim_row
                .get::<_, Option<Uuid>>("credential_review_id")
                .is_some()
            || claim_row
                .get::<_, Option<Uuid>>("terminalization_id")
                .is_some()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let stored_safe = claim_row.get::<_, Option<i64>>("recovery_safe_after_unix_s");
        let stored_retired = claim_row.get::<_, Option<i64>>("recovery_retired_unix_s");
        if match claim_state.as_str() {
            "CLAIMED" => stored_safe.is_some() || stored_retired.is_some(),
            "RECOVERY_NO_SEND" => stored_retired.is_some(),
            "RECOVERY_RETIRED" => stored_safe.is_none() || stored_retired.is_none(),
            _ => true,
        } {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let artifact_row = transaction.query_one(
            "SELECT EXISTS (
                        SELECT 1 FROM public.accordlock_admission_authorizations
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4
                    ) AS has_admission,
                    EXISTS (
                        SELECT 1 FROM public.accordlock_terminal_retirements
                         WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                           AND transaction_id=$4
                    ) AS has_terminal",
            &[
                &claim.key().scope.tenant,
                &claim.key().scope.environment,
                &claim.key().authorization_id,
                &claim.key().transaction_id,
            ],
        )?;
        if artifact_row.get::<_, bool>("has_admission")
            || artifact_row.get::<_, bool>("has_terminal")
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let inputs = Self::lock_frozen_dispatch_inputs(transaction, claim.key())?;
        let destination = Self::registry_frozen_destination_for_authority(
            transaction,
            &claim.key().scope,
            &inputs.issued.authorization().authority,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        let facts = derive_attempt_facts(
            &claim.key().scope,
            claim.key().transaction_id,
            claim.key().authorization_id,
            inputs.issued.authorization().template_hash,
            &inputs.issued.authorization().template,
            &destination,
        )
        .map_err(|_| StateError::BrokerOperationMismatch)?;
        if facts.physical_resource() != claim.physical_resource() {
            return Err(StateError::BrokerOperationMismatch);
        }
        let rooted_route = Digest32::from_bytes(*facts.route().commitment().as_bytes());
        let create_row = Self::broker_operation_row(
            transaction,
            claim.key(),
            BrokerJournalOperation::CreateSecret,
            true,
        )?
        .ok_or(StateError::BrokerOperationNotFound)?;
        let create = Self::stored_broker_operation(&create_row)?;
        let create_binding_version = if latest.selection_kind == "CONTROL_QUEUE" {
            2
        } else {
            1
        };
        if create.key != *claim.key()
            || create.claim_id != claim.claim_id()
            || create.fence != claim.fence()
            || create.state_instance_id != state_instance_id
            || create.origin_acquisition_id != latest.acquisition_id
            || create.origin_lease_fence != latest.lease_fence
            || create.acquisition_binding_version != create_binding_version
            || create.physical_resource != *claim.physical_resource()
            || create.route_commitment != rooted_route
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let issue_row = Self::broker_operation_row(
            transaction,
            claim.key(),
            BrokerJournalOperation::IssueToken,
            true,
        )?;
        if let Some(issue_row) = &issue_row {
            let issue = Self::stored_broker_operation(issue_row)?;
            if issue.key != *claim.key()
                || issue.claim_id != create.claim_id
                || issue.fence != create.fence
                || issue.state_instance_id != create.state_instance_id
                || issue.origin_acquisition_id != create.origin_acquisition_id
                || issue.origin_lease_fence != create.origin_lease_fence
                || issue.acquisition_binding_version != create_binding_version
                || issue.physical_resource != create.physical_resource
                || issue.route_commitment != rooted_route
                || issue.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        let review_row = Self::dispatch_credential_review_row(transaction, claim.key(), true)?;
        let review = review_row
            .as_ref()
            .map(|row| Self::stored_dispatch_credential_review(row, &latest))
            .transpose()?;
        if let Some(review) = &review {
            if latest.selection_kind != "CONTROL_QUEUE" || create_binding_version != 2 {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            if review.acquisition_id != latest.acquisition_id {
                return Err(StateError::DispatchCredentialReviewMismatch);
            }
            Self::validate_postgres_credential_review_frozen_lineage(transaction, review)?;
        }
        let delete = Self::broker_operation_row(
            transaction,
            claim.key(),
            BrokerJournalOperation::DeleteSecret,
            true,
        )?
        .map(|row| Self::stored_broker_operation(&row))
        .transpose()?;
        if let Some(delete) = &delete {
            let valid_delete_binding = match latest.selection_kind.as_str() {
                "CONTROL_QUEUE" => delete.acquisition_binding_version == 2,
                "CONTROL_BOOTSTRAP_V13" => {
                    matches!(delete.acquisition_binding_version, 1 | 2)
                }
                _ => false,
            };
            if !valid_delete_binding
                || delete.claim_id != create.claim_id
                || delete.fence != create.fence
                || delete.state_instance_id != create.state_instance_id
                || delete.origin_acquisition_id != create.origin_acquisition_id
                || delete.origin_lease_fence != create.origin_lease_fence
                || delete.physical_resource != create.physical_resource
                || delete.route_commitment != rooted_route
                || delete.bound_secret_uid != create.bound_secret_uid
            {
                return Err(StateError::BrokerOperationMismatch);
            }
        }
        Ok(PostgresNoSendLineage {
            acquisition: latest,
            claim_row,
            lifecycle_policy: facts.credential_lifecycle_policy(),
            create,
            has_issue: issue_row.is_some(),
            review,
            delete,
        })
    }

    fn mark_dispatch_acquisition_attempt_in_flight_once(
        &self,
        reviewed: &ReviewedDispatchCredential,
    ) -> Result<AttemptInFlight, StateError> {
        reviewed.stored.validate()?;
        let authority = reviewed.stored.authority();
        let review_commitment = reviewed
            .stored
            .review_commitment
            .ok_or(StateError::DispatchCredentialReviewMismatch)?;
        if !reviewed.binding.matches_review(
            &authority,
            reviewed.stored.review_id,
            review_commitment,
        ) {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let (snapshot, acquisition) =
            Self::validate_current_control_acquisition(&mut transaction, &authority)?;
        let row =
            Self::dispatch_credential_review_row(&mut transaction, authority.claim().key(), true)?
                .ok_or(StateError::DispatchCredentialReviewNotFound)?;
        let durable = Self::stored_dispatch_credential_review(&row, &acquisition)?;
        if durable != reviewed.stored
            || durable.phase != DispatchCredentialReviewPhase::Authenticated
        {
            return Err(StateError::DispatchCredentialReviewMismatch);
        }
        Self::validate_postgres_credential_review_frozen_lineage(&mut transaction, &durable)?;
        if reviewed.binding.not_before() > snapshot.checked_at()
            || reviewed.binding.expires_at() <= snapshot.checked_at()
        {
            return Err(StateError::DispatchCredentialExpired);
        }
        let fence = i64::try_from(authority.claim().fence()).map_err(|_| {
            StateError::InvalidRecord(
                "dispatch claim fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let acquisition_lease_fence = i64::try_from(authority.lease_fence()).map_err(|_| {
            StateError::InvalidRecord(
                "dispatch acquisition fence does not fit PostgreSQL BIGINT".to_owned(),
            )
        })?;
        let credential_token_digest = reviewed.binding.token_digest().to_string();
        let credential_binding_commitment = reviewed.binding.commitment().to_string();
        let started_at = snapshot.checked_at();
        let updated = transaction.execute(
            "UPDATE public.accordlock_dispatch_claims
                SET state='ATTEMPT_IN_FLIGHT', attempt_started_at=$8,
                    credential_token_digest=$9, service_account_uid=$10,
                    credential_id=$11, credential_not_before=$12,
                    credential_expires_at=$13,
                    credential_binding_commitment=$14,
                    attempt_acquisition_id=$15, attempt_lease_fence=$16,
                    attempt_acquired_unix_s=$17, attempt_lease_until=$18,
                    acquisition_binding_version=2, credential_review_id=$19,
                    updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                AND state_instance_id=$7 AND state='CLAIMED'",
            &[
                &authority.claim().key().scope.tenant,
                &authority.claim().key().scope.environment,
                &authority.claim().key().authorization_id,
                &authority.claim().key().transaction_id,
                &authority.claim().claim_id(),
                &fence,
                &authority.claim().state_instance_id(),
                &started_at,
                &credential_token_digest,
                &reviewed.binding.service_account_uid(),
                &reviewed.binding.credential_id(),
                &reviewed.binding.not_before(),
                &reviewed.binding.expires_at(),
                &credential_binding_commitment,
                &authority.acquisition_id(),
                &acquisition_lease_fence,
                &authority.acquired_at(),
                &authority.lease_until(),
                &reviewed.stored.review_id,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let attempt = AttemptInFlight::new_reviewed(snapshot, authority, reviewed, started_at);
        transaction
            .commit()
            .map_err(|_| StateError::DispatchAttemptOutcomeUnknown)?;
        Ok(attempt)
    }

    fn close_dispatch_acquisition_no_send_once(
        &self,
        recovery_key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendReceipt, StateError> {
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        // Frozen no-send closure: metadata -> submission root -> claim/latest
        // acquisition -> immutable dispatch/journal lineage. It deliberately
        // takes no current-authority, clock, ingress-HWM, or scope-HWM lock.
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let lineage =
            Self::lock_postgres_no_send_lineage(&mut transaction, recovery_key, state_instance_id)?;
        let recovery_acquisition = Self::dispatch_recovery_acquisition(&lineage.acquisition)?;
        let receipt = RecoveryNoSendReceipt::new(
            lineage.acquisition.token.key().clone(),
            recovery_acquisition,
        );
        match lineage.acquisition.claim_state.as_str() {
            "CLAIMED" => {
                let updated = transaction.execute(
                    "UPDATE public.accordlock_dispatch_claims
                        SET state='RECOVERY_NO_SEND', updated_at=clock_timestamp()
                      WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                        AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                        AND state_instance_id=$7 AND state='CLAIMED'",
                    &[
                        &lineage.acquisition.token.key().scope.tenant,
                        &lineage.acquisition.token.key().scope.environment,
                        &lineage.acquisition.token.key().authorization_id,
                        &lineage.acquisition.token.key().transaction_id,
                        &lineage.acquisition.token.claim_id(),
                        &i64::try_from(lineage.acquisition.token.fence())
                            .map_err(|_| StateError::DispatchAcquisitionMismatch)?,
                        &state_instance_id,
                    ],
                )?;
                if updated != 1 {
                    return Err(StateError::DispatchAttemptOutcomeUnknown);
                }
            }
            "RECOVERY_NO_SEND" | "RECOVERY_RETIRED" => {}
            _ => return Err(StateError::DispatchAttemptOutcomeUnknown),
        }
        transaction
            .commit()
            .map_err(|_| StateError::DispatchAttemptOutcomeUnknown)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_lines)]
    fn retire_recovery_no_send_once(
        &self,
        recovery_key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendRetirementOutcome, StateError> {
        recovery_key.scope().validate()?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let state_instance_id = Self::locked_state_instance(&mut transaction)?;
        let acquisition =
            Self::dispatch_acquisition_row(&mut transaction, recovery_key.acquisition_id())?
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
        if acquisition.acquisition_id != recovery_key.acquisition_id()
            || acquisition.worker_id != recovery_key.worker_id()
            || acquisition.token.key().scope != *recovery_key.scope()
            || acquisition.token.state_instance_id() != state_instance_id
            || !matches!(
                acquisition.selection_kind.as_str(),
                "CONTROL_QUEUE" | "CONTROL_BOOTSTRAP_V13"
            )
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let submission_id = acquisition
            .control_submission_id
            .ok_or(StateError::DispatchAcquisitionMismatch)?;
        let submission =
            control_plane::load_submission_for_update(&mut transaction, submission_id)?;
        if submission.submission_id != submission_id
            || submission.scope() != acquisition.token.key().scope
            || submission.state_instance_id != state_instance_id
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        control_plane::validate_dispatch_pending_lineage(
            &mut transaction,
            &submission,
            acquisition.token.key(),
        )?;
        if Self::dispatch_queue_disposition(&mut transaction, None, Some(submission_id))?.is_some()
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }

        let preflight =
            Self::dispatch_claim_row_unlocked(&mut transaction, acquisition.token.key())?
                .ok_or(StateError::DispatchClaimNotFound)?;
        let (_, preflight_state) = Self::token_from_claim_row(acquisition.token.key(), &preflight)?;
        let creation_absent_preflight = if matches!(
            preflight_state.as_str(),
            "RECOVERY_NO_SEND" | "RECOVERY_RETIRED"
        ) {
            let create = Self::broker_operation_row(
                &mut transaction,
                acquisition.token.key(),
                BrokerJournalOperation::CreateSecret,
                false,
            )?
            .map(|row| Self::stored_broker_operation(&row))
            .transpose()?;
            create.as_ref().is_some_and(|create| {
                create.phase == BrokerJournalPhase::ReconcileOnly
                    && create.outcome.is_none()
                    && create.bound_secret_uid.is_none()
                    && create.reconciliation_count > 0
                    && create.last_reconciliation_outcome
                        == Some(BrokerJournalOutcome::CreateAbsent)
                    && create.last_reconciliation_evidence_commitment.is_some()
                    && create.last_reconciled_at.is_some()
            }) && Self::broker_operation_row(
                &mut transaction,
                acquisition.token.key(),
                BrokerJournalOperation::IssueToken,
                false,
            )?
            .is_none()
                && Self::dispatch_credential_review_row(
                    &mut transaction,
                    acquisition.token.key(),
                    false,
                )?
                .is_none()
                && Self::broker_operation_row(
                    &mut transaction,
                    acquisition.token.key(),
                    BrokerJournalOperation::DeleteSecret,
                    false,
                )?
                .is_none()
        } else {
            false
        };
        let time_inputs = if preflight_state == "RECOVERY_NO_SEND" && !creation_absent_preflight {
            let (replay_scope, ingress_high_water, scope_high_water, dispatch) =
                Self::lock_v14_dispatch_inputs(
                    &mut transaction,
                    &submission,
                    acquisition.token.key(),
                )?;
            Some(LockedBrokerTimeInputs {
                dispatch,
                control: Some(LockedControlBrokerTime {
                    submission: submission.clone(),
                    replay_scope,
                    ingress_high_water,
                    scope_high_water,
                }),
            })
        } else if matches!(
            preflight_state.as_str(),
            "RECOVERY_NO_SEND" | "RECOVERY_RETIRED"
        ) {
            Self::lock_frozen_dispatch_inputs(&mut transaction, acquisition.token.key())?;
            None
        } else {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        };

        let lineage =
            Self::lock_postgres_no_send_lineage(&mut transaction, recovery_key, state_instance_id)?;
        if lineage.acquisition.acquisition_id != acquisition.acquisition_id
            || lineage.acquisition.lease_fence != acquisition.lease_fence
            || lineage.acquisition.claim_state != preflight_state
        {
            return Err(StateError::DispatchAcquisitionMismatch);
        }
        let acquisition = lineage.acquisition;
        let claim_row = lineage.claim_row;
        let claim_state = acquisition.claim_state.clone();
        let creation_absent_at = if lineage.create.phase == BrokerJournalPhase::ReconcileOnly
            && lineage.create.outcome.is_none()
            && lineage.create.bound_secret_uid.is_none()
            && lineage.create.reconciliation_count > 0
            && lineage.create.last_reconciliation_outcome
                == Some(BrokerJournalOutcome::CreateAbsent)
            && !lineage.has_issue
            && lineage.review.is_none()
            && lineage.delete.is_none()
        {
            Some(
                lineage
                    .create
                    .last_reconciled_at
                    .ok_or(StateError::BrokerOperationMismatch)?,
            )
        } else {
            None
        };
        if let Some(absent_at) = creation_absent_at {
            let recovery_acquisition = Self::dispatch_recovery_acquisition(&acquisition)?;
            if claim_state == "RECOVERY_RETIRED" {
                if claim_row.get::<_, Option<i64>>("recovery_safe_after_unix_s") != Some(absent_at)
                    || claim_row.get::<_, Option<i64>>("recovery_retired_unix_s") != Some(absent_at)
                {
                    return Err(StateError::DispatchAcquisitionMismatch);
                }
                transaction.commit()?;
                return Ok(RecoveryNoSendRetirementOutcome::Recovered(
                    RecoveryNoSendRetirementReceipt::new(
                        acquisition.token.key().clone(),
                        recovery_acquisition,
                        absent_at,
                        absent_at,
                    ),
                ));
            }
            let updated = transaction.execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET state='RECOVERY_RETIRED',
                        recovery_safe_after_unix_s=$8,
                        recovery_retired_unix_s=$8,
                        updated_at=clock_timestamp()
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                    AND state_instance_id=$7 AND state='RECOVERY_NO_SEND'",
                &[
                    &acquisition.token.key().scope.tenant,
                    &acquisition.token.key().scope.environment,
                    &acquisition.token.key().authorization_id,
                    &acquisition.token.key().transaction_id,
                    &acquisition.token.claim_id(),
                    &i64::try_from(acquisition.token.fence())
                        .map_err(|_| StateError::DispatchAcquisitionMismatch)?,
                    &state_instance_id,
                    &absent_at,
                ],
            )?;
            if updated != 1 {
                return Err(StateError::DispatchAttemptOutcomeUnknown);
            }
            let receipt = RecoveryNoSendRetirementReceipt::new(
                acquisition.token.key().clone(),
                recovery_acquisition,
                absent_at,
                absent_at,
            );
            transaction.commit()?;
            return Ok(RecoveryNoSendRetirementOutcome::Retired(receipt));
        }
        let delete = lineage
            .delete
            .as_ref()
            .ok_or(StateError::BrokerOperationNotFound)?;
        let valid_delete_binding = match acquisition.selection_kind.as_str() {
            "CONTROL_QUEUE" => delete.acquisition_binding_version == 2,
            "CONTROL_BOOTSTRAP_V13" => {
                matches!(delete.acquisition_binding_version, 1 | 2)
            }
            _ => false,
        };
        if delete.phase != BrokerJournalPhase::Committed
            || delete.outcome != Some(BrokerJournalOutcome::DeleteAbsent)
            || !valid_delete_binding
            || delete.origin_acquisition_id != acquisition.acquisition_id
            || delete.origin_lease_fence != acquisition.lease_fence
            || delete.claim_id != acquisition.token.claim_id()
            || delete.fence != acquisition.token.fence()
            || delete.state_instance_id != state_instance_id
            || delete.physical_resource != *acquisition.token.physical_resource()
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let deletion_row =
            Self::secret_deletion_observation_row(&mut transaction, acquisition.token.key(), true)?
                .ok_or(StateError::BrokerOperationMismatch)?;
        let deletion = Self::stored_secret_deletion_observation(&deletion_row)?;
        if deletion
            != StoredSecretDeletionObservation::from_committed_delete(delete, deletion.observed_at)?
        {
            return Err(StateError::BrokerOperationMismatch);
        }
        let propagation_safe_after = deletion
            .observed_at
            .checked_add(
                lineage
                    .lifecycle_policy
                    .deletion_propagation_hard_max_seconds(),
            )
            .and_then(|value| {
                value.checked_add(lineage.lifecycle_policy.clock_uncertainty_seconds())
            })
            .ok_or(StateError::DeadlineOverflow)?;
        let computed_safe_after = propagation_safe_after;
        // Pending persists the retirement bound.  A later durable review
        // transition may add evidence, but must not rewrite that established
        // byte-stable recovery decision on a retry.
        let safe_after = claim_row
            .get::<_, Option<i64>>("recovery_safe_after_unix_s")
            .unwrap_or(computed_safe_after);
        let recovery_acquisition = Self::dispatch_recovery_acquisition(&acquisition)?;

        if claim_state == "RECOVERY_RETIRED" {
            let stored_safe_after = claim_row
                .get::<_, Option<i64>>("recovery_safe_after_unix_s")
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            let retired_at = claim_row
                .get::<_, Option<i64>>("recovery_retired_unix_s")
                .ok_or(StateError::DispatchAcquisitionMismatch)?;
            if stored_safe_after != safe_after || retired_at < safe_after {
                return Err(StateError::DispatchAcquisitionMismatch);
            }
            transaction.commit()?;
            return Ok(RecoveryNoSendRetirementOutcome::Recovered(
                RecoveryNoSendRetirementReceipt::new(
                    acquisition.token.key().clone(),
                    recovery_acquisition,
                    safe_after,
                    retired_at,
                ),
            ));
        }

        let time_inputs = time_inputs.ok_or(StateError::DispatchAcquisitionMismatch)?;
        let observed_at = Self::sample_trusted_time(&mut transaction)?;
        Self::validate_and_advance_broker_time(
            &mut transaction,
            acquisition.token.key(),
            &time_inputs,
            observed_at,
        )?;
        if observed_at < safe_after {
            let updated = transaction.execute(
                "UPDATE public.accordlock_dispatch_claims
                    SET recovery_safe_after_unix_s=$8,
                        updated_at=clock_timestamp()
                  WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                    AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                    AND state_instance_id=$7 AND state='RECOVERY_NO_SEND'
                    AND (recovery_safe_after_unix_s IS NULL
                         OR recovery_safe_after_unix_s=$8)
                    AND recovery_retired_unix_s IS NULL",
                &[
                    &acquisition.token.key().scope.tenant,
                    &acquisition.token.key().scope.environment,
                    &acquisition.token.key().authorization_id,
                    &acquisition.token.key().transaction_id,
                    &acquisition.token.claim_id(),
                    &i64::try_from(acquisition.token.fence())
                        .map_err(|_| StateError::DispatchAcquisitionMismatch)?,
                    &state_instance_id,
                    &safe_after,
                ],
            )?;
            if updated != 1 {
                return Err(StateError::DispatchAttemptOutcomeUnknown);
            }
            transaction.commit()?;
            return Ok(RecoveryNoSendRetirementOutcome::Pending { safe_after });
        }
        let updated = transaction.execute(
            "UPDATE public.accordlock_dispatch_claims
                SET state='RECOVERY_RETIRED',
                    recovery_safe_after_unix_s=$8,
                    recovery_retired_unix_s=$9,
                    updated_at=clock_timestamp()
              WHERE tenant=$1 AND environment=$2 AND authorization_id=$3
                AND transaction_id=$4 AND claim_id=$5 AND fence=$6
                AND state_instance_id=$7 AND state='RECOVERY_NO_SEND'
                AND (recovery_safe_after_unix_s IS NULL
                     OR recovery_safe_after_unix_s=$8)
                AND recovery_retired_unix_s IS NULL",
            &[
                &acquisition.token.key().scope.tenant,
                &acquisition.token.key().scope.environment,
                &acquisition.token.key().authorization_id,
                &acquisition.token.key().transaction_id,
                &acquisition.token.claim_id(),
                &i64::try_from(acquisition.token.fence())
                    .map_err(|_| StateError::DispatchAcquisitionMismatch)?,
                &state_instance_id,
                &safe_after,
                &observed_at,
            ],
        )?;
        if updated != 1 {
            return Err(StateError::DispatchAttemptOutcomeUnknown);
        }
        let receipt = RecoveryNoSendRetirementReceipt::new(
            acquisition.token.key().clone(),
            recovery_acquisition,
            safe_after,
            observed_at,
        );
        transaction
            .commit()
            .map_err(|_| StateError::DispatchAttemptOutcomeUnknown)?;
        Ok(RecoveryNoSendRetirementOutcome::Retired(receipt))
    }
}

impl EksDestinationRegistryState for PostgresStore {
    fn activate_eks_destination(
        &self,
        scope: &Scope,
        profile: &EksDestinationProfile,
    ) -> Result<(), EksRegistryError> {
        scope.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.activate_eks_destination_once(scope, profile) {
                Err(EksRegistryError::State(StateError::Database(error)))
                    if is_retryable(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted.into());
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted.into())
    }

    fn load_current_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        scope.validate()?;
        if transaction_id.is_nil() {
            return Err(EksRegistryError::NotFound);
        }
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.load_current_eks_attempt_once(scope, transaction_id) {
                Err(EksRegistryError::State(StateError::Database(error)))
                    if is_retryable(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted.into());
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted.into())
    }

    fn load_current_eks_attempt_for_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.load_current_eks_attempt_for_acquisition_once(authority) {
                Err(EksRegistryError::State(StateError::Database(error)))
                    if is_retryable(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted.into());
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted.into())
    }

    fn load_frozen_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        scope.validate()?;
        if transaction_id.is_nil() {
            return Err(EksRegistryError::NotFound);
        }
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.load_frozen_eks_attempt_once(scope, transaction_id) {
                Err(EksRegistryError::State(StateError::Database(error)))
                    if is_retryable(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted.into());
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted.into())
    }

    fn load_frozen_eks_attempt_for_journal(
        &self,
        selector: &crate::BrokerJournalSelector,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.load_frozen_eks_attempt_for_journal_once(selector) {
                Err(EksRegistryError::State(StateError::Database(error)))
                    if is_retryable(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted.into());
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted.into())
    }
}

impl EksDestinationRegistryState for TlsPostgresStore {
    fn activate_eks_destination(
        &self,
        scope: &Scope,
        profile: &EksDestinationProfile,
    ) -> Result<(), EksRegistryError> {
        self.inner.activate_eks_destination(scope, profile)
    }

    fn load_current_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        self.inner.load_current_eks_attempt(scope, transaction_id)
    }

    fn load_current_eks_attempt_for_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<CurrentEksAttempt, EksRegistryError> {
        self.inner
            .load_current_eks_attempt_for_acquisition(authority)
    }

    fn load_frozen_eks_attempt(
        &self,
        scope: &Scope,
        transaction_id: Uuid,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        self.inner.load_frozen_eks_attempt(scope, transaction_id)
    }

    fn load_frozen_eks_attempt_for_journal(
        &self,
        selector: &crate::BrokerJournalSelector,
    ) -> Result<FrozenEksAttempt, EksRegistryError> {
        self.inner.load_frozen_eks_attempt_for_journal(selector)
    }
}

impl TerminalRetirementState for PostgresStore {
    fn register_terminal_witness_registry_or_recover(
        &self,
        scope: &Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry: &ActivatedWitnessRegistry,
    ) -> Result<TerminalWitnessRegistryReceipt, StateError> {
        scope.validate()?;
        if resource_activation_id.is_nil()
            || mediation_activation_id.is_nil()
            || registry.commitment() == Digest32::from_bytes([0; 32])
        {
            return Err(StateError::TerminalWitnessRegistryMismatch);
        }
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.register_terminal_registry_once(
                scope,
                resource_activation_id,
                mediation_activation_id,
                registry,
            ) {
                Err(StateError::Database(_)) => {
                    // A unique race or lost COMMIT response is resolved only
                    // by reloading and comparing the complete registry and
                    // rooted binding on the next attempt.
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::TerminalWitnessRegistryOutcomeUnknown);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::TerminalWitnessRegistryOutcomeUnknown)
    }

    fn terminal_retirement_context(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementContext, StateError> {
        key.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            let mut client = self.connect()?;
            let mut transaction = Self::serializable(&mut client)?;
            match Self::locked_terminal_inputs(&mut transaction, key) {
                Ok((inputs, state)) if state == "ATTEMPT_IN_FLIGHT" => {
                    transaction.commit()?;
                    return Ok(inputs.context);
                }
                Ok(_) => return Err(StateError::TerminalRetirementLineageUnavailable),
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn finalize_terminal_retirement_or_recover(
        &self,
        request: &TerminalRetirementRequest,
    ) -> Result<TerminalRetirementReceipt, StateError> {
        request.key().validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.finalize_terminal_retirement_once(request) {
                Err(StateError::Database(_)) => {
                    // Includes serialization/unique races and an ambiguous
                    // COMMIT. No new authority is reconstructed: the retry
                    // succeeds only through the exact stored terminal tuple.
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::TerminalRetirementOutcomeUnknown);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::TerminalRetirementOutcomeUnknown)
    }

    fn terminal_retirement_audit(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementAudit, StateError> {
        key.validate()?;
        self.terminal_retirement_audit_once(key)
    }
}

impl TerminalRetirementState for TlsPostgresStore {
    fn register_terminal_witness_registry_or_recover(
        &self,
        scope: &Scope,
        resource_activation_id: Uuid,
        mediation_activation_id: Uuid,
        registry: &ActivatedWitnessRegistry,
    ) -> Result<TerminalWitnessRegistryReceipt, StateError> {
        self.inner.register_terminal_witness_registry_or_recover(
            scope,
            resource_activation_id,
            mediation_activation_id,
            registry,
        )
    }

    fn terminal_retirement_context(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementContext, StateError> {
        self.inner.terminal_retirement_context(key)
    }

    fn finalize_terminal_retirement_or_recover(
        &self,
        request: &TerminalRetirementRequest,
    ) -> Result<TerminalRetirementReceipt, StateError> {
        self.inner.finalize_terminal_retirement_or_recover(request)
    }

    fn terminal_retirement_audit(
        &self,
        key: &ConsumeKey,
    ) -> Result<TerminalRetirementAudit, StateError> {
        self.inner.terminal_retirement_audit(key)
    }
}

impl TransactionalState for PostgresStore {
    fn compare_and_activate_authority(
        &self,
        scope: &Scope,
        expected: Option<&AuthorityVector>,
        next: &AuthorityVector,
    ) -> Result<(), StateError> {
        scope.validate()?;
        validate_authority_vector(next)?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let row = transaction.query_opt(
            "SELECT authority_json
               FROM accordlock_authority_state
              WHERE tenant = $1 AND environment = $2
              FOR UPDATE",
            &[&scope.tenant, &scope.environment],
        )?;
        match (row, expected) {
            (None, None) => {
                let next_json = encode_json(next)?;
                transaction.execute(
                    "INSERT INTO accordlock_authority_state
                                (tenant, environment, authority_json)
                         VALUES ($1, $2, $3)",
                    &[&scope.tenant, &scope.environment, &next_json],
                )?;
            }
            (Some(row), Some(expected)) => {
                let current: AuthorityVector = decode_json(row.get("authority_json"))?;
                if &current != expected {
                    return Err(StateError::AuthorityCompareFailed);
                }
                ensure_monotone_authority(&current, next)?;
                let next_json = encode_json(next)?;
                transaction.execute(
                    "UPDATE accordlock_authority_state
                        SET authority_json = $3, updated_at = clock_timestamp()
                      WHERE tenant = $1 AND environment = $2",
                    &[&scope.tenant, &scope.environment, &next_json],
                )?;
            }
            _ => return Err(StateError::AuthorityCompareFailed),
        }
        transaction.commit()?;
        Ok(())
    }

    fn active_authority(&self, scope: &Scope) -> Result<AuthorityVector, StateError> {
        scope.validate()?;
        let mut client = self.connect()?;
        let row = client
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        decode_json(row.get("authority_json"))
    }

    fn register_grant(&self, grant: &GrantRegistration) -> Result<(), StateError> {
        grant.validate()?;
        let scope = grant.scope();
        let registration_json = encode_json(grant)?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let authority_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let active: AuthorityVector = decode_json(authority_row.get("authority_json"))?;
        if transaction
            .query_opt(
                "SELECT grant_id
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )?
            .is_some()
        {
            return Err(StateError::GrantAlreadyExists);
        }
        let high_water = Self::lock_or_create_high_water(&mut transaction, &scope)?;
        let observed_time = Self::sample_trusted_time(&mut transaction)?;
        if observed_time < high_water {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        let snapshot = GrantSnapshot {
            registration: grant.clone(),
            uses: 0,
            revoked: false,
        };
        match validate_current_grant(&active, &snapshot, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                Self::update_dispatch_high_water(&mut transaction, &scope, observed_time)?;
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        Self::update_dispatch_high_water(&mut transaction, &scope, observed_time)?;
        match transaction.execute(
            "INSERT INTO accordlock_grants
                        (tenant, environment, grant_id, registration_json,
                         maximum_uses, not_before, expires_at,
                         issuance_profile_version)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 2)",
            &[
                &scope.tenant,
                &scope.environment,
                &grant.grant.grant_id,
                &registration_json,
                &i64::from(grant.grant.maximum_uses),
                &grant.grant.not_before,
                &grant.grant.expires_at,
            ],
        ) {
            Ok(1) => {
                transaction.commit()?;
                Ok(())
            }
            Ok(_) => Err(StateError::GrantAlreadyExists),
            Err(error) if is_unique_violation(&error) => Err(StateError::GrantAlreadyExists),
            Err(error) => Err(StateError::Database(error)),
        }
    }

    fn grant_snapshot(&self, scope: &Scope, grant_id: Uuid) -> Result<GrantSnapshot, StateError> {
        scope.validate()?;
        let mut client = self.connect()?;
        let row = client
            .query_opt(
                "SELECT registration_json, uses, maximum_uses, not_before,
                        expires_at, revoked, issuance_profile_version
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2 AND grant_id = $3",
                &[&scope.tenant, &scope.environment, &grant_id],
            )?
            .ok_or(StateError::GrantNotFound)?;
        let uses_i64: i64 = row.get("uses");
        let snapshot = GrantSnapshot {
            registration: decode_json(row.get("registration_json"))?,
            uses: u32::try_from(uses_i64).map_err(|_| {
                StateError::InvalidRecord("stored grant use count does not fit u32".to_owned())
            })?,
            revoked: row.get("revoked"),
        };
        snapshot.registration.validate()?;
        if row.get::<_, i16>("issuance_profile_version") != 2
            || snapshot.registration.scope() != *scope
            || snapshot.registration.grant.grant_id != grant_id
            || row.get::<_, i64>("maximum_uses")
                != i64::from(snapshot.registration.grant.maximum_uses)
            || row.get::<_, i64>("not_before") != snapshot.registration.grant.not_before
            || row.get::<_, i64>("expires_at") != snapshot.registration.grant.expires_at
        {
            return Err(StateError::InvalidRecord(
                "stored grant columns and registration JSON do not agree".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    fn issuance_snapshot(
        &self,
        scope: &Scope,
        grant_id: Uuid,
    ) -> Result<IssuanceSnapshot, StateError> {
        scope.validate()?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let authority_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let active: AuthorityVector = decode_json(authority_row.get("authority_json"))?;
        let high_water = Self::lock_or_create_high_water(&mut transaction, scope)?;
        let row = transaction
            .query_opt(
                "SELECT registration_json, uses, maximum_uses, not_before,
                        expires_at, revoked, issuance_profile_version
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                  FOR SHARE",
                &[&scope.tenant, &scope.environment, &grant_id],
            )?
            .ok_or(StateError::GrantNotFound)?;
        let uses_i64: i64 = row.get("uses");
        let snapshot = GrantSnapshot {
            registration: decode_json(row.get("registration_json"))?,
            uses: u32::try_from(uses_i64).map_err(|_| {
                StateError::InvalidRecord("stored grant use count does not fit u32".to_owned())
            })?,
            revoked: row.get("revoked"),
        };
        if row.get::<_, i16>("issuance_profile_version") != 2
            || snapshot.registration.scope() != *scope
            || snapshot.registration.grant.grant_id != grant_id
            || row.get::<_, i64>("maximum_uses")
                != i64::from(snapshot.registration.grant.maximum_uses)
            || row.get::<_, i64>("not_before") != snapshot.registration.grant.not_before
            || row.get::<_, i64>("expires_at") != snapshot.registration.grant.expires_at
        {
            return Err(StateError::InvalidRecord(
                "stored grant columns and issuance profile do not agree".to_owned(),
            ));
        }
        let observed_time = Self::sample_trusted_time(&mut transaction)?;
        if observed_time < high_water {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        match validate_current_grant(&active, &snapshot, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                Self::update_dispatch_high_water(&mut transaction, scope, observed_time)?;
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        Self::update_dispatch_high_water(&mut transaction, scope, observed_time)?;
        let result = IssuanceSnapshot::new(scope.clone(), snapshot.registration, observed_time);
        transaction.commit()?;
        Ok(result)
    }

    fn revoke_grant(
        &self,
        scope: &Scope,
        grant_id: Uuid,
        expected_authority: &AuthorityVector,
        next_authority: &AuthorityVector,
    ) -> Result<(), StateError> {
        scope.validate()?;
        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        let row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR UPDATE",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let active: AuthorityVector = decode_json(row.get("authority_json"))?;
        if &active != expected_authority {
            return Err(StateError::AuthorityCompareFailed);
        }
        validate_revocation_transition(grant_id, expected_authority, next_authority)?;
        let updated = transaction.execute(
            "UPDATE accordlock_grants
                SET revoked = TRUE, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                AND issuance_profile_version = 2",
            &[&scope.tenant, &scope.environment, &grant_id],
        )?;
        if updated != 1 {
            return Err(StateError::GrantNotFound);
        }
        let next_json = encode_json(next_authority)?;
        transaction.execute(
            "UPDATE accordlock_authority_state
                SET authority_json = $3, updated_at = clock_timestamp()
              WHERE tenant = $1 AND environment = $2",
            &[&scope.tenant, &scope.environment, &next_json],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Keep the final locked issuance rechecks visible in one transaction.
    fn record_issued_authorization(
        &self,
        record: &IssuedAuthorizationRecord,
    ) -> Result<(), StateError> {
        record.validate()?;
        let scope = record.scope();
        scope.validate()?;

        let mut client = self.connect()?;
        let mut transaction = Self::serializable(&mut client)?;
        if transaction
            .query_opt(
                "SELECT 1
                  FROM public.accordlock_control_submissions
                  WHERE (tenant = $1 AND environment = $2 AND request_id = $3)
                     OR evaluation_nonce = $4
                  FOR SHARE",
                &[
                    &scope.tenant,
                    &scope.environment,
                    &record.authorization().request_id,
                    &record.authorization().evaluation_nonce,
                ],
            )?
            .is_some()
        {
            return Err(StateError::ControlWorkMismatch);
        }
        let authority_row = transaction
            .query_opt(
                "SELECT authority_json
                   FROM accordlock_authority_state
                  WHERE tenant = $1 AND environment = $2
                  FOR SHARE",
                &[&scope.tenant, &scope.environment],
            )?
            .ok_or(StateError::AuthorityNotInitialized)?;
        let authority: AuthorityVector = decode_json(authority_row.get("authority_json"))?;
        if authority != record.signed_authorization.authorization.authority {
            return Err(StateError::AuthorityMismatch);
        }
        let high_water = Self::lock_or_create_high_water(&mut transaction, &scope)?;
        let grant_row = transaction
            .query_opt(
                "SELECT registration_json, uses, maximum_uses, not_before,
                        expires_at, revoked, issuance_profile_version
                   FROM accordlock_grants
                  WHERE tenant = $1 AND environment = $2 AND grant_id = $3
                  FOR SHARE",
                &[
                    &scope.tenant,
                    &scope.environment,
                    &record.signed_authorization.authorization.grant_id,
                ],
            )?
            .ok_or(StateError::GrantNotFound)?;
        let uses_i64: i64 = grant_row.get("uses");
        let grant = GrantSnapshot {
            registration: decode_json(grant_row.get("registration_json"))?,
            uses: u32::try_from(uses_i64).map_err(|_| {
                StateError::InvalidRecord("stored grant use count does not fit u32".to_owned())
            })?,
            revoked: grant_row.get("revoked"),
        };
        if grant_row.get::<_, i16>("issuance_profile_version") != 2
            || grant_row.get::<_, i64>("maximum_uses")
                != i64::from(grant.registration.grant.maximum_uses)
            || grant_row.get::<_, i64>("not_before") != grant.registration.grant.not_before
            || grant_row.get::<_, i64>("expires_at") != grant.registration.grant.expires_at
        {
            return Err(StateError::InvalidRecord(
                "stored grant columns and issuance profile do not agree".to_owned(),
            ));
        }
        validate_grant_for_authorization(
            &grant.registration,
            &record.signed_authorization.authorization,
        )?;
        let observed_time = Self::sample_trusted_time(&mut transaction)?;
        if observed_time < high_water {
            return Err(StateError::ClockRollback {
                observed: observed_time,
                high_water,
            });
        }
        match validate_current_grant(&authority, &grant, observed_time) {
            Ok(()) => {}
            Err(error) if is_temporal_rejection_for_sample(&error, observed_time) => {
                Self::update_dispatch_high_water(&mut transaction, &scope, observed_time)?;
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        if record.signed_authorization.authorization.issued_at > observed_time
            || observed_time >= record.signed_authorization.authorization.consume_before
        {
            let error = StateError::AuthorizationExpired {
                observed: observed_time,
                consume_before: record.signed_authorization.authorization.consume_before,
            };
            Self::update_dispatch_high_water(&mut transaction, &scope, observed_time)?;
            transaction.commit()?;
            return Err(error);
        }
        Self::update_dispatch_high_water(&mut transaction, &scope, observed_time)?;
        let record_json = encode_json(record)?;

        match transaction.execute(
            "INSERT INTO accordlock_issued_authorizations
                         (tenant, environment, authorization_id, transaction_id, grant_id,
                         record_json, authorization_hash, consume_before,
                         issuance_profile_version, request_id, evaluation_nonce)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 2, $9, $10)",
            &[
                &scope.tenant,
                &scope.environment,
                &record.signed_authorization.authorization.authorization_id,
                &record.transaction_id,
                &record.signed_authorization.authorization.grant_id,
                &record_json,
                &record.authorization_hash.to_string(),
                &record.signed_authorization.authorization.consume_before,
                &record.signed_authorization.authorization.request_id,
                &record.signed_authorization.authorization.evaluation_nonce,
            ],
        ) {
            Ok(1) => {
                transaction.commit()?;
                Ok(())
            }
            Ok(_) => Err(StateError::AuthorizationAlreadyExists),
            Err(error) if is_unique_violation(&error) => {
                Err(StateError::AuthorizationAlreadyExists)
            }
            Err(error) => Err(StateError::Database(error)),
        }
    }

    fn consume(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        key.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.consume_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn consume_or_recover(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        match self.recover_exact(key) {
            Ok(success) => return Ok(success),
            Err(StateError::ConsumptionNotFound | StateError::AuthorizationNotFound) => {}
            Err(StateError::Database(_)) => {
                return Err(StateError::ConsumptionOutcomeUnknown);
            }
            Err(error) => return Err(error),
        }
        match self.consume(key) {
            Err(StateError::AlreadyConsumed) => match self.recover_exact(key) {
                Err(StateError::ConsumptionNotFound | StateError::AuthorizationNotFound) => {
                    Err(StateError::InvalidRecord(
                        "consumed authorization lacks its exact receipt and outbox tuple"
                            .to_owned(),
                    ))
                }
                Err(StateError::Database(_)) => Err(StateError::ConsumptionOutcomeUnknown),
                result => result,
            },
            Err(StateError::Database(_)) => match self.recover_exact(key) {
                Ok(success) => Ok(success),
                Err(StateError::Database(_) | StateError::ConsumptionNotFound) => {
                    Err(StateError::ConsumptionOutcomeUnknown)
                }
                Err(error) => Err(error),
            },
            result => result,
        }
    }

    fn dispatch_snapshot(&self, key: &ConsumeKey) -> Result<DispatchSnapshot, StateError> {
        key.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.dispatch_snapshot_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn claim_dispatch(
        &self,
        request: &DispatchClaimRequest,
    ) -> Result<ClaimedDispatch, StateError> {
        request.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.claim_dispatch_once(request) {
                Err(StateError::Database(error)) if is_unique_violation(&error) => {
                    return self.classify_claim_collision(request);
                }
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return self.classify_claim_collision(request);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchClaimOutcomeUnknown);
                }
                result => return result,
            }
        }
        self.classify_claim_collision(request)
    }

    fn claim_next_pending_dispatch_or_recover(
        &self,
        scope: &Scope,
        request: &DispatchAcquisitionRequest,
    ) -> Result<DispatchAcquisitionOutcome, StateError> {
        scope.validate()?;
        request.validate()?;
        let recovery_key = DispatchAcquisitionRecoveryKey::from_request(scope, request);
        let mut excluded_submissions = Vec::new();
        let mut transient_retries = 0_usize;
        loop {
            let mut step = None;
            for attempt in 0..SERIALIZATION_ATTEMPTS {
                match self.claim_next_dispatch_once(scope, request, &excluded_submissions) {
                    Err(StateError::Database(error))
                        if is_retryable(&error) || is_unique_violation(&error) =>
                    {
                        if attempt + 1 == SERIALIZATION_ATTEMPTS {
                            return Ok(DispatchAcquisitionOutcome::OutcomeUnknown(recovery_key));
                        }
                    }
                    // A transport/connection failure has no SQLSTATE and may
                    // have hidden a successful COMMIT. Deterministic server
                    // errors (constraints, triggers, schema drift) carry a
                    // SQLSTATE and must remain visible to the caller.
                    Err(StateError::Database(error)) if error.code().is_none() => {
                        return Ok(DispatchAcquisitionOutcome::OutcomeUnknown(recovery_key));
                    }
                    Err(StateError::Database(error)) => {
                        return Err(StateError::Database(error));
                    }
                    result => {
                        step = Some(result?);
                        break;
                    }
                }
            }
            match step.ok_or(StateError::RetryLimitExhausted)? {
                DispatchAcquisitionStep::Outcome(outcome) => return Ok(*outcome),
                DispatchAcquisitionStep::ExactRecoveryRetry => {
                    transient_retries = transient_retries.saturating_add(1);
                    if transient_retries >= MAX_DISPATCH_ACQUISITION_SCAN {
                        return Ok(DispatchAcquisitionOutcome::NoWork);
                    }
                }
                DispatchAcquisitionStep::SkippedCandidate(submission_id) => {
                    if excluded_submissions.contains(&submission_id) {
                        return Ok(DispatchAcquisitionOutcome::NoWork);
                    }
                    // Durable, non-actionable heads are paginated out of this
                    // invocation rather than consuming the transient-race
                    // retry budget.  This keeps a valid tail reachable even
                    // when more than MAX_DISPATCH_ACQUISITION_SCAN historical
                    // generations are waiting on another resource or margin.
                    excluded_submissions.push(submission_id);
                }
            }
        }
    }

    fn revalidate_dispatch_claim(
        &self,
        token: &DispatchClaimToken,
    ) -> Result<DispatchSnapshot, StateError> {
        token.key().validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.revalidate_dispatch_claim_once(token) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn revalidate_dispatch_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<DispatchSnapshot, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.revalidate_dispatch_acquisition_once(authority) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn mark_attempt_in_flight(
        &self,
        token: &DispatchClaimToken,
        credential: DispatchCredentialBinding,
    ) -> Result<AttemptInFlight, StateError> {
        token.key().validate()?;
        match self.mark_attempt_in_flight_once(token, credential) {
            Err(StateError::Database(_)) => Err(StateError::DispatchAttemptOutcomeUnknown),
            result => result,
        }
    }

    fn mark_dispatch_acquisition_attempt_in_flight(
        &self,
        reviewed: ReviewedDispatchCredential,
    ) -> Result<AttemptInFlight, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.mark_dispatch_acquisition_attempt_in_flight_once(&reviewed) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchAttemptOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchAttemptOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchAttemptOutcomeUnknown)
    }

    fn close_dispatch_acquisition_no_send(
        &self,
        key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendReceipt, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.close_dispatch_acquisition_no_send_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchAttemptOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchAttemptOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchAttemptOutcomeUnknown)
    }

    fn retire_recovery_no_send(
        &self,
        key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendRetirementOutcome, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.retire_recovery_no_send_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchAttemptOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchAttemptOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchAttemptOutcomeUnknown)
    }

    fn admission_context(&self, key: &ConsumeKey) -> Result<AdmissionContext, StateError> {
        key.validate()?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.admission_context_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn authorize_admission_or_recover(
        &self,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<AdmissionAuthorization, StateError> {
        request.validate()?;
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.authorize_admission_once(request) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) => {}
                Err(StateError::Database(_) | StateError::AdmissionOutcomeUnknown) => {}
                result => return result,
            }
        }
        Err(StateError::AdmissionOutcomeUnknown)
    }

    fn consumption_receipt(&self, key: &ConsumeKey) -> Result<ConsumptionReceipt, StateError> {
        Ok(self.recover_exact(key)?.into_parts().0)
    }

    fn outbox_entry(&self, key: &ConsumeKey) -> Result<OutboxEntry, StateError> {
        Ok(self.recover_exact(key)?.into_parts().1)
    }

    fn time_high_water(&self, scope: &Scope) -> Result<Option<i64>, StateError> {
        scope.validate()?;
        let mut client = self.connect()?;
        Ok(client
            .query_opt(
                "SELECT observed_unix_s
                   FROM accordlock_time_high_water
                  WHERE tenant = $1 AND environment = $2",
                &[&scope.tenant, &scope.environment],
            )?
            .map(|row| row.get("observed_unix_s")))
    }
}

impl IngressReplayState for PostgresStore {
    fn observe_ingress_time(
        &self,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
    ) -> Result<(), StateError> {
        validate_observed_time(observed_unix_s)?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.observe_ingress_time_once(scope, observed_unix_s) {
                Ok(()) => return Ok(()),
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn consume_ingress_nonce(
        &self,
        request: &IngressNonceConsumption,
    ) -> Result<IngressReplayDecision, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.consume_ingress_nonce_once(request) {
                Ok(decision) => return Ok(decision),
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn prune_expired_ingress_nonces(
        &self,
        scope: &IngressReplayScope,
        limit: u32,
    ) -> Result<u32, StateError> {
        if !valid_gc_limit(limit) {
            return Err(StateError::InvalidRecord(
                "ingress replay GC batch is outside the bounded profile".to_owned(),
            ));
        }
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.prune_expired_ingress_nonces_once(scope, limit) {
                Ok(deleted) => return Ok(deleted),
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::RetryLimitExhausted)
    }
}

impl BrokerJournalState for PostgresStore {
    fn issue_broker_journal_capability(&mut self) -> Result<BrokerJournalCapability, StateError> {
        self.broker_capability_issuer
            .issue(self.state_instance_id()?)
    }

    fn prepare_broker_operation(
        &self,
        capability: &BrokerJournalCapability,
        request: BrokerOperationRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.require_broker_capability(capability)?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.prepare_broker_operation_once(&request) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::BrokerOperationOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::BrokerOperationOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn begin_broker_operation_for_acquisition(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        request: AcquiredBrokerOperationRequest,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.begin_broker_operation_for_acquisition_once(authority, &request) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::BrokerOperationOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::BrokerOperationOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn begin_dispatch_credential_review(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        token_journal: &BrokerJournalSelector,
    ) -> Result<crate::CredentialReviewIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.begin_dispatch_credential_review_once(authority, token_journal) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchCredentialReviewOutcomeUnknown)
    }

    fn record_authenticated_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: AuthenticatedDispatchCredentialReview,
    ) -> Result<crate::ReviewedDispatchCredential, StateError> {
        let expected = authority.stored;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.record_authenticated_dispatch_credential_once(&expected, observation.clone())
            {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchCredentialReviewOutcomeUnknown)
    }

    fn recover_authenticated_dispatch_credential(
        &self,
        key: &DispatchCredentialReviewRecoveryKey,
    ) -> Result<crate::ReviewedDispatchCredential, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.recover_authenticated_dispatch_credential_once(key) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn record_rejected_dispatch_credential(
        &self,
        authority: CredentialReviewIoAuthority,
        observation: RejectedDispatchCredentialReview,
    ) -> Result<crate::DispatchCredentialReviewAudit, StateError> {
        let expected = authority.stored;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.record_rejected_dispatch_credential_once(&expected, observation.clone()) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::DispatchCredentialReviewOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::DispatchCredentialReviewOutcomeUnknown)
    }

    fn dispatch_credential_review_audit(
        &self,
        acquisition: &DispatchAcquisitionRecoveryKey,
    ) -> Result<crate::DispatchCredentialReviewAudit, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.dispatch_credential_review_audit_once(acquisition) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn dispatch_broker_restart_context(
        &self,
        acquisition: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<crate::DispatchBrokerRestartContext, StateError> {
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.dispatch_broker_restart_context_once(acquisition) {
                Err(StateError::Database(error)) if is_retryable(&error) => {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::RetryLimitExhausted);
                    }
                }
                result => return result,
            }
        }
        Err(StateError::RetryLimitExhausted)
    }

    fn prepare_broker_cleanup(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerCleanupRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.require_broker_capability(capability)?;
        for attempt in 0..SERIALIZATION_ATTEMPTS {
            match self.prepare_broker_cleanup_once(request) {
                Err(StateError::Database(error))
                    if is_retryable(&error) || is_unique_violation(&error) =>
                {
                    if attempt + 1 == SERIALIZATION_ATTEMPTS {
                        return Err(StateError::BrokerOperationOutcomeUnknown);
                    }
                }
                Err(StateError::Database(_)) => {
                    return Err(StateError::BrokerOperationOutcomeUnknown);
                }
                result => return result,
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn begin_broker_io(
        &self,
        capability: &BrokerJournalCapability,
        intent: BrokerOperationIntent,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.require_broker_capability(capability)?;
        // Never retry or reconstruct mutation authority after a database
        // ambiguity. If the transaction definitely aborted, the retained
        // INTENT remains safe for a future explicit prepare/adopt call.
        match self.begin_broker_io_once(&intent.stored) {
            Err(StateError::Database(_)) => Err(StateError::BrokerOperationOutcomeUnknown),
            result => result,
        }
    }

    fn commit_broker_create(
        &self,
        authority: BrokerIoAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        let expected = authority.stored;
        let (_, _, _, _, desired) = Self::broker_secret_result(&expected, &observation, true)?;
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.commit_broker_secret_once(&expected, &observation, true) {
                Ok(receipt) => return Ok(receipt),
                Err(StateError::Database(_) | StateError::BrokerOperationOutcomeUnknown) => {
                    if let Ok(stored) =
                        self.load_stored_broker_operation(&expected.key, expected.operation)
                        && stored.result_commitment == Some(desired)
                    {
                        return Ok(BrokerOperationReceipt::new(stored.audit(), true));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn commit_broker_token_issue(
        &self,
        authority: BrokerIoAuthority,
        observation: &BrokerTokenIssueObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        let expected = authority.stored;
        let desired = broker_result_commitment(
            expected.request_commitment,
            BrokerJournalOutcome::TokenIssued,
            expected.bound_secret_uid.as_deref(),
            observation.evidence_commitment(),
            Some(observation.token_digest()),
            Some(observation.expires_at()),
        )?;
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.commit_broker_token_once(&expected, observation) {
                Ok(receipt) => return Ok(receipt),
                Err(StateError::Database(_) | StateError::BrokerOperationOutcomeUnknown) => {
                    if let Ok(stored) =
                        self.load_stored_broker_operation(&expected.key, expected.operation)
                        && stored.result_commitment == Some(desired)
                    {
                        return Ok(BrokerOperationReceipt::new(stored.audit(), true));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn mark_broker_io_unknown(
        &self,
        authority: BrokerIoAuthority,
    ) -> Result<BrokerOperationAudit, StateError> {
        let expected = authority.stored;
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.mark_broker_unknown_once(&expected) {
                Ok(audit) => return Ok(audit),
                Err(StateError::Database(_) | StateError::BrokerOperationOutcomeUnknown) => {
                    if let Ok(stored) =
                        self.load_stored_broker_operation(&expected.key, expected.operation)
                        && stored.phase == BrokerJournalPhase::Unknown
                    {
                        return Ok(stored.audit());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn begin_broker_reconciliation(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerReconciliationRequest,
    ) -> Result<BrokerReconciliationAuthority, StateError> {
        self.require_broker_capability(capability)?;
        if request.operation() == BrokerJournalOperation::IssueToken {
            return Err(StateError::BrokerTokenReissueForbidden);
        }
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.begin_broker_reconciliation_once(request) {
                Ok(authority) => return Ok(authority),
                Err(StateError::Database(_) | StateError::BrokerOperationOutcomeUnknown) => {
                    if let Ok(stored) =
                        self.load_stored_broker_operation(request.key(), request.operation())
                        && stored.route_commitment == request.route_commitment()
                        && stored.phase == BrokerJournalPhase::ReconcileOnly
                    {
                        return Ok(BrokerReconciliationAuthority::new(stored));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn commit_broker_reconciliation(
        &self,
        authority: BrokerReconciliationAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerReconciliationResult, StateError> {
        let expected = authority.stored;
        let pending = pending_broker_reconciliation(&expected, &observation);
        let next_reconciliation_count = pending
            .map(|_| {
                expected
                    .reconciliation_count
                    .checked_add(1)
                    .ok_or(StateError::BrokerOperationOutcomeUnknown)
            })
            .transpose()?;
        let completed_commitment = if pending.is_none() {
            Some(Self::broker_secret_result(&expected, &observation, false)?.4)
        } else {
            None
        };
        for _ in 0..SERIALIZATION_ATTEMPTS {
            match self.commit_broker_reconciliation_once(&expected, &observation) {
                Ok(result) => return Ok(result),
                Err(StateError::Database(_) | StateError::BrokerOperationOutcomeUnknown) => {
                    if let Ok(stored) =
                        self.load_stored_broker_operation(&expected.key, expected.operation)
                    {
                        if let Some((outcome, evidence)) = pending
                            && stored.phase == BrokerJournalPhase::ReconcileOnly
                            && Some(stored.reconciliation_count) == next_reconciliation_count
                            && stored.last_reconciliation_outcome == Some(outcome)
                            && stored.last_reconciliation_evidence_commitment == Some(evidence)
                        {
                            return Ok(BrokerReconciliationResult::Pending(
                                BrokerReconciliationAuthority::new(stored),
                            ));
                        }
                        if let Some(desired) = completed_commitment
                            && stored.result_commitment == Some(desired)
                        {
                            return Ok(BrokerReconciliationResult::Completed(
                                BrokerOperationReceipt::new(stored.audit(), true),
                            ));
                        }
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StateError::BrokerOperationOutcomeUnknown)
    }

    fn broker_operation_audit(
        &self,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
    ) -> Result<BrokerOperationAudit, StateError> {
        key.validate()?;
        Ok(self.load_stored_broker_operation(key, operation)?.audit())
    }
}

impl TransactionalState for TlsPostgresStore {
    fn compare_and_activate_authority(
        &self,
        scope: &Scope,
        expected: Option<&AuthorityVector>,
        next: &AuthorityVector,
    ) -> Result<(), StateError> {
        self.inner
            .compare_and_activate_authority(scope, expected, next)
    }

    fn active_authority(&self, scope: &Scope) -> Result<AuthorityVector, StateError> {
        self.inner.active_authority(scope)
    }

    fn register_grant(&self, grant: &GrantRegistration) -> Result<(), StateError> {
        self.inner.register_grant(grant)
    }

    fn grant_snapshot(&self, scope: &Scope, grant_id: Uuid) -> Result<GrantSnapshot, StateError> {
        self.inner.grant_snapshot(scope, grant_id)
    }

    fn issuance_snapshot(
        &self,
        scope: &Scope,
        grant_id: Uuid,
    ) -> Result<IssuanceSnapshot, StateError> {
        self.inner.issuance_snapshot(scope, grant_id)
    }

    fn revoke_grant(
        &self,
        scope: &Scope,
        grant_id: Uuid,
        expected_authority: &AuthorityVector,
        next_authority: &AuthorityVector,
    ) -> Result<(), StateError> {
        self.inner
            .revoke_grant(scope, grant_id, expected_authority, next_authority)
    }

    fn record_issued_authorization(
        &self,
        record: &IssuedAuthorizationRecord,
    ) -> Result<(), StateError> {
        self.inner.record_issued_authorization(record)
    }

    fn consume(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        self.inner.consume(key)
    }

    fn consume_or_recover(&self, key: &ConsumeKey) -> Result<ConsumeSuccess, StateError> {
        self.inner.consume_or_recover(key)
    }

    fn dispatch_snapshot(&self, key: &ConsumeKey) -> Result<DispatchSnapshot, StateError> {
        self.inner.dispatch_snapshot(key)
    }

    fn claim_dispatch(
        &self,
        request: &DispatchClaimRequest,
    ) -> Result<ClaimedDispatch, StateError> {
        self.inner.claim_dispatch(request)
    }

    fn claim_next_pending_dispatch_or_recover(
        &self,
        scope: &Scope,
        request: &DispatchAcquisitionRequest,
    ) -> Result<DispatchAcquisitionOutcome, StateError> {
        self.inner
            .claim_next_pending_dispatch_or_recover(scope, request)
    }

    fn revalidate_dispatch_claim(
        &self,
        token: &DispatchClaimToken,
    ) -> Result<DispatchSnapshot, StateError> {
        self.inner.revalidate_dispatch_claim(token)
    }

    fn revalidate_dispatch_acquisition(
        &self,
        authority: &DispatchAcquisitionAuthority,
    ) -> Result<DispatchSnapshot, StateError> {
        self.inner.revalidate_dispatch_acquisition(authority)
    }

    fn mark_attempt_in_flight(
        &self,
        token: &DispatchClaimToken,
        credential: DispatchCredentialBinding,
    ) -> Result<AttemptInFlight, StateError> {
        self.inner.mark_attempt_in_flight(token, credential)
    }

    fn mark_dispatch_acquisition_attempt_in_flight(
        &self,
        reviewed: crate::ReviewedDispatchCredential,
    ) -> Result<AttemptInFlight, StateError> {
        self.inner
            .mark_dispatch_acquisition_attempt_in_flight(reviewed)
    }

    fn close_dispatch_acquisition_no_send(
        &self,
        key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendReceipt, StateError> {
        self.inner.close_dispatch_acquisition_no_send(key)
    }

    fn retire_recovery_no_send(
        &self,
        key: &DispatchAcquisitionRecoveryKey,
    ) -> Result<RecoveryNoSendRetirementOutcome, StateError> {
        self.inner.retire_recovery_no_send(key)
    }

    fn admission_context(&self, key: &ConsumeKey) -> Result<AdmissionContext, StateError> {
        self.inner.admission_context(key)
    }

    fn authorize_admission_or_recover(
        &self,
        request: &AdmissionAuthorizationRequest,
    ) -> Result<AdmissionAuthorization, StateError> {
        self.inner.authorize_admission_or_recover(request)
    }

    fn consumption_receipt(&self, key: &ConsumeKey) -> Result<ConsumptionReceipt, StateError> {
        self.inner.consumption_receipt(key)
    }

    fn outbox_entry(&self, key: &ConsumeKey) -> Result<OutboxEntry, StateError> {
        self.inner.outbox_entry(key)
    }

    fn time_high_water(&self, scope: &Scope) -> Result<Option<i64>, StateError> {
        self.inner.time_high_water(scope)
    }
}

impl IngressReplayState for TlsPostgresStore {
    fn observe_ingress_time(
        &self,
        scope: &IngressReplayScope,
        observed_unix_s: i64,
    ) -> Result<(), StateError> {
        self.inner.observe_ingress_time(scope, observed_unix_s)
    }

    fn consume_ingress_nonce(
        &self,
        request: &IngressNonceConsumption,
    ) -> Result<IngressReplayDecision, StateError> {
        self.inner.consume_ingress_nonce(request)
    }

    fn prune_expired_ingress_nonces(
        &self,
        scope: &IngressReplayScope,
        limit: u32,
    ) -> Result<u32, StateError> {
        self.inner.prune_expired_ingress_nonces(scope, limit)
    }
}

impl BrokerJournalState for TlsPostgresStore {
    fn issue_broker_journal_capability(&mut self) -> Result<BrokerJournalCapability, StateError> {
        self.inner.issue_broker_journal_capability()
    }

    fn prepare_broker_operation(
        &self,
        capability: &BrokerJournalCapability,
        request: BrokerOperationRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.inner.prepare_broker_operation(capability, request)
    }

    fn begin_broker_operation_for_acquisition(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        request: crate::AcquiredBrokerOperationRequest,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.inner
            .begin_broker_operation_for_acquisition(capability, authority, request)
    }

    fn begin_dispatch_credential_review(
        &self,
        capability: &BrokerJournalCapability,
        authority: &DispatchAcquisitionAuthority,
        token_journal: &crate::BrokerJournalSelector,
    ) -> Result<crate::CredentialReviewIoAuthority, StateError> {
        self.inner
            .begin_dispatch_credential_review(capability, authority, token_journal)
    }

    fn record_authenticated_dispatch_credential(
        &self,
        authority: crate::CredentialReviewIoAuthority,
        observation: crate::AuthenticatedDispatchCredentialReview,
    ) -> Result<crate::ReviewedDispatchCredential, StateError> {
        self.inner
            .record_authenticated_dispatch_credential(authority, observation)
    }

    fn recover_authenticated_dispatch_credential(
        &self,
        key: &crate::DispatchCredentialReviewRecoveryKey,
    ) -> Result<crate::ReviewedDispatchCredential, StateError> {
        self.inner.recover_authenticated_dispatch_credential(key)
    }

    fn record_rejected_dispatch_credential(
        &self,
        authority: crate::CredentialReviewIoAuthority,
        observation: crate::RejectedDispatchCredentialReview,
    ) -> Result<crate::DispatchCredentialReviewAudit, StateError> {
        self.inner
            .record_rejected_dispatch_credential(authority, observation)
    }

    fn dispatch_credential_review_audit(
        &self,
        acquisition: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<crate::DispatchCredentialReviewAudit, StateError> {
        self.inner.dispatch_credential_review_audit(acquisition)
    }

    fn dispatch_broker_restart_context(
        &self,
        acquisition: &crate::DispatchAcquisitionRecoveryKey,
    ) -> Result<crate::DispatchBrokerRestartContext, StateError> {
        self.inner.dispatch_broker_restart_context(acquisition)
    }

    fn prepare_broker_cleanup(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerCleanupRequest,
    ) -> Result<BrokerOperationIntent, StateError> {
        self.inner.prepare_broker_cleanup(capability, request)
    }

    fn begin_broker_io(
        &self,
        capability: &BrokerJournalCapability,
        intent: BrokerOperationIntent,
    ) -> Result<BrokerIoAuthority, StateError> {
        self.inner.begin_broker_io(capability, intent)
    }

    fn commit_broker_create(
        &self,
        authority: BrokerIoAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        self.inner.commit_broker_create(authority, observation)
    }

    fn commit_broker_token_issue(
        &self,
        authority: BrokerIoAuthority,
        observation: &BrokerTokenIssueObservation,
    ) -> Result<BrokerOperationReceipt, StateError> {
        self.inner.commit_broker_token_issue(authority, observation)
    }

    fn mark_broker_io_unknown(
        &self,
        authority: BrokerIoAuthority,
    ) -> Result<BrokerOperationAudit, StateError> {
        self.inner.mark_broker_io_unknown(authority)
    }

    fn begin_broker_reconciliation(
        &self,
        capability: &BrokerJournalCapability,
        request: &BrokerReconciliationRequest,
    ) -> Result<BrokerReconciliationAuthority, StateError> {
        self.inner.begin_broker_reconciliation(capability, request)
    }

    fn commit_broker_reconciliation(
        &self,
        authority: BrokerReconciliationAuthority,
        observation: BrokerSecretObservation,
    ) -> Result<BrokerReconciliationResult, StateError> {
        self.inner
            .commit_broker_reconciliation(authority, observation)
    }

    fn broker_operation_audit(
        &self,
        key: &ConsumeKey,
        operation: BrokerJournalOperation,
    ) -> Result<BrokerOperationAudit, StateError> {
        self.inner.broker_operation_audit(key, operation)
    }
}

fn valid_postgres_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_POSTGRES_NAME_BYTES
        && value.trim() == value
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn parse_ca_certificates(pem: &[u8]) -> Result<RootCertStore, TlsPostgresConfigError> {
    if pem.is_empty() || pem.len() > MAX_CA_PEM_BYTES {
        return Err(TlsPostgresConfigError::InvalidCaPem);
    }
    let certificates = parse_certificate_pem(pem, TlsPostgresConfigError::InvalidCaPem)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| TlsPostgresConfigError::InvalidCaCertificate)?;
    }
    if roots.is_empty() {
        return Err(TlsPostgresConfigError::InvalidCaPem);
    }
    Ok(roots)
}

fn parse_client_certificate_chain(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, TlsPostgresConfigError> {
    if pem.is_empty() || pem.len() > MAX_CLIENT_CERTIFICATE_PEM_BYTES {
        return Err(TlsPostgresConfigError::InvalidClientCertificatePem);
    }
    parse_certificate_pem(pem, TlsPostgresConfigError::InvalidClientCertificatePem)
}

fn parse_certificate_pem(
    pem: &[u8],
    invalid: TlsPostgresConfigError,
) -> Result<Vec<CertificateDer<'static>>, TlsPostgresConfigError> {
    let mut certificates = Vec::new();
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        match item.map_err(|_| invalid)? {
            (SectionKind::Certificate, certificate) => {
                certificates.push(CertificateDer::from(certificate));
            }
            _ => return Err(invalid),
        }
    }
    if certificates.is_empty() {
        return Err(invalid);
    }
    Ok(certificates)
}

fn parse_client_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsPostgresConfigError> {
    if pem.is_empty() || pem.len() > MAX_CLIENT_KEY_PEM_BYTES {
        return Err(TlsPostgresConfigError::InvalidClientPrivateKeyPem);
    }
    let mut private_key = None;
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let item = item.map_err(|_| TlsPostgresConfigError::InvalidClientPrivateKeyPem)?;
        let candidate = match item {
            (SectionKind::RsaPrivateKey, key) => PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key)),
            (SectionKind::PrivateKey, key) => PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
            (SectionKind::EcPrivateKey, key) => PrivateKeyDer::from(PrivateSec1KeyDer::from(key)),
            _ => return Err(TlsPostgresConfigError::InvalidClientPrivateKeyPem),
        };
        if private_key.replace(candidate).is_some() {
            return Err(TlsPostgresConfigError::InvalidClientPrivateKeyCount);
        }
    }
    private_key.ok_or(TlsPostgresConfigError::InvalidClientPrivateKeyCount)
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<Value, StateError> {
    serde_json::to_value(value).map_err(StateError::Serialization)
}

fn decode_json<T: DeserializeOwned>(value: Value) -> Result<T, StateError> {
    serde_json::from_value(value).map_err(StateError::Serialization)
}

fn migration_checksum(sql: &str) -> String {
    let normalized = sql.replace("\r\n", "\n").replace('\r', "\n");
    Digest32::sha256(normalized.as_bytes()).to_string()
}

fn is_local_host(host: &Host) -> bool {
    match host {
        Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
        Host::Tcp(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

fn is_unique_violation(error: &postgres::Error) -> bool {
    error
        .as_db_error()
        .is_some_and(|db_error| db_error.code() == &SqlState::UNIQUE_VIOLATION)
}

fn is_retryable(error: &postgres::Error) -> bool {
    error.as_db_error().is_some_and(|db_error| {
        db_error.code() == &SqlState::T_R_SERIALIZATION_FAILURE
            || db_error.code() == &SqlState::T_R_DEADLOCK_DETECTED
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use postgres::config::{ChannelBinding, Host, SslMode, TargetSessionAttrs};

    use super::{
        PostgresStore, TlsPostgresConfig, TlsPostgresConfigError, TlsPostgresStore,
        migration_checksum,
    };
    use crate::{ConsumeKey, Scope, StateError, TransactionalState};
    use uuid::Uuid;

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw\n\
HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\n\
DzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw\n\
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+\n\
5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP\n\
BgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP\n\
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop\n\
PAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik\n\
cy4eNw==\n\
-----END CERTIFICATE-----\n";

    const TEST_CLIENT_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBszCCAVmgAwIBAgIUUg3keFcU1xXWK8BNVb1KynPulV8wCgYIKoZIzj0EAwIw\n\
JjEkMCIGA1UEAwwbUnVzdGxzIFJvYnVzdCBSb290IC0gUnVuZyAyMCAXDTc1MDEw\n\
MTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAhMR8wHQYDVQQDDBZyY2dlbiBzZWxm\n\
IHNpZ25lZCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEud6w4gtZ0xbw\n\
J3E69SSMy5TZfdIifl9L5ZY+hgEe4UiUsBWS32f6Y5NR5Jo8FO1f6o13b3+FvVHR\n\
EHCGdvppL6NoMGYwFQYDVR0RBA4wDIIKZm9vYmFyLmNvbTAdBgNVHSUEFjAUBggr\n\
BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFELvxbj5tD75n4pYFvJyr+c8qVEi\n\
MA8GA1UdEwEB/wQFMAMBAQAwCgYIKoZIzj0EAwIDSAAwRQIhALxSSdUsrRFnwNMu\n\
/doBqI8i8u5HdohVAheFTDwObkOMAiASSjULUtkWSD15u/7Sr01Wm9J1MpqW1pob\n\
BVqU3CNRlA==\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIBiTCCATCgAwIBAgIUHWiVYIvMMWoZEFYvSz46COf2FqowCgYIKoZIzj0EAwIw\n\
HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\n\
DzQwOTYwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtSdXN0bHMgUm9idXN0IFJvb3Qg\n\
LSBSdW5nIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAOCcBD7dXjmAZ3te5\n\
D47cCJ9ec93PWv7BKYIL826CJsKfXQOGrBTthLm77hXLhHu6uv8E5QXNLZpfowLQ\n\
Do1ao0MwQTAPBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRdza76r11Ok9vRmlg6\n\
Nn/wL/N+jTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFmZrXeK\n\
hnfkahocvkhhNT3cDv1LWf6WBoFaCiBwZXFPAiARaKRiSCMG7PCHmSqFe82TBVmL\n\
odHGogAVax1Dh/aYAA==\n\
-----END CERTIFICATE-----\n";

    fn runtime_client_identity() -> (String, String) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["accordlock-postgres-client.test".to_owned()])
                .unwrap_or_else(|_| unreachable!());
        (certified.cert.pem(), certified.key_pair.serialize_pem())
    }

    #[test]
    fn debug_redacts_connection_secret() {
        let store = PostgresStore::new(
            "postgresql://accordlock:do-not-print@127.0.0.1:5432/accordlock_test",
        );
        let debug = format!("{store:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("do-not-print"));
    }

    #[test]
    fn no_tls_profile_rejects_remote_and_overridden_addresses() {
        let remote = PostgresStore::new("postgresql://accordlock@db.example/accordlock");
        assert!(matches!(
            remote.connection_config(),
            Err(StateError::UnsafePostgresConnection)
        ));

        let overridden = PostgresStore::new(
            "host=localhost hostaddr=192.0.2.1 user=accordlock dbname=accordlock",
        );
        assert!(matches!(
            overridden.connection_config(),
            Err(StateError::UnsafePostgresConnection)
        ));

        let loopback = PostgresStore::new("postgresql://accordlock@127.0.0.1:5432/accordlock");
        assert!(loopback.connection_config().is_ok());
    }

    #[test]
    fn tls_profile_is_programmatic_strict_and_debug_is_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let config = TlsPostgresConfig::new(
            "DB.Example.COM",
            "accordlock_state",
            "accordlock_runtime",
            "do-not-print-password",
            TEST_CA_PEM,
        )?
        .with_target_address(target)
        .with_port(6432)?
        .with_connect_timeout(Duration::from_secs(7))?;
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("db.example.com"));
        assert!(config_debug.contains("<redacted>"));
        assert!(!config_debug.contains("do-not-print-password"));
        assert!(!config_debug.contains("accordlock_runtime"));

        let store = TlsPostgresStore::new(config)?;
        let debug = format!("{store:?}");
        assert!(debug.contains("remote-authenticated-tls"));
        assert!(!debug.contains("do-not-print-password"));

        let postgres = store.inner.connection_config()?;
        assert_eq!(postgres.get_ssl_mode(), SslMode::Require);
        assert_eq!(postgres.get_channel_binding(), ChannelBinding::Require);
        assert_eq!(
            postgres.get_target_session_attrs(),
            TargetSessionAttrs::ReadWrite
        );
        assert_eq!(postgres.get_hosts(), &[Host::Tcp("db.example.com".into())]);
        assert_eq!(postgres.get_hostaddrs(), &[target]);
        assert_eq!(postgres.get_ports(), &[6432]);
        assert_eq!(
            postgres.get_connect_timeout(),
            Some(&Duration::from_secs(7))
        );
        assert_eq!(postgres.get_dbname(), Some("accordlock_state"));
        assert_eq!(postgres.get_user(), Some("accordlock_runtime"));
        Ok(())
    }

    #[test]
    fn tls_profile_accepts_a_matching_optional_client_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (client_chain_pem, client_key_pem) = runtime_client_identity();
        let config = TlsPostgresConfig::new(
            "db.example.com",
            "accordlock_state",
            "accordlock_runtime",
            "secret",
            TEST_CA_PEM,
        )?
        .with_client_identity(&client_chain_pem, &client_key_pem)?;
        assert!(TlsPostgresStore::new(config).is_ok());
        Ok(())
    }

    #[test]
    fn tls_profile_rejects_ambiguous_or_unsafe_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        for invalid_name in ["127.0.0.1", " db.example.com", "db example.com", ""] {
            assert!(matches!(
                TlsPostgresConfig::new(
                    invalid_name,
                    "accordlock_state",
                    "accordlock_runtime",
                    "secret",
                    TEST_CA_PEM,
                ),
                Err(TlsPostgresConfigError::InvalidServerName)
            ));
        }
        assert!(matches!(
            TlsPostgresConfig::new(
                "db.example.com",
                "",
                "accordlock_runtime",
                "secret",
                TEST_CA_PEM,
            ),
            Err(TlsPostgresConfigError::InvalidDatabaseName)
        ));
        assert!(matches!(
            TlsPostgresConfig::new(
                "db.example.com",
                "accordlock_state",
                "accordlock_runtime",
                "",
                TEST_CA_PEM,
            ),
            Err(TlsPostgresConfigError::InvalidPassword)
        ));
        assert!(matches!(
            TlsPostgresConfig::new(
                "db.example.com",
                "accordlock_state",
                "accordlock_runtime",
                "secret",
                "not a PEM certificate",
            ),
            Err(TlsPostgresConfigError::InvalidCaPem)
        ));

        let config = TlsPostgresConfig::new(
            "db.example.com",
            "accordlock_state",
            "accordlock_runtime",
            "secret",
            TEST_CA_PEM,
        )?;
        assert!(matches!(
            config.with_port(0),
            Err(TlsPostgresConfigError::InvalidPort)
        ));

        let config = TlsPostgresConfig::new(
            "db.example.com",
            "accordlock_state",
            "accordlock_runtime",
            "secret",
            TEST_CA_PEM,
        )?;
        assert!(matches!(
            config.with_connect_timeout(Duration::ZERO),
            Err(TlsPostgresConfigError::InvalidConnectTimeout)
        ));
        Ok(())
    }

    #[test]
    fn tls_profile_rejects_wrong_or_multiple_client_key_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = TlsPostgresConfig::new(
            "db.example.com",
            "accordlock_state",
            "accordlock_runtime",
            "secret",
            TEST_CA_PEM,
        )?;
        assert!(matches!(
            config.with_client_identity(TEST_CLIENT_CHAIN_PEM, TEST_CA_PEM),
            Err(TlsPostgresConfigError::InvalidClientPrivateKeyPem)
        ));

        let (_, client_key_pem) = runtime_client_identity();
        let multiple_keys = format!("{client_key_pem}{client_key_pem}");
        let config = TlsPostgresConfig::new(
            "db.example.com",
            "accordlock_state",
            "accordlock_runtime",
            "secret",
            TEST_CA_PEM,
        )?;
        assert!(matches!(
            config.with_client_identity(TEST_CLIENT_CHAIN_PEM, multiple_keys),
            Err(TlsPostgresConfigError::InvalidClientPrivateKeyCount)
        ));
        Ok(())
    }

    #[test]
    fn migration_checksum_is_line_ending_independent() {
        assert_eq!(
            migration_checksum("one\r\ntwo\r"),
            migration_checksum("one\ntwo\n")
        );
    }

    #[test]
    fn unavailable_database_yields_unknown_consumption_outcome() -> Result<(), StateError> {
        let store =
            PostgresStore::new("postgresql://accordlock@127.0.0.1:1/accordlock?connect_timeout=1");
        let key = ConsumeKey {
            scope: Scope::new("acme", "test")?,
            transaction_id: Uuid::from_u128(1),
            authorization_id: Uuid::from_u128(2),
        };

        assert!(matches!(
            store.consume_or_recover(&key),
            Err(StateError::ConsumptionOutcomeUnknown)
        ));
        Ok(())
    }
}

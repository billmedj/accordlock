-- Durable one-shot journal for Secret create, bound TokenRequest, and exact
-- Secret cleanup. INTENT is safe to adopt because no external I/O authority
-- exists yet. IN_FLIGHT is irreversible: after crash it can become only
-- UNKNOWN/RECONCILE_ONLY, never a second mutation authority.

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_broker_binding_key
        UNIQUE (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        );

CREATE TABLE public.accordlock_broker_operations (
    entry_id                         UUID NOT NULL,
    tenant                           TEXT COLLATE "C" NOT NULL,
    environment                      TEXT COLLATE "C" NOT NULL,
    authorization_id                              UUID NOT NULL,
    transaction_id                   UUID NOT NULL,
    claim_id                         UUID NOT NULL,
    fence                            BIGINT NOT NULL,
    state_instance_id                UUID NOT NULL,
    cluster_identity                 TEXT COLLATE "C" NOT NULL,
    namespace                        TEXT COLLATE "C" NOT NULL,
    deployment_uid                   TEXT COLLATE "C" NOT NULL,
    route_commitment                 TEXT COLLATE "C" NOT NULL,
    bound_secret_name                TEXT COLLATE "C" NOT NULL,
    bound_secret_uid                 TEXT COLLATE "C",
    operation                        TEXT COLLATE "C" NOT NULL,
    phase                            TEXT COLLATE "C" NOT NULL DEFAULT 'INTENT',
    prepared_unix_s                  BIGINT NOT NULL,
    started_unix_s                   BIGINT,
    credential_lifetime_upper_s      BIGINT,
    credential_clock_uncertainty_s   BIGINT,
    credential_safe_after            BIGINT,
    reconciliation_count             BIGINT NOT NULL DEFAULT 0,
    last_reconciliation_outcome      TEXT COLLATE "C",
    last_reconciliation_evidence_commitment TEXT COLLATE "C",
    last_reconciled_unix_s            BIGINT,
    outcome                          TEXT COLLATE "C",
    provider_evidence_commitment     TEXT COLLATE "C",
    token_digest                     TEXT COLLATE "C",
    token_expires_at                 BIGINT,
    request_commitment               TEXT COLLATE "C" NOT NULL,
    result_commitment                TEXT COLLATE "C",
    created_at                       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at                       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_broker_operations_pkey PRIMARY KEY (entry_id),
    CONSTRAINT accordlock_broker_operations_operation_key
        UNIQUE (tenant, environment, authorization_id, operation),
    CONSTRAINT accordlock_broker_operations_transaction_operation_key
        UNIQUE (tenant, environment, transaction_id, operation),
    CONSTRAINT accordlock_broker_operations_claim_operation_key
        UNIQUE (claim_id, operation),
    CONSTRAINT accordlock_broker_operations_fence_operation_key
        UNIQUE (fence, operation),
    CONSTRAINT accordlock_broker_operations_claim_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        )
        REFERENCES public.accordlock_dispatch_claims (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_broker_operations_state_instance_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_broker_operations_identity_check
        CHECK (
            entry_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND fence > 0
        ),
    CONSTRAINT accordlock_broker_operations_physical_identity_check
        CHECK (
            octet_length(cluster_identity) BETWEEN 1 AND 512
            AND cluster_identity = btrim(cluster_identity)
            AND cluster_identity !~ '[[:cntrl:]]'
            AND octet_length(namespace) BETWEEN 1 AND 253
            AND namespace = btrim(namespace)
            AND namespace !~ '[[:cntrl:]]'
            AND octet_length(deployment_uid) BETWEEN 1 AND 512
            AND deployment_uid = btrim(deployment_uid)
            AND deployment_uid !~ '[[:cntrl:]]'
        ),
    CONSTRAINT accordlock_broker_operations_secret_identity_check
        CHECK (
            bound_secret_name =
                'accordlock-' || replace(transaction_id::text, '-', '')
            AND octet_length(bound_secret_name) = 43
            AND (
                bound_secret_uid IS NULL
                OR (
                    octet_length(bound_secret_uid) BETWEEN 1 AND 512
                    AND bound_secret_uid = btrim(bound_secret_uid)
                    AND bound_secret_uid !~ '[[:cntrl:]]'
                )
            )
        ),
    CONSTRAINT accordlock_broker_operations_commitments_check
        CHECK (
            route_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND route_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND request_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND request_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND (
                provider_evidence_commitment IS NULL
                OR (
                    provider_evidence_commitment ~ '^sha256:[0-9a-f]{64}$'
                    AND provider_evidence_commitment <>
                        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                )
            )
            AND (
                token_digest IS NULL
                OR (
                    token_digest ~ '^sha256:[0-9a-f]{64}$'
                    AND token_digest <>
                        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                )
            )
            AND (
                result_commitment IS NULL
                OR (
                    result_commitment ~ '^sha256:[0-9a-f]{64}$'
                    AND result_commitment <>
                        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                )
            )
            AND (
                last_reconciliation_evidence_commitment IS NULL
                OR (
                    last_reconciliation_evidence_commitment ~
                        '^sha256:[0-9a-f]{64}$'
                    AND last_reconciliation_evidence_commitment <>
                        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                )
            )
        ),
    CONSTRAINT accordlock_broker_operations_operation_check
        CHECK (operation IN ('CREATE_SECRET', 'ISSUE_TOKEN', 'DELETE_SECRET')),
    CONSTRAINT accordlock_broker_operations_phase_check
        CHECK (
            phase IN (
                'INTENT', 'IN_FLIGHT', 'UNKNOWN', 'RECONCILE_ONLY',
                'COMMITTED', 'TERMINAL'
            )
        ),
    CONSTRAINT accordlock_broker_operations_outcome_check
        CHECK (
            outcome IS NULL
            OR outcome IN (
                'CREATE_MATCHING', 'CREATE_ABSENT', 'CREATE_CONFLICTING',
                'TOKEN_ISSUED', 'DELETE_ABSENT', 'DELETE_PRESENT',
                'DELETE_CONFLICTING'
            )
        ),
    CONSTRAINT accordlock_broker_operations_operation_shape_check
        CHECK (
            (
                operation = 'CREATE_SECRET'
                AND credential_lifetime_upper_s IS NULL
                AND credential_clock_uncertainty_s IS NULL
                AND credential_safe_after IS NULL
            )
            OR (
                operation = 'ISSUE_TOKEN'
                AND bound_secret_uid IS NOT NULL
                AND credential_lifetime_upper_s BETWEEN 1 AND 86400
                AND credential_clock_uncertainty_s BETWEEN 0 AND 300
                AND (
                    (phase = 'INTENT' AND credential_safe_after IS NULL)
                    OR (phase <> 'INTENT' AND credential_safe_after IS NOT NULL)
                )
            )
            OR (
                operation = 'DELETE_SECRET'
                AND bound_secret_uid IS NOT NULL
                AND credential_lifetime_upper_s IS NULL
                AND credential_clock_uncertainty_s IS NULL
                AND credential_safe_after IS NULL
            )
        ),
    CONSTRAINT accordlock_broker_operations_reconciliation_check
        CHECK (
            (
                reconciliation_count = 0
                AND last_reconciliation_outcome IS NULL
                AND last_reconciliation_evidence_commitment IS NULL
                AND last_reconciled_unix_s IS NULL
            )
            OR (
                reconciliation_count > 0
                AND phase IN ('RECONCILE_ONLY', 'COMMITTED', 'TERMINAL')
                AND last_reconciliation_evidence_commitment IS NOT NULL
                AND last_reconciled_unix_s IS NOT NULL
                AND last_reconciled_unix_s >= started_unix_s
                AND (
                    (operation = 'CREATE_SECRET'
                        AND last_reconciliation_outcome = 'CREATE_ABSENT')
                    OR (operation = 'DELETE_SECRET'
                        AND last_reconciliation_outcome = 'DELETE_PRESENT')
                )
            )
        ),
    CONSTRAINT accordlock_broker_operations_state_result_check
        CHECK (
            (
                phase = 'INTENT'
                AND started_unix_s IS NULL
                AND outcome IS NULL
                AND provider_evidence_commitment IS NULL
                AND token_digest IS NULL
                AND token_expires_at IS NULL
                AND result_commitment IS NULL
            )
            OR (
                phase IN ('IN_FLIGHT', 'UNKNOWN', 'RECONCILE_ONLY')
                AND started_unix_s IS NOT NULL
                AND outcome IS NULL
                AND provider_evidence_commitment IS NULL
                AND token_digest IS NULL
                AND token_expires_at IS NULL
                AND result_commitment IS NULL
            )
            OR (
                phase = 'COMMITTED'
                AND (
                    (operation = 'CREATE_SECRET' AND outcome = 'CREATE_MATCHING'
                        AND bound_secret_uid IS NOT NULL
                        AND token_digest IS NULL AND token_expires_at IS NULL)
                    OR (operation = 'ISSUE_TOKEN' AND outcome = 'TOKEN_ISSUED'
                        AND token_digest IS NOT NULL AND token_expires_at IS NOT NULL)
                    OR (operation = 'DELETE_SECRET' AND outcome = 'DELETE_ABSENT'
                        AND token_digest IS NULL AND token_expires_at IS NULL)
                )
                AND started_unix_s IS NOT NULL
                AND provider_evidence_commitment IS NOT NULL
                AND result_commitment IS NOT NULL
            )
            OR (
                phase = 'TERMINAL'
                AND (
                    (operation = 'CREATE_SECRET'
                        AND outcome = 'CREATE_CONFLICTING')
                    OR (operation = 'DELETE_SECRET'
                        AND outcome = 'DELETE_CONFLICTING')
                )
                AND started_unix_s IS NOT NULL
                AND provider_evidence_commitment IS NOT NULL
                AND token_digest IS NULL
                AND token_expires_at IS NULL
                AND result_commitment IS NOT NULL
            )
        ),
    CONSTRAINT accordlock_broker_operations_time_check
        CHECK (
            prepared_unix_s >= 0
            AND (started_unix_s IS NULL OR started_unix_s >= prepared_unix_s)
            AND (
                credential_safe_after IS NULL
                OR credential_safe_after > started_unix_s
            )
            AND (
                token_expires_at IS NULL
                OR (
                    token_expires_at > started_unix_s
                    AND token_expires_at <= credential_safe_after
                )
            )
        )
);

CREATE INDEX accordlock_broker_operations_recovery_idx
    ON public.accordlock_broker_operations (phase, operation, credential_safe_after);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (9, '0009_broker_operation_journal');

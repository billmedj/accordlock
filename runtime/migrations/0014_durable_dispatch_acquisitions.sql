-- Durable, append-only acquisition leases for server-selected v13 dispatch
-- outbox work. The stable dispatch claim remains the identity referenced by
-- broker, admission, and terminal history. A takeover appends a new lease
-- generation and never rewrites claim_id or fence.

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_acquisition_binding_key
    UNIQUE (
        tenant, environment, authorization_id, transaction_id, claim_id, fence,
        state_instance_id
    );

-- One global namespace makes acquisition and disposition idempotency mutually
-- exclusive even for direct DML. A request is inserted unbound, then bound
-- exactly once in the same transaction that creates its durable outcome.
CREATE TABLE public.accordlock_dispatch_request_identities (
    dispatch_request_id UUID PRIMARY KEY,
    request_kind       TEXT COLLATE "C",
    worker_id          TEXT COLLATE "C" NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    bound_at           TIMESTAMPTZ,
    CONSTRAINT accordlock_dispatch_request_identities_binding_key
        UNIQUE (dispatch_request_id, request_kind, worker_id),
    CONSTRAINT accordlock_dispatch_request_identities_identity_check CHECK (
        dispatch_request_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(worker_id) BETWEEN 1 AND 253
        AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
        AND (request_kind IS NULL OR request_kind IN ('ACQUISITION', 'DISPOSITION'))
        AND (request_kind IS NULL) = (bound_at IS NULL)
    )
);

CREATE TABLE public.accordlock_dispatch_acquisitions (
    acquisition_id       UUID PRIMARY KEY,
    request_kind         TEXT COLLATE "C" NOT NULL DEFAULT 'ACQUISITION',
    tenant               TEXT COLLATE "C" NOT NULL,
    environment          TEXT COLLATE "C" NOT NULL,
    authorization_id                  UUID NOT NULL,
    transaction_id       UUID NOT NULL,
    claim_id             UUID NOT NULL,
    claim_fence          BIGINT NOT NULL,
    state_instance_id    UUID NOT NULL,
    control_submission_id UUID,
    selection_kind       TEXT COLLATE "C" NOT NULL,
    worker_id            TEXT COLLATE "C" NOT NULL,
    lease_fence          BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    acquired_unix_s      BIGINT NOT NULL,
    lease_until          BIGINT NOT NULL,
    dispatch_deadline    BIGINT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_dispatch_acquisitions_request_identity_fkey
        FOREIGN KEY (acquisition_id, request_kind, worker_id)
        REFERENCES public.accordlock_dispatch_request_identities (
            dispatch_request_id, request_kind, worker_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_acquisitions_claim_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, claim_id, claim_fence,
            state_instance_id
        )
        REFERENCES public.accordlock_dispatch_claims (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            state_instance_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_acquisitions_outbox_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, dispatch_deadline
        )
        REFERENCES public.accordlock_execution_outbox (
            tenant, environment, authorization_id, transaction_id, dispatch_deadline
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_acquisitions_control_fkey
        FOREIGN KEY (
            control_submission_id, tenant, environment, authorization_id, transaction_id
        )
        REFERENCES public.accordlock_control_consumptions (
            submission_id, tenant, environment, authorization_id, transaction_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_acquisitions_full_lineage_key
        UNIQUE (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence,
            acquired_unix_s, lease_until
        ),
    CONSTRAINT accordlock_dispatch_acquisitions_broker_lineage_key
        UNIQUE (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence
        ),
    CONSTRAINT accordlock_dispatch_acquisitions_claim_generation_key
        UNIQUE (claim_id, lease_fence),
    CONSTRAINT accordlock_dispatch_acquisitions_identity_check CHECK (
        acquisition_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_fence > 0
        AND lease_fence > 0
        AND request_kind = 'ACQUISITION'
        AND octet_length(worker_id) BETWEEN 1 AND 253
        AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
        AND selection_kind IN (
            'CONTROL_QUEUE', 'CONTROL_BOOTSTRAP_V13', 'LEGACY_BOOTSTRAP'
        )
        AND (selection_kind = 'CONTROL_QUEUE') =
            (acquisition_id <> claim_id)
        AND (selection_kind IN ('CONTROL_QUEUE', 'CONTROL_BOOTSTRAP_V13')) =
            (control_submission_id IS NOT NULL)
    ),
    CONSTRAINT accordlock_dispatch_acquisitions_time_check CHECK (
        acquired_unix_s >= 0
        AND lease_until > acquired_unix_s
        AND lease_until <= dispatch_deadline
        -- v13 dispatch claims had no 30-second upper bound.  Their exact
        -- bootstrap acquisition must remain representable during backfill;
        -- every post-v14 INSERT is capped by the insert guard below.
        AND (
            selection_kind IN ('CONTROL_BOOTSTRAP_V13', 'LEGACY_BOOTSTRAP')
            OR lease_until - acquired_unix_s <= 30
        )
    )
);

-- Every historical claim is its own deterministic bootstrap acquisition.
-- The optional control link is populated only for v13-owned outbox work;
-- legacy/harness claims remain recoverable by their existing APIs but are not
-- candidates for server-selected v14 work.
INSERT INTO public.accordlock_dispatch_request_identities (
    dispatch_request_id, request_kind, worker_id, bound_at
)
SELECT claim_id, 'ACQUISITION', worker_id, clock_timestamp()
  FROM public.accordlock_dispatch_claims;

INSERT INTO public.accordlock_dispatch_acquisitions (
    acquisition_id, tenant, environment, authorization_id, transaction_id, claim_id,
    claim_fence, state_instance_id, control_submission_id, selection_kind,
    worker_id,
    lease_fence, acquired_unix_s, lease_until, dispatch_deadline
)
OVERRIDING SYSTEM VALUE
SELECT
    claim.claim_id, claim.tenant, claim.environment, claim.authorization_id,
    claim.transaction_id, claim.claim_id, claim.fence,
    claim.state_instance_id, control.submission_id,
    CASE WHEN control.submission_id IS NULL
         THEN 'LEGACY_BOOTSTRAP' ELSE 'CONTROL_BOOTSTRAP_V13' END,
    claim.worker_id,
    claim.fence, claim.claimed_unix_s, claim.lease_until,
    outbox.dispatch_deadline
FROM public.accordlock_dispatch_claims AS claim
JOIN public.accordlock_execution_outbox AS outbox
  ON outbox.tenant = claim.tenant
 AND outbox.environment = claim.environment
 AND outbox.authorization_id = claim.authorization_id
 AND outbox.transaction_id = claim.transaction_id
LEFT JOIN public.accordlock_control_consumptions AS control
  ON control.tenant = claim.tenant
 AND control.environment = claim.environment
 AND control.authorization_id = claim.authorization_id
 AND control.transaction_id = claim.transaction_id;

DO $migration_assertion$
BEGIN
    IF (SELECT count(*) FROM public.accordlock_dispatch_claims) <>
       (SELECT count(*) FROM public.accordlock_dispatch_acquisitions)
       OR (SELECT count(*) FROM public.accordlock_dispatch_claims) <>
          (SELECT count(*) FROM public.accordlock_dispatch_request_identities)
       OR EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_claims AS claim
             WHERE NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_acquisitions AS acquisition
                     WHERE acquisition.acquisition_id = claim.claim_id
                       AND acquisition.tenant = claim.tenant
                       AND acquisition.environment = claim.environment
                       AND acquisition.authorization_id = claim.authorization_id
                       AND acquisition.transaction_id = claim.transaction_id
                       AND acquisition.claim_id = claim.claim_id
                       AND acquisition.claim_fence = claim.fence
                       AND acquisition.state_instance_id = claim.state_instance_id
                )
                OR NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_request_identities AS identity
                     WHERE identity.dispatch_request_id = claim.claim_id
                       AND identity.request_kind = 'ACQUISITION'
                       AND identity.worker_id = claim.worker_id
                )
       )
       OR EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_request_identities AS identity
             WHERE identity.request_kind <> 'ACQUISITION'
                OR NOT EXISTS (
                    SELECT 1
                      FROM public.accordlock_dispatch_acquisitions AS acquisition
                     WHERE acquisition.acquisition_id = identity.dispatch_request_id
                )
       ) THEN
        RAISE EXCEPTION
            'v13 dispatch claims cannot be backfilled to exact v14 acquisitions';
    END IF;
END
$migration_assertion$;

SELECT pg_catalog.setval(
    pg_catalog.pg_get_serial_sequence(
        'public.accordlock_dispatch_acquisitions', 'lease_fence'
    ),
    GREATEST(COALESCE(MAX(lease_fence), 1), 1),
    COUNT(*) > 0
)
FROM public.accordlock_dispatch_acquisitions;

CREATE INDEX accordlock_dispatch_acquisitions_latest_idx
    ON public.accordlock_dispatch_acquisitions (
        tenant, environment, authorization_id, lease_fence DESC
    );
CREATE INDEX accordlock_dispatch_acquisitions_ready_lease_idx
    ON public.accordlock_dispatch_acquisitions (
        lease_until, tenant, environment, authorization_id
    );
CREATE INDEX accordlock_dispatch_acquisitions_control_idx
    ON public.accordlock_dispatch_acquisitions (
        control_submission_id, lease_fence DESC
    )
    WHERE control_submission_id IS NOT NULL;

CREATE TABLE public.accordlock_dispatch_queue_dispositions (
    dispatch_request_id             UUID PRIMARY KEY,
    request_kind                   TEXT COLLATE "C" NOT NULL
                                       DEFAULT 'DISPOSITION',
    worker_id                      TEXT COLLATE "C" NOT NULL,
    control_submission_id          UUID NOT NULL,
    tenant                         TEXT COLLATE "C" NOT NULL,
    environment                    TEXT COLLATE "C" NOT NULL,
    authorization_id                            UUID NOT NULL,
    transaction_id                 UUID NOT NULL,
    state_instance_id              UUID NOT NULL,
    claim_id                       UUID,
    claim_fence                    BIGINT,
    acquisition_id                 UUID,
    lease_fence                    BIGINT,
    reason                         TEXT COLLATE "C" NOT NULL,
    observed_unix_s                BIGINT NOT NULL,
    dispatch_deadline              BIGINT NOT NULL,
    authorization_commitment              TEXT COLLATE "C" NOT NULL,
    grant_commitment               TEXT COLLATE "C" NOT NULL,
    outbox_commitment              TEXT COLLATE "C" NOT NULL,
    expected_authority_commitment  TEXT COLLATE "C" NOT NULL,
    current_authority_commitment   TEXT COLLATE "C" NOT NULL,
    disposition_commitment         TEXT COLLATE "C" NOT NULL,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_dispatch_queue_dispositions_submission_key
        UNIQUE (control_submission_id),
    CONSTRAINT accordlock_dispatch_queue_dispositions_tuple_key
        UNIQUE (tenant, environment, authorization_id, transaction_id),
    CONSTRAINT accordlock_dispatch_queue_dispositions_request_identity_fkey
        FOREIGN KEY (dispatch_request_id, request_kind, worker_id)
        REFERENCES public.accordlock_dispatch_request_identities (
            dispatch_request_id, request_kind, worker_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_queue_dispositions_control_fkey
        FOREIGN KEY (
            control_submission_id, tenant, environment, authorization_id, transaction_id
        )
        REFERENCES public.accordlock_control_consumptions (
            submission_id, tenant, environment, authorization_id, transaction_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_queue_dispositions_outbox_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, dispatch_deadline
        )
        REFERENCES public.accordlock_execution_outbox (
            tenant, environment, authorization_id, transaction_id, dispatch_deadline
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_queue_dispositions_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_queue_dispositions_acquisition_fkey
        FOREIGN KEY (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence
        )
        REFERENCES public.accordlock_dispatch_acquisitions (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_queue_dispositions_identity_check CHECK (
        dispatch_request_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND request_kind = 'DISPOSITION'
        AND octet_length(worker_id) BETWEEN 1 AND 253
        AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
        AND (claim_id IS NULL) = (claim_fence IS NULL)
        AND (claim_id IS NULL) = (acquisition_id IS NULL)
        AND (claim_id IS NULL) = (lease_fence IS NULL)
        AND (claim_id IS NULL OR claim_id <>
            '00000000-0000-0000-0000-000000000000'::uuid)
        AND (acquisition_id IS NULL OR acquisition_id <>
            '00000000-0000-0000-0000-000000000000'::uuid)
        AND (claim_fence IS NULL OR claim_fence > 0)
        AND (lease_fence IS NULL OR lease_fence > 0)
    ),
    CONSTRAINT accordlock_dispatch_queue_dispositions_reason_check CHECK (
        reason IN (
            'AUTHORITY_CHANGED', 'GRANT_REVOKED',
            'DISPATCH_DEADLINE_EXPIRED'
        )
        AND (
            reason = 'DISPATCH_DEADLINE_EXPIRED'
            OR reason = 'AUTHORITY_CHANGED'
            AND expected_authority_commitment <> current_authority_commitment
            OR reason = 'GRANT_REVOKED'
            AND expected_authority_commitment = current_authority_commitment
        ) IS TRUE
    ),
    CONSTRAINT accordlock_dispatch_queue_dispositions_time_check CHECK (
        observed_unix_s >= 0 AND dispatch_deadline > 0
    ),
    CONSTRAINT accordlock_dispatch_queue_dispositions_commitments_check CHECK (
        authorization_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND grant_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND outbox_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND expected_authority_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND current_authority_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND disposition_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND authorization_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND grant_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND outbox_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND expected_authority_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND current_authority_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND disposition_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    )
);

CREATE INDEX accordlock_dispatch_queue_dispositions_reason_idx
    ON public.accordlock_dispatch_queue_dispositions (
        reason, observed_unix_s, control_submission_id
    );

-- Freeze the acquisition generation that crossed ATTEMPT_IN_FLIGHT. Copied
-- lease bounds make the row self-validating while the composite FK prevents
-- a lease from another claim or state instance being substituted.
ALTER TABLE public.accordlock_dispatch_claims
    DROP CONSTRAINT accordlock_dispatch_claims_state_check,
    DROP CONSTRAINT accordlock_dispatch_claims_state_time_check,
    ADD COLUMN attempt_acquisition_id UUID,
    ADD COLUMN attempt_lease_fence BIGINT,
    ADD COLUMN attempt_acquired_unix_s BIGINT,
    ADD COLUMN attempt_lease_until BIGINT,
    ADD COLUMN acquisition_binding_version SMALLINT,
    ADD COLUMN credential_review_id UUID,
    ADD COLUMN recovery_safe_after_unix_s BIGINT,
    ADD COLUMN recovery_retired_unix_s BIGINT;

UPDATE public.accordlock_dispatch_claims
   SET attempt_acquisition_id = claim_id,
       attempt_lease_fence = fence,
       attempt_acquired_unix_s = claimed_unix_s,
       attempt_lease_until = lease_until,
       acquisition_binding_version = 1
 WHERE state IN ('ATTEMPT_IN_FLIGHT', 'TERMINAL');

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_attempt_acquisition_fkey
        FOREIGN KEY (
            attempt_acquisition_id, tenant, environment, authorization_id,
            transaction_id, claim_id, fence, state_instance_id,
            attempt_lease_fence, attempt_acquired_unix_s,
            attempt_lease_until
        )
        REFERENCES public.accordlock_dispatch_acquisitions (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence,
            acquired_unix_s, lease_until
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT accordlock_dispatch_claims_state_check
        CHECK (state IN (
            'CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND',
            'RECOVERY_RETIRED', 'DISPOSED', 'TERMINAL'
        )),
    ADD CONSTRAINT accordlock_dispatch_claims_state_time_check CHECK ((
        state IN (
            'CLAIMED', 'RECOVERY_NO_SEND', 'RECOVERY_RETIRED', 'DISPOSED'
        )
        AND terminalization_id IS NULL
        AND attempt_started_at IS NULL
        AND credential_token_digest IS NULL
        AND service_account_uid IS NULL
        AND credential_id IS NULL
        AND credential_not_before IS NULL
        AND credential_expires_at IS NULL
        AND credential_binding_commitment IS NULL
        AND attempt_acquisition_id IS NULL
        AND attempt_lease_fence IS NULL
        AND attempt_acquired_unix_s IS NULL
        AND attempt_lease_until IS NULL
        AND acquisition_binding_version IS NULL
        AND credential_review_id IS NULL
        AND (
            state IN ('CLAIMED', 'DISPOSED')
            AND recovery_safe_after_unix_s IS NULL
            AND recovery_retired_unix_s IS NULL
            OR state = 'RECOVERY_NO_SEND'
            AND (
                recovery_safe_after_unix_s IS NULL
                OR recovery_safe_after_unix_s >= 0
            )
            AND recovery_retired_unix_s IS NULL
            OR state = 'RECOVERY_RETIRED'
            AND recovery_safe_after_unix_s IS NOT NULL
            AND recovery_safe_after_unix_s >= 0
            AND recovery_retired_unix_s IS NOT NULL
            AND recovery_retired_unix_s >= recovery_safe_after_unix_s
        )
        OR state IN ('ATTEMPT_IN_FLIGHT', 'TERMINAL')
        AND (state = 'TERMINAL') = (terminalization_id IS NOT NULL)
        AND attempt_started_at IS NOT NULL
        AND attempt_acquisition_id IS NOT NULL
        AND attempt_lease_fence IS NOT NULL
        AND attempt_acquired_unix_s IS NOT NULL
        AND attempt_lease_until IS NOT NULL
        AND acquisition_binding_version IN (1, 2)
        AND attempt_started_at >= claimed_unix_s
        AND attempt_started_at >= attempt_acquired_unix_s
        AND attempt_started_at < attempt_lease_until
        AND credential_token_digest IS NOT NULL
        AND service_account_uid IS NOT NULL
        AND credential_id IS NOT NULL
        AND credential_not_before IS NOT NULL
        AND credential_expires_at IS NOT NULL
        AND credential_binding_commitment IS NOT NULL
        AND credential_not_before >= 0
        AND credential_not_before <= attempt_started_at
        AND credential_expires_at > attempt_started_at
        AND recovery_safe_after_unix_s IS NULL
        AND recovery_retired_unix_s IS NULL
    ) IS TRUE);

-- RECOVERY_NO_SEND retains exclusive physical ownership until exact Secret
-- absence has crossed the rooted conservative retirement bound. The retired
-- state is inert and releases that ownership without fabricating terminal
-- provider evidence.
DROP INDEX public.accordlock_dispatch_claims_active_physical_resource_key;
CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
    ON public.accordlock_dispatch_claims (
        cluster_identity, namespace, deployment_uid
    )
    WHERE state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND');

-- Journal rows written before v14 retain commitment profile v1. Their exact
-- claim/fence already equals the deterministic bootstrap acquisition tuple,
-- so the new FK binds history without rewriting any commitment. New rows use
-- profile v2 and hash acquisition_id + lease_fence in Rust.
ALTER TABLE public.accordlock_broker_operations
    ADD COLUMN origin_acquisition_id UUID,
    ADD COLUMN origin_lease_fence BIGINT,
    ADD COLUMN acquisition_binding_version SMALLINT;

UPDATE public.accordlock_broker_operations
   SET origin_acquisition_id = claim_id,
       origin_lease_fence = fence,
       acquisition_binding_version = 1;

ALTER TABLE public.accordlock_broker_operations
    ALTER COLUMN origin_acquisition_id SET NOT NULL,
    ALTER COLUMN origin_lease_fence SET NOT NULL,
    ALTER COLUMN acquisition_binding_version SET NOT NULL,
    ADD CONSTRAINT accordlock_broker_operations_acquisition_fkey
        FOREIGN KEY (
            origin_acquisition_id, tenant, environment, authorization_id,
            transaction_id, claim_id, fence, state_instance_id,
            origin_lease_fence
        )
        REFERENCES public.accordlock_dispatch_acquisitions (
            acquisition_id, tenant, environment, authorization_id, transaction_id,
            claim_id, claim_fence, state_instance_id, lease_fence
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT accordlock_broker_operations_acquisition_version_check
        CHECK (acquisition_binding_version IN (1, 2));

-- Exact, acquisition-bound Kubernetes TokenReview journal. The only mutable
-- operation is the one-way IN_FLIGHT -> AUTHENTICATED/REJECTED completion;
-- every frozen expectation is committed before the external review request.
CREATE TABLE public.accordlock_dispatch_credential_reviews (
    review_id UUID PRIMARY KEY,
    acquisition_id UUID NOT NULL UNIQUE
        REFERENCES public.accordlock_dispatch_acquisitions(acquisition_id)
        ON DELETE RESTRICT,
    tenant TEXT NOT NULL,
    environment TEXT NOT NULL,
    authorization_id UUID NOT NULL,
    transaction_id UUID NOT NULL,
    control_submission_id UUID NOT NULL
        REFERENCES public.accordlock_control_submissions(submission_id)
        ON DELETE RESTRICT,
    create_entry_id UUID NOT NULL,
    create_request_commitment TEXT NOT NULL,
    create_result_commitment TEXT NOT NULL,
    token_entry_id UUID NOT NULL,
    token_request_commitment TEXT NOT NULL,
    token_result_commitment TEXT NOT NULL,
    expected_route_commitment TEXT NOT NULL,
    credential_lifetime_upper_s BIGINT NOT NULL,
    credential_clock_uncertainty_s BIGINT NOT NULL,
    expected_token_digest TEXT NOT NULL,
    expected_token_expires_at BIGINT NOT NULL,
    expected_subject TEXT NOT NULL,
    expected_audience TEXT NOT NULL,
    expected_service_account_uid TEXT NOT NULL,
    expected_bound_secret_uid TEXT NOT NULL,
    credential_lifecycle_policy_json JSONB NOT NULL,
    destination_activation_commitment TEXT NOT NULL,
    phase TEXT NOT NULL,
    begun_unix_s BIGINT NOT NULL,
    reviewed_unix_s BIGINT,
    claims_json JSONB,
    review_evidence_commitment TEXT,
    review_commitment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_dispatch_credential_reviews_key
        UNIQUE (tenant, environment, authorization_id, transaction_id),
    CONSTRAINT accordlock_dispatch_credential_reviews_phase_check CHECK (
        phase = 'IN_FLIGHT'
        AND reviewed_unix_s IS NULL
        AND claims_json IS NULL
        AND review_evidence_commitment IS NULL
        AND review_commitment IS NULL
        OR phase = 'AUTHENTICATED'
        AND reviewed_unix_s IS NOT NULL
        AND claims_json IS NOT NULL
        AND review_evidence_commitment IS NOT NULL
        AND review_commitment IS NOT NULL
        OR phase = 'REJECTED'
        AND reviewed_unix_s IS NOT NULL
        AND claims_json IS NULL
        AND review_evidence_commitment IS NOT NULL
        AND review_commitment IS NOT NULL
    ),
    CONSTRAINT accordlock_dispatch_credential_reviews_time_check CHECK (
        begun_unix_s >= 0
        AND expected_token_expires_at > begun_unix_s
        AND (reviewed_unix_s IS NULL OR reviewed_unix_s >= begun_unix_s)
    ),
    CONSTRAINT accordlock_dispatch_credential_reviews_policy_check CHECK (
        credential_lifetime_upper_s > 0
        AND credential_clock_uncertainty_s >= 0
        AND credential_clock_uncertainty_s <= credential_lifetime_upper_s
    ),
    CONSTRAINT accordlock_dispatch_credential_reviews_digest_check CHECK (
        create_request_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND create_result_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND token_request_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND token_result_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND expected_route_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND expected_token_digest ~ '^sha256:[0-9a-f]{64}$'
        AND destination_activation_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND (review_evidence_commitment IS NULL OR
             review_evidence_commitment ~ '^sha256:[0-9a-f]{64}$')
        AND (review_commitment IS NULL OR
             review_commitment ~ '^sha256:[0-9a-f]{64}$')
    )
);

CREATE INDEX accordlock_dispatch_credential_reviews_phase_idx
    ON public.accordlock_dispatch_credential_reviews (
        phase, tenant, environment, authorization_id, transaction_id
    );

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_credential_review_fkey
        FOREIGN KEY (credential_review_id)
        REFERENCES public.accordlock_dispatch_credential_reviews(review_id)
        ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION public.accordlock_reject_dispatch_acquisition_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'dispatch acquisition history is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_reject_dispatch_disposition_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'dispatch queue disposition history is append-only';
END
$function$;

-- SQL-verifiable commitments for disposition facts. Every part is framed by
-- its UTF-8 byte length, so concatenation cannot alias embedded separators.
-- Rust uses the same framing before SHA-256.
CREATE OR REPLACE FUNCTION public.accordlock_dispatch_frame_commitment(
    commitment_domain TEXT,
    commitment_parts TEXT[]
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $function$
DECLARE
    material BYTEA := ''::bytea;
    part TEXT;
    encoded BYTEA;
BEGIN
    FOREACH part IN ARRAY array_prepend(commitment_domain, commitment_parts)
    LOOP
        IF part IS NULL THEN
            RAISE EXCEPTION 'dispatch commitment part is null';
        END IF;
        encoded := convert_to(part, 'UTF8');
        material := material
            || convert_to(octet_length(encoded)::text || ':', 'UTF8')
            || encoded;
    END LOOP;
    RETURN 'sha256:' || encode(sha256(material), 'hex');
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_dispatch_authority_fact_commitment(
    authority JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $function$
DECLARE
    parts TEXT[];
    domain_index INTEGER;
    domain_name TEXT;
    domain_value JSONB;
BEGIN
    IF jsonb_typeof(authority) IS DISTINCT FROM 'object'
       OR ARRAY(
            SELECT authority_key
              FROM jsonb_object_keys(authority) AS authority_key
             ORDER BY authority_key
          ) IS DISTINCT FROM ARRAY[
            'connector', 'grant_registry', 'kernel_configuration',
            'mediation', 'office_act_registry', 'policy',
            'principal_registry', 'registry', 'resource', 'revocation',
            'signer', 'workload_build_allowlist'
          ]::TEXT[] THEN
        RAISE EXCEPTION 'dispatch authority vector has invalid shape';
    END IF;
    FOREACH domain_name IN ARRAY ARRAY[
        'policy', 'registry', 'revocation', 'connector', 'resource',
        'signer', 'mediation', 'grant_registry', 'office_act_registry',
        'principal_registry', 'workload_build_allowlist',
        'kernel_configuration'
    ]::TEXT[] LOOP
        domain_value := authority -> domain_name;
        IF jsonb_typeof(domain_value) IS DISTINCT FROM 'object'
           OR ARRAY(
                SELECT domain_key
                  FROM jsonb_object_keys(domain_value) AS domain_key
                 ORDER BY domain_key
              ) IS DISTINCT FROM ARRAY[
                'activation_id', 'epoch', 'root'
              ]::TEXT[]
           OR jsonb_typeof(domain_value -> 'root') IS DISTINCT FROM 'string'
           OR jsonb_typeof(domain_value -> 'epoch') IS DISTINCT FROM 'number'
           OR jsonb_typeof(domain_value -> 'activation_id')
              IS DISTINCT FROM 'string' THEN
            RAISE EXCEPTION 'dispatch authority domain % has invalid shape',
                domain_name;
        END IF;
    END LOOP;
    parts := ARRAY[
        authority #>> '{policy,root}', authority #>> '{policy,epoch}',
        authority #>> '{policy,activation_id}',
        authority #>> '{registry,root}', authority #>> '{registry,epoch}',
        authority #>> '{registry,activation_id}',
        authority #>> '{revocation,root}', authority #>> '{revocation,epoch}',
        authority #>> '{revocation,activation_id}',
        authority #>> '{connector,root}', authority #>> '{connector,epoch}',
        authority #>> '{connector,activation_id}',
        authority #>> '{resource,root}', authority #>> '{resource,epoch}',
        authority #>> '{resource,activation_id}',
        authority #>> '{signer,root}', authority #>> '{signer,epoch}',
        authority #>> '{signer,activation_id}',
        authority #>> '{mediation,root}', authority #>> '{mediation,epoch}',
        authority #>> '{mediation,activation_id}',
        authority #>> '{grant_registry,root}',
        authority #>> '{grant_registry,epoch}',
        authority #>> '{grant_registry,activation_id}',
        authority #>> '{office_act_registry,root}',
        authority #>> '{office_act_registry,epoch}',
        authority #>> '{office_act_registry,activation_id}',
        authority #>> '{principal_registry,root}',
        authority #>> '{principal_registry,epoch}',
        authority #>> '{principal_registry,activation_id}',
        authority #>> '{workload_build_allowlist,root}',
        authority #>> '{workload_build_allowlist,epoch}',
        authority #>> '{workload_build_allowlist,activation_id}',
        authority #>> '{kernel_configuration,root}',
        authority #>> '{kernel_configuration,epoch}',
        authority #>> '{kernel_configuration,activation_id}'
    ];
    IF array_position(parts, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'dispatch authority fact is incomplete';
    END IF;
    FOR domain_index IN 0..11 LOOP
        IF parts[domain_index * 3 + 1] !~ '^sha256:[0-9a-f]{64}$'
           OR parts[domain_index * 3 + 2] !~ '^(0|[1-9][0-9]*)$'
           OR (parts[domain_index * 3 + 2])::numeric < 0
           OR (parts[domain_index * 3 + 2])::numeric > 18446744073709551615
           OR (parts[domain_index * 3 + 3])::uuid =
              '00000000-0000-0000-0000-000000000000'::uuid
           OR parts[domain_index * 3 + 3] IS DISTINCT FROM
              ((parts[domain_index * 3 + 3])::uuid)::text THEN
            RAISE EXCEPTION 'dispatch authority fact is malformed';
        END IF;
    END LOOP;
    RETURN public.accordlock_dispatch_frame_commitment(
        'ACCORDLOCK_DISPATCH_AUTHORITY_FACT_V1', parts
    );
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_dispatch_grant_fact_commitment(
    registration JSONB,
    uses BIGINT,
    maximum_uses BIGINT,
    not_before BIGINT,
    expires_at BIGINT,
    revoked BOOLEAN
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $function$
DECLARE
    parts TEXT[];
BEGIN
    parts := ARRAY[
        registration #>> '{grant,tenant}',
        registration #>> '{environment}',
        registration #>> '{grant,grant_id}',
        registration #>> '{grant,holder}',
        registration #>> '{grant,operation}',
        registration #>> '{grant,repository}',
        registration #>> '{grant,audience}',
        registration #>> '{grant,cluster_identity}',
        registration #>> '{grant,namespace}',
        registration #>> '{grant,deployment_uid}',
        registration #>> '{grant,container}',
        registration #>> '{grant,image_repository}',
        registration #>> '{grant,not_before}',
        registration #>> '{grant,expires_at}',
        registration #>> '{grant,maximum_uses}',
        registration #>> '{dispatch_deadline_policy,max_dispatch_delay_seconds}',
        registration #>> '{dispatch_deadline_policy,profile_hard_cap}',
        jsonb_array_length(
            registration #> '{dispatch_deadline_policy,immutable_dependency_expiries}'
        )::text
    ];
    parts := parts || ARRAY(
        SELECT dependency.value::text
          FROM jsonb_array_elements(
                   registration #> '{dispatch_deadline_policy,immutable_dependency_expiries}'
               ) WITH ORDINALITY AS dependency(value, position)
         ORDER BY dependency.position
    );
    parts := parts || ARRAY[
        registration #>> '{authority,grant_registry,root}',
        public.accordlock_dispatch_authority_fact_commitment(
            registration -> 'authority'
        ),
        uses::text, maximum_uses::text, not_before::text,
        expires_at::text, revoked::text
    ];
    IF array_position(parts, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'dispatch grant fact is incomplete';
    END IF;
    RETURN public.accordlock_dispatch_frame_commitment(
        'ACCORDLOCK_DISPATCH_GRANT_FACT_V2', parts
    );
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_dispatch_outbox_fact_commitment(
    entry JSONB
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $function$
BEGIN
    RETURN public.accordlock_dispatch_frame_commitment(
        'ACCORDLOCK_DISPATCH_OUTBOX_FACT_V1',
        ARRAY[
            entry #>> '{scope,tenant}', entry #>> '{scope,environment}',
            entry #>> '{authorization_id}', entry #>> '{transaction_id}',
            entry #>> '{dispatch_deadline}', entry #>> '{status}',
            entry #>> '{receipt,consumed_at}',
            entry #>> '{receipt,authorization_hash}',
            public.accordlock_dispatch_authority_fact_commitment(
                entry #> '{receipt,authority}'
            )
        ]
    );
END
$function$;

-- Once a v13 control consumption reaches DISPATCH_PENDING, its immutable
-- dispatch sources are frozen at the database boundary. Rust remains the TCB
-- for COSE verification and canonical protocol hashing at ingress/load time;
-- these guards prevent a later SQL writer from changing already-authenticated
-- JSON and then laundering the mutation into a queue disposition.
CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_grant_source_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispatch grant source cannot be deleted';
    END IF;
    IF ROW(
           NEW.tenant, NEW.environment, NEW.grant_id,
           NEW.registration_json, NEW.maximum_uses, NEW.not_before,
           NEW.expires_at, NEW.issuance_profile_version, NEW.created_at
       ) IS DISTINCT FROM ROW(
           OLD.tenant, OLD.environment, OLD.grant_id,
           OLD.registration_json, OLD.maximum_uses, OLD.not_before,
           OLD.expires_at, OLD.issuance_profile_version, OLD.created_at
       )
       OR NEW.uses < OLD.uses OR NEW.uses > OLD.uses + 1
       OR (OLD.revoked AND NOT NEW.revoked) THEN
        RAISE EXCEPTION 'control-owned dispatch grant source mutation is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_authorization_source_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispatch authorization source cannot be deleted';
    END IF;
    IF ROW(
           NEW.tenant, NEW.environment, NEW.authorization_id, NEW.transaction_id,
           NEW.grant_id, NEW.record_json, NEW.authorization_hash,
           NEW.consume_before, NEW.created_at, NEW.issuance_profile_version,
           NEW.request_id, NEW.evaluation_nonce
       ) IS DISTINCT FROM ROW(
           OLD.tenant, OLD.environment, OLD.authorization_id, OLD.transaction_id,
           OLD.grant_id, OLD.record_json, OLD.authorization_hash,
           OLD.consume_before, OLD.created_at, OLD.issuance_profile_version,
           OLD.request_id, OLD.evaluation_nonce
       ) THEN
        RAISE EXCEPTION 'dispatch authorization immutable source differs';
    END IF;
    IF ROW(NEW.state, NEW.consumed_at) IS DISTINCT FROM
       ROW(OLD.state, OLD.consumed_at)
       AND NOT (
           OLD.state = 'ISSUED' AND OLD.consumed_at IS NULL
           AND NEW.state = 'CONSUMED' AND NEW.consumed_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'dispatch authorization transition is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_reject_dispatch_consumption_source_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'dispatch consumption source is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_reject_dispatch_outbox_source_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'dispatch outbox source is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_validate_dispatch_authority_source()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    domain_name TEXT;
    old_epoch NUMERIC;
    new_epoch NUMERIC;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispatch authority source cannot be deleted';
    END IF;
    PERFORM public.accordlock_dispatch_authority_fact_commitment(NEW.authority_json);
    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant IS DISTINCT FROM OLD.tenant
           OR NEW.environment IS DISTINCT FROM OLD.environment THEN
            RAISE EXCEPTION 'dispatch authority scope is immutable';
        END IF;
        FOREACH domain_name IN ARRAY ARRAY[
            'policy', 'registry', 'revocation', 'connector', 'resource',
            'signer', 'mediation', 'grant_registry', 'office_act_registry',
            'principal_registry', 'workload_build_allowlist',
            'kernel_configuration'
        ]::TEXT[] LOOP
            old_epoch := (OLD.authority_json #>> ARRAY[domain_name, 'epoch'])::numeric;
            new_epoch := (NEW.authority_json #>> ARRAY[domain_name, 'epoch'])::numeric;
            IF new_epoch < old_epoch
               OR (NEW.authority_json -> domain_name IS DISTINCT FROM
                   OLD.authority_json -> domain_name
                   AND new_epoch <= old_epoch) THEN
                RAISE EXCEPTION 'dispatch authority transition is non-monotone';
            END IF;
        END LOOP;
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_high_water_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispatch trusted-time high-water cannot be deleted';
    END IF;
    IF NEW.observed_unix_s < OLD.observed_unix_s THEN
        RAISE EXCEPTION 'dispatch trusted-time high-water cannot decrease';
    END IF;
    -- A trigger record is typed to its relation.  Referencing a field that
    -- exists only on the other high-water relation fails during expression
    -- planning even when the TG_TABLE_NAME branch is false, so compare the
    -- relation-specific identity through JSONB instead.
    IF TG_TABLE_NAME = 'accordlock_time_high_water'
       AND jsonb_build_array(
               to_jsonb(NEW) -> 'tenant',
               to_jsonb(NEW) -> 'environment'
           ) IS DISTINCT FROM jsonb_build_array(
               to_jsonb(OLD) -> 'tenant',
               to_jsonb(OLD) -> 'environment'
           ) THEN
        RAISE EXCEPTION 'dispatch scope high-water identity is immutable';
    END IF;
    IF TG_TABLE_NAME = 'accordlock_ingress_replay_scopes'
       AND jsonb_build_array(
               to_jsonb(NEW) -> 'replay_scope',
               to_jsonb(NEW) -> 'state_instance_id',
               to_jsonb(NEW) -> 'created_at'
           ) IS DISTINCT FROM jsonb_build_array(
               to_jsonb(OLD) -> 'replay_scope',
               to_jsonb(OLD) -> 'state_instance_id',
               to_jsonb(OLD) -> 'created_at'
           ) THEN
        RAISE EXCEPTION 'dispatch ingress high-water identity is immutable';
    END IF;
    RETURN NEW;
END
$function$;

DO $block$
BEGIN
    PERFORM public.accordlock_dispatch_authority_fact_commitment(
        authority.authority_json
    )
      FROM public.accordlock_authority_state AS authority;
END
$block$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_request_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'dispatch request identity is not deletable';
    END IF;
    IF OLD.request_kind IS NULL
       AND NEW.request_kind IN ('ACQUISITION', 'DISPOSITION')
       AND NEW.bound_at IS NOT NULL
       AND NEW.dispatch_request_id = OLD.dispatch_request_id
       AND NEW.worker_id = OLD.worker_id
       AND NEW.created_at = OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'dispatch request identity may be bound exactly once';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_check_dispatch_request_identity_child()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    bound_kind TEXT;
    acquisition_count BIGINT;
    disposition_count BIGINT;
BEGIN
    SELECT request_kind
      INTO STRICT bound_kind
      FROM public.accordlock_dispatch_request_identities
     WHERE dispatch_request_id = NEW.dispatch_request_id
     FOR UPDATE;
    SELECT count(*) INTO acquisition_count
      FROM public.accordlock_dispatch_acquisitions
     WHERE acquisition_id = NEW.dispatch_request_id;
    SELECT count(*) INTO disposition_count
      FROM public.accordlock_dispatch_queue_dispositions
     WHERE dispatch_request_id = NEW.dispatch_request_id;
    IF bound_kind IS NULL
       OR bound_kind = 'ACQUISITION'
          AND (acquisition_count <> 1 OR disposition_count <> 0)
       OR bound_kind = 'DISPOSITION'
          AND (disposition_count <> 1 OR acquisition_count <> 0) THEN
        RAISE EXCEPTION
            'dispatch request identity lacks its exact one-of durable child';
    END IF;
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_claim_v14_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF current_setting('accordlock.state_writer_schema', true)
       IS DISTINCT FROM '14' THEN
        RAISE EXCEPTION 'dispatch claim writer schema is not v14';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_check_dispatch_claim_acquisition()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_acquisitions AS acquisition
         WHERE acquisition.tenant = NEW.tenant
           AND acquisition.environment = NEW.environment
           AND acquisition.authorization_id = NEW.authorization_id
           AND acquisition.transaction_id = NEW.transaction_id
           AND acquisition.claim_id = NEW.claim_id
           AND acquisition.claim_fence = NEW.fence
           AND acquisition.state_instance_id = NEW.state_instance_id
    ) THEN
        RAISE EXCEPTION
            'new dispatch claim lacks its exact acquisition at commit';
    END IF;
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_acquisition_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    claim_state TEXT;
    prior_lease_until BIGINT;
    request_kind TEXT;
BEGIN
    SELECT identity.request_kind
      INTO STRICT request_kind
      FROM public.accordlock_dispatch_request_identities AS identity
     WHERE identity.dispatch_request_id = NEW.acquisition_id
       AND identity.worker_id = NEW.worker_id
     FOR UPDATE;
    IF request_kind <> 'ACQUISITION'
       OR NEW.request_kind <> 'ACQUISITION'
       OR EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions
             WHERE dispatch_request_id = NEW.acquisition_id
       ) THEN
        RAISE EXCEPTION 'dispatch request identity is not acquisition-bound';
    END IF;

    IF NEW.selection_kind = 'CONTROL_BOOTSTRAP_V13' THEN
        RAISE EXCEPTION 'CONTROL_BOOTSTRAP_V13 is migration-backfill only';
    END IF;

    IF NEW.lease_until - NEW.acquired_unix_s > 30 THEN
        RAISE EXCEPTION 'new dispatch acquisition lease exceeds 30 seconds';
    END IF;

    IF NEW.control_submission_id IS NOT NULL THEN
        PERFORM 1
          FROM public.accordlock_control_submissions AS submission
         WHERE submission.submission_id = NEW.control_submission_id
           AND submission.tenant = NEW.tenant
           AND submission.environment = NEW.environment
           AND submission.state_instance_id = NEW.state_instance_id
         FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'dispatch acquisition control root differs';
        END IF;
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions AS disposition
             WHERE disposition.control_submission_id = NEW.control_submission_id
        ) THEN
            RAISE EXCEPTION
                'dispatch acquisition follows a durable queue disposition';
        END IF;
    END IF;

    SELECT state
      INTO STRICT claim_state
      FROM public.accordlock_dispatch_claims
     WHERE tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND fence = NEW.claim_fence
       AND state_instance_id = NEW.state_instance_id
     FOR UPDATE;

    IF claim_state <> 'CLAIMED' THEN
        RAISE EXCEPTION 'dispatch acquisition requires a CLAIMED stable claim';
    END IF;

    IF NEW.selection_kind = 'LEGACY_BOOTSTRAP'
       AND EXISTS (
            SELECT 1
              FROM public.accordlock_control_consumptions
             WHERE tenant = NEW.tenant
               AND environment = NEW.environment
               AND authorization_id = NEW.authorization_id
               AND transaction_id = NEW.transaction_id
       ) THEN
        RAISE EXCEPTION
            'control-owned dispatch acquisition requires its submission link';
    END IF;

    SELECT lease_until
      INTO prior_lease_until
      FROM public.accordlock_dispatch_acquisitions
     WHERE tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND claim_fence = NEW.claim_fence
       AND state_instance_id = NEW.state_instance_id
     ORDER BY lease_fence DESC
     LIMIT 1
     FOR UPDATE;

    IF FOUND THEN
        IF NEW.acquired_unix_s < prior_lease_until THEN
            RAISE EXCEPTION 'dispatch acquisition takeover precedes prior expiry';
        END IF;
        IF EXISTS (
            SELECT 1 FROM public.accordlock_broker_operations
             WHERE tenant = NEW.tenant AND environment = NEW.environment
               AND authorization_id = NEW.authorization_id
               AND transaction_id = NEW.transaction_id
               AND claim_id = NEW.claim_id
               AND fence = NEW.claim_fence
        ) OR EXISTS (
            SELECT 1 FROM public.accordlock_admission_authorizations
             WHERE tenant = NEW.tenant AND environment = NEW.environment
               AND authorization_id = NEW.authorization_id
               AND transaction_id = NEW.transaction_id
               AND claim_id = NEW.claim_id
               AND fence = NEW.claim_fence
        ) OR EXISTS (
            SELECT 1 FROM public.accordlock_terminal_retirements
             WHERE tenant = NEW.tenant AND environment = NEW.environment
               AND authorization_id = NEW.authorization_id
               AND transaction_id = NEW.transaction_id
               AND claim_id = NEW.claim_id
               AND fence = NEW.claim_fence
        ) OR EXISTS (
            SELECT 1 FROM public.accordlock_dispatch_credential_reviews
             WHERE tenant = NEW.tenant AND environment = NEW.environment
               AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION
                'dispatch acquisition takeover is barred by durable artifacts';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_claim_v14_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    latest_acquisition UUID;
    latest_lease_fence BIGINT;
    latest_acquired BIGINT;
    latest_lease_until BIGINT;
    latest_selection_kind TEXT;
    expected_recovery_safe_after BIGINT;
    expected_creation_absent_at BIGINT;
BEGIN
    IF ROW(
        NEW.tenant, NEW.environment, NEW.authorization_id, NEW.transaction_id,
        NEW.claim_id, NEW.worker_id, NEW.fence, NEW.state_instance_id,
        NEW.claimed_unix_s, NEW.lease_until, NEW.cluster_identity,
        NEW.namespace, NEW.deployment_uid
    ) IS DISTINCT FROM ROW(
        OLD.tenant, OLD.environment, OLD.authorization_id, OLD.transaction_id,
        OLD.claim_id, OLD.worker_id, OLD.fence, OLD.state_instance_id,
        OLD.claimed_unix_s, OLD.lease_until, OLD.cluster_identity,
        OLD.namespace, OLD.deployment_uid
    ) THEN
        RAISE EXCEPTION 'stable dispatch claim identity is immutable';
    END IF;

    IF NOT (
        OLD.state = 'CLAIMED'
        AND NEW.state IN (
            'CLAIMED', 'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND', 'DISPOSED'
        )
        OR OLD.state = 'ATTEMPT_IN_FLIGHT'
           AND NEW.state IN ('ATTEMPT_IN_FLIGHT', 'TERMINAL')
        OR OLD.state = 'RECOVERY_NO_SEND'
           AND NEW.state IN ('RECOVERY_NO_SEND', 'RECOVERY_RETIRED')
        OR OLD.state = 'RECOVERY_RETIRED'
           AND NEW.state = 'RECOVERY_RETIRED'
        OR OLD.state = 'DISPOSED' AND NEW.state = 'DISPOSED'
        OR OLD.state = 'TERMINAL' AND NEW.state = 'TERMINAL'
    ) THEN
        RAISE EXCEPTION 'dispatch claim state transition is not monotone';
    END IF;

    IF OLD.state = 'CLAIMED' AND NEW.state = 'DISPOSED' THEN
        IF NOT EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions AS disposition
             WHERE disposition.tenant = NEW.tenant
               AND disposition.environment = NEW.environment
               AND disposition.authorization_id = NEW.authorization_id
               AND disposition.transaction_id = NEW.transaction_id
               AND disposition.state_instance_id = NEW.state_instance_id
               AND disposition.claim_id = NEW.claim_id
               AND disposition.claim_fence = NEW.fence
        ) THEN
            RAISE EXCEPTION
                'disposed claim lacks its exact durable queue disposition';
        END IF;
    END IF;

    IF NEW.terminalization_id IS DISTINCT FROM OLD.terminalization_id
       AND NOT (
            OLD.state = 'ATTEMPT_IN_FLIGHT'
            AND NEW.state = 'TERMINAL'
            AND OLD.terminalization_id IS NULL
            AND NEW.terminalization_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'dispatch claim terminalization identity is immutable';
    END IF;

    IF OLD.state = 'CLAIMED'
       AND NEW.state = 'ATTEMPT_IN_FLIGHT' THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions AS disposition
             WHERE disposition.tenant = NEW.tenant
               AND disposition.environment = NEW.environment
               AND disposition.authorization_id = NEW.authorization_id
               AND disposition.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION
                'provider/no-send boundary follows a durable queue disposition';
        END IF;
        SELECT acquisition_id, lease_fence, acquired_unix_s, lease_until,
               selection_kind
          INTO STRICT latest_acquisition, latest_lease_fence,
              latest_acquired, latest_lease_until, latest_selection_kind
          FROM public.accordlock_dispatch_acquisitions
         WHERE tenant = NEW.tenant
           AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND claim_fence = NEW.fence
           AND state_instance_id = NEW.state_instance_id
         ORDER BY lease_fence DESC
         LIMIT 1
         FOR SHARE;
        IF NEW.attempt_acquisition_id <> latest_acquisition
           OR NEW.attempt_lease_fence <> latest_lease_fence
           OR NEW.attempt_acquired_unix_s <> latest_acquired
           OR NEW.attempt_lease_until <> latest_lease_until
           OR NEW.attempt_started_at < latest_acquired
           OR NEW.attempt_started_at >= latest_lease_until
           OR NEW.acquisition_binding_version <> 2 THEN
            RAISE EXCEPTION
                'provider/no-send boundary is not bound to the latest acquisition';
        END IF;
        IF latest_selection_kind = 'CONTROL_QUEUE' THEN
            IF NEW.credential_review_id IS NULL OR NOT EXISTS (
                SELECT 1
                  FROM public.accordlock_dispatch_credential_reviews AS review
                 WHERE review.review_id = NEW.credential_review_id
                   AND review.acquisition_id = latest_acquisition
                   AND review.tenant = NEW.tenant
                   AND review.environment = NEW.environment
                   AND review.authorization_id = NEW.authorization_id
                   AND review.transaction_id = NEW.transaction_id
                   AND review.phase = 'AUTHENTICATED'
                  FOR SHARE
            ) THEN
                RAISE EXCEPTION
                    'control provider boundary lacks authenticated credential review';
            END IF;
        ELSIF latest_selection_kind <> 'LEGACY_BOOTSTRAP'
              OR NEW.credential_review_id IS NOT NULL THEN
            RAISE EXCEPTION
                'provider attempt requires control-v2 or exact legacy bootstrap lineage';
        END IF;
    END IF;
    IF OLD.state = 'CLAIMED' AND NEW.state = 'RECOVERY_NO_SEND' THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions AS disposition
             WHERE disposition.tenant = NEW.tenant
               AND disposition.environment = NEW.environment
               AND disposition.authorization_id = NEW.authorization_id
               AND disposition.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION
                'no-send recovery follows a durable queue disposition';
        END IF;
        SELECT acquisition_id, lease_fence, acquired_unix_s, lease_until,
               selection_kind
          INTO STRICT latest_acquisition, latest_lease_fence,
              latest_acquired, latest_lease_until, latest_selection_kind
          FROM public.accordlock_dispatch_acquisitions
         WHERE tenant = NEW.tenant
           AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND claim_fence = NEW.fence
           AND state_instance_id = NEW.state_instance_id
         ORDER BY lease_fence DESC
         LIMIT 1
         FOR SHARE;
        IF latest_selection_kind NOT IN (
                'CONTROL_QUEUE', 'CONTROL_BOOTSTRAP_V13'
           )
           OR latest_selection_kind = 'CONTROL_BOOTSTRAP_V13'
              AND (
                  latest_acquisition IS DISTINCT FROM NEW.claim_id
                  OR latest_lease_fence IS DISTINCT FROM NEW.fence
                  OR latest_acquired IS DISTINCT FROM NEW.claimed_unix_s
                  OR latest_lease_until IS DISTINCT FROM NEW.lease_until
              ) THEN
            RAISE EXCEPTION
                'no-send recovery is not bound to an exact control acquisition';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM public.accordlock_broker_operations AS broker
             WHERE broker.tenant = NEW.tenant
               AND broker.environment = NEW.environment
               AND broker.authorization_id = NEW.authorization_id
               AND broker.transaction_id = NEW.transaction_id
               AND broker.claim_id = NEW.claim_id
               AND broker.fence = NEW.fence
               AND broker.state_instance_id = NEW.state_instance_id
               AND broker.origin_acquisition_id = latest_acquisition
             FOR SHARE
        ) AND NOT EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_credential_reviews AS review
             WHERE review.tenant = NEW.tenant
               AND review.environment = NEW.environment
               AND review.authorization_id = NEW.authorization_id
               AND review.transaction_id = NEW.transaction_id
               AND review.acquisition_id = latest_acquisition
             FOR SHARE
        ) THEN
            RAISE EXCEPTION
                'no-send recovery requires an exact durable broker artifact';
        END IF;
        IF EXISTS (
            SELECT 1 FROM public.accordlock_admission_authorizations AS admission
             WHERE admission.tenant = NEW.tenant
               AND admission.environment = NEW.environment
               AND admission.authorization_id = NEW.authorization_id
               AND admission.transaction_id = NEW.transaction_id
        ) OR EXISTS (
            SELECT 1 FROM public.accordlock_terminal_retirements AS terminal
             WHERE terminal.tenant = NEW.tenant
               AND terminal.environment = NEW.environment
               AND terminal.authorization_id = NEW.authorization_id
               AND terminal.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION
                'no-send recovery cannot follow admission or terminal evidence';
        END IF;
    END IF;
    IF OLD.state IN (
        'ATTEMPT_IN_FLIGHT', 'RECOVERY_NO_SEND',
        'RECOVERY_RETIRED', 'TERMINAL'
    )
       AND ROW(
            NEW.attempt_started_at, NEW.credential_token_digest,
            NEW.service_account_uid, NEW.credential_id,
            NEW.credential_not_before, NEW.credential_expires_at,
            NEW.credential_binding_commitment,
            NEW.attempt_acquisition_id, NEW.attempt_lease_fence,
            NEW.attempt_acquired_unix_s, NEW.attempt_lease_until,
            NEW.acquisition_binding_version, NEW.credential_review_id
       ) IS DISTINCT FROM ROW(
            OLD.attempt_started_at, OLD.credential_token_digest,
            OLD.service_account_uid, OLD.credential_id,
            OLD.credential_not_before, OLD.credential_expires_at,
            OLD.credential_binding_commitment,
            OLD.attempt_acquisition_id, OLD.attempt_lease_fence,
            OLD.attempt_acquired_unix_s, OLD.attempt_lease_until,
            OLD.acquisition_binding_version, OLD.credential_review_id
       ) THEN
        RAISE EXCEPTION
            'provider attempt and acquisition binding are immutable';
    END IF;
    IF ROW(
        NEW.recovery_safe_after_unix_s, NEW.recovery_retired_unix_s
    ) IS DISTINCT FROM ROW(
        OLD.recovery_safe_after_unix_s, OLD.recovery_retired_unix_s
    ) AND NOT (
        OLD.state = 'RECOVERY_NO_SEND'
        AND NEW.state = 'RECOVERY_NO_SEND'
        AND OLD.recovery_safe_after_unix_s IS NULL
        AND OLD.recovery_retired_unix_s IS NULL
        AND NEW.recovery_safe_after_unix_s IS NOT NULL
        AND NEW.recovery_retired_unix_s IS NULL
        OR OLD.state = 'RECOVERY_NO_SEND'
        AND NEW.state = 'RECOVERY_RETIRED'
        AND OLD.recovery_retired_unix_s IS NULL
        AND (
            OLD.recovery_safe_after_unix_s IS NULL
            OR OLD.recovery_safe_after_unix_s
                IS NOT DISTINCT FROM NEW.recovery_safe_after_unix_s
        )
        AND NEW.recovery_safe_after_unix_s IS NOT NULL
        AND NEW.recovery_retired_unix_s IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'no-send recovery retirement facts are immutable';
    END IF;
    IF OLD.state = 'RECOVERY_NO_SEND'
       AND NEW.state = 'RECOVERY_RETIRED' THEN
        SELECT acquisition_id, selection_kind
          INTO STRICT latest_acquisition, latest_selection_kind
          FROM public.accordlock_dispatch_acquisitions
         WHERE tenant = NEW.tenant
           AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND claim_fence = NEW.fence
           AND state_instance_id = NEW.state_instance_id
         ORDER BY lease_fence DESC
         LIMIT 1
         FOR SHARE;
        IF latest_selection_kind NOT IN (
                'CONTROL_QUEUE', 'CONTROL_BOOTSTRAP_V13'
           ) THEN
            RAISE EXCEPTION
                'no-send retirement requires an exact control acquisition';
        END IF;

        SELECT create_journal.last_reconciled_unix_s
          INTO expected_creation_absent_at
          FROM public.accordlock_broker_operations AS create_journal
         WHERE create_journal.tenant = NEW.tenant
           AND create_journal.environment = NEW.environment
           AND create_journal.authorization_id = NEW.authorization_id
           AND create_journal.transaction_id = NEW.transaction_id
           AND create_journal.claim_id = NEW.claim_id
           AND create_journal.fence = NEW.fence
           AND create_journal.state_instance_id = NEW.state_instance_id
           AND create_journal.origin_acquisition_id = latest_acquisition
           AND create_journal.operation = 'CREATE_SECRET'
           AND create_journal.phase = 'RECONCILE_ONLY'
           AND create_journal.outcome IS NULL
           AND create_journal.bound_secret_uid IS NULL
           AND create_journal.reconciliation_count > 0
           AND create_journal.last_reconciliation_outcome = 'CREATE_ABSENT'
           AND create_journal.last_reconciliation_evidence_commitment IS NOT NULL
           AND create_journal.last_reconciled_unix_s IS NOT NULL
           AND (
               latest_selection_kind = 'CONTROL_QUEUE'
               AND create_journal.acquisition_binding_version = 2
               OR latest_selection_kind = 'CONTROL_BOOTSTRAP_V13'
               AND create_journal.acquisition_binding_version = 1
           )
           AND NOT EXISTS (
               SELECT 1 FROM public.accordlock_broker_operations AS other
                WHERE other.tenant = NEW.tenant
                  AND other.environment = NEW.environment
                  AND other.authorization_id = NEW.authorization_id
                  AND other.transaction_id = NEW.transaction_id
                  AND other.operation IN ('ISSUE_TOKEN', 'DELETE_SECRET')
           )
           AND NOT EXISTS (
               SELECT 1 FROM public.accordlock_dispatch_credential_reviews AS review
                WHERE review.tenant = NEW.tenant
                  AND review.environment = NEW.environment
                  AND review.authorization_id = NEW.authorization_id
                  AND review.transaction_id = NEW.transaction_id
           )
         FOR SHARE;
        IF expected_creation_absent_at IS NOT NULL THEN
            IF NEW.recovery_safe_after_unix_s
                    IS DISTINCT FROM expected_creation_absent_at
               OR NEW.recovery_retired_unix_s
                    IS DISTINCT FROM expected_creation_absent_at THEN
                RAISE EXCEPTION
                    'creation-absent recovery retirement facts mismatch';
            END IF;
            RETURN NEW;
        END IF;

        SELECT DISTINCT
               deletion.observed_unix_s
               + activation.deletion_propagation_hard_max_seconds
               + activation.clock_uncertainty_seconds
          INTO STRICT expected_recovery_safe_after
          FROM public.accordlock_broker_operations AS deletion_journal
          JOIN public.accordlock_broker_operations AS create_journal
            ON create_journal.tenant = deletion_journal.tenant
           AND create_journal.environment = deletion_journal.environment
           AND create_journal.authorization_id = deletion_journal.authorization_id
           AND create_journal.transaction_id = deletion_journal.transaction_id
           AND create_journal.claim_id = deletion_journal.claim_id
           AND create_journal.fence = deletion_journal.fence
           AND create_journal.state_instance_id = deletion_journal.state_instance_id
           AND create_journal.origin_acquisition_id
                = deletion_journal.origin_acquisition_id
           AND create_journal.operation = 'CREATE_SECRET'
           AND create_journal.phase = 'COMMITTED'
           AND create_journal.outcome = 'CREATE_MATCHING'
           AND create_journal.bound_secret_uid
                = deletion_journal.bound_secret_uid
           AND create_journal.route_commitment
                = deletion_journal.route_commitment
           JOIN public.accordlock_broker_secret_deletion_observations AS deletion
             ON deletion.entry_id = deletion_journal.entry_id
            AND deletion.tenant = deletion_journal.tenant
            AND deletion.environment = deletion_journal.environment
            AND deletion.authorization_id = deletion_journal.authorization_id
            AND deletion.transaction_id = deletion_journal.transaction_id
          JOIN public.accordlock_issued_authorizations AS issued
            ON issued.tenant = deletion_journal.tenant
           AND issued.environment = deletion_journal.environment
           AND issued.authorization_id = deletion_journal.authorization_id
           AND issued.transaction_id = deletion_journal.transaction_id
          JOIN public.accordlock_eks_destination_activations AS activation
            ON activation.tenant = deletion_journal.tenant
           AND activation.environment = deletion_journal.environment
           AND activation.state_instance_id = deletion_journal.state_instance_id
           AND activation.resource_activation_id = (
                   issued.record_json #>>
                       '{signed_authorization,authorization,authority,resource,activation_id}'
               )::UUID
           AND activation.mediation_activation_id = (
                   issued.record_json #>>
                       '{signed_authorization,authorization,authority,mediation,activation_id}'
               )::UUID
           AND activation.route_commitment = deletion_journal.route_commitment
           AND activation.cluster_identity = deletion_journal.cluster_identity
           AND activation.namespace = deletion_journal.namespace
           AND activation.deployment_uid = deletion_journal.deployment_uid
         WHERE deletion_journal.tenant = NEW.tenant
           AND deletion_journal.environment = NEW.environment
           AND deletion_journal.authorization_id = NEW.authorization_id
           AND deletion_journal.transaction_id = NEW.transaction_id
           AND deletion_journal.claim_id = NEW.claim_id
           AND deletion_journal.fence = NEW.fence
           AND deletion_journal.state_instance_id = NEW.state_instance_id
           AND deletion_journal.origin_acquisition_id = latest_acquisition
           AND deletion_journal.operation = 'DELETE_SECRET'
           AND deletion_journal.phase = 'COMMITTED'
           AND deletion_journal.outcome = 'DELETE_ABSENT'
           AND (
               latest_selection_kind = 'CONTROL_QUEUE'
               AND create_journal.acquisition_binding_version = 2
               AND deletion_journal.acquisition_binding_version = 2
               OR latest_selection_kind = 'CONTROL_BOOTSTRAP_V13'
               AND create_journal.acquisition_binding_version = 1
               AND deletion_journal.acquisition_binding_version IN (1, 2)
           );
        IF NEW.recovery_safe_after_unix_s
                IS DISTINCT FROM expected_recovery_safe_after
           OR NEW.recovery_retired_unix_s
                < NEW.recovery_safe_after_unix_s THEN
            RAISE EXCEPTION
                'no-send recovery retired before its rooted safe bound';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_check_dispatch_disposition_claim_state()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    durable_state TEXT;
BEGIN
    IF NEW.claim_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT claim.state
      INTO STRICT durable_state
      FROM public.accordlock_dispatch_claims AS claim
     WHERE claim.tenant = NEW.tenant
       AND claim.environment = NEW.environment
       AND claim.authorization_id = NEW.authorization_id
       AND claim.transaction_id = NEW.transaction_id
       AND claim.claim_id = NEW.claim_id
       AND claim.fence = NEW.claim_fence
       AND claim.state_instance_id = NEW.state_instance_id;
    IF durable_state <> 'DISPOSED' THEN
        RAISE EXCEPTION
            'claim-bound queue disposition must atomically dispose its claim';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_check_disposed_claim_disposition()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.state = 'DISPOSED' AND NOT EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_queue_dispositions AS disposition
         WHERE disposition.tenant = NEW.tenant
           AND disposition.environment = NEW.environment
           AND disposition.authorization_id = NEW.authorization_id
           AND disposition.transaction_id = NEW.transaction_id
           AND disposition.state_instance_id = NEW.state_instance_id
           AND disposition.claim_id = NEW.claim_id
           AND disposition.claim_fence = NEW.fence
    ) THEN
        RAISE EXCEPTION
            'disposed claim lacks its exact durable queue disposition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_queue_disposition_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    bound_kind TEXT;
    replay_name TEXT;
    submission_accepted_at BIGINT;
    ingress_high_water BIGINT;
    scope_high_water BIGINT;
    claim_state TEXT;
    claim_attempt BIGINT;
    latest_acquisition UUID;
    latest_lease_fence BIGINT;
    latest_lease_until BIGINT;
    authorization_record JSONB;
    stored_authorization_commitment TEXT;
    authorization_grant_id UUID;
    authorization_transaction_id UUID;
    authorization_consume_before BIGINT;
    authorization_profile_version SMALLINT;
    authorization_request_id UUID;
    authorization_evaluation_nonce UUID;
    authorization_state TEXT;
    grant_registration JSONB;
    grant_uses BIGINT;
    grant_maximum_uses BIGINT;
    grant_not_before BIGINT;
    grant_expires_at BIGINT;
    grant_revoked BOOLEAN;
    grant_profile_version SMALLINT;
    receipt_json JSONB;
    receipt_consumed_unix_s BIGINT;
    outbox_entry JSONB;
    outbox_status TEXT;
    current_authority JSONB;
    expected_authority JSONB;
    expected_authority_commitment TEXT;
    current_authority_commitment TEXT;
    expected_reason TEXT;
    expected_disposition_commitment TEXT;
    policy_max_delay BIGINT;
    policy_hard_cap BIGINT;
    dependency_count INTEGER;
    dependency_expiry BIGINT;
    previous_dependency BIGINT;
    computed_dispatch_deadline BIGINT;
BEGIN
    SELECT identity.request_kind
      INTO STRICT bound_kind
      FROM public.accordlock_dispatch_request_identities AS identity
     WHERE identity.dispatch_request_id = NEW.dispatch_request_id
       AND identity.worker_id = NEW.worker_id
     FOR UPDATE;
    IF bound_kind <> 'DISPOSITION'
       OR NEW.request_kind <> 'DISPOSITION'
       OR EXISTS (
            SELECT 1 FROM public.accordlock_dispatch_acquisitions
             WHERE acquisition_id = NEW.dispatch_request_id
       ) THEN
        RAISE EXCEPTION 'dispatch request identity is not disposition-bound';
    END IF;

    SELECT submission.replay_scope, submission.accepted_at
      INTO STRICT replay_name, submission_accepted_at
      FROM public.accordlock_control_submissions AS submission
     WHERE submission.submission_id = NEW.control_submission_id
       AND submission.tenant = NEW.tenant
       AND submission.environment = NEW.environment
       AND submission.state_instance_id = NEW.state_instance_id
     FOR UPDATE;

    IF NEW.claim_id IS NULL AND EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_acquisitions AS acquisition
         WHERE acquisition.control_submission_id = NEW.control_submission_id
    ) THEN
        RAISE EXCEPTION
            'dispatch disposition races another acquisition generation';
    END IF;

    SELECT authority.authority_json
      INTO STRICT current_authority
      FROM public.accordlock_authority_state AS authority
     WHERE authority.tenant = NEW.tenant
       AND authority.environment = NEW.environment
     FOR SHARE;

    SELECT ingress.observed_unix_s
      INTO STRICT ingress_high_water
      FROM public.accordlock_ingress_replay_scopes AS ingress
     WHERE ingress.replay_scope = replay_name
       AND ingress.state_instance_id = NEW.state_instance_id
     FOR UPDATE;
    SELECT scope.observed_unix_s
      INTO STRICT scope_high_water
      FROM public.accordlock_time_high_water AS scope
     WHERE scope.tenant = NEW.tenant
       AND scope.environment = NEW.environment
     FOR UPDATE;
    IF ingress_high_water IS DISTINCT FROM NEW.observed_unix_s
       OR scope_high_water IS DISTINCT FROM NEW.observed_unix_s
       OR NEW.observed_unix_s >
          floor(extract(epoch FROM clock_timestamp()))::bigint THEN
        RAISE EXCEPTION
            'dispatch disposition is not covered by both trusted-time HWMs';
    END IF;

    SELECT issued.record_json, issued.authorization_hash, issued.grant_id,
           issued.transaction_id, issued.consume_before,
           issued.issuance_profile_version, issued.request_id,
           issued.evaluation_nonce, issued.state
      INTO STRICT authorization_record, stored_authorization_commitment,
          authorization_grant_id, authorization_transaction_id, authorization_consume_before,
          authorization_profile_version, authorization_request_id,
          authorization_evaluation_nonce, authorization_state
      FROM public.accordlock_issued_authorizations AS issued
     WHERE issued.tenant = NEW.tenant
       AND issued.environment = NEW.environment
       AND issued.authorization_id = NEW.authorization_id
       AND issued.transaction_id = NEW.transaction_id
     FOR UPDATE;

    SELECT grant_row.registration_json, grant_row.uses,
           grant_row.maximum_uses, grant_row.not_before,
           grant_row.expires_at, grant_row.revoked,
           grant_row.issuance_profile_version
      INTO STRICT grant_registration, grant_uses, grant_maximum_uses,
          grant_not_before, grant_expires_at, grant_revoked,
          grant_profile_version
      FROM public.accordlock_grants AS grant_row
     WHERE grant_row.tenant = NEW.tenant
       AND grant_row.environment = NEW.environment
       AND grant_row.grant_id = authorization_grant_id
     FOR UPDATE;

    SELECT consumption.receipt_json, consumption.consumed_unix_s
      INTO STRICT receipt_json, receipt_consumed_unix_s
      FROM public.accordlock_consumptions AS consumption
     WHERE consumption.tenant = NEW.tenant
       AND consumption.environment = NEW.environment
       AND consumption.authorization_id = NEW.authorization_id
       AND consumption.transaction_id = NEW.transaction_id
       AND consumption.dispatch_deadline = NEW.dispatch_deadline
     FOR UPDATE;

    SELECT outbox.entry_json, outbox.status
      INTO STRICT outbox_entry, outbox_status
      FROM public.accordlock_execution_outbox AS outbox
     WHERE outbox.tenant = NEW.tenant
       AND outbox.environment = NEW.environment
       AND outbox.authorization_id = NEW.authorization_id
       AND outbox.transaction_id = NEW.transaction_id
       AND outbox.dispatch_deadline = NEW.dispatch_deadline
     FOR UPDATE;

    expected_authority := authorization_record #> '{signed_authorization,authorization,authority}';
    expected_authority_commitment :=
        public.accordlock_dispatch_authority_fact_commitment(expected_authority);
    current_authority_commitment :=
        public.accordlock_dispatch_authority_fact_commitment(current_authority);

    IF jsonb_typeof(
           authorization_record #> '{signed_authorization,authorization,dispatch_deadline_policy}'
       ) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
           authorization_record #>
               '{signed_authorization,authorization,dispatch_deadline_policy,immutable_dependency_expiries}'
       ) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'dispatch authorization deadline policy is malformed';
    END IF;
    policy_max_delay := (
        authorization_record #>>
            '{signed_authorization,authorization,dispatch_deadline_policy,max_dispatch_delay_seconds}'
    )::bigint;
    policy_hard_cap := (
        authorization_record #>>
            '{signed_authorization,authorization,dispatch_deadline_policy,profile_hard_cap}'
    )::bigint;
    dependency_count := jsonb_array_length(
        authorization_record #>
            '{signed_authorization,authorization,dispatch_deadline_policy,immutable_dependency_expiries}'
    );
    IF policy_max_delay IS NULL OR policy_max_delay <= 0
       OR policy_hard_cap IS NULL OR policy_hard_cap < 0
       OR policy_hard_cap <= grant_not_before
       OR dependency_count > 64 THEN
        RAISE EXCEPTION 'dispatch authorization deadline policy is invalid';
    END IF;
    computed_dispatch_deadline := LEAST(
        receipt_consumed_unix_s + policy_max_delay,
        authorization_consume_before,
        policy_hard_cap
    );
    previous_dependency := NULL;
    FOR dependency_expiry IN
        SELECT dependency.value::text::bigint
          FROM jsonb_array_elements(
                   authorization_record #>
                       '{signed_authorization,authorization,dispatch_deadline_policy,immutable_dependency_expiries}'
               ) WITH ORDINALITY AS dependency(value, position)
         ORDER BY dependency.position
    LOOP
        IF dependency_expiry < 0
           OR dependency_expiry <= receipt_consumed_unix_s
           OR dependency_expiry <= grant_not_before
           OR (previous_dependency IS NOT NULL
               AND dependency_expiry <= previous_dependency) THEN
            RAISE EXCEPTION 'dispatch authorization dependency expiries are invalid';
        END IF;
        computed_dispatch_deadline := LEAST(
            computed_dispatch_deadline, dependency_expiry
        );
        previous_dependency := dependency_expiry;
    END LOOP;

    IF authorization_state IS DISTINCT FROM 'CONSUMED'
       OR authorization_profile_version IS DISTINCT FROM 2
       OR grant_profile_version IS DISTINCT FROM 2
       OR outbox_status IS DISTINCT FROM 'PENDING_WITNESS'
       OR grant_uses <= 0
       OR grant_uses > grant_maximum_uses
       OR grant_maximum_uses <= 0
       OR grant_maximum_uses > 4294967295
       OR grant_not_before < 0
       OR grant_expires_at <= grant_not_before
       OR grant_registration #>> '{grant,tenant}'
          IS DISTINCT FROM NEW.tenant
       OR grant_registration #>> '{environment}'
          IS DISTINCT FROM NEW.environment
       OR grant_registration #>> '{grant,grant_id}'
          IS DISTINCT FROM authorization_grant_id::text
       OR grant_registration #>> '{grant,maximum_uses}'
          IS DISTINCT FROM grant_maximum_uses::text
       OR grant_registration #>> '{grant,not_before}'
          IS DISTINCT FROM grant_not_before::text
       OR grant_registration #>> '{grant,expires_at}'
          IS DISTINCT FROM grant_expires_at::text
       OR grant_registration #>> '{grant,holder}' IS NULL
       OR grant_registration #>> '{grant,operation}' IS NULL
       OR grant_registration #>> '{grant,repository}' IS NULL
       OR grant_registration #>> '{grant,audience}' IS NULL
       OR grant_registration #>> '{grant,cluster_identity}' IS NULL
       OR grant_registration #>> '{grant,namespace}' IS NULL
       OR grant_registration #>> '{grant,deployment_uid}' IS NULL
       OR grant_registration #>> '{grant,container}' IS NULL
       OR grant_registration #>> '{grant,image_repository}' IS NULL
       OR btrim(grant_registration #>> '{grant,holder}') = ''
       OR btrim(grant_registration #>> '{grant,operation}') = ''
       OR btrim(grant_registration #>> '{grant,repository}') = ''
       OR btrim(grant_registration #>> '{grant,audience}') = ''
       OR btrim(grant_registration #>> '{grant,cluster_identity}') = ''
       OR btrim(grant_registration #>> '{grant,namespace}') = ''
       OR btrim(grant_registration #>> '{grant,deployment_uid}') = ''
       OR btrim(grant_registration #>> '{grant,container}') = ''
       OR btrim(grant_registration #>> '{grant,image_repository}') = ''
       OR grant_registration #> '{authority}'
          IS DISTINCT FROM expected_authority
       OR grant_registration #> '{dispatch_deadline_policy}'
          IS DISTINCT FROM authorization_record #>
              '{signed_authorization,authorization,dispatch_deadline_policy}'
       OR grant_registration #>> '{grant,holder}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,holder}'
       OR grant_registration #>> '{grant,operation}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,template,operation}'
       OR grant_registration #>> '{grant,repository}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,template,repository}'
       OR grant_registration #>> '{grant,audience}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,audience}'
       OR grant_registration #>> '{grant,cluster_identity}'
          IS DISTINCT FROM authorization_record #>>
              '{signed_authorization,authorization,template,cluster_identity}'
       OR grant_registration #>> '{grant,namespace}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,template,namespace}'
       OR grant_registration #>> '{grant,deployment_uid}'
          IS DISTINCT FROM authorization_record #>>
              '{signed_authorization,authorization,template,deployment_uid}'
       OR grant_registration #>> '{grant,container}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,template,container}'
       OR grant_registration #>> '{grant,image_repository}'
          IS DISTINCT FROM authorization_record #>>
              '{signed_authorization,authorization,template,image_repository}'
       OR authorization_record #>> '{signed_authorization,authorization,grant_id}'
          IS DISTINCT FROM authorization_grant_id::text
       OR authorization_record #>> '{signed_authorization,authorization,tenant}'
          IS DISTINCT FROM NEW.tenant
       OR authorization_record #>> '{signed_authorization,authorization,template,environment}'
          IS DISTINCT FROM NEW.environment
       OR authorization_record #>> '{signed_authorization,authorization,authorization_id}'
          IS DISTINCT FROM NEW.authorization_id::text
       OR authorization_record #>> '{transaction_id}'
          IS DISTINCT FROM authorization_transaction_id::text
       OR authorization_transaction_id IS DISTINCT FROM NEW.transaction_id
       OR authorization_record #>> '{authorization_hash}'
          IS DISTINCT FROM stored_authorization_commitment
       OR authorization_record #>> '{signed_authorization,authorization,consume_before}'
          IS DISTINCT FROM authorization_consume_before::text
       OR authorization_record #>> '{signed_authorization,authorization,schema_version}'
          IS DISTINCT FROM '2'
       OR authorization_record #>> '{signed_authorization,authorization,issued_at}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,not_before}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,consume_before}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,request_id}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,evaluation_nonce}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,request_id}'
          IS DISTINCT FROM authorization_request_id::text
       OR authorization_record #>> '{signed_authorization,authorization,evaluation_nonce}'
          IS DISTINCT FROM authorization_evaluation_nonce::text
       OR authorization_request_id IS NULL OR authorization_request_id =
          '00000000-0000-0000-0000-000000000000'::uuid
       OR authorization_evaluation_nonce IS NULL OR authorization_evaluation_nonce =
          '00000000-0000-0000-0000-000000000000'::uuid
       OR authorization_grant_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR NEW.authorization_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR NEW.transaction_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR authorization_record #>> '{signed_authorization,authorization,policy_root}'
          IS DISTINCT FROM expected_authority #>> '{policy,root}'
       OR authorization_record #>> '{signed_authorization,authorization,template_hash}' IS NULL
       OR authorization_record #>> '{signed_authorization,authorization,evidence_root}' IS NULL
       OR authorization_record #>> '{signer_key_id}' IS NULL
       OR authorization_record #> '{signer_public_key}' IS NULL
       OR authorization_record #>> '{signed_authorization,cose_sign1}' IS NULL
       OR authorization_record #>> '{signed_authorization,cose_sign1}' = ''
       OR authorization_record #>> '{signer_key_id}' IS NULL
       OR btrim(authorization_record #>> '{signer_key_id}') = ''
       OR authorization_record #>> '{signed_authorization,authorization,tenant}' = ''
       OR authorization_record #>> '{signed_authorization,authorization,holder}' = ''
       OR authorization_record #>> '{signed_authorization,authorization,audience}' = ''
       OR authorization_record #>> '{signed_authorization,authorization,template,environment}' = ''
       OR authorization_record #>> '{signed_authorization,authorization,audience}'
          IS DISTINCT FROM authorization_record #>>
              '{signed_authorization,authorization,template,audience}'
       OR (authorization_record #>> '{signed_authorization,authorization,issued_at}')::bigint
          < grant_not_before
       OR (authorization_record #>> '{signed_authorization,authorization,issued_at}')::bigint
          >= grant_expires_at
       OR (authorization_record #>> '{signed_authorization,authorization,not_before}')::bigint
          < grant_not_before
       OR (authorization_record #>> '{signed_authorization,authorization,not_before}')::bigint
          < (authorization_record #>> '{signed_authorization,authorization,issued_at}')::bigint
       OR (authorization_record #>> '{signed_authorization,authorization,consume_before}')::bigint
          <= (authorization_record #>> '{signed_authorization,authorization,not_before}')::bigint
       OR (authorization_record #>> '{signed_authorization,authorization,consume_before}')::bigint
          > grant_expires_at
       OR receipt_json #>> '{schema_version}'
          IS DISTINCT FROM authorization_record #>> '{signed_authorization,authorization,schema_version}'
       OR receipt_json #>> '{transaction_id}'
          IS DISTINCT FROM NEW.transaction_id::text
       OR receipt_json #>> '{authorization_id}' IS DISTINCT FROM NEW.authorization_id::text
       OR receipt_json #> '{authority}' IS DISTINCT FROM expected_authority
       OR receipt_json #>> '{authorization_hash}'
          IS DISTINCT FROM stored_authorization_commitment
       OR receipt_json #>> '{dispatch_deadline}'
          IS DISTINCT FROM NEW.dispatch_deadline::text
       OR computed_dispatch_deadline IS DISTINCT FROM NEW.dispatch_deadline
       OR computed_dispatch_deadline <= receipt_consumed_unix_s
       OR receipt_json #>> '{consumed_at}' IS NULL
       OR receipt_json #>> '{consumed_at}'
          IS DISTINCT FROM receipt_consumed_unix_s::text
       OR receipt_consumed_unix_s > NEW.observed_unix_s
       OR submission_accepted_at > NEW.observed_unix_s
       OR (receipt_json #>> '{consumed_at}')::bigint
          < (authorization_record #>> '{signed_authorization,authorization,not_before}')::bigint
       OR (receipt_json #>> '{consumed_at}')::bigint
          >= (authorization_record #>> '{signed_authorization,authorization,consume_before}')::bigint
       OR outbox_entry #>> '{scope,tenant}' IS DISTINCT FROM NEW.tenant
       OR outbox_entry #>> '{scope,environment}' IS DISTINCT FROM NEW.environment
       OR outbox_entry #>> '{authorization_id}' IS DISTINCT FROM NEW.authorization_id::text
       OR outbox_entry #>> '{transaction_id}'
          IS DISTINCT FROM NEW.transaction_id::text
       OR outbox_entry #>> '{dispatch_deadline}'
          IS DISTINCT FROM NEW.dispatch_deadline::text
       OR outbox_entry #>> '{status}' IS DISTINCT FROM 'PENDING_WITNESS'
       OR outbox_entry #> '{receipt}' IS DISTINCT FROM receipt_json
       OR NEW.authorization_commitment IS DISTINCT FROM stored_authorization_commitment
       OR NEW.grant_commitment IS DISTINCT FROM
          public.accordlock_dispatch_grant_fact_commitment(
              grant_registration, grant_uses, grant_maximum_uses,
              grant_not_before, grant_expires_at, grant_revoked
          )
       OR NEW.outbox_commitment IS DISTINCT FROM
          public.accordlock_dispatch_outbox_fact_commitment(outbox_entry)
       OR NEW.expected_authority_commitment IS DISTINCT FROM
          expected_authority_commitment
       OR NEW.current_authority_commitment IS DISTINCT FROM
          current_authority_commitment THEN
        RAISE EXCEPTION
            'dispatch disposition source facts or commitments differ';
    END IF;

    expected_reason := CASE
        WHEN NEW.observed_unix_s >= NEW.dispatch_deadline
            THEN 'DISPATCH_DEADLINE_EXPIRED'
        WHEN current_authority IS DISTINCT FROM expected_authority
            THEN 'AUTHORITY_CHANGED'
        WHEN grant_revoked THEN 'GRANT_REVOKED'
        ELSE NULL
    END;
    IF expected_reason IS NULL OR NEW.reason IS DISTINCT FROM expected_reason THEN
        RAISE EXCEPTION 'dispatch disposition reason differs from source facts';
    END IF;

    IF NEW.claim_id IS NULL THEN
        IF EXISTS (
            SELECT 1 FROM public.accordlock_dispatch_claims AS claim
             WHERE claim.tenant = NEW.tenant
               AND claim.environment = NEW.environment
               AND claim.authorization_id = NEW.authorization_id
               AND claim.transaction_id = NEW.transaction_id
        ) THEN
            RAISE EXCEPTION 'unclaimed disposition races a stable claim';
        END IF;
    ELSE
        SELECT claim.state, claim.attempt_started_at
          INTO STRICT claim_state, claim_attempt
          FROM public.accordlock_dispatch_claims AS claim
         WHERE claim.tenant = NEW.tenant
           AND claim.environment = NEW.environment
           AND claim.authorization_id = NEW.authorization_id
           AND claim.transaction_id = NEW.transaction_id
           AND claim.claim_id = NEW.claim_id
           AND claim.fence = NEW.claim_fence
           AND claim.state_instance_id = NEW.state_instance_id
         FOR UPDATE;
        IF claim_state <> 'CLAIMED' OR claim_attempt IS NOT NULL THEN
            RAISE EXCEPTION 'dispatch disposition claim is already productive';
        END IF;
        SELECT acquisition_id, lease_fence, lease_until
          INTO STRICT latest_acquisition, latest_lease_fence,
              latest_lease_until
          FROM public.accordlock_dispatch_acquisitions
         WHERE tenant = NEW.tenant
           AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND claim_fence = NEW.claim_fence
           AND state_instance_id = NEW.state_instance_id
         ORDER BY lease_fence DESC
         LIMIT 1
         FOR UPDATE;
        IF latest_acquisition <> NEW.acquisition_id
           OR latest_lease_fence <> NEW.lease_fence
           OR latest_lease_until > NEW.observed_unix_s THEN
            RAISE EXCEPTION
                'dispatch disposition is not bound to latest expired acquisition';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.accordlock_broker_operations
         WHERE tenant = NEW.tenant AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
    ) OR EXISTS (
        SELECT 1 FROM public.accordlock_admission_authorizations
         WHERE tenant = NEW.tenant AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
    ) OR EXISTS (
        SELECT 1 FROM public.accordlock_terminal_retirements
         WHERE tenant = NEW.tenant AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
    ) OR EXISTS (
        SELECT 1 FROM public.accordlock_dispatch_credential_reviews
         WHERE tenant = NEW.tenant AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION 'dispatch disposition is barred by durable artifacts';
    END IF;

    expected_disposition_commitment :=
        public.accordlock_dispatch_frame_commitment(
            'ACCORDLOCK_DISPATCH_QUEUE_DISPOSITION_V1',
            ARRAY[
                NEW.dispatch_request_id::text, NEW.worker_id,
                NEW.control_submission_id::text, NEW.tenant,
                NEW.environment, NEW.authorization_id::text, NEW.transaction_id::text,
                NEW.state_instance_id::text,
                COALESCE(NEW.claim_id::text, 'NONE'),
                COALESCE(NEW.claim_fence::text, 'NONE'),
                COALESCE(NEW.acquisition_id::text, 'NONE'),
                COALESCE(NEW.lease_fence::text, 'NONE'),
                NEW.reason, NEW.observed_unix_s::text,
                NEW.dispatch_deadline::text, NEW.authorization_commitment,
                NEW.grant_commitment, NEW.outbox_commitment,
                NEW.expected_authority_commitment,
                NEW.current_authority_commitment
            ]
        );
    IF NEW.disposition_commitment <> expected_disposition_commitment THEN
        RAISE EXCEPTION 'dispatch disposition commitment differs';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_broker_acquisition_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    acquisition_lease_until BIGINT;
    acquisition_acquired BIGINT;
    latest_acquisition UUID;
    latest_lease_fence BIGINT;
    attempt_acquisition UUID;
    attempt_lease_fence BIGINT;
    create_acquisition UUID;
    create_lease_fence BIGINT;
    control_submission UUID;
BEGIN
    IF NEW.acquisition_binding_version <> 2 THEN
        RAISE EXCEPTION
            'new broker journal rows require acquisition binding profile v2';
    END IF;

    -- Control-owned productive writers serialize at the immutable submission
    -- root before the stable claim. Legacy rows have no control root.
    SELECT control_submission_id
      INTO STRICT control_submission
      FROM public.accordlock_dispatch_acquisitions
     WHERE acquisition_id = NEW.origin_acquisition_id
       AND tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND claim_fence = NEW.fence
       AND state_instance_id = NEW.state_instance_id
       AND lease_fence = NEW.origin_lease_fence;
    IF control_submission IS NOT NULL THEN
        PERFORM 1
          FROM public.accordlock_control_submissions
         WHERE submission_id = control_submission
         FOR UPDATE;
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_dispatch_queue_dispositions
             WHERE control_submission_id = control_submission
        ) THEN
            RAISE EXCEPTION
                'broker journal follows a durable queue disposition';
        END IF;
    END IF;

    SELECT claim.attempt_acquisition_id, claim.attempt_lease_fence
      INTO STRICT attempt_acquisition, attempt_lease_fence
      FROM public.accordlock_dispatch_claims AS claim
     WHERE claim.tenant = NEW.tenant
       AND claim.environment = NEW.environment
       AND claim.authorization_id = NEW.authorization_id
       AND claim.transaction_id = NEW.transaction_id
       AND claim.claim_id = NEW.claim_id
       AND claim.fence = NEW.fence
       AND claim.state_instance_id = NEW.state_instance_id
     FOR UPDATE;

    SELECT acquired_unix_s, lease_until
      INTO STRICT acquisition_acquired, acquisition_lease_until
      FROM public.accordlock_dispatch_acquisitions
     WHERE acquisition_id = NEW.origin_acquisition_id
       AND tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND claim_fence = NEW.fence
       AND state_instance_id = NEW.state_instance_id
       AND lease_fence = NEW.origin_lease_fence
     FOR SHARE;

    IF NEW.operation = 'DELETE_SECRET' THEN
        SELECT origin_acquisition_id, origin_lease_fence
          INTO STRICT create_acquisition, create_lease_fence
          FROM public.accordlock_broker_operations
         WHERE tenant = NEW.tenant
           AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND fence = NEW.fence
           AND operation = 'CREATE_SECRET'
           AND phase = 'COMMITTED'
           AND outcome = 'CREATE_MATCHING'
         FOR SHARE;
        IF create_acquisition <> NEW.origin_acquisition_id
           OR create_lease_fence <> NEW.origin_lease_fence
           OR attempt_acquisition IS NOT NULL
              AND (
                   attempt_acquisition <> NEW.origin_acquisition_id
                   OR attempt_lease_fence <> NEW.origin_lease_fence
              ) THEN
            RAISE EXCEPTION
                'cleanup journal is not bound to its create/attempt acquisition';
        END IF;
    ELSE
        SELECT acquisition_id, lease_fence
          INTO STRICT latest_acquisition, latest_lease_fence
          FROM public.accordlock_dispatch_acquisitions
         WHERE tenant = NEW.tenant AND environment = NEW.environment
           AND authorization_id = NEW.authorization_id
           AND transaction_id = NEW.transaction_id
           AND claim_id = NEW.claim_id
           AND claim_fence = NEW.fence
           AND state_instance_id = NEW.state_instance_id
         ORDER BY lease_fence DESC
         LIMIT 1
         FOR SHARE;
        IF latest_acquisition <> NEW.origin_acquisition_id
           OR latest_lease_fence <> NEW.origin_lease_fence
           OR NEW.prepared_unix_s < acquisition_acquired
           OR NEW.prepared_unix_s >= acquisition_lease_until THEN
            RAISE EXCEPTION
                'broker journal is not bound to the latest live acquisition';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_admission_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    control_submission UUID;
BEGIN
    SELECT consumption.submission_id
      INTO control_submission
      FROM public.accordlock_control_consumptions AS consumption
     WHERE consumption.tenant = NEW.tenant
       AND consumption.environment = NEW.environment
       AND consumption.authorization_id = NEW.authorization_id
       AND consumption.transaction_id = NEW.transaction_id;
    IF control_submission IS NOT NULL THEN
        PERFORM 1
          FROM public.accordlock_control_submissions
         WHERE submission_id = control_submission
         FOR UPDATE;
    END IF;
    PERFORM 1
      FROM public.accordlock_dispatch_claims
     WHERE tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND fence = NEW.fence
     FOR UPDATE;
    IF EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_queue_dispositions AS disposition
         WHERE disposition.tenant = NEW.tenant
           AND disposition.environment = NEW.environment
           AND disposition.authorization_id = NEW.authorization_id
           AND disposition.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION
            'admission authorization follows a durable queue disposition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_terminal_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    control_submission UUID;
BEGIN
    SELECT consumption.submission_id
      INTO control_submission
      FROM public.accordlock_control_consumptions AS consumption
     WHERE consumption.tenant = NEW.tenant
       AND consumption.environment = NEW.environment
       AND consumption.authorization_id = NEW.authorization_id
       AND consumption.transaction_id = NEW.transaction_id;
    IF control_submission IS NOT NULL THEN
        PERFORM 1
          FROM public.accordlock_control_submissions
         WHERE submission_id = control_submission
         FOR UPDATE;
    END IF;
    PERFORM 1
      FROM public.accordlock_dispatch_claims
     WHERE tenant = NEW.tenant
       AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id
       AND transaction_id = NEW.transaction_id
       AND claim_id = NEW.claim_id
       AND fence = NEW.fence
     FOR UPDATE;
    IF EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_queue_dispositions AS disposition
         WHERE disposition.tenant = NEW.tenant
           AND disposition.environment = NEW.environment
           AND disposition.authorization_id = NEW.authorization_id
           AND disposition.transaction_id = NEW.transaction_id
    ) THEN
        RAISE EXCEPTION
            'terminal history follows a durable queue disposition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_broker_acquisition_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    acquisition_kind TEXT;
    acquisition_control UUID;
BEGIN
    -- Freeze the request and lineage material.  Only the journal FSM facts
    -- listed below may evolve after INSERT.
    IF (
        to_jsonb(NEW) - ARRAY[
            'phase', 'bound_secret_uid', 'started_unix_s',
            'credential_safe_after', 'reconciliation_count',
            'last_reconciliation_outcome',
            'last_reconciliation_evidence_commitment',
            'last_reconciled_unix_s', 'outcome',
            'provider_evidence_commitment', 'token_digest',
            'token_expires_at', 'result_commitment',
            'deletion_observation_floor_unix_s', 'updated_at'
        ]::TEXT[]
    ) IS DISTINCT FROM (
        to_jsonb(OLD) - ARRAY[
            'phase', 'bound_secret_uid', 'started_unix_s',
            'credential_safe_after', 'reconciliation_count',
            'last_reconciliation_outcome',
            'last_reconciliation_evidence_commitment',
            'last_reconciled_unix_s', 'outcome',
            'provider_evidence_commitment', 'token_digest',
            'token_expires_at', 'result_commitment',
            'deletion_observation_floor_unix_s', 'updated_at'
        ]::TEXT[]
    ) THEN
        RAISE EXCEPTION 'broker request and acquisition lineage are immutable';
    END IF;

    -- An exact no-op (apart from the diagnostic updated_at column) is safe.
    IF (
        to_jsonb(NEW) - 'updated_at'
    ) IS NOT DISTINCT FROM (
        to_jsonb(OLD) - 'updated_at'
    ) THEN
        RETURN NEW;
    END IF;

    -- A v1 broker row can only be a deterministic pre-v14 bootstrap.  Load
    -- that immutable discriminator once for every transition so a
    -- CONTROL_BOOTSTRAP_V13 row cannot launder productive I/O through
    -- UNKNOWN/RECONCILE_ONLY.  Exact historical DELETE cleanup remains
    -- available for CONTROL_BOOTSTRAP_V13, and strict LEGACY_BOOTSTRAP stays
    -- compatible; no v1 CONTROL_QUEUE row is admissible.
    IF OLD.acquisition_binding_version = 1 THEN
        SELECT selection_kind, control_submission_id
          INTO STRICT acquisition_kind, acquisition_control
          FROM public.accordlock_dispatch_acquisitions
         WHERE acquisition_id = OLD.origin_acquisition_id
         FOR SHARE;
        IF NOT (
            (acquisition_kind = 'LEGACY_BOOTSTRAP'
             AND acquisition_control IS NULL)
            OR
            (acquisition_kind = 'CONTROL_BOOTSTRAP_V13'
             AND acquisition_control IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'invalid v1 broker acquisition profile';
        END IF;
    END IF;

    IF OLD.phase = 'INTENT' AND NEW.phase = 'IN_FLIGHT' THEN
        IF OLD.operation <> 'DELETE_SECRET'
           AND OLD.acquisition_binding_version = 1
           AND acquisition_kind = 'CONTROL_BOOTSTRAP_V13' THEN
            RAISE EXCEPTION
                'pre-v14 control broker intent cannot cross productive I/O';
        END IF;
        IF OLD.started_unix_s IS NOT NULL
           OR NEW.started_unix_s IS NULL
           OR NEW.bound_secret_uid IS DISTINCT FROM OLD.bound_secret_uid
           OR NEW.reconciliation_count IS DISTINCT FROM OLD.reconciliation_count
           OR NEW.last_reconciliation_outcome IS DISTINCT FROM OLD.last_reconciliation_outcome
           OR NEW.last_reconciliation_evidence_commitment IS DISTINCT FROM OLD.last_reconciliation_evidence_commitment
           OR NEW.last_reconciled_unix_s IS DISTINCT FROM OLD.last_reconciled_unix_s
           OR NEW.outcome IS DISTINCT FROM OLD.outcome
           OR NEW.provider_evidence_commitment IS DISTINCT FROM OLD.provider_evidence_commitment
           OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
           OR NEW.token_expires_at IS DISTINCT FROM OLD.token_expires_at
           OR NEW.result_commitment IS DISTINCT FROM OLD.result_commitment THEN
            RAISE EXCEPTION 'invalid broker INTENT to IN_FLIGHT transition';
        END IF;
        RETURN NEW;
    END IF;

    -- A crash after durable CREATE INTENT but before mutation authority is
    -- recoverable only through a GET.  Starting reconciliation records the
    -- trusted GET boundary; it never authorizes the original mutation and is
    -- deliberately unavailable to ISSUE_TOKEN or DELETE_SECRET intents.
    IF OLD.phase = 'INTENT' AND NEW.phase = 'RECONCILE_ONLY' THEN
        IF OLD.operation <> 'CREATE_SECRET'
           OR OLD.started_unix_s IS NOT NULL
           OR NEW.started_unix_s IS NULL
           OR NEW.started_unix_s < OLD.prepared_unix_s
           OR NEW.bound_secret_uid IS DISTINCT FROM OLD.bound_secret_uid
           OR NEW.credential_safe_after IS DISTINCT FROM OLD.credential_safe_after
           OR NEW.reconciliation_count IS DISTINCT FROM OLD.reconciliation_count
           OR NEW.last_reconciliation_outcome IS DISTINCT FROM OLD.last_reconciliation_outcome
           OR NEW.last_reconciliation_evidence_commitment IS DISTINCT FROM OLD.last_reconciliation_evidence_commitment
           OR NEW.last_reconciled_unix_s IS DISTINCT FROM OLD.last_reconciled_unix_s
           OR NEW.outcome IS DISTINCT FROM OLD.outcome
           OR NEW.provider_evidence_commitment IS DISTINCT FROM OLD.provider_evidence_commitment
           OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
           OR NEW.token_expires_at IS DISTINCT FROM OLD.token_expires_at
           OR NEW.result_commitment IS DISTINCT FROM OLD.result_commitment THEN
            RAISE EXCEPTION 'invalid broker INTENT to reconciliation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.phase = 'IN_FLIGHT'
       AND NEW.phase IN ('UNKNOWN', 'RECONCILE_ONLY')
       OR OLD.phase = 'UNKNOWN' AND NEW.phase = 'RECONCILE_ONLY' THEN
        IF NEW.bound_secret_uid IS DISTINCT FROM OLD.bound_secret_uid
           OR NEW.started_unix_s IS DISTINCT FROM OLD.started_unix_s
           OR NEW.credential_safe_after IS DISTINCT FROM OLD.credential_safe_after
           OR NEW.reconciliation_count IS DISTINCT FROM OLD.reconciliation_count
           OR NEW.last_reconciliation_outcome IS DISTINCT FROM OLD.last_reconciliation_outcome
           OR NEW.last_reconciliation_evidence_commitment IS DISTINCT FROM OLD.last_reconciliation_evidence_commitment
           OR NEW.last_reconciled_unix_s IS DISTINCT FROM OLD.last_reconciled_unix_s
           OR NEW.outcome IS DISTINCT FROM OLD.outcome
           OR NEW.provider_evidence_commitment IS DISTINCT FROM OLD.provider_evidence_commitment
           OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
           OR NEW.token_expires_at IS DISTINCT FROM OLD.token_expires_at
           OR NEW.result_commitment IS DISTINCT FROM OLD.result_commitment THEN
            RAISE EXCEPTION 'invalid broker uncertainty transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.phase = 'RECONCILE_ONLY' AND NEW.phase = 'RECONCILE_ONLY' THEN
        IF NEW.reconciliation_count IS DISTINCT FROM OLD.reconciliation_count + 1
           OR NEW.last_reconciliation_outcome IS NULL
           OR NEW.last_reconciliation_evidence_commitment IS NULL
           OR NEW.last_reconciled_unix_s IS NULL
           OR NEW.bound_secret_uid IS DISTINCT FROM OLD.bound_secret_uid
           OR NEW.started_unix_s IS DISTINCT FROM OLD.started_unix_s
           OR NEW.credential_safe_after IS DISTINCT FROM OLD.credential_safe_after
           OR NEW.outcome IS DISTINCT FROM OLD.outcome
           OR NEW.provider_evidence_commitment IS DISTINCT FROM OLD.provider_evidence_commitment
           OR NEW.token_digest IS DISTINCT FROM OLD.token_digest
           OR NEW.token_expires_at IS DISTINCT FROM OLD.token_expires_at
           OR NEW.result_commitment IS DISTINCT FROM OLD.result_commitment THEN
            RAISE EXCEPTION 'invalid broker reconciliation transition';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.phase IN ('IN_FLIGHT', 'RECONCILE_ONLY')
       AND NEW.phase IN ('COMMITTED', 'TERMINAL') THEN
        IF OLD.operation <> 'DELETE_SECRET'
           AND OLD.acquisition_binding_version = 1
           AND acquisition_kind = 'CONTROL_BOOTSTRAP_V13'
           AND NEW.phase = 'COMMITTED'
           AND (OLD.phase = 'IN_FLIGHT'
                OR OLD.operation = 'ISSUE_TOKEN') THEN
            -- CREATE may be proven matching by a frozen GET after entering
            -- RECONCILE_ONLY.  ISSUE_TOKEN has no corresponding safe
            -- historical adoption: it can never become productively
            -- COMMITTED under the v1 control bootstrap profile.
            RAISE EXCEPTION
                'pre-v14 control broker I/O cannot commit productively';
        END IF;
        IF NEW.started_unix_s IS DISTINCT FROM OLD.started_unix_s
           OR NEW.credential_safe_after IS DISTINCT FROM OLD.credential_safe_after
           OR NEW.reconciliation_count IS DISTINCT FROM OLD.reconciliation_count
           OR NEW.last_reconciliation_outcome IS DISTINCT FROM OLD.last_reconciliation_outcome
           OR NEW.last_reconciliation_evidence_commitment IS DISTINCT FROM OLD.last_reconciliation_evidence_commitment
           OR NEW.last_reconciled_unix_s IS DISTINCT FROM OLD.last_reconciled_unix_s THEN
            RAISE EXCEPTION 'invalid broker terminal transition';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'broker operation phase transition is non-monotone';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_reject_broker_operation_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    -- Cleanup/reconciliation is itself an append-only DELETE operation row.
    -- Removing journal history could erase an external-I/O barrier and make a
    -- later dispatch acquisition look safe to recover or take over.
    RAISE EXCEPTION 'broker operation history is append-only';
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_credential_review_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    acquisition_row RECORD;
    create_row RECORD;
    token_row RECORD;
BEGIN
    -- The control submission is the serialization root shared by acquisition,
    -- disposition, broker, review, admission, and terminal mutations.
    PERFORM 1
      FROM public.accordlock_control_submissions AS submission
     WHERE submission.submission_id = NEW.control_submission_id
       AND submission.tenant = NEW.tenant
       AND submission.environment = NEW.environment
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'credential review has no exact control root';
    END IF;

    SELECT acquisition.tenant, acquisition.environment, acquisition.authorization_id,
           acquisition.transaction_id, acquisition.control_submission_id,
           acquisition.selection_kind, acquisition.claim_id,
           acquisition.claim_fence, acquisition.state_instance_id,
           acquisition.lease_fence, acquisition.acquired_unix_s,
           acquisition.lease_until, acquisition.dispatch_deadline,
           claim.state AS claim_state
      INTO STRICT acquisition_row
      FROM public.accordlock_dispatch_acquisitions AS acquisition
      JOIN public.accordlock_dispatch_claims AS claim
        ON claim.tenant = acquisition.tenant
       AND claim.environment = acquisition.environment
       AND claim.authorization_id = acquisition.authorization_id
       AND claim.transaction_id = acquisition.transaction_id
       AND claim.claim_id = acquisition.claim_id
       AND claim.fence = acquisition.claim_fence
       AND claim.state_instance_id = acquisition.state_instance_id
     WHERE acquisition.acquisition_id = NEW.acquisition_id
     FOR SHARE OF acquisition, claim;
    IF ROW(
        acquisition_row.tenant, acquisition_row.environment,
        acquisition_row.authorization_id, acquisition_row.transaction_id,
        acquisition_row.control_submission_id
    ) IS DISTINCT FROM ROW(
        NEW.tenant, NEW.environment, NEW.authorization_id, NEW.transaction_id,
        NEW.control_submission_id
    )
       OR acquisition_row.selection_kind <> 'CONTROL_QUEUE'
       OR acquisition_row.claim_state <> 'CLAIMED'
       OR NEW.phase <> 'IN_FLIGHT'
       OR NEW.begun_unix_s < acquisition_row.acquired_unix_s
       OR NEW.begun_unix_s >= acquisition_row.lease_until THEN
        RAISE EXCEPTION 'credential review is not bound to a live control acquisition';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_acquisitions AS later
         WHERE later.tenant = NEW.tenant
           AND later.environment = NEW.environment
           AND later.authorization_id = NEW.authorization_id
           AND later.transaction_id = NEW.transaction_id
           AND later.lease_fence > acquisition_row.lease_fence
    ) OR EXISTS (
        SELECT 1
          FROM public.accordlock_dispatch_queue_dispositions AS disposition
         WHERE disposition.control_submission_id = NEW.control_submission_id
    ) THEN
        RAISE EXCEPTION 'credential review follows a superseding queue outcome';
    END IF;

    SELECT entry_id, request_commitment, result_commitment,
           route_commitment, bound_secret_uid, phase, outcome,
           origin_acquisition_id, origin_lease_fence,
           acquisition_binding_version
      INTO STRICT create_row
      FROM public.accordlock_broker_operations
     WHERE tenant = NEW.tenant AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
       AND operation = 'CREATE_SECRET'
     FOR SHARE;
    SELECT entry_id, request_commitment, result_commitment,
           route_commitment, bound_secret_uid, phase, outcome,
           origin_acquisition_id, origin_lease_fence,
           acquisition_binding_version, token_digest, token_expires_at,
           credential_lifetime_upper_s, credential_clock_uncertainty_s
      INTO STRICT token_row
      FROM public.accordlock_broker_operations
     WHERE tenant = NEW.tenant AND environment = NEW.environment
       AND authorization_id = NEW.authorization_id AND transaction_id = NEW.transaction_id
       AND operation = 'ISSUE_TOKEN'
     FOR SHARE;
    IF create_row.phase <> 'COMMITTED'
       OR create_row.outcome <> 'CREATE_MATCHING'
       OR token_row.phase <> 'COMMITTED'
       OR token_row.outcome <> 'TOKEN_ISSUED'
       OR create_row.origin_acquisition_id <> NEW.acquisition_id
       OR token_row.origin_acquisition_id <> NEW.acquisition_id
       OR create_row.origin_lease_fence <> acquisition_row.lease_fence
       OR token_row.origin_lease_fence <> acquisition_row.lease_fence
       OR create_row.acquisition_binding_version <> 2
       OR token_row.acquisition_binding_version <> 2
       OR create_row.entry_id <> NEW.create_entry_id
       OR create_row.request_commitment <> NEW.create_request_commitment
       OR create_row.result_commitment <> NEW.create_result_commitment
       OR token_row.entry_id <> NEW.token_entry_id
       OR token_row.request_commitment <> NEW.token_request_commitment
       OR token_row.result_commitment <> NEW.token_result_commitment
       OR create_row.route_commitment <> NEW.expected_route_commitment
       OR token_row.route_commitment <> NEW.expected_route_commitment
       OR token_row.bound_secret_uid IS DISTINCT FROM create_row.bound_secret_uid
       OR token_row.bound_secret_uid IS DISTINCT FROM NEW.expected_bound_secret_uid
       OR token_row.token_digest <> NEW.expected_token_digest
       OR token_row.token_expires_at <> NEW.expected_token_expires_at
       OR token_row.credential_lifetime_upper_s <> NEW.credential_lifetime_upper_s
       OR token_row.credential_clock_uncertainty_s <>
          NEW.credential_clock_uncertainty_s THEN
        RAISE EXCEPTION 'credential review differs from committed broker lineage';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_guard_dispatch_credential_review_update()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    acquisition_lease_until BIGINT;
BEGIN
    IF (
        to_jsonb(NEW) - ARRAY[
            'phase', 'reviewed_unix_s', 'claims_json',
            'review_evidence_commitment', 'review_commitment', 'updated_at'
        ]::TEXT[]
    ) IS DISTINCT FROM (
        to_jsonb(OLD) - ARRAY[
            'phase', 'reviewed_unix_s', 'claims_json',
            'review_evidence_commitment', 'review_commitment', 'updated_at'
        ]::TEXT[]
    ) THEN
        RAISE EXCEPTION 'credential review frozen expectations are immutable';
    END IF;
    IF OLD.phase <> 'IN_FLIGHT'
       OR NEW.phase NOT IN ('AUTHENTICATED', 'REJECTED')
       OR NEW.reviewed_unix_s < OLD.begun_unix_s
       OR NEW.review_evidence_commitment =
          'sha256:0000000000000000000000000000000000000000000000000000000000000000'
       OR NEW.review_commitment =
          'sha256:0000000000000000000000000000000000000000000000000000000000000000' THEN
        RAISE EXCEPTION 'credential review phase transition is invalid';
    END IF;
    IF NEW.phase = 'AUTHENTICATED' THEN
        SELECT lease_until INTO STRICT acquisition_lease_until
          FROM public.accordlock_dispatch_acquisitions
         WHERE acquisition_id = NEW.acquisition_id
         FOR SHARE;
        IF NEW.reviewed_unix_s >= acquisition_lease_until
           OR jsonb_typeof(NEW.claims_json) <> 'object'
           OR NEW.claims_json ->> 'token_digest' <> NEW.expected_token_digest
           OR NEW.claims_json ->> 'subject' <> NEW.expected_subject
           OR NEW.claims_json ->> 'audience' <> NEW.expected_audience
           OR NEW.claims_json ->> 'service_account_uid' <>
              NEW.expected_service_account_uid
           OR NEW.claims_json ->> 'bound_secret_uid' <>
              NEW.expected_bound_secret_uid
           OR (NEW.claims_json ->> 'expires_at')::BIGINT <>
              NEW.expected_token_expires_at
           OR (NEW.claims_json ->> 'not_before')::BIGINT > NEW.reviewed_unix_s
           OR NEW.reviewed_unix_s >=
              (NEW.claims_json ->> 'expires_at')::BIGINT THEN
            RAISE EXCEPTION 'authenticated credential review facts differ';
        END IF;
    ELSIF NEW.claims_json IS NOT NULL THEN
        RAISE EXCEPTION 'rejected credential review cannot carry claims';
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.accordlock_reject_dispatch_credential_review_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'credential review history is append-only';
END
$function$;

CREATE TRIGGER accordlock_dispatch_request_identities_update_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_dispatch_request_identities
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_request_identity_update();
CREATE CONSTRAINT TRIGGER accordlock_dispatch_request_identities_child_guard
    AFTER INSERT OR UPDATE ON public.accordlock_dispatch_request_identities
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_dispatch_request_identity_child();
CREATE TRIGGER accordlock_dispatch_claims_v14_insert_guard
    BEFORE INSERT ON public.accordlock_dispatch_claims
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_claim_v14_insert();
CREATE CONSTRAINT TRIGGER accordlock_dispatch_claims_v14_acquisition_guard
    AFTER INSERT ON public.accordlock_dispatch_claims
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_dispatch_claim_acquisition();
CREATE TRIGGER accordlock_dispatch_acquisitions_guard_insert
    BEFORE INSERT ON public.accordlock_dispatch_acquisitions
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_acquisition_insert();
CREATE TRIGGER accordlock_dispatch_acquisitions_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_dispatch_acquisitions
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_dispatch_acquisition_mutation();
CREATE TRIGGER accordlock_dispatch_claims_v14_update_guard
    BEFORE UPDATE ON public.accordlock_dispatch_claims
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_claim_v14_update();
CREATE CONSTRAINT TRIGGER accordlock_dispatch_claims_disposition_guard
    AFTER UPDATE ON public.accordlock_dispatch_claims
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_disposed_claim_disposition();
CREATE TRIGGER accordlock_broker_operations_acquisition_guard
    BEFORE INSERT ON public.accordlock_broker_operations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_broker_acquisition_insert();
CREATE TRIGGER accordlock_broker_operations_acquisition_update_guard
    BEFORE UPDATE ON public.accordlock_broker_operations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_broker_acquisition_update();
CREATE TRIGGER accordlock_broker_operations_delete_guard
    BEFORE DELETE ON public.accordlock_broker_operations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_broker_operation_delete();
CREATE TRIGGER accordlock_dispatch_credential_reviews_insert_guard
    BEFORE INSERT ON public.accordlock_dispatch_credential_reviews
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_credential_review_insert();
CREATE TRIGGER accordlock_dispatch_credential_reviews_update_guard
    BEFORE UPDATE ON public.accordlock_dispatch_credential_reviews
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_credential_review_update();
CREATE TRIGGER accordlock_dispatch_credential_reviews_delete_guard
    BEFORE DELETE ON public.accordlock_dispatch_credential_reviews
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_dispatch_credential_review_delete();
CREATE TRIGGER accordlock_dispatch_queue_dispositions_guard_insert
    BEFORE INSERT ON public.accordlock_dispatch_queue_dispositions
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_queue_disposition_insert();
CREATE CONSTRAINT TRIGGER accordlock_dispatch_queue_dispositions_claim_guard
    AFTER INSERT ON public.accordlock_dispatch_queue_dispositions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_dispatch_disposition_claim_state();
CREATE TRIGGER accordlock_dispatch_queue_dispositions_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_dispatch_queue_dispositions
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_dispatch_disposition_mutation();
CREATE TRIGGER accordlock_admission_authorizations_dispatch_guard
    BEFORE INSERT ON public.accordlock_admission_authorizations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_admission_insert();
CREATE TRIGGER accordlock_terminal_retirements_dispatch_guard
    BEFORE INSERT ON public.accordlock_terminal_retirements
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_terminal_insert();
CREATE TRIGGER accordlock_grants_dispatch_source_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_grants
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_grant_source_mutation();
CREATE TRIGGER accordlock_issued_authorizations_dispatch_source_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_issued_authorizations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_authorization_source_mutation();
CREATE TRIGGER accordlock_consumptions_dispatch_source_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_consumptions
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_dispatch_consumption_source_mutation();
CREATE TRIGGER accordlock_execution_outbox_dispatch_source_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_execution_outbox
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_dispatch_outbox_source_mutation();
CREATE TRIGGER accordlock_authority_state_dispatch_source_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.accordlock_authority_state
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_validate_dispatch_authority_source();
CREATE TRIGGER accordlock_time_high_water_dispatch_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_time_high_water
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_high_water_mutation();
CREATE TRIGGER accordlock_ingress_high_water_dispatch_guard
    BEFORE UPDATE OR DELETE ON public.accordlock_ingress_replay_scopes
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_guard_dispatch_high_water_mutation();

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (14, '0014_durable_dispatch_acquisitions');

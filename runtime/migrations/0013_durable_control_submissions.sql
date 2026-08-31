-- Durable v13 signed-submission/control-plane junction.
--
-- Security profile:
-- * the signed canonical payload is the recovery identity;
-- * first_wire_* is immutable audit material only;
-- * replay nonce + submission + ACCEPTED projection/event + EVALUATE READY
--   queue are committed by one application transaction;
-- * requests contain no grant or authority selector;
-- * evaluation, decision, issuance, consumption, claims, events, and terminal
--   work finalizations are append-only history;
-- * status and work_queue are the only mutable projections.

-- Exact v13 lineage uses wider foreign keys than the legacy adapters needed.
-- These keys do not change legacy behavior; they only make every control
-- child prove the full immutable parent tuple it claims to reference.
ALTER TABLE public.accordlock_ingress_replay_nonces
    ADD CONSTRAINT accordlock_ingress_replay_nonces_control_lineage_key
    UNIQUE (
        replay_scope, key_id, nonce, state_instance_id,
        expires_unix_s, consumed_unix_s
    );

ALTER TABLE public.accordlock_issued_authorizations
    ADD COLUMN request_id UUID,
    ADD COLUMN evaluation_nonce UUID;

-- Profile-v1 authorizations are retained as inert audit rows and their historical
-- JSON was intentionally not constrained to the signed-v2 record shape.
-- Validate profile-v2 material before casting, then backfill only those rows.
DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.accordlock_issued_authorizations
         WHERE issuance_profile_version = 2
           AND (
                COALESCE(
                    record_json #>> '{signed_authorization,authorization,request_id}', ''
                ) !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                OR COALESCE(
                    record_json #>> '{signed_authorization,authorization,evaluation_nonce}', ''
                ) !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
           )
    ) THEN
        RAISE EXCEPTION
            'profile-v2 issued authorization lacks canonical request/evaluation UUID lineage';
    END IF;
END
$migration$;

UPDATE public.accordlock_issued_authorizations
   SET request_id = (
           record_json #>> '{signed_authorization,authorization,request_id}'
       )::uuid,
       evaluation_nonce = (
           record_json #>> '{signed_authorization,authorization,evaluation_nonce}'
       )::uuid
 WHERE issuance_profile_version = 2;

ALTER TABLE public.accordlock_issued_authorizations
    ADD CONSTRAINT accordlock_issued_authorizations_control_lineage_ids_check CHECK ((
        issuance_profile_version = 1
        OR issuance_profile_version = 2
        AND request_id IS NOT NULL
        AND evaluation_nonce IS NOT NULL
        AND request_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND evaluation_nonce <> '00000000-0000-0000-0000-000000000000'::uuid
    ) IS TRUE);

ALTER TABLE public.accordlock_issued_authorizations
    ADD CONSTRAINT accordlock_issued_authorizations_control_hash_key
    UNIQUE (tenant, environment, authorization_id, transaction_id, authorization_hash);

ALTER TABLE public.accordlock_issued_authorizations
    ADD CONSTRAINT accordlock_issued_authorizations_control_grant_hash_key
    UNIQUE (
        tenant, environment, authorization_id, transaction_id, authorization_hash, grant_id,
        issuance_profile_version, request_id, evaluation_nonce
    );

ALTER TABLE public.accordlock_execution_outbox
    ADD CONSTRAINT accordlock_execution_outbox_full_identity_key
    UNIQUE (tenant, environment, authorization_id, transaction_id);

ALTER TABLE public.accordlock_consumptions
    ADD CONSTRAINT accordlock_consumptions_control_exact_key
    UNIQUE (
        tenant, environment, authorization_id, transaction_id,
        consumed_unix_s, dispatch_deadline
    );

ALTER TABLE public.accordlock_execution_outbox
    ADD CONSTRAINT accordlock_execution_outbox_control_deadline_key
    UNIQUE (
        tenant, environment, authorization_id, transaction_id, dispatch_deadline
    );

CREATE TABLE public.accordlock_control_submissions (
    submission_id                  UUID PRIMARY KEY,
    receipt_id                     UUID NOT NULL UNIQUE,
    state_instance_id              UUID NOT NULL,
    replay_scope                   TEXT COLLATE "C" NOT NULL,
    key_id                         TEXT COLLATE "C" NOT NULL,
    nonce                          UUID NOT NULL,
    canonical_payload_commitment            TEXT COLLATE "C" NOT NULL UNIQUE,
    first_wire_commitment          TEXT COLLATE "C" NOT NULL,
    first_wire_json                BYTEA NOT NULL,
    canonical_claims               BYTEA NOT NULL,
    cose_sign1                     BYTEA NOT NULL,
    proposal_json                  JSONB NOT NULL,
    proposal_commitment            TEXT COLLATE "C" NOT NULL,
    request_id                     UUID NOT NULL,
    tenant                         TEXT COLLATE "C" NOT NULL,
    environment                    TEXT COLLATE "C" NOT NULL,
    actor                          TEXT COLLATE "C" NOT NULL,
    audience                       TEXT COLLATE "C" NOT NULL,
    ingress_issued_at              BIGINT NOT NULL,
    ingress_expires_at             BIGINT NOT NULL,
    accepted_at                    BIGINT NOT NULL,
    key_public_key                 BYTEA NOT NULL,
    key_not_before                 BIGINT NOT NULL,
    key_expires_at                 BIGINT NOT NULL,
    maximum_lifetime_seconds       BIGINT NOT NULL,
    ingress_authority_json         JSONB NOT NULL,
    evaluation_nonce               UUID NOT NULL,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_submissions_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_submissions_nonce_fkey
        FOREIGN KEY (
            replay_scope, key_id, nonce, state_instance_id,
            ingress_expires_at, accepted_at
        )
        REFERENCES public.accordlock_ingress_replay_nonces
            (
                replay_scope, key_id, nonce, state_instance_id,
                expires_unix_s, consumed_unix_s
            )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_submissions_request_key
        UNIQUE (tenant, environment, request_id),
    CONSTRAINT accordlock_control_submissions_nonce_key
        UNIQUE (replay_scope, key_id, nonce),
    CONSTRAINT accordlock_control_submissions_scope_receipt_key
        UNIQUE (tenant, environment, receipt_id),
    CONSTRAINT accordlock_control_submissions_exact_receipt_key
        UNIQUE (submission_id, tenant, environment, receipt_id),
    CONSTRAINT accordlock_control_submissions_receipt_pair_key
        UNIQUE (submission_id, receipt_id),
    CONSTRAINT accordlock_control_submissions_scope_key
        UNIQUE (submission_id, tenant, environment),
    CONSTRAINT accordlock_control_submissions_evaluation_nonce_key
        UNIQUE (submission_id, evaluation_nonce),
    CONSTRAINT accordlock_control_submissions_global_evaluation_nonce_key
        UNIQUE (evaluation_nonce),
    CONSTRAINT accordlock_control_submissions_authorization_lineage_key
        UNIQUE (
            submission_id, tenant, environment, request_id, evaluation_nonce
        ),
    CONSTRAINT accordlock_control_submissions_identity_check CHECK (
        submission_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND receipt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND request_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND nonce <> '00000000-0000-0000-0000-000000000000'::uuid
        AND evaluation_nonce <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT accordlock_control_submissions_text_check CHECK (
        octet_length(replay_scope) BETWEEN 1 AND 4096
        AND replay_scope = btrim(replay_scope)
        AND replay_scope !~ '[[:cntrl:]]'
        AND octet_length(key_id) BETWEEN 1 AND 256
        AND key_id = btrim(key_id)
        AND key_id !~ '[[:cntrl:]]'
        AND octet_length(tenant) BETWEEN 1 AND 4096
        AND tenant = btrim(tenant)
        AND tenant !~ '[[:cntrl:]]'
        AND octet_length(environment) BETWEEN 1 AND 4096
        AND environment = btrim(environment)
        AND environment !~ '[[:cntrl:]]'
        AND octet_length(actor) BETWEEN 1 AND 4096
        AND actor = btrim(actor)
        AND actor !~ '[[:cntrl:]]'
        AND octet_length(audience) BETWEEN 1 AND 4096
        AND audience = btrim(audience)
        AND audience !~ '[[:cntrl:]]'
        AND replay_scope = audience
    ),
    CONSTRAINT accordlock_control_submissions_commitments_check CHECK (
        canonical_payload_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND canonical_payload_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND first_wire_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND first_wire_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND proposal_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND proposal_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    ),
    CONSTRAINT accordlock_control_submissions_bytes_check CHECK (
        octet_length(first_wire_json) BETWEEN 1 AND 65536
        AND octet_length(canonical_claims) BETWEEN 1 AND 65536
        AND octet_length(cose_sign1) BETWEEN 1 AND 65536
        AND octet_length(key_public_key) = 32
    ),
    CONSTRAINT accordlock_control_submissions_time_check CHECK (
        key_not_before >= 0
        AND key_expires_at > key_not_before
        AND ingress_issued_at >= key_not_before
        AND ingress_expires_at > ingress_issued_at
        AND ingress_expires_at <= key_expires_at
        AND maximum_lifetime_seconds > 0
        AND ingress_expires_at - ingress_issued_at <= maximum_lifetime_seconds
        AND accepted_at >= ingress_issued_at
        AND accepted_at < ingress_expires_at
        AND accepted_at >= key_not_before
        AND accepted_at < key_expires_at
    )
);

CREATE TABLE public.accordlock_control_status (
    submission_id       UUID PRIMARY KEY,
    receipt_id          UUID NOT NULL UNIQUE,
    tenant              TEXT COLLATE "C" NOT NULL,
    environment         TEXT COLLATE "C" NOT NULL,
    status              TEXT COLLATE "C" NOT NULL,
    reason_kind         TEXT COLLATE "C",
    reason_code         TEXT COLLATE "C",
    revision            BIGINT NOT NULL,
    observed_at         BIGINT NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_status_exact_submission_fkey
        FOREIGN KEY (submission_id, tenant, environment, receipt_id)
        REFERENCES public.accordlock_control_submissions
            (submission_id, tenant, environment, receipt_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_status_code_check CHECK (
        status IN (
            'ACCEPTED', 'AUTHORIZED', 'CONTROL_DENIED',
            'AUTHORIZATION_ISSUED', 'DISPATCH_PENDING', 'FAILED_CLOSED'
        )
    ),
    CONSTRAINT accordlock_control_status_reason_check CHECK ((
        status = 'ACCEPTED'
        AND reason_kind IS NULL AND reason_code IS NULL
        OR status IN ('AUTHORIZED', 'AUTHORIZATION_ISSUED', 'DISPATCH_PENDING')
        AND reason_kind = 'DECISION' AND reason_code = 'CONTROL_ALLOW'
        OR status = 'CONTROL_DENIED'
        AND reason_kind = 'DECISION'
        AND reason_code IN (
            'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
            'KERNEL_DENY', 'GRANT_UNAVAILABLE'
        )
        OR status = 'FAILED_CLOSED'
        AND reason_kind = 'FINALIZATION'
        AND reason_code IN (
            'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
            'GRANT_UNAVAILABLE', 'AUTHORIZATION_EXPIRED',
            'DISPATCH_WINDOW_EXPIRED'
        )
    ) IS TRUE),
    CONSTRAINT accordlock_control_status_revision_check CHECK (
        revision >= 1 AND observed_at >= 0
        AND (status = 'ACCEPTED') = (revision = 1)
    )
);

CREATE TABLE public.accordlock_control_events (
    submission_id       UUID NOT NULL,
    revision            BIGINT NOT NULL,
    receipt_id          UUID NOT NULL,
    status              TEXT COLLATE "C" NOT NULL,
    reason_kind         TEXT COLLATE "C",
    reason_code         TEXT COLLATE "C",
    observed_at         BIGINT NOT NULL,
    event_commitment    TEXT COLLATE "C" NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_events_pkey PRIMARY KEY (submission_id, revision),
    CONSTRAINT accordlock_control_events_exact_submission_fkey
        FOREIGN KEY (submission_id, receipt_id)
        REFERENCES public.accordlock_control_submissions (submission_id, receipt_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_events_commitment_key UNIQUE (event_commitment),
    CONSTRAINT accordlock_control_events_shape_check CHECK ((
        revision >= 1 AND observed_at >= 0
        AND status IN (
            'ACCEPTED', 'AUTHORIZED', 'CONTROL_DENIED',
            'AUTHORIZATION_ISSUED', 'DISPATCH_PENDING', 'FAILED_CLOSED'
        )
        AND (
            status = 'ACCEPTED'
            AND reason_kind IS NULL AND reason_code IS NULL
            OR status IN ('AUTHORIZED', 'AUTHORIZATION_ISSUED', 'DISPATCH_PENDING')
            AND reason_kind = 'DECISION' AND reason_code = 'CONTROL_ALLOW'
            OR status = 'CONTROL_DENIED'
            AND reason_kind = 'DECISION'
            AND reason_code IN (
                'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
                'KERNEL_DENY', 'GRANT_UNAVAILABLE'
            )
            OR status = 'FAILED_CLOSED'
            AND reason_kind = 'FINALIZATION'
            AND reason_code IN (
                'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
                'GRANT_UNAVAILABLE', 'AUTHORIZATION_EXPIRED',
                'DISPATCH_WINDOW_EXPIRED'
            )
        )
        AND (status = 'ACCEPTED') = (revision = 1)
        AND event_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND event_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    ) IS TRUE)
);

ALTER TABLE public.accordlock_control_status
    ADD CONSTRAINT accordlock_control_status_current_event_fkey
    FOREIGN KEY (submission_id, revision)
    REFERENCES public.accordlock_control_events (submission_id, revision)
    ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION public.accordlock_check_control_status_event()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.revision <> 1 THEN
        RAISE EXCEPTION 'Initial AccordLock control status revision must be one';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.submission_id <> OLD.submission_id
        OR NEW.receipt_id <> OLD.receipt_id
        OR NEW.tenant <> OLD.tenant
        OR NEW.environment <> OLD.environment
        OR NEW.revision <> OLD.revision + 1
        OR NEW.observed_at < OLD.observed_at
    ) THEN
        RAISE EXCEPTION 'AccordLock control status transition is non-monotone';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM public.accordlock_control_events AS event
         WHERE event.submission_id = NEW.submission_id
           AND event.revision = NEW.revision
           AND event.receipt_id = NEW.receipt_id
           AND event.status = NEW.status
           AND event.reason_kind IS NOT DISTINCT FROM NEW.reason_kind
           AND event.reason_code IS NOT DISTINCT FROM NEW.reason_code
           AND event.observed_at = NEW.observed_at
    ) THEN
        RAISE EXCEPTION 'AccordLock control status must equal its append-only event';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER accordlock_control_status_event_exact
BEFORE INSERT OR UPDATE ON public.accordlock_control_status
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_status_event();

CREATE OR REPLACE FUNCTION public.accordlock_check_control_event_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    prior_status TEXT;
    prior_observed_at BIGINT;
    current_status TEXT;
    current_revision BIGINT;
BEGIN
    IF NEW.revision = 1 THEN
        IF NEW.status <> 'ACCEPTED' OR EXISTS (
            SELECT 1 FROM public.accordlock_control_events AS existing
             WHERE existing.submission_id = NEW.submission_id
        ) THEN
            RAISE EXCEPTION 'Invalid initial AccordLock control event';
        END IF;
        RETURN NEW;
    END IF;

    SELECT event.status, event.observed_at
      INTO prior_status, prior_observed_at
      FROM public.accordlock_control_events AS event
     WHERE event.submission_id = NEW.submission_id
       AND event.revision = NEW.revision - 1
     FOR SHARE;
    IF NOT FOUND OR NEW.observed_at < prior_observed_at THEN
        RAISE EXCEPTION 'AccordLock control event chain has a gap or time rollback';
    END IF;
    SELECT status.status, status.revision
      INTO current_status, current_revision
      FROM public.accordlock_control_status AS status
     WHERE status.submission_id = NEW.submission_id
     FOR UPDATE;
    IF NOT FOUND
       OR current_revision <> NEW.revision - 1
       OR current_status <> prior_status THEN
        RAISE EXCEPTION 'AccordLock control event is ahead of its current projection';
    END IF;
    IF NOT (
        prior_status = 'ACCEPTED'
        AND NEW.status IN (
            'AUTHORIZED', 'CONTROL_DENIED'
        )
        OR prior_status = 'AUTHORIZED'
        AND NEW.status IN ('AUTHORIZATION_ISSUED', 'FAILED_CLOSED')
        OR prior_status = 'AUTHORIZATION_ISSUED'
        AND NEW.status IN ('DISPATCH_PENDING', 'FAILED_CLOSED')
    ) THEN
        RAISE EXCEPTION 'Invalid AccordLock control event transition';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER accordlock_control_events_monotone
BEFORE INSERT ON public.accordlock_control_events
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_event_chain();

CREATE TABLE public.accordlock_control_evaluations (
    evaluation_id           UUID PRIMARY KEY,
    submission_id           UUID NOT NULL UNIQUE,
    claim_id                UUID NOT NULL UNIQUE,
    claim_phase             TEXT COLLATE "C" NOT NULL,
    evaluation_nonce        UUID NOT NULL UNIQUE,
    kernel_outcome          TEXT COLLATE "C" NOT NULL,
    signed_evaluation_json  JSONB NOT NULL,
    evaluator_key_id        TEXT COLLATE "C" NOT NULL,
    evaluator_public_key    BYTEA NOT NULL,
    evaluation_commitment   TEXT COLLATE "C" NOT NULL UNIQUE,
    evaluated_at            BIGINT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_evaluations_submission_nonce_fkey
        FOREIGN KEY (submission_id, evaluation_nonce)
        REFERENCES public.accordlock_control_submissions
            (submission_id, evaluation_nonce)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_evaluations_decision_lineage_key
        UNIQUE (submission_id, claim_id, evaluation_id, kernel_outcome),
    CONSTRAINT accordlock_control_evaluations_completion_lineage_key
        UNIQUE (submission_id, claim_id, evaluation_id, evaluated_at),
    CONSTRAINT accordlock_control_evaluations_kernel_outcome_check
        CHECK (kernel_outcome IN ('ALLOW', 'DENY')),
    CONSTRAINT accordlock_control_evaluations_shape_check CHECK (
        evaluation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND evaluation_nonce <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_phase = 'EVALUATE'
        AND octet_length(evaluator_key_id) BETWEEN 1 AND 256
        AND evaluator_key_id = btrim(evaluator_key_id)
        AND evaluator_key_id !~ '[[:cntrl:]]'
        AND octet_length(evaluator_public_key) = 32
        AND evaluation_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND evaluation_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND evaluated_at >= 0
    )
);

CREATE TABLE public.accordlock_control_decisions (
    decision_id            UUID PRIMARY KEY,
    submission_id          UUID NOT NULL UNIQUE,
    claim_id               UUID NOT NULL UNIQUE,
    claim_phase            TEXT COLLATE "C" NOT NULL,
    evaluation_id          UUID UNIQUE,
    kernel_outcome         TEXT COLLATE "C",
    control_outcome        TEXT COLLATE "C" NOT NULL,
    reason                 TEXT COLLATE "C" NOT NULL,
    selected_grant_id      UUID,
    tenant                 TEXT COLLATE "C" NOT NULL,
    environment            TEXT COLLATE "C" NOT NULL,
    decided_at             BIGINT NOT NULL,
    decision_commitment    TEXT COLLATE "C" NOT NULL UNIQUE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_decisions_submission_scope_fkey
        FOREIGN KEY (submission_id, tenant, environment)
        REFERENCES public.accordlock_control_submissions
            (submission_id, tenant, environment)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_decisions_evaluation_fkey
        FOREIGN KEY (submission_id, claim_id, evaluation_id, kernel_outcome)
        REFERENCES public.accordlock_control_evaluations
            (submission_id, claim_id, evaluation_id, kernel_outcome)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_decisions_grant_fkey
        FOREIGN KEY (tenant, environment, selected_grant_id)
        REFERENCES public.accordlock_grants (tenant, environment, grant_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_decisions_issuance_lineage_key
        UNIQUE (
            submission_id, decision_id, tenant, environment,
            control_outcome, selected_grant_id
        ),
    CONSTRAINT accordlock_control_decisions_completion_lineage_key
        UNIQUE (submission_id, decision_id, tenant, environment),
    CONSTRAINT accordlock_control_decisions_finalization_lineage_key
        UNIQUE (
            submission_id, decision_id, tenant, environment, control_outcome
        ),
    CONSTRAINT accordlock_control_decisions_evaluate_completion_key
        UNIQUE (submission_id, claim_id, decision_id, decided_at),
    CONSTRAINT accordlock_control_decisions_signed_completion_key
        UNIQUE (
            submission_id, claim_id, decision_id, evaluation_id, decided_at
        ),
    CONSTRAINT accordlock_control_decisions_matrix_check CHECK ((
        control_outcome IN ('ALLOW', 'DENY')
        AND claim_phase = 'EVALUATE'
        AND decision_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (evaluation_id IS NULL OR evaluation_id <>
            '00000000-0000-0000-0000-000000000000'::uuid)
        AND (selected_grant_id IS NULL OR selected_grant_id <>
            '00000000-0000-0000-0000-000000000000'::uuid)
        AND reason IN (
            'CONTROL_ALLOW', 'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
            'KERNEL_DENY', 'GRANT_UNAVAILABLE'
        )
        AND (
            control_outcome = 'ALLOW'
            AND kernel_outcome = 'ALLOW'
            AND evaluation_id IS NOT NULL
            AND selected_grant_id IS NOT NULL
            AND reason = 'CONTROL_ALLOW'
            OR control_outcome = 'DENY'
            AND selected_grant_id IS NULL
            AND (
                kernel_outcome = 'DENY'
                AND evaluation_id IS NOT NULL
                AND reason = 'KERNEL_DENY'
                OR kernel_outcome = 'ALLOW'
                AND evaluation_id IS NOT NULL
                AND reason = 'GRANT_UNAVAILABLE'
                OR kernel_outcome IS NULL
                AND evaluation_id IS NULL
                AND reason IN ('INGRESS_EXPIRED', 'AUTHORITY_CHANGED')
            )
        )
        AND decided_at >= 0
        AND decision_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND decision_commitment <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    ) IS TRUE)
);

CREATE TABLE public.accordlock_control_work_claims (
    claim_id           UUID PRIMARY KEY,
    submission_id      UUID NOT NULL,
    role               TEXT COLLATE "C" NOT NULL,
    phase              TEXT COLLATE "C" NOT NULL,
    worker_id          TEXT COLLATE "C" NOT NULL,
    fence              BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    claimed_at         BIGINT NOT NULL,
    lease_until        BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_work_claims_submission_fkey
        FOREIGN KEY (submission_id)
        REFERENCES public.accordlock_control_submissions (submission_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_claims_phase_lineage_key
        UNIQUE (submission_id, claim_id, phase),
    CONSTRAINT accordlock_control_work_claims_evaluation_time_key
        UNIQUE (submission_id, claim_id, phase, claimed_at),
    CONSTRAINT accordlock_control_work_claims_completion_lineage_key
        UNIQUE (submission_id, claim_id, phase, fence, worker_id),
    CONSTRAINT accordlock_control_work_claims_role_phase_check CHECK (
        role IN ('EVALUATOR', 'ISSUER', 'CONSUMER')
        AND phase IN ('EVALUATE', 'ISSUE', 'CONSUME')
        AND (role, phase) IN (
            ('EVALUATOR', 'EVALUATE'),
            ('ISSUER', 'ISSUE'),
            ('CONSUMER', 'CONSUME')
        )
    ),
    CONSTRAINT accordlock_control_work_claims_identity_check CHECK (
        claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND fence > 0
        AND octet_length(worker_id) BETWEEN 1 AND 253
        AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
    ),
    CONSTRAINT accordlock_control_work_claims_time_check CHECK (
        claimed_at >= 0
        AND lease_until - claimed_at = 30
    )
);

ALTER TABLE public.accordlock_control_evaluations
    ADD CONSTRAINT accordlock_control_evaluations_claim_fkey
    FOREIGN KEY (submission_id, claim_id, claim_phase, evaluated_at)
    REFERENCES public.accordlock_control_work_claims
        (submission_id, claim_id, phase, claimed_at)
    ON DELETE RESTRICT;

ALTER TABLE public.accordlock_control_decisions
    ADD CONSTRAINT accordlock_control_decisions_claim_fkey
    FOREIGN KEY (submission_id, claim_id, claim_phase)
    REFERENCES public.accordlock_control_work_claims
        (submission_id, claim_id, phase)
    ON DELETE RESTRICT;

CREATE TABLE public.accordlock_control_work_queue (
    submission_id      UUID PRIMARY KEY,
    phase              TEXT COLLATE "C" NOT NULL,
    state              TEXT COLLATE "C" NOT NULL,
    active_claim_id    UUID,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_work_queue_submission_fkey
        FOREIGN KEY (submission_id)
        REFERENCES public.accordlock_control_submissions (submission_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_queue_claim_fkey
        FOREIGN KEY (submission_id, active_claim_id, phase)
        REFERENCES public.accordlock_control_work_claims
            (submission_id, claim_id, phase)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_queue_state_check CHECK (
        phase IN ('EVALUATE', 'ISSUE', 'CONSUME', 'DONE')
        AND state IN ('READY', 'LEASED', 'DONE')
        AND (
            phase = 'DONE' AND state = 'DONE' AND active_claim_id IS NULL
            OR phase <> 'DONE' AND state = 'READY' AND active_claim_id IS NULL
            OR phase <> 'DONE' AND state = 'LEASED' AND active_claim_id IS NOT NULL
        )
    )
);

CREATE INDEX accordlock_control_work_queue_ready_idx
    ON public.accordlock_control_work_queue (phase, state, submission_id)
    WHERE state = 'READY';

CREATE INDEX accordlock_control_work_claims_lease_idx
    ON public.accordlock_control_work_claims (phase, lease_until, submission_id);

CREATE TABLE public.accordlock_control_work_finalizations (
    submission_id      UUID PRIMARY KEY,
    claim_id           UUID NOT NULL UNIQUE,
    phase              TEXT COLLATE "C" NOT NULL,
    decision_id        UUID NOT NULL,
    decision_outcome   TEXT COLLATE "C" NOT NULL,
    tenant             TEXT COLLATE "C" NOT NULL,
    environment        TEXT COLLATE "C" NOT NULL,
    issuance_authorization_id       UUID,
    issuance_transaction_id UUID,
    reason             TEXT COLLATE "C" NOT NULL,
    finalized_at       BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_work_finalizations_submission_scope_fkey
        FOREIGN KEY (submission_id, tenant, environment)
        REFERENCES public.accordlock_control_submissions
            (submission_id, tenant, environment)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_finalizations_claim_fkey
        FOREIGN KEY (submission_id, claim_id, phase)
        REFERENCES public.accordlock_control_work_claims
            (submission_id, claim_id, phase)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_finalizations_decision_fkey
        FOREIGN KEY (
            submission_id, decision_id, tenant, environment, decision_outcome
        )
        REFERENCES public.accordlock_control_decisions
            (submission_id, decision_id, tenant, environment, control_outcome)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_work_finalizations_shape_check CHECK ((
        phase IN ('ISSUE', 'CONSUME')
        AND decision_outcome = 'ALLOW'
        AND decision_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND reason IN (
            'INGRESS_EXPIRED', 'AUTHORITY_CHANGED',
            'GRANT_UNAVAILABLE', 'AUTHORIZATION_EXPIRED',
            'DISPATCH_WINDOW_EXPIRED'
        )
        AND (
            phase = 'ISSUE'
            AND issuance_authorization_id IS NULL
            AND issuance_transaction_id IS NULL
            AND reason <> 'DISPATCH_WINDOW_EXPIRED'
            OR phase = 'CONSUME'
            AND issuance_authorization_id IS NOT NULL
            AND issuance_transaction_id IS NOT NULL
        )
        AND finalized_at >= 0
    ) IS TRUE)
);

CREATE TABLE public.accordlock_control_issuances (
    submission_id      UUID PRIMARY KEY,
    claim_id           UUID NOT NULL UNIQUE,
    claim_phase        TEXT COLLATE "C" NOT NULL,
    decision_id        UUID NOT NULL UNIQUE,
    decision_outcome   TEXT COLLATE "C" NOT NULL,
    tenant             TEXT COLLATE "C" NOT NULL,
    environment        TEXT COLLATE "C" NOT NULL,
    grant_id            UUID NOT NULL,
    issuance_profile_version SMALLINT NOT NULL,
    request_id          UUID NOT NULL,
    evaluation_nonce    UUID NOT NULL,
    authorization_id                UUID NOT NULL,
    transaction_id     UUID NOT NULL,
    authorization_hash        TEXT COLLATE "C" NOT NULL,
    linked_at          BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_issuances_submission_scope_fkey
        FOREIGN KEY (submission_id, tenant, environment)
        REFERENCES public.accordlock_control_submissions
            (submission_id, tenant, environment)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_issuances_claim_fkey
        FOREIGN KEY (submission_id, claim_id, claim_phase)
        REFERENCES public.accordlock_control_work_claims
            (submission_id, claim_id, phase)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_issuances_decision_fkey
        FOREIGN KEY (
            submission_id, decision_id, tenant, environment,
            decision_outcome, grant_id
        )
        REFERENCES public.accordlock_control_decisions
            (
                submission_id, decision_id, tenant, environment,
                control_outcome, selected_grant_id
            )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_issuance_authorization_lineage_fkey
        FOREIGN KEY (
            submission_id, tenant, environment, request_id, evaluation_nonce
        )
        REFERENCES public.accordlock_control_submissions
            (
                submission_id, tenant, environment,
                request_id, evaluation_nonce
            )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_issuances_authorization_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, authorization_hash, grant_id,
            issuance_profile_version, request_id, evaluation_nonce
        )
        REFERENCES public.accordlock_issued_authorizations
            (
                tenant, environment, authorization_id, transaction_id, authorization_hash, grant_id,
                issuance_profile_version, request_id, evaluation_nonce
            )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_issuances_consumption_lineage_key
        UNIQUE (submission_id, tenant, environment, authorization_id, transaction_id),
    CONSTRAINT accordlock_control_issuances_completion_lineage_key
        UNIQUE (submission_id, claim_id, decision_id, linked_at),
    CONSTRAINT accordlock_control_issuances_shape_check CHECK (
        authorization_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND transaction_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND grant_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND request_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND evaluation_nonce <> '00000000-0000-0000-0000-000000000000'::uuid
        AND issuance_profile_version = 2
        AND claim_phase = 'ISSUE'
        AND decision_outcome = 'ALLOW'
        AND authorization_hash ~ '^sha256:[0-9a-f]{64}$'
        AND authorization_hash <>
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        AND linked_at >= 0
    )
);

ALTER TABLE public.accordlock_control_work_finalizations
    ADD CONSTRAINT accordlock_control_work_finalizations_issuance_fkey
    FOREIGN KEY (
        submission_id, tenant, environment,
        issuance_authorization_id, issuance_transaction_id
    )
    REFERENCES public.accordlock_control_issuances
        (submission_id, tenant, environment, authorization_id, transaction_id)
    ON DELETE RESTRICT;

CREATE TABLE public.accordlock_control_consumptions (
    submission_id      UUID PRIMARY KEY,
    claim_id           UUID NOT NULL UNIQUE,
    claim_phase        TEXT COLLATE "C" NOT NULL,
    tenant             TEXT COLLATE "C" NOT NULL,
    environment        TEXT COLLATE "C" NOT NULL,
    authorization_id                UUID NOT NULL,
    transaction_id     UUID NOT NULL,
    linked_at          BIGINT NOT NULL,
    dispatch_deadline  BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_consumptions_issuance_fkey
        FOREIGN KEY (
            submission_id, tenant, environment, authorization_id, transaction_id
        )
        REFERENCES public.accordlock_control_issuances
            (submission_id, tenant, environment, authorization_id, transaction_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_consumptions_claim_fkey
        FOREIGN KEY (submission_id, claim_id, claim_phase)
        REFERENCES public.accordlock_control_work_claims
            (submission_id, claim_id, phase)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_consumptions_receipt_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id,
            linked_at, dispatch_deadline
        )
        REFERENCES public.accordlock_consumptions
            (
                tenant, environment, authorization_id, transaction_id,
                consumed_unix_s, dispatch_deadline
            )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_consumptions_outbox_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, dispatch_deadline
        )
        REFERENCES public.accordlock_execution_outbox
            (tenant, environment, authorization_id, transaction_id, dispatch_deadline)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_consumptions_completion_lineage_key
        UNIQUE (submission_id, tenant, environment, authorization_id, transaction_id),
    CONSTRAINT accordlock_control_consumptions_claim_completion_key
        UNIQUE (submission_id, claim_id, authorization_id, transaction_id, linked_at),
    CONSTRAINT accordlock_control_consumptions_shape_check CHECK (
        authorization_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND transaction_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_phase = 'CONSUME'
        AND linked_at >= 0
        AND dispatch_deadline > linked_at
    )
);

CREATE TABLE public.accordlock_control_phase_completions (
    claim_id           UUID PRIMARY KEY,
    submission_id      UUID NOT NULL,
    phase              TEXT COLLATE "C" NOT NULL,
    fence              BIGINT NOT NULL,
    worker_id          TEXT COLLATE "C" NOT NULL,
    completed_at       BIGINT NOT NULL,
    decision_id        UUID NOT NULL,
    evaluation_id      UUID,
    evaluation_artifact_at BIGINT,
    issuance_artifact_at   BIGINT,
    consumption_artifact_at BIGINT,
    tenant             TEXT COLLATE "C" NOT NULL,
    environment        TEXT COLLATE "C" NOT NULL,
    consume_authorization_id        UUID,
    consume_transaction_id UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_control_phase_completions_claim_fkey
        FOREIGN KEY (submission_id, claim_id, phase, fence, worker_id)
        REFERENCES public.accordlock_control_work_claims
            (submission_id, claim_id, phase, fence, worker_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_decision_fkey
        FOREIGN KEY (submission_id, decision_id, tenant, environment)
        REFERENCES public.accordlock_control_decisions
            (submission_id, decision_id, tenant, environment)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_consumption_fkey
        FOREIGN KEY (
            submission_id, tenant, environment,
            consume_authorization_id, consume_transaction_id
        )
        REFERENCES public.accordlock_control_consumptions
            (submission_id, tenant, environment, authorization_id, transaction_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_evaluation_artifact_fkey
        FOREIGN KEY (
            submission_id, claim_id, decision_id,
            evaluation_id, evaluation_artifact_at
        )
        REFERENCES public.accordlock_control_decisions
            (submission_id, claim_id, decision_id, evaluation_id, decided_at)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_issuance_artifact_fkey
        FOREIGN KEY (
            submission_id, claim_id, decision_id, issuance_artifact_at
        )
        REFERENCES public.accordlock_control_issuances
            (submission_id, claim_id, decision_id, linked_at)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_consumption_artifact_fkey
        FOREIGN KEY (
            submission_id, claim_id, consume_authorization_id,
            consume_transaction_id, consumption_artifact_at
        )
        REFERENCES public.accordlock_control_consumptions
            (submission_id, claim_id, authorization_id, transaction_id, linked_at)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_control_phase_completions_shape_check CHECK ((
        phase IN ('EVALUATE', 'ISSUE', 'CONSUME')
        AND claim_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND submission_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND decision_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND fence > 0
        AND completed_at >= 0
        AND octet_length(worker_id) BETWEEN 1 AND 253
        AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
        AND (
            phase = 'CONSUME'
            AND consume_authorization_id IS NOT NULL
            AND consume_transaction_id IS NOT NULL
            AND evaluation_id IS NULL
            AND evaluation_artifact_at IS NULL
            AND issuance_artifact_at IS NULL
            AND consumption_artifact_at IS NOT NULL
            AND consumption_artifact_at = completed_at
            OR phase IN ('EVALUATE', 'ISSUE')
            AND consume_authorization_id IS NULL
            AND consume_transaction_id IS NULL
            AND consumption_artifact_at IS NULL
            AND (
                phase = 'EVALUATE'
                AND evaluation_id IS NOT NULL
                AND evaluation_artifact_at IS NOT NULL
                AND evaluation_artifact_at = completed_at
                AND issuance_artifact_at IS NULL
                OR phase = 'ISSUE'
                AND evaluation_id IS NULL
                AND evaluation_artifact_at IS NULL
                AND issuance_artifact_at IS NOT NULL
                AND issuance_artifact_at = completed_at
            )
        )
    ) IS TRUE)
);

CREATE OR REPLACE FUNCTION public.accordlock_check_control_terminal_exclusion()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    target_phase TEXT;
BEGIN
    -- Do not use a CASE expression with NEW.phase here. PostgreSQL resolves
    -- record fields before choosing a CASE arm, while issuance/consumption
    -- rows intentionally have no `phase` column.
    IF TG_TABLE_NAME = 'accordlock_control_issuances' THEN
        target_phase := 'ISSUE';
    ELSIF TG_TABLE_NAME = 'accordlock_control_consumptions' THEN
        target_phase := 'CONSUME';
    ELSIF TG_TABLE_NAME IN (
        'accordlock_control_evaluations', 'accordlock_control_decisions'
    ) THEN
        target_phase := 'EVALUATE';
    ELSE
        target_phase := NEW.phase;
    END IF;
    -- Serialize every competing claim and artifact for a submission on its
    -- immutable root row. Different takeover claim IDs must not each commit a
    -- contradictory terminal result for the same payload phase.
    PERFORM 1
     FROM public.accordlock_control_submissions AS submission
     WHERE submission.submission_id = NEW.submission_id
     FOR NO KEY UPDATE;
    IF TG_TABLE_NAME = 'accordlock_control_evaluations' THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_control_decisions AS decision
             WHERE decision.submission_id = NEW.submission_id
               AND decision.evaluation_id IS NULL
        ) THEN
            RAISE EXCEPTION
                'Pre-kernel control decision cannot acquire a signed evaluation';
        END IF;
    ELSIF TG_TABLE_NAME = 'accordlock_control_decisions'
          AND to_jsonb(NEW) ->> 'evaluation_id' IS NULL THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_control_evaluations AS evaluation
             WHERE evaluation.submission_id = NEW.submission_id
        ) THEN
            RAISE EXCEPTION
                'Pre-kernel control decision conflicts with a signed evaluation';
        END IF;
    ELSIF TG_TABLE_NAME = 'accordlock_control_phase_completions' THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_control_work_finalizations AS finalization
             WHERE finalization.submission_id = NEW.submission_id
               AND finalization.phase = target_phase
        ) THEN
            RAISE EXCEPTION 'Control submission phase is already fail-closed';
        END IF;
    ELSIF TG_TABLE_NAME = 'accordlock_control_work_finalizations' THEN
        IF EXISTS (
            SELECT 1
              FROM public.accordlock_control_phase_completions AS completion
             WHERE completion.submission_id = NEW.submission_id
               AND completion.phase = target_phase
        ) OR target_phase = 'ISSUE' AND EXISTS (
            SELECT 1 FROM public.accordlock_control_issuances AS issuance
             WHERE issuance.submission_id = NEW.submission_id
        ) OR target_phase = 'CONSUME' AND EXISTS (
            SELECT 1 FROM public.accordlock_control_consumptions AS consumption
             WHERE consumption.submission_id = NEW.submission_id
        ) THEN
            RAISE EXCEPTION 'Control submission phase is already successfully completed';
        END IF;
    ELSIF EXISTS (
        SELECT 1
          FROM public.accordlock_control_work_finalizations AS finalization
         WHERE finalization.submission_id = NEW.submission_id
           AND finalization.phase = target_phase
    ) THEN
        RAISE EXCEPTION 'Control submission phase is already fail-closed';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER accordlock_control_phase_completions_exclusive
BEFORE INSERT ON public.accordlock_control_phase_completions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE TRIGGER accordlock_control_evaluations_prekernel_exclusive
BEFORE INSERT ON public.accordlock_control_evaluations
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE TRIGGER accordlock_control_decisions_prekernel_exclusive
BEFORE INSERT ON public.accordlock_control_decisions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE TRIGGER accordlock_control_work_finalizations_exclusive
BEFORE INSERT ON public.accordlock_control_work_finalizations
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE TRIGGER accordlock_control_issuances_exclusive
BEFORE INSERT ON public.accordlock_control_issuances
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE TRIGGER accordlock_control_consumptions_exclusive
BEFORE INSERT ON public.accordlock_control_consumptions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_terminal_exclusion();

CREATE OR REPLACE FUNCTION public.accordlock_check_control_event_artifact()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.status = 'ACCEPTED' AND NOT EXISTS (
        SELECT 1 FROM public.accordlock_control_submissions AS submission
         WHERE submission.submission_id = NEW.submission_id
           AND submission.receipt_id = NEW.receipt_id
           AND submission.accepted_at = NEW.observed_at
    ) THEN
        RAISE EXCEPTION 'ACCEPTED event lacks its exact intake artifact';
    ELSIF NEW.status IN ('AUTHORIZED', 'CONTROL_DENIED') AND NOT EXISTS (
        SELECT 1 FROM public.accordlock_control_decisions AS decision
         WHERE decision.submission_id = NEW.submission_id
           AND decision.decided_at = NEW.observed_at
           AND decision.reason = NEW.reason_code
           AND (
               NEW.status = 'AUTHORIZED'
               AND decision.control_outcome = 'ALLOW'
               OR NEW.status = 'CONTROL_DENIED'
               AND decision.control_outcome = 'DENY'
           )
    ) THEN
        RAISE EXCEPTION 'Decision event lacks its exact decision artifact';
    ELSIF NEW.status = 'AUTHORIZATION_ISSUED' AND NOT EXISTS (
        SELECT 1 FROM public.accordlock_control_issuances AS issuance
         WHERE issuance.submission_id = NEW.submission_id
           AND issuance.linked_at = NEW.observed_at
    ) THEN
        RAISE EXCEPTION 'AUTHORIZATION_ISSUED event lacks its exact issuance artifact';
    ELSIF NEW.status = 'DISPATCH_PENDING' AND NOT EXISTS (
        SELECT 1 FROM public.accordlock_control_consumptions AS consumption
         WHERE consumption.submission_id = NEW.submission_id
           AND consumption.linked_at = NEW.observed_at
    ) THEN
        RAISE EXCEPTION 'DISPATCH_PENDING event lacks its exact consumption artifact';
    ELSIF NEW.status = 'FAILED_CLOSED' AND NOT EXISTS (
        SELECT 1 FROM public.accordlock_control_work_finalizations AS finalization
         WHERE finalization.submission_id = NEW.submission_id
           AND finalization.finalized_at = NEW.observed_at
           AND finalization.reason = NEW.reason_code
           AND (
               finalization.phase = 'ISSUE'
               AND EXISTS (
                   SELECT 1 FROM public.accordlock_control_status AS status
                    WHERE status.submission_id = NEW.submission_id
                      AND status.revision = NEW.revision - 1
                      AND status.status = 'AUTHORIZED'
               )
               OR finalization.phase = 'CONSUME'
               AND EXISTS (
                   SELECT 1 FROM public.accordlock_control_status AS status
                    WHERE status.submission_id = NEW.submission_id
                      AND status.revision = NEW.revision - 1
                      AND status.status = 'AUTHORIZATION_ISSUED'
               )
           )
    ) THEN
        RAISE EXCEPTION 'FAILED_CLOSED event lacks its exact finalization artifact';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER accordlock_control_events_exact_artifact
BEFORE INSERT ON public.accordlock_control_events
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_event_artifact();

CREATE OR REPLACE FUNCTION public.accordlock_check_control_artifact_lease()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    artifact JSONB;
    artifact_claim_id UUID;
    artifact_phase TEXT;
    artifact_at BIGINT;
    claim_start BIGINT;
    claim_end BIGINT;
    accepted_time BIGINT;
BEGIN
    artifact := to_jsonb(NEW);
    artifact_claim_id := (artifact ->> 'claim_id')::uuid;
    artifact_phase := COALESCE(
        artifact ->> 'claim_phase', artifact ->> 'phase'
    );
    artifact_at := CASE TG_TABLE_NAME
        WHEN 'accordlock_control_evaluations'
            THEN (artifact ->> 'evaluated_at')::bigint
        WHEN 'accordlock_control_decisions'
            THEN (artifact ->> 'decided_at')::bigint
        WHEN 'accordlock_control_work_finalizations'
            THEN (artifact ->> 'finalized_at')::bigint
        WHEN 'accordlock_control_issuances'
            THEN (artifact ->> 'linked_at')::bigint
        WHEN 'accordlock_control_consumptions'
            THEN (artifact ->> 'linked_at')::bigint
        WHEN 'accordlock_control_phase_completions'
            THEN (artifact ->> 'completed_at')::bigint
        ELSE NULL
    END;
    PERFORM 1
      FROM public.accordlock_control_submissions AS submission
     WHERE submission.submission_id = NEW.submission_id
     FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Control artifact lacks its immutable submission';
    END IF;
    SELECT submission.accepted_at
      INTO accepted_time
      FROM public.accordlock_control_submissions AS submission
     WHERE submission.submission_id = NEW.submission_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Control artifact lacks its trusted-time lineage';
    END IF;
    PERFORM 1
      FROM public.accordlock_control_work_queue AS queue
     WHERE queue.submission_id = NEW.submission_id
       AND queue.phase = artifact_phase
       AND queue.state = 'LEASED'
       AND queue.active_claim_id = artifact_claim_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Control artifact does not belong to the active fenced claim';
    END IF;
    SELECT claim.claimed_at, claim.lease_until
      INTO claim_start, claim_end
      FROM public.accordlock_control_work_claims AS claim
     WHERE claim.submission_id = NEW.submission_id
       AND claim.claim_id = artifact_claim_id
      AND claim.phase = artifact_phase
      FOR SHARE;
    -- DB time and both HWM rows are sampled, checked, and advanced once by
    -- the state transaction before it inserts an artifact. Re-sampling time
    -- here creates a second linearization point: crossing lease expiry inside
    -- this trigger would roll back the HWM advance and could let a later clock
    -- rollback resurrect the capability. The schema trigger therefore proves
    -- exact active-claim identity and the committed artifact timestamp only.
    IF claim_start IS NULL
       OR artifact_at IS NULL
       OR artifact_at < claim_start
       OR artifact_at >= claim_end
       OR artifact_at < accepted_time THEN
        RAISE EXCEPTION 'Control artifact is outside its exact claim lease';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER accordlock_control_evaluations_active_lease
BEFORE INSERT ON public.accordlock_control_evaluations
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();
CREATE TRIGGER accordlock_control_decisions_active_lease
BEFORE INSERT ON public.accordlock_control_decisions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();
CREATE TRIGGER accordlock_control_work_finalizations_active_lease
BEFORE INSERT ON public.accordlock_control_work_finalizations
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();
CREATE TRIGGER accordlock_control_issuances_active_lease
BEFORE INSERT ON public.accordlock_control_issuances
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();
CREATE TRIGGER accordlock_control_consumptions_active_lease
BEFORE INSERT ON public.accordlock_control_consumptions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();
CREATE TRIGGER accordlock_control_phase_completions_active_lease
BEFORE INSERT ON public.accordlock_control_phase_completions
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_artifact_lease();

CREATE OR REPLACE FUNCTION public.accordlock_check_control_queue_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    database_now BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.phase <> 'EVALUATE'
           OR NEW.state <> 'READY'
           OR NEW.active_claim_id IS NOT NULL THEN
            RAISE EXCEPTION 'Control queue must start EVALUATE READY';
        END IF;
        RETURN NEW;
    END IF;
    SELECT floor(extract(epoch FROM clock_timestamp()))::bigint
      INTO database_now;
    IF NEW.submission_id <> OLD.submission_id OR OLD.phase = 'DONE' THEN
        RAISE EXCEPTION 'Control queue identity or DONE state is immutable';
    END IF;
    IF NEW.phase = OLD.phase
       AND NEW.state = 'LEASED'
       AND NEW.active_claim_id IS NOT NULL
       AND OLD.state = 'READY'
       AND OLD.active_claim_id IS NULL
       AND EXISTS (
           SELECT 1
             FROM public.accordlock_control_work_claims AS new_claim
             JOIN public.accordlock_control_submissions AS submission
               ON submission.submission_id = new_claim.submission_id
             JOIN public.accordlock_time_high_water AS scope_hwm
               ON scope_hwm.tenant = submission.tenant
              AND scope_hwm.environment = submission.environment
             JOIN public.accordlock_ingress_replay_scopes AS ingress_hwm
               ON ingress_hwm.replay_scope = submission.replay_scope
            WHERE new_claim.submission_id = NEW.submission_id
              AND new_claim.phase = NEW.phase
              AND new_claim.claim_id = NEW.active_claim_id
              AND new_claim.claimed_at <= database_now
              AND database_now < new_claim.lease_until
              AND new_claim.claimed_at >= submission.accepted_at
              AND new_claim.claimed_at >= scope_hwm.observed_unix_s
              AND new_claim.claimed_at >= ingress_hwm.observed_unix_s
       ) THEN
        RETURN NEW;
    END IF;
    IF NEW.phase = OLD.phase
       AND NEW.state = 'LEASED'
       AND OLD.state = 'LEASED'
       AND OLD.active_claim_id IS NOT NULL
       AND NEW.active_claim_id IS NOT NULL
       AND NEW.active_claim_id <> OLD.active_claim_id
       AND EXISTS (
           SELECT 1
              FROM public.accordlock_control_work_claims AS old_claim
              JOIN public.accordlock_control_work_claims AS new_claim
                ON new_claim.submission_id = old_claim.submission_id
               AND new_claim.phase = old_claim.phase
              JOIN public.accordlock_control_submissions AS submission
                ON submission.submission_id = new_claim.submission_id
              JOIN public.accordlock_time_high_water AS scope_hwm
                ON scope_hwm.tenant = submission.tenant
               AND scope_hwm.environment = submission.environment
              JOIN public.accordlock_ingress_replay_scopes AS ingress_hwm
                ON ingress_hwm.replay_scope = submission.replay_scope
            WHERE old_claim.submission_id = NEW.submission_id
              AND old_claim.phase = NEW.phase
              AND old_claim.claim_id = OLD.active_claim_id
               AND new_claim.claim_id = NEW.active_claim_id
               AND new_claim.claimed_at >= old_claim.lease_until
               AND new_claim.fence > old_claim.fence
               AND new_claim.claimed_at <= database_now
               AND database_now < new_claim.lease_until
               AND new_claim.claimed_at >= submission.accepted_at
               AND new_claim.claimed_at >= scope_hwm.observed_unix_s
               AND new_claim.claimed_at >= ingress_hwm.observed_unix_s
       ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state <> 'LEASED'
       OR OLD.active_claim_id IS NULL
       OR NEW.active_claim_id IS NOT NULL THEN
        RAISE EXCEPTION 'Invalid control queue lease transition';
    END IF;

    IF OLD.phase = 'EVALUATE' AND NEW.phase = 'ISSUE' AND NEW.state = 'READY'
       AND EXISTS (
           SELECT 1 FROM public.accordlock_control_phase_completions AS completion
            JOIN public.accordlock_control_decisions AS decision
              ON decision.submission_id = completion.submission_id
             AND decision.decision_id = completion.decision_id
           WHERE completion.submission_id = NEW.submission_id
             AND completion.claim_id = OLD.active_claim_id
             AND completion.phase = 'EVALUATE'
             AND decision.control_outcome = 'ALLOW'
       ) THEN
        RETURN NEW;
    END IF;
    IF OLD.phase = 'EVALUATE' AND NEW.phase = 'DONE' AND NEW.state = 'DONE'
       AND EXISTS (
           SELECT 1 FROM public.accordlock_control_decisions AS decision
            WHERE decision.submission_id = NEW.submission_id
              AND decision.claim_id = OLD.active_claim_id
              AND decision.control_outcome = 'DENY'
              AND (
                  decision.evaluation_id IS NULL
                  OR EXISTS (
                      SELECT 1
                        FROM public.accordlock_control_phase_completions AS completion
                       WHERE completion.submission_id = NEW.submission_id
                         AND completion.claim_id = OLD.active_claim_id
                         AND completion.phase = 'EVALUATE'
                  )
              )
       ) THEN
        RETURN NEW;
    END IF;
    IF OLD.phase = 'ISSUE' AND NEW.phase = 'CONSUME' AND NEW.state = 'READY'
       AND EXISTS (
           SELECT 1 FROM public.accordlock_control_phase_completions AS completion
            WHERE completion.submission_id = NEW.submission_id
              AND completion.claim_id = OLD.active_claim_id
              AND completion.phase = 'ISSUE'
       ) THEN
        RETURN NEW;
    END IF;
    IF OLD.phase = 'CONSUME' AND NEW.phase = 'DONE' AND NEW.state = 'DONE'
       AND EXISTS (
           SELECT 1 FROM public.accordlock_control_phase_completions AS completion
            WHERE completion.submission_id = NEW.submission_id
              AND completion.claim_id = OLD.active_claim_id
              AND completion.phase = 'CONSUME'
       ) THEN
        RETURN NEW;
    END IF;
    IF OLD.phase IN ('ISSUE', 'CONSUME')
       AND NEW.phase = 'DONE' AND NEW.state = 'DONE'
       AND EXISTS (
           SELECT 1 FROM public.accordlock_control_work_finalizations AS finalization
            WHERE finalization.submission_id = NEW.submission_id
              AND finalization.claim_id = OLD.active_claim_id
              AND finalization.phase = OLD.phase
       ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Invalid or artifact-free control queue transition';
END
$function$;

CREATE TRIGGER accordlock_control_work_queue_forward_only
BEFORE INSERT OR UPDATE ON public.accordlock_control_work_queue
FOR EACH ROW EXECUTE FUNCTION public.accordlock_check_control_queue_transition();

CREATE OR REPLACE FUNCTION public.accordlock_reject_control_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'AccordLock control history is append-only';
END
$function$;

DO $triggers$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'accordlock_control_submissions',
        'accordlock_control_events',
        'accordlock_control_evaluations',
        'accordlock_control_decisions',
        'accordlock_control_work_claims',
        'accordlock_control_work_finalizations',
        'accordlock_control_issuances',
        'accordlock_control_consumptions',
        'accordlock_control_phase_completions'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON public.%I '
            'FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_control_history_mutation()',
            table_name,
            table_name
        );
        EXECUTE format(
            'CREATE TRIGGER %I_truncate_rejected BEFORE TRUNCATE ON public.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION public.accordlock_reject_control_history_mutation()',
            table_name,
            table_name
        );
    END LOOP;
END
$triggers$;

CREATE TRIGGER accordlock_control_status_delete_rejected
BEFORE DELETE ON public.accordlock_control_status
FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_control_history_mutation();
CREATE TRIGGER accordlock_control_status_truncate_rejected
BEFORE TRUNCATE ON public.accordlock_control_status
FOR EACH STATEMENT EXECUTE FUNCTION public.accordlock_reject_control_history_mutation();
CREATE TRIGGER accordlock_control_work_queue_delete_rejected
BEFORE DELETE ON public.accordlock_control_work_queue
FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_control_history_mutation();
CREATE TRIGGER accordlock_control_work_queue_truncate_rejected
BEFORE TRUNCATE ON public.accordlock_control_work_queue
FOR EACH STATEMENT EXECUTE FUNCTION public.accordlock_reject_control_history_mutation();

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (13, '0013_durable_control_submissions');

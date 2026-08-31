-- Durable, exclusive dispatch authority. This table deliberately does not
-- mutate the immutable consumption outbox. A claim is unique per consumed
-- authorization, and ATTEMPT_IN_FLIGHT is an irreversible local ambiguity boundary.

CREATE TABLE IF NOT EXISTS public.accordlock_dispatch_claims (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    authorization_id                 UUID NOT NULL,
    transaction_id      UUID NOT NULL,
    claim_id            UUID NOT NULL,
    worker_id           TEXT NOT NULL,
    fence               BIGINT GENERATED ALWAYS AS IDENTITY,
    state_instance_id   UUID NOT NULL,
    claimed_unix_s      BIGINT NOT NULL,
    lease_until         BIGINT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'CLAIMED',
    attempt_started_at  BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_dispatch_claims_pkey
        PRIMARY KEY (tenant, environment, authorization_id),
    CONSTRAINT accordlock_dispatch_claims_transaction_key
        UNIQUE (tenant, environment, transaction_id),
    CONSTRAINT accordlock_dispatch_claims_claim_id_key UNIQUE (claim_id),
    CONSTRAINT accordlock_dispatch_claims_fence_key UNIQUE (fence),
    CONSTRAINT accordlock_dispatch_claims_consumption_fkey
        FOREIGN KEY (tenant, environment, authorization_id, transaction_id)
        REFERENCES public.accordlock_consumptions
            (tenant, environment, authorization_id, transaction_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_claims_state_instance_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_dispatch_claims_claim_id_check
        CHECK (claim_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT accordlock_dispatch_claims_worker_id_check
        CHECK (
            octet_length(worker_id) BETWEEN 1 AND 253
            AND worker_id ~ '^[a-z]([a-z0-9._:/@-]*[a-z0-9])?$'
        ),
    CONSTRAINT accordlock_dispatch_claims_fence_check CHECK (fence > 0),
    CONSTRAINT accordlock_dispatch_claims_time_check
        CHECK (claimed_unix_s >= 0 AND lease_until > claimed_unix_s),
    CONSTRAINT accordlock_dispatch_claims_state_check
        CHECK (state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT')),
    CONSTRAINT accordlock_dispatch_claims_state_time_check
        CHECK (
            (state = 'CLAIMED' AND attempt_started_at IS NULL)
            OR
            (state = 'ATTEMPT_IN_FLIGHT'
             AND attempt_started_at IS NOT NULL
             AND attempt_started_at >= claimed_unix_s
             AND attempt_started_at < lease_until)
        )
);

CREATE INDEX IF NOT EXISTS accordlock_dispatch_claims_active_idx
    ON public.accordlock_dispatch_claims (state, lease_until, fence);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (5, '0005_dispatch_claims')
ON CONFLICT (version) DO NOTHING;

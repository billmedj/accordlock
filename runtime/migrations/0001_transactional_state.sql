-- Local transactional state for AccordLock authorization consumption.
--
-- Safety-critical consumption code runs at SERIALIZABLE isolation and locks
-- the relevant authority, authorization, grant, and time rows before mutation.

CREATE TABLE IF NOT EXISTS public.accordlock_authority_state (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    authority_json      JSONB NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, environment),
    CHECK (tenant <> '' AND environment <> '')
);

CREATE TABLE IF NOT EXISTS public.accordlock_time_high_water (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    observed_unix_s     BIGINT NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, environment),
    CHECK (tenant <> '' AND environment <> ''),
    CHECK (observed_unix_s >= 0)
);

CREATE TABLE IF NOT EXISTS public.accordlock_grants (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    grant_id            UUID NOT NULL,
    registration_json   JSONB NOT NULL,
    uses                BIGINT NOT NULL DEFAULT 0,
    maximum_uses        BIGINT NOT NULL,
    not_before          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, environment, grant_id),
    CHECK (tenant <> '' AND environment <> ''),
    CHECK (maximum_uses > 0),
    CHECK (uses >= 0 AND uses <= maximum_uses),
    CHECK (not_before >= 0 AND expires_at > not_before)
);

CREATE TABLE IF NOT EXISTS public.accordlock_issued_authorizations (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    authorization_id                 UUID NOT NULL,
    transaction_id      UUID NOT NULL,
    grant_id            UUID NOT NULL,
    record_json         JSONB NOT NULL,
    authorization_hash         TEXT NOT NULL,
    consume_before      BIGINT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'ISSUED',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    consumed_at         TIMESTAMPTZ,
    PRIMARY KEY (tenant, environment, authorization_id),
    UNIQUE (tenant, environment, transaction_id),
    FOREIGN KEY (tenant, environment, grant_id)
        REFERENCES public.accordlock_grants (tenant, environment, grant_id)
        ON DELETE RESTRICT,
    CHECK (tenant <> '' AND environment <> ''),
    CHECK (consume_before >= 0),
    CHECK (state IN ('ISSUED', 'CONSUMED'))
);

CREATE TABLE IF NOT EXISTS public.accordlock_consumptions (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    authorization_id                 UUID NOT NULL,
    transaction_id      UUID NOT NULL,
    receipt_json        JSONB NOT NULL,
    consumed_unix_s     BIGINT NOT NULL,
    dispatch_deadline   BIGINT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, environment, authorization_id),
    UNIQUE (tenant, environment, transaction_id),
    FOREIGN KEY (tenant, environment, authorization_id)
        REFERENCES public.accordlock_issued_authorizations (tenant, environment, authorization_id)
        ON DELETE RESTRICT,
    CHECK (consumed_unix_s >= 0),
    CHECK (dispatch_deadline > consumed_unix_s)
);

CREATE TABLE IF NOT EXISTS public.accordlock_execution_outbox (
    tenant              TEXT NOT NULL,
    environment         TEXT NOT NULL,
    authorization_id                 UUID NOT NULL,
    transaction_id      UUID NOT NULL,
    dispatch_deadline   BIGINT NOT NULL,
    status              TEXT NOT NULL,
    entry_json          JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant, environment, authorization_id),
    UNIQUE (tenant, environment, transaction_id),
    FOREIGN KEY (tenant, environment, authorization_id)
        REFERENCES public.accordlock_consumptions (tenant, environment, authorization_id)
        ON DELETE RESTRICT,
    CHECK (status IN ('PENDING_WITNESS'))
);

CREATE INDEX IF NOT EXISTS accordlock_execution_outbox_pending_idx
    ON public.accordlock_execution_outbox (tenant, environment, created_at)
    WHERE status = 'PENDING_WITNESS';

-- Integrity constraints and explicit migration ledger for the local state profile.

CREATE TABLE IF NOT EXISTS public.accordlock_schema_migrations (
    version             INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    applied_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (version > 0 AND name <> '')
);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES
    (1, '0001_transactional_state'),
    (2, '0002_state_integrity')
ON CONFLICT (version) DO NOTHING;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_issued_authorizations'::regclass
           AND conname = 'accordlock_issued_authorizations_full_identity_key'
    ) THEN
        ALTER TABLE public.accordlock_issued_authorizations
            ADD CONSTRAINT accordlock_issued_authorizations_full_identity_key
            UNIQUE (tenant, environment, authorization_id, transaction_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_issued_authorizations'::regclass
           AND conname = 'accordlock_issued_authorizations_state_time_check'
    ) THEN
        ALTER TABLE public.accordlock_issued_authorizations
            ADD CONSTRAINT accordlock_issued_authorizations_state_time_check
            CHECK (
                (state = 'ISSUED' AND consumed_at IS NULL)
                OR (state = 'CONSUMED' AND consumed_at IS NOT NULL)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_issued_authorizations'::regclass
           AND conname = 'accordlock_issued_authorizations_hash_check'
    ) THEN
        ALTER TABLE public.accordlock_issued_authorizations
            ADD CONSTRAINT accordlock_issued_authorizations_hash_check
            CHECK (authorization_hash ~ '^sha256:[0-9a-f]{64}$');
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_consumptions'::regclass
           AND conname = 'accordlock_consumptions_full_identity_key'
    ) THEN
        ALTER TABLE public.accordlock_consumptions
            ADD CONSTRAINT accordlock_consumptions_full_identity_key
            UNIQUE (tenant, environment, authorization_id, transaction_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_consumptions'::regclass
           AND conname = 'accordlock_consumptions_issued_authorization_fkey'
    ) THEN
        ALTER TABLE public.accordlock_consumptions
            ADD CONSTRAINT accordlock_consumptions_issued_authorization_fkey
            FOREIGN KEY (tenant, environment, authorization_id, transaction_id)
            REFERENCES public.accordlock_issued_authorizations
                (tenant, environment, authorization_id, transaction_id)
            ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_execution_outbox'::regclass
           AND conname = 'accordlock_execution_outbox_consumption_fkey'
    ) THEN
        ALTER TABLE public.accordlock_execution_outbox
            ADD CONSTRAINT accordlock_execution_outbox_consumption_fkey
            FOREIGN KEY (tenant, environment, authorization_id, transaction_id)
            REFERENCES public.accordlock_consumptions
                (tenant, environment, authorization_id, transaction_id)
            ON DELETE RESTRICT;
    END IF;
END
$migration$;

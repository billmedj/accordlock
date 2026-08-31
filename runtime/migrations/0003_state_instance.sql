-- Durable logical state-store identity used to bind exported live sessions to
-- the PostgreSQL state lineage that committed their receipt and outbox tuple.

ALTER TABLE public.accordlock_schema_migrations
    ADD COLUMN IF NOT EXISTS sha256 TEXT;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_schema_migrations'::regclass
           AND conname = 'accordlock_schema_migrations_sha256_check'
    ) THEN
        ALTER TABLE public.accordlock_schema_migrations
            ADD CONSTRAINT accordlock_schema_migrations_sha256_check
            CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$');
    END IF;
END
$migration$;

CREATE TABLE IF NOT EXISTS public.accordlock_state_metadata (
    singleton           BOOLEAN NOT NULL,
    state_instance_id   UUID NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_state_metadata_singleton_pkey PRIMARY KEY (singleton),
    CONSTRAINT accordlock_state_metadata_instance_id_key UNIQUE (state_instance_id),
    CONSTRAINT accordlock_state_metadata_singleton_check CHECK (singleton)
);

INSERT INTO public.accordlock_state_metadata (singleton, state_instance_id)
VALUES (TRUE, gen_random_uuid())
ON CONFLICT (singleton) DO NOTHING;

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (3, '0003_state_instance')
ON CONFLICT (version) DO NOTHING;

-- Fail-closed storage discriminator for the signed dispatch-policy,
-- signer-authority-bound COSE envelope, and authority-bound grant profile.
-- Existing v1 rows remain present for audit but are never consumed by the v2
-- adapter.

ALTER TABLE public.accordlock_grants
    ADD COLUMN IF NOT EXISTS issuance_profile_version SMALLINT NOT NULL DEFAULT 1;

ALTER TABLE public.accordlock_issued_authorizations
    ADD COLUMN IF NOT EXISTS issuance_profile_version SMALLINT NOT NULL DEFAULT 1;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_grants'::regclass
           AND conname = 'accordlock_grants_scope_key'
    ) THEN
        ALTER TABLE public.accordlock_grants
            ADD CONSTRAINT accordlock_grants_scope_key UNIQUE (tenant, environment);
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_grants'::regclass
           AND conname = 'accordlock_grants_issuance_profile_version_check'
    ) THEN
        ALTER TABLE public.accordlock_grants
            ADD CONSTRAINT accordlock_grants_issuance_profile_version_check
            CHECK (issuance_profile_version IN (1, 2));
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.accordlock_issued_authorizations'::regclass
           AND conname = 'accordlock_issued_authorizations_issuance_profile_version_check'
    ) THEN
        ALTER TABLE public.accordlock_issued_authorizations
            ADD CONSTRAINT accordlock_issued_authorizations_issuance_profile_version_check
            CHECK (issuance_profile_version IN (1, 2));
    END IF;
END
$migration$;

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (4, '0004_signed_issuance_profile')
ON CONFLICT (version) DO NOTHING;

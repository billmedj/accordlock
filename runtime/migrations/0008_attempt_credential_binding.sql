-- Kubernetes v1.32+ exact credential identity binding for provider attempts.
-- Pre-G1 rows that crossed the provider-attempt or admission boundary cannot
-- be authenticated retroactively and must be purged before this migration.

DO $accordlock$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.accordlock_dispatch_claims
         WHERE state = 'ATTEMPT_IN_FLIGHT'
    ) OR EXISTS (
        SELECT 1 FROM public.accordlock_admission_authorizations
    ) THEN
        RAISE EXCEPTION
            'v8 requires pre-G1 purge of in-flight attempts and admission rows';
    END IF;
END
$accordlock$;

ALTER TABLE public.accordlock_admission_authorizations
    DROP CONSTRAINT accordlock_admission_authorizations_claim_fkey;

ALTER TABLE public.accordlock_dispatch_claims
    DROP CONSTRAINT accordlock_dispatch_claims_admission_binding_key,
    DROP CONSTRAINT accordlock_dispatch_claims_state_time_check,
    ADD COLUMN credential_token_digest TEXT COLLATE "C",
    ADD COLUMN service_account_uid TEXT COLLATE "C",
    ADD COLUMN credential_id TEXT COLLATE "C",
    ADD COLUMN credential_not_before BIGINT,
    ADD COLUMN credential_expires_at BIGINT,
    ADD COLUMN credential_binding_commitment TEXT COLLATE "C",
    ADD CONSTRAINT accordlock_dispatch_claims_credential_identity_check
        CHECK (
            service_account_uid IS NULL
            OR (
                octet_length(service_account_uid) BETWEEN 1 AND 512
                AND service_account_uid = btrim(service_account_uid)
                AND service_account_uid !~ '[[:cntrl:]]'
                AND credential_id ~
                    '^AUTHORIZATION_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                AND credential_id <>
                    'AUTHORIZATION_ID=00000000-0000-0000-0000-000000000000'
            )
        ),
    ADD CONSTRAINT accordlock_dispatch_claims_credential_commitments_check
        CHECK (
            credential_token_digest IS NULL
            OR (
                credential_token_digest ~ '^sha256:[0-9a-f]{64}$'
                AND credential_token_digest <>
                    'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                AND credential_binding_commitment ~ '^sha256:[0-9a-f]{64}$'
                AND credential_binding_commitment <>
                    'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            )
        ),
    ADD CONSTRAINT accordlock_dispatch_claims_state_time_check
        CHECK (
            (
                state = 'CLAIMED'
                AND attempt_started_at IS NULL
                AND credential_token_digest IS NULL
                AND service_account_uid IS NULL
                AND credential_id IS NULL
                AND credential_not_before IS NULL
                AND credential_expires_at IS NULL
                AND credential_binding_commitment IS NULL
            )
            OR (
                state = 'ATTEMPT_IN_FLIGHT'
                AND attempt_started_at IS NOT NULL
                AND attempt_started_at >= claimed_unix_s
                AND attempt_started_at < lease_until
                AND credential_token_digest IS NOT NULL
                AND service_account_uid IS NOT NULL
                AND credential_id IS NOT NULL
                AND credential_not_before IS NOT NULL
                AND credential_expires_at IS NOT NULL
                AND credential_binding_commitment IS NOT NULL
                AND credential_not_before >= 0
                AND credential_not_before <= attempt_started_at
                AND credential_expires_at > attempt_started_at
            )
        ),
    ADD CONSTRAINT accordlock_dispatch_claims_admission_binding_key
        UNIQUE (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid,
            credential_token_digest, service_account_uid, credential_id,
            credential_binding_commitment
        );

ALTER TABLE public.accordlock_admission_authorizations
    ADD COLUMN credential_token_digest TEXT COLLATE "C" NOT NULL,
    ADD COLUMN service_account_uid TEXT COLLATE "C" NOT NULL,
    ADD COLUMN credential_id TEXT COLLATE "C" NOT NULL,
    ADD COLUMN credential_binding_commitment TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT accordlock_admission_authorizations_credential_identity_check
        CHECK (
            octet_length(service_account_uid) BETWEEN 1 AND 512
            AND service_account_uid = btrim(service_account_uid)
            AND service_account_uid !~ '[[:cntrl:]]'
            AND credential_id ~
                '^AUTHORIZATION_ID=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND credential_id <>
                'AUTHORIZATION_ID=00000000-0000-0000-0000-000000000000'
        ),
    ADD CONSTRAINT accordlock_admission_authorizations_cred_commitments_check
        CHECK (
            credential_token_digest ~ '^sha256:[0-9a-f]{64}$'
            AND credential_token_digest <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND credential_binding_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND credential_binding_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        ),
    ADD CONSTRAINT accordlock_admission_authorizations_claim_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid,
            credential_token_digest, service_account_uid, credential_id,
            credential_binding_commitment
        )
        REFERENCES public.accordlock_dispatch_claims (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid,
            credential_token_digest, service_account_uid, credential_id,
            credential_binding_commitment
        )
        ON DELETE RESTRICT;

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (8, '0008_attempt_credential_binding')
ON CONFLICT (version) DO NOTHING;

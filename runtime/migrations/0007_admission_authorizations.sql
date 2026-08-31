-- Durable one-shot Kubernetes admission authorization. This is a second
-- linearization boundary after ATTEMPT_IN_FLIGHT. It records that AccordLock
-- authorized an exact AdmissionReview tuple; it does not assert that the API
-- server persisted the admitted object and it does not release the physical
-- resource reservation.

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_admission_binding_key
        UNIQUE (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        );

CREATE TABLE public.accordlock_admission_authorizations (
    admission_uid                  TEXT COLLATE "C" NOT NULL,
    tenant                         TEXT COLLATE "C" NOT NULL,
    environment                    TEXT COLLATE "C" NOT NULL,
    transaction_id                 UUID NOT NULL,
    authorization_id                            UUID NOT NULL,
    claim_id                       UUID NOT NULL,
    fence                          BIGINT NOT NULL,
    cluster_identity               TEXT COLLATE "C" NOT NULL,
    namespace                      TEXT COLLATE "C" NOT NULL,
    deployment_uid                 TEXT COLLATE "C" NOT NULL,
    provider_request_commitment    TEXT COLLATE "C" NOT NULL,
    old_object_commitment          TEXT COLLATE "C" NOT NULL,
    new_object_commitment          TEXT COLLATE "C" NOT NULL,
    executor_identity_commitment   TEXT COLLATE "C" NOT NULL,
    observer_identity_commitment   TEXT COLLATE "C" NOT NULL,
    request_commitment             TEXT COLLATE "C" NOT NULL,
    grant_id                       UUID NOT NULL,
    authorized_authority_json      JSONB NOT NULL,
    dispatch_deadline              BIGINT NOT NULL,
    authorized_unix_s              BIGINT NOT NULL,
    decision                       TEXT COLLATE "C" NOT NULL DEFAULT 'ADMITTED',
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_admission_authorizations_pkey
        PRIMARY KEY (admission_uid),
    CONSTRAINT accordlock_admission_authorizations_transaction_key
        UNIQUE (tenant, environment, transaction_id),
    CONSTRAINT accordlock_admission_authorizations_claim_id_key UNIQUE (claim_id),
    CONSTRAINT accordlock_admission_authorizations_fence_key UNIQUE (fence),
    CONSTRAINT accordlock_admission_authorizations_provider_request_key
        UNIQUE (provider_request_commitment),
    CONSTRAINT accordlock_admission_authorizations_claim_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        )
        REFERENCES public.accordlock_dispatch_claims (
            tenant, environment, authorization_id, transaction_id, claim_id, fence,
            cluster_identity, namespace, deployment_uid
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_admission_authorizations_uid_check
        CHECK (
            octet_length(admission_uid) BETWEEN 1 AND 128
            AND admission_uid ~ '^[A-Za-z0-9._:-]+$'
        ),
    CONSTRAINT accordlock_admission_authorizations_claim_id_check
        CHECK (claim_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT accordlock_admission_authorizations_fence_check CHECK (fence > 0),
    CONSTRAINT accordlock_admission_authorizations_physical_identity_check
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
    CONSTRAINT accordlock_admission_authorizations_commitments_check
        CHECK (
            provider_request_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND old_object_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND new_object_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND executor_identity_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND observer_identity_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND request_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND provider_request_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND old_object_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND new_object_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND executor_identity_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND observer_identity_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND request_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        ),
    CONSTRAINT accordlock_admission_authorizations_decision_check
        CHECK (decision = 'ADMITTED'),
    CONSTRAINT accordlock_admission_authorizations_time_check
        CHECK (
            authorized_unix_s >= 0
            AND dispatch_deadline > authorized_unix_s
        ),
    CONSTRAINT accordlock_admission_authorizations_grant_id_check
        CHECK (grant_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (7, '0007_admission_authorizations')
ON CONFLICT (version) DO NOTHING;

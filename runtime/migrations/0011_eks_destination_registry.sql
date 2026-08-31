-- Rooted, append-only registry for the single narrow EKS destination profile.
--
-- Physical ownership is global and intentionally has no release operation in
-- this migration. Reassignment requires a future authenticated terminal
-- witness; process death, deadline expiry, or authority rotation is not a
-- release signal. Destination activations are historical and are selected as
-- current only by exact equality with active resource+mediation domains.

CREATE TABLE public.accordlock_eks_physical_owners (
    api_server_identity                TEXT COLLATE "C" NOT NULL,
    namespace                          TEXT COLLATE "C" NOT NULL,
    deployment_uid                     TEXT COLLATE "C" NOT NULL,
    tenant                             TEXT COLLATE "C" NOT NULL,
    environment                        TEXT COLLATE "C" NOT NULL,
    cluster_identity                   TEXT COLLATE "C" NOT NULL,
    cluster_trust_domain               TEXT COLLATE "C" NOT NULL,
    socket_target                      TEXT COLLATE "C" NOT NULL,
    ca_trust_commitment                TEXT COLLATE "C" NOT NULL,
    first_resource_root                TEXT COLLATE "C" NOT NULL,
    first_resource_epoch               BIGINT NOT NULL,
    first_resource_activation_id       UUID NOT NULL,
    state_instance_id                  UUID NOT NULL,
    created_at                         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_eks_physical_owners_pkey
        PRIMARY KEY (api_server_identity, namespace, deployment_uid),
    CONSTRAINT accordlock_eks_physical_owners_route_key
        UNIQUE (
            socket_target, ca_trust_commitment, namespace, deployment_uid
        ),
    CONSTRAINT accordlock_eks_physical_owners_binding_key
        UNIQUE (
            api_server_identity, namespace, deployment_uid,
            tenant, environment, cluster_identity, cluster_trust_domain,
            socket_target, ca_trust_commitment, state_instance_id
        ),
    CONSTRAINT accordlock_eks_physical_owners_authority_fkey
        FOREIGN KEY (tenant, environment)
        REFERENCES public.accordlock_authority_state (tenant, environment)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_eks_physical_owners_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_eks_physical_owners_identity_check
        CHECK (
            octet_length(api_server_identity) BETWEEN 1 AND 512
            AND api_server_identity = btrim(api_server_identity)
            AND api_server_identity !~ '[[:cntrl:]]'
            AND octet_length(namespace) BETWEEN 1 AND 63
            AND namespace = btrim(namespace)
            AND namespace !~ '[[:cntrl:]]'
            AND octet_length(deployment_uid) BETWEEN 1 AND 512
            AND deployment_uid = btrim(deployment_uid)
            AND deployment_uid !~ '[[:cntrl:]]'
            AND octet_length(tenant) BETWEEN 1 AND 253
            AND tenant = btrim(tenant)
            AND tenant !~ '[[:cntrl:]]'
            AND octet_length(environment) BETWEEN 1 AND 253
            AND environment = btrim(environment)
            AND environment !~ '[[:cntrl:]]'
            AND octet_length(cluster_identity) BETWEEN 1 AND 512
            AND cluster_identity = btrim(cluster_identity)
            AND cluster_identity !~ '[[:cntrl:]]'
            AND octet_length(cluster_trust_domain) BETWEEN 1 AND 512
            AND cluster_trust_domain = btrim(cluster_trust_domain)
            AND cluster_trust_domain !~ '[[:cntrl:]]'
            AND octet_length(socket_target) BETWEEN 3 AND 64
            AND socket_target = btrim(socket_target)
            AND socket_target !~ '[[:cntrl:]]'
        ),
    CONSTRAINT accordlock_eks_physical_owners_root_check
        CHECK (
            ca_trust_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND ca_trust_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND first_resource_root ~ '^sha256:[0-9a-f]{64}$'
            AND first_resource_root <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND first_resource_epoch >= 0
            AND first_resource_activation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        )
);

CREATE TABLE public.accordlock_eks_destination_activations (
    tenant                             TEXT COLLATE "C" NOT NULL,
    environment                        TEXT COLLATE "C" NOT NULL,
    state_instance_id                  UUID NOT NULL,
    resource_root                      TEXT COLLATE "C" NOT NULL,
    resource_epoch                     BIGINT NOT NULL,
    resource_activation_id             UUID NOT NULL,
    mediation_root                     TEXT COLLATE "C" NOT NULL,
    mediation_epoch                    BIGINT NOT NULL,
    mediation_activation_id            UUID NOT NULL,
    activation_commitment              TEXT COLLATE "C" NOT NULL,
    route_commitment                   TEXT COLLATE "C" NOT NULL,
    cluster_trust_domain               TEXT COLLATE "C" NOT NULL,
    cluster_identity                   TEXT COLLATE "C" NOT NULL,
    api_server_identity                TEXT COLLATE "C" NOT NULL,
    dns_server_name                    TEXT COLLATE "C" NOT NULL,
    api_server_port                    INTEGER NOT NULL,
    socket_target                      TEXT COLLATE "C" NOT NULL,
    ca_trust_commitment                TEXT COLLATE "C" NOT NULL,
    namespace                          TEXT COLLATE "C" NOT NULL,
    deployment_name                    TEXT COLLATE "C" NOT NULL,
    deployment_uid                     TEXT COLLATE "C" NOT NULL,
    attempt_service_account_name       TEXT COLLATE "C" NOT NULL,
    attempt_service_account_uid        TEXT COLLATE "C" NOT NULL,
    token_subject                      TEXT COLLATE "C" NOT NULL,
    token_audience                     TEXT COLLATE "C" NOT NULL,
    effective_rbac_commitment          TEXT COLLATE "C" NOT NULL,
    terminal_witness_registry_commitment TEXT COLLATE "C" NOT NULL,
    credential_lifecycle_schema_version SMALLINT NOT NULL,
    credential_lifecycle_policy_id      TEXT COLLATE "C" NOT NULL,
    credential_lifecycle_commitment     TEXT COLLATE "C" NOT NULL,
    requested_expiration_seconds       BIGINT NOT NULL,
    server_lifetime_hard_max_seconds   BIGINT NOT NULL,
    clock_uncertainty_seconds          BIGINT NOT NULL,
    deletion_propagation_hard_max_seconds BIGINT NOT NULL,
    secret_lifecycle_subject           TEXT COLLATE "C" NOT NULL,
    secret_lifecycle_rbac_commitment   TEXT COLLATE "C" NOT NULL,
    service_account_token_subject      TEXT COLLATE "C" NOT NULL,
    service_account_token_rbac_commitment TEXT COLLATE "C" NOT NULL,
    token_review_subject               TEXT COLLATE "C" NOT NULL,
    token_review_rbac_commitment       TEXT COLLATE "C" NOT NULL,
    created_at                         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_eks_destination_activations_pkey
        PRIMARY KEY (
            tenant, environment,
            resource_activation_id, mediation_activation_id
        ),
    CONSTRAINT accordlock_eks_destination_activations_commitment_key
        UNIQUE (activation_commitment),
    CONSTRAINT accordlock_eks_destination_activations_domain_key
        UNIQUE (
            tenant, environment,
            resource_root, resource_epoch, resource_activation_id,
            mediation_root, mediation_epoch, mediation_activation_id
        ),
    CONSTRAINT accordlock_eks_destination_activations_owner_fkey
        FOREIGN KEY (
            api_server_identity, namespace, deployment_uid,
            tenant, environment, cluster_identity, cluster_trust_domain,
            socket_target, ca_trust_commitment, state_instance_id
        )
        REFERENCES public.accordlock_eks_physical_owners (
            api_server_identity, namespace, deployment_uid,
            tenant, environment, cluster_identity, cluster_trust_domain,
            socket_target, ca_trust_commitment, state_instance_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_eks_destination_activations_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_eks_destination_activations_domain_check
        CHECK (
            resource_root ~ '^sha256:[0-9a-f]{64}$'
            AND resource_root <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND resource_epoch >= 0
            AND resource_activation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND mediation_root ~ '^sha256:[0-9a-f]{64}$'
            AND mediation_root <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND mediation_epoch >= 0
            AND mediation_activation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        ),
    CONSTRAINT accordlock_eks_destination_activations_commitments_check
        CHECK (
            activation_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND activation_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND route_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND route_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND ca_trust_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND ca_trust_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND effective_rbac_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND effective_rbac_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND terminal_witness_registry_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND terminal_witness_registry_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND credential_lifecycle_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND credential_lifecycle_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND secret_lifecycle_rbac_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND secret_lifecycle_rbac_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND service_account_token_rbac_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND service_account_token_rbac_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND token_review_rbac_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND token_review_rbac_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND secret_lifecycle_rbac_commitment <>
                service_account_token_rbac_commitment
            AND secret_lifecycle_rbac_commitment <> token_review_rbac_commitment
            AND service_account_token_rbac_commitment <> token_review_rbac_commitment
        ),
    CONSTRAINT accordlock_eks_destination_activations_lifecycle_check
        CHECK (
            credential_lifecycle_schema_version = 1
            AND credential_lifecycle_policy_id = 'eks-credential-lifecycle-v1'
            AND requested_expiration_seconds BETWEEN 1 AND 86400
            AND server_lifetime_hard_max_seconds BETWEEN
                requested_expiration_seconds AND 86400
            AND clock_uncertainty_seconds BETWEEN 0 AND 300
            AND deletion_propagation_hard_max_seconds BETWEEN 60 AND 86400
        ),
    CONSTRAINT accordlock_eks_destination_activations_identity_check
        CHECK (
            octet_length(tenant) BETWEEN 1 AND 253
            AND tenant = btrim(tenant)
            AND tenant !~ '[[:cntrl:]]'
            AND octet_length(environment) BETWEEN 1 AND 253
            AND environment = btrim(environment)
            AND environment !~ '[[:cntrl:]]'
            AND octet_length(cluster_trust_domain) BETWEEN 1 AND 512
            AND cluster_trust_domain = btrim(cluster_trust_domain)
            AND cluster_trust_domain !~ '[[:cntrl:]]'
            AND octet_length(cluster_identity) BETWEEN 1 AND 512
            AND cluster_identity = btrim(cluster_identity)
            AND cluster_identity !~ '[[:cntrl:]]'
            AND octet_length(api_server_identity) BETWEEN 1 AND 512
            AND api_server_identity = btrim(api_server_identity)
            AND api_server_identity !~ '[[:cntrl:]]'
            AND octet_length(dns_server_name) BETWEEN 1 AND 253
            AND dns_server_name = btrim(dns_server_name)
            AND dns_server_name !~ '[[:cntrl:]]'
            AND api_server_port BETWEEN 1 AND 65535
            AND octet_length(socket_target) BETWEEN 3 AND 64
            AND socket_target = btrim(socket_target)
            AND socket_target !~ '[[:cntrl:]]'
            AND octet_length(namespace) BETWEEN 1 AND 63
            AND namespace = btrim(namespace)
            AND namespace !~ '[[:cntrl:]]'
            AND octet_length(deployment_name) BETWEEN 1 AND 253
            AND deployment_name = btrim(deployment_name)
            AND deployment_name !~ '[[:cntrl:]]'
            AND octet_length(deployment_uid) BETWEEN 1 AND 512
            AND deployment_uid = btrim(deployment_uid)
            AND deployment_uid !~ '[[:cntrl:]]'
            AND octet_length(attempt_service_account_name) BETWEEN 1 AND 253
            AND attempt_service_account_name = btrim(attempt_service_account_name)
            AND attempt_service_account_name !~ '[[:cntrl:]]'
            AND octet_length(attempt_service_account_uid) BETWEEN 1 AND 512
            AND attempt_service_account_uid = btrim(attempt_service_account_uid)
            AND attempt_service_account_uid !~ '[[:cntrl:]]'
            AND octet_length(token_audience) BETWEEN 1 AND 512
            AND token_audience = btrim(token_audience)
            AND token_audience !~ '[[:cntrl:]]'
            AND octet_length(secret_lifecycle_subject) BETWEEN 1 AND 512
            AND secret_lifecycle_subject = btrim(secret_lifecycle_subject)
            AND secret_lifecycle_subject !~ '[[:space:][:cntrl:]]'
            AND octet_length(service_account_token_subject) BETWEEN 1 AND 512
            AND service_account_token_subject = btrim(service_account_token_subject)
            AND service_account_token_subject !~ '[[:space:][:cntrl:]]'
            AND octet_length(token_review_subject) BETWEEN 1 AND 512
            AND token_review_subject = btrim(token_review_subject)
            AND token_review_subject !~ '[[:space:][:cntrl:]]'
            AND secret_lifecycle_subject <> service_account_token_subject
            AND secret_lifecycle_subject <> token_review_subject
            AND service_account_token_subject <> token_review_subject
            AND token_subject =
                'system:serviceaccount:' || namespace || ':' ||
                attempt_service_account_name
        )
);

CREATE INDEX accordlock_eks_destination_activations_current_idx
    ON public.accordlock_eks_destination_activations (
        tenant, environment,
        resource_activation_id, mediation_activation_id
    );

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (11, '0011_eks_destination_registry');

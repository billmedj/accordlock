-- Root-mediated terminal witness material and atomic physical-reservation
-- retirement. Registry material is not a new trust root: every binding is an
-- exact foreign key to the full registry commitment already frozen by a v11
-- destination activation.

CREATE FUNCTION public.accordlock_reject_terminal_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $accordlock$
BEGIN
    RAISE EXCEPTION 'AccordLock terminal history is append-only';
END
$accordlock$;

ALTER TABLE public.accordlock_eks_destination_activations
    ADD CONSTRAINT accordlock_eks_destination_activations_terminal_registry_key
        UNIQUE (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            activation_commitment, cluster_identity,
            terminal_witness_registry_commitment
        );

CREATE TABLE public.accordlock_terminal_witness_registries (
    registry_commitment       TEXT COLLATE "C" NOT NULL,
    tenant                    TEXT COLLATE "C" NOT NULL,
    environment               TEXT COLLATE "C" NOT NULL,
    cluster_identity          TEXT COLLATE "C" NOT NULL,
    material_root             TEXT COLLATE "C" NOT NULL,
    registry_epoch            BIGINT NOT NULL,
    registry_activation_id    UUID NOT NULL,
    entry_count               SMALLINT NOT NULL,
    state_instance_id         UUID NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_terminal_witness_registries_pkey
        PRIMARY KEY (registry_commitment),
    CONSTRAINT accordlock_terminal_witness_registries_scope_key
        UNIQUE (
            registry_commitment, tenant, environment, cluster_identity
        ),
    CONSTRAINT accordlock_terminal_witness_registries_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_witness_registries_identity_check
        CHECK (
            octet_length(tenant) BETWEEN 1 AND 253
            AND tenant = btrim(tenant)
            AND tenant !~ '[[:cntrl:]]'
            AND octet_length(environment) BETWEEN 1 AND 253
            AND environment = btrim(environment)
            AND environment !~ '[[:cntrl:]]'
            AND octet_length(cluster_identity) BETWEEN 1 AND 512
            AND cluster_identity = btrim(cluster_identity)
            AND cluster_identity !~ '[[:cntrl:]]'
            AND registry_epoch > 0
            AND registry_activation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND entry_count BETWEEN 2 AND 256
        ),
    CONSTRAINT accordlock_terminal_witness_registries_commitments_check
        CHECK (
            registry_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND registry_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND material_root ~ '^sha256:[0-9a-f]{64}$'
            AND material_root <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
);

CREATE TABLE public.accordlock_terminal_witness_registry_entries (
    registry_commitment       TEXT COLLATE "C" NOT NULL,
    ordinal                   SMALLINT NOT NULL,
    tenant                    TEXT COLLATE "C" NOT NULL,
    environment               TEXT COLLATE "C" NOT NULL,
    cluster_identity          TEXT COLLATE "C" NOT NULL,
    role                      TEXT COLLATE "C" NOT NULL,
    observer_identity         TEXT COLLATE "C" NOT NULL,
    key_id                    TEXT COLLATE "C" NOT NULL,
    public_key                BYTEA NOT NULL,
    not_before                BIGINT NOT NULL,
    valid_until               BIGINT NOT NULL,
    accepted_through          BIGINT NOT NULL,
    authority_version         BIGINT NOT NULL,
    authorizing_root          TEXT COLLATE "C" NOT NULL,
    status                    TEXT COLLATE "C" NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_terminal_witness_registry_entries_pkey
        PRIMARY KEY (registry_commitment, ordinal),
    CONSTRAINT accordlock_terminal_witness_registry_entries_key_id_key
        UNIQUE (registry_commitment, key_id),
    CONSTRAINT accordlock_terminal_witness_registry_entries_public_key_key
        UNIQUE (registry_commitment, public_key),
    CONSTRAINT accordlock_terminal_witness_registry_entries_observer_key
        UNIQUE (registry_commitment, observer_identity),
    CONSTRAINT accordlock_terminal_witness_registry_entries_registry_fkey
        FOREIGN KEY (
            registry_commitment, tenant, environment, cluster_identity
        )
        REFERENCES public.accordlock_terminal_witness_registries (
            registry_commitment, tenant, environment, cluster_identity
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_witness_registry_entries_shape_check
        CHECK (
            ordinal BETWEEN 0 AND 255
            AND role IN ('EXACT_EFFECT', 'CREDENTIAL_RETIREMENT')
            AND status IN ('ACTIVE', 'RETIRED', 'REVOKED')
            AND octet_length(observer_identity) BETWEEN 1 AND 512
            AND observer_identity = btrim(observer_identity)
            AND observer_identity !~ '[[:cntrl:]]'
            AND octet_length(key_id) BETWEEN 1 AND 256
            AND key_id = btrim(key_id)
            AND key_id !~ '[[:cntrl:]]'
            AND octet_length(public_key) = 32
            AND not_before > 0
            AND valid_until > not_before
            AND accepted_through BETWEEN not_before AND valid_until - 1
            AND authority_version > 0
            AND authorizing_root ~ '^sha256:[0-9a-f]{64}$'
            AND authorizing_root <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
);

CREATE TABLE public.accordlock_terminal_witness_registry_bindings (
    tenant                    TEXT COLLATE "C" NOT NULL,
    environment               TEXT COLLATE "C" NOT NULL,
    resource_activation_id    UUID NOT NULL,
    mediation_activation_id   UUID NOT NULL,
    destination_activation_commitment TEXT COLLATE "C" NOT NULL,
    cluster_identity          TEXT COLLATE "C" NOT NULL,
    registry_commitment       TEXT COLLATE "C" NOT NULL,
    state_instance_id         UUID NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_terminal_witness_registry_bindings_pkey
        PRIMARY KEY (
            tenant, environment,
            resource_activation_id, mediation_activation_id
        ),
    CONSTRAINT accordlock_terminal_witness_registry_bindings_full_key
        UNIQUE (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            registry_commitment
        ),
    CONSTRAINT accordlock_terminal_witness_registry_bindings_destination_fkey
        FOREIGN KEY (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            destination_activation_commitment, cluster_identity,
            registry_commitment
        )
        REFERENCES public.accordlock_eks_destination_activations (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            activation_commitment, cluster_identity,
            terminal_witness_registry_commitment
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_witness_registry_bindings_registry_fkey
        FOREIGN KEY (
            registry_commitment, tenant, environment, cluster_identity
        )
        REFERENCES public.accordlock_terminal_witness_registries (
            registry_commitment, tenant, environment, cluster_identity
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_witness_registry_bindings_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT
);

ALTER TABLE public.accordlock_broker_operations
    ADD COLUMN deletion_observation_floor_unix_s BIGINT
        GENERATED ALWAYS AS (
            COALESCE(last_reconciled_unix_s, started_unix_s)
        ) STORED,
    ADD CONSTRAINT accordlock_broker_operations_deletion_observation_key
        UNIQUE (
            entry_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid,
            route_commitment, bound_secret_name, bound_secret_uid,
            operation, phase, started_unix_s,
            deletion_observation_floor_unix_s,
            outcome, request_commitment, result_commitment,
            provider_evidence_commitment
        );

CREATE TABLE public.accordlock_broker_secret_deletion_observations (
    entry_id                         UUID NOT NULL,
    tenant                           TEXT COLLATE "C" NOT NULL,
    environment                      TEXT COLLATE "C" NOT NULL,
    authorization_id                              UUID NOT NULL,
    transaction_id                   UUID NOT NULL,
    claim_id                         UUID NOT NULL,
    fence                            BIGINT NOT NULL,
    state_instance_id                UUID NOT NULL,
    cluster_identity                 TEXT COLLATE "C" NOT NULL,
    namespace                        TEXT COLLATE "C" NOT NULL,
    deployment_uid                   TEXT COLLATE "C" NOT NULL,
    route_commitment                 TEXT COLLATE "C" NOT NULL,
    bound_secret_name                TEXT COLLATE "C" NOT NULL,
    bound_secret_uid                 TEXT COLLATE "C" NOT NULL,
    operation                        TEXT COLLATE "C" NOT NULL,
    phase                            TEXT COLLATE "C" NOT NULL,
    started_unix_s                   BIGINT NOT NULL,
    reconciliation_floor_unix_s      BIGINT NOT NULL,
    outcome                          TEXT COLLATE "C" NOT NULL,
    journal_request_commitment       TEXT COLLATE "C" NOT NULL,
    journal_result_commitment        TEXT COLLATE "C" NOT NULL,
    provider_evidence_commitment     TEXT COLLATE "C" NOT NULL,
    observed_unix_s                  BIGINT NOT NULL,
    created_at                       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_broker_secret_deletion_observations_pkey
        PRIMARY KEY (entry_id),
    CONSTRAINT accordlock_broker_secret_deletion_observations_claim_key
        UNIQUE (claim_id),
    CONSTRAINT accordlock_broker_secret_deletion_observations_fence_key
        UNIQUE (fence),
    CONSTRAINT accordlock_broker_secret_deletion_observations_transaction_key
        UNIQUE (tenant, environment, transaction_id),
    CONSTRAINT accordlock_broker_deletion_obs_authorization_id_key
        UNIQUE (
            entry_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid
        ),
    CONSTRAINT accordlock_broker_secret_deletion_observations_operation_fkey
        FOREIGN KEY (
            entry_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid,
            route_commitment, bound_secret_name, bound_secret_uid,
            operation, phase, started_unix_s,
            reconciliation_floor_unix_s,
            outcome, journal_request_commitment, journal_result_commitment,
            provider_evidence_commitment
        )
        REFERENCES public.accordlock_broker_operations (
            entry_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid,
            route_commitment, bound_secret_name, bound_secret_uid,
            operation, phase, started_unix_s,
            deletion_observation_floor_unix_s,
            outcome, request_commitment, result_commitment,
            provider_evidence_commitment
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_broker_secret_deletion_observations_shape_check
        CHECK (
            operation = 'DELETE_SECRET'
            AND phase = 'COMMITTED'
            AND outcome = 'DELETE_ABSENT'
            AND observed_unix_s >= started_unix_s
            AND reconciliation_floor_unix_s >= started_unix_s
            AND observed_unix_s >= reconciliation_floor_unix_s
            AND bound_secret_name =
                'accordlock-' || replace(transaction_id::text, '-', '')
            AND octet_length(bound_secret_uid) BETWEEN 1 AND 512
            AND bound_secret_uid = btrim(bound_secret_uid)
            AND bound_secret_uid !~ '[[:cntrl:]]'
            AND route_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND journal_request_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND journal_result_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND provider_evidence_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND route_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND journal_request_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND journal_result_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND provider_evidence_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
);

ALTER TABLE public.accordlock_admission_authorizations
    ADD CONSTRAINT accordlock_admission_authorizations_terminal_binding_key
        UNIQUE (
            admission_uid, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid,
            request_commitment
        );

ALTER TABLE public.accordlock_dispatch_claims
    DROP CONSTRAINT accordlock_dispatch_claims_physical_resource_key,
    DROP CONSTRAINT accordlock_dispatch_claims_state_check,
    DROP CONSTRAINT accordlock_dispatch_claims_state_time_check,
    ADD COLUMN terminalization_id UUID,
    ADD CONSTRAINT accordlock_dispatch_claims_state_check
        CHECK (state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT', 'TERMINAL')),
    ADD CONSTRAINT accordlock_dispatch_claims_terminalization_id_check
        CHECK (
            terminalization_id IS NULL
            OR terminalization_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        ),
    ADD CONSTRAINT accordlock_dispatch_claims_state_time_check
        CHECK (
            (
                state = 'CLAIMED'
                AND terminalization_id IS NULL
                AND attempt_started_at IS NULL
                AND credential_token_digest IS NULL
                AND service_account_uid IS NULL
                AND credential_id IS NULL
                AND credential_not_before IS NULL
                AND credential_expires_at IS NULL
                AND credential_binding_commitment IS NULL
            )
            OR (
                state IN ('ATTEMPT_IN_FLIGHT', 'TERMINAL')
                AND (state = 'TERMINAL') = (terminalization_id IS NOT NULL)
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
        );

CREATE UNIQUE INDEX accordlock_dispatch_claims_active_physical_resource_key
    ON public.accordlock_dispatch_claims (
        cluster_identity, namespace, deployment_uid
    )
    WHERE state IN ('CLAIMED', 'ATTEMPT_IN_FLIGHT');

CREATE TABLE public.accordlock_terminal_retirements (
    terminalization_id                   UUID NOT NULL,
    tenant                               TEXT COLLATE "C" NOT NULL,
    environment                          TEXT COLLATE "C" NOT NULL,
    authorization_id                                  UUID NOT NULL,
    transaction_id                       UUID NOT NULL,
    claim_id                             UUID NOT NULL,
    fence                                BIGINT NOT NULL,
    state_instance_id                    UUID NOT NULL,
    cluster_identity                     TEXT COLLATE "C" NOT NULL,
    namespace                            TEXT COLLATE "C" NOT NULL,
    deployment_uid                       TEXT COLLATE "C" NOT NULL,
    resource_activation_id               UUID NOT NULL,
    mediation_activation_id              UUID NOT NULL,
    attempt_binding_commitment            TEXT COLLATE "C" NOT NULL,
    registry_commitment                   TEXT COLLATE "C" NOT NULL,
    admission_uid                        TEXT COLLATE "C" NOT NULL,
    admission_request_commitment          TEXT COLLATE "C" NOT NULL,
    effect_evidence_id                    UUID NOT NULL,
    effect_envelope_commitment            TEXT COLLATE "C" NOT NULL,
    effect_envelope                       BYTEA NOT NULL,
    retirement_evidence_id                UUID NOT NULL,
    retirement_envelope_commitment        TEXT COLLATE "C" NOT NULL,
    retirement_envelope                   BYTEA NOT NULL,
    deletion_journal_entry_id             UUID NOT NULL,
    deletion_observation_commitment       TEXT COLLATE "C" NOT NULL,
    finalized_unix_s                      BIGINT NOT NULL,
    terminal_record_commitment            TEXT COLLATE "C" NOT NULL,
    created_at                            TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_terminal_retirements_pkey
        PRIMARY KEY (terminalization_id),
    CONSTRAINT accordlock_terminal_retirements_authorization_id_key
        UNIQUE (tenant, environment, authorization_id),
    CONSTRAINT accordlock_terminal_retirements_transaction_key
        UNIQUE (tenant, environment, transaction_id),
    CONSTRAINT accordlock_terminal_retirements_claim_key UNIQUE (claim_id),
    CONSTRAINT accordlock_terminal_retirements_fence_key UNIQUE (fence),
    CONSTRAINT accordlock_terminal_retirements_effect_evidence_key
        UNIQUE (effect_evidence_id),
    CONSTRAINT accordlock_terminal_retirements_retirement_evidence_key
        UNIQUE (retirement_evidence_id),
    CONSTRAINT accordlock_terminal_retirements_effect_envelope_key
        UNIQUE (effect_envelope_commitment),
    CONSTRAINT accordlock_terminal_retirements_retirement_envelope_key
        UNIQUE (retirement_envelope_commitment),
    CONSTRAINT accordlock_terminal_retirements_record_key
        UNIQUE (terminal_record_commitment),
    CONSTRAINT accordlock_terminal_retirements_claim_pointer_key
        UNIQUE (
            terminalization_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid
        ),
    CONSTRAINT accordlock_terminal_retirements_claim_fkey
        FOREIGN KEY (
            tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid
        )
        REFERENCES public.accordlock_dispatch_claims (
            tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_retirements_registry_fkey
        FOREIGN KEY (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            registry_commitment
        )
        REFERENCES public.accordlock_terminal_witness_registry_bindings (
            tenant, environment,
            resource_activation_id, mediation_activation_id,
            registry_commitment
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_retirements_admission_fkey
        FOREIGN KEY (
            admission_uid, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid,
            admission_request_commitment
        )
        REFERENCES public.accordlock_admission_authorizations (
            admission_uid, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid,
            request_commitment
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_retirements_deletion_fkey
        FOREIGN KEY (
            deletion_journal_entry_id, tenant, environment, authorization_id,
            transaction_id, claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid
        )
        REFERENCES public.accordlock_broker_secret_deletion_observations (
            entry_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, state_instance_id,
            cluster_identity, namespace, deployment_uid
        )
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_retirements_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_terminal_retirements_identity_check
        CHECK (
            terminalization_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND claim_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND effect_evidence_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND retirement_evidence_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND deletion_journal_entry_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND fence > 0
            AND finalized_unix_s > 0
            AND octet_length(effect_envelope) BETWEEN 1 AND 1115136
            AND octet_length(retirement_envelope) BETWEEN 1 AND 1115136
        ),
    CONSTRAINT accordlock_terminal_retirements_commitments_check
        CHECK (
            attempt_binding_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND registry_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND admission_request_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND effect_envelope_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND retirement_envelope_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND deletion_observation_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND terminal_record_commitment ~ '^sha256:[0-9a-f]{64}$'
            AND attempt_binding_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND registry_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND admission_request_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND effect_envelope_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND retirement_envelope_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND deletion_observation_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
            AND terminal_record_commitment <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
);

ALTER TABLE public.accordlock_dispatch_claims
    ADD CONSTRAINT accordlock_dispatch_claims_terminal_fkey
        FOREIGN KEY (
            terminalization_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid
        )
        REFERENCES public.accordlock_terminal_retirements (
            terminalization_id, tenant, environment, authorization_id, transaction_id,
            claim_id, fence, cluster_identity, namespace, deployment_uid
        )
        ON DELETE RESTRICT;

CREATE TRIGGER accordlock_terminal_witness_registries_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_terminal_witness_registries
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_terminal_history_mutation();
CREATE TRIGGER accordlock_terminal_witness_registry_entries_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_terminal_witness_registry_entries
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_terminal_history_mutation();
CREATE TRIGGER accordlock_terminal_witness_registry_bindings_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_terminal_witness_registry_bindings
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_terminal_history_mutation();
CREATE TRIGGER accordlock_broker_secret_deletion_observations_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_broker_secret_deletion_observations
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_terminal_history_mutation();
CREATE TRIGGER accordlock_terminal_retirements_append_only
    BEFORE UPDATE OR DELETE ON public.accordlock_terminal_retirements
    FOR EACH ROW EXECUTE FUNCTION public.accordlock_reject_terminal_history_mutation();

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (12, '0012_terminal_retirement');

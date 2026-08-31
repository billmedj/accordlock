-- Durable application-ingress replay ledger. The scope high-water row is
-- permanent: deleting or lowering it could make an expired authenticated
-- request valid after trusted-clock rollback. Only expired nonce rows are GC
-- candidates, and only relative to that durable high-water value.

CREATE TABLE public.accordlock_ingress_replay_scopes (
    replay_scope       TEXT COLLATE "C" NOT NULL,
    state_instance_id  UUID NOT NULL,
    observed_unix_s    BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_ingress_replay_scopes_pkey
        PRIMARY KEY (replay_scope),
    CONSTRAINT accordlock_ingress_replay_scopes_lineage_key
        UNIQUE (replay_scope, state_instance_id),
    CONSTRAINT accordlock_ingress_replay_scopes_state_fkey
        FOREIGN KEY (state_instance_id)
        REFERENCES public.accordlock_state_metadata (state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_ingress_replay_scopes_identity_check
        CHECK (
            octet_length(replay_scope) BETWEEN 1 AND 4096
            AND replay_scope = btrim(replay_scope)
            AND replay_scope !~ '[[:cntrl:]]'
        ),
    CONSTRAINT accordlock_ingress_replay_scopes_time_check
        CHECK (observed_unix_s >= 0)
);

CREATE TABLE public.accordlock_ingress_replay_nonces (
    replay_scope       TEXT COLLATE "C" NOT NULL,
    state_instance_id  UUID NOT NULL,
    key_id             TEXT COLLATE "C" NOT NULL,
    nonce              UUID NOT NULL,
    expires_unix_s     BIGINT NOT NULL,
    consumed_unix_s    BIGINT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT accordlock_ingress_replay_nonces_pkey
        PRIMARY KEY (replay_scope, key_id, nonce),
    CONSTRAINT accordlock_ingress_replay_nonces_scope_fkey
        FOREIGN KEY (replay_scope, state_instance_id)
        REFERENCES public.accordlock_ingress_replay_scopes
            (replay_scope, state_instance_id)
        ON DELETE RESTRICT,
    CONSTRAINT accordlock_ingress_replay_nonces_key_check
        CHECK (
            octet_length(key_id) BETWEEN 1 AND 256
            AND key_id = btrim(key_id)
            AND key_id !~ '[[:cntrl:]]'
        ),
    CONSTRAINT accordlock_ingress_replay_nonces_nonce_check
        CHECK (nonce <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT accordlock_ingress_replay_nonces_time_check
        CHECK (
            consumed_unix_s >= 0
            AND expires_unix_s > consumed_unix_s
        )
);

CREATE INDEX accordlock_ingress_replay_nonces_expiry_idx
    ON public.accordlock_ingress_replay_nonces
        (replay_scope, expires_unix_s, key_id, nonce);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (10, '0010_ingress_replay');

-- Bind every durable dispatch claim to the physical Deployment identity
-- committed by its stored signed authorization. The unique key is intentionally
-- global: tenant, environment, logical Deployment name, container, operation,
-- and resourceVersion cannot alias one physical object into two reservations.

ALTER TABLE public.accordlock_dispatch_claims
    ADD COLUMN cluster_identity TEXT COLLATE "C",
    ADD COLUMN namespace TEXT COLLATE "C",
    ADD COLUMN deployment_uid TEXT COLLATE "C";

-- Upgrade existing v5 claims from trusted immutable issuance records. A
-- partial or corrupt lineage remains NULL and makes the migration fail closed.
UPDATE public.accordlock_dispatch_claims AS claim
   SET cluster_identity = issued.record_json #>>
            '{signed_authorization,authorization,template,cluster_identity}',
       namespace = issued.record_json #>>
            '{signed_authorization,authorization,template,namespace}',
       deployment_uid = issued.record_json #>>
            '{signed_authorization,authorization,template,deployment_uid}'
  FROM public.accordlock_issued_authorizations AS issued
 WHERE issued.tenant = claim.tenant
   AND issued.environment = claim.environment
   AND issued.authorization_id = claim.authorization_id
   AND issued.transaction_id = claim.transaction_id;

ALTER TABLE public.accordlock_dispatch_claims
    ALTER COLUMN cluster_identity SET NOT NULL,
    ALTER COLUMN namespace SET NOT NULL,
    ALTER COLUMN deployment_uid SET NOT NULL,
    ADD CONSTRAINT accordlock_dispatch_claims_physical_identity_check
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
    ADD CONSTRAINT accordlock_dispatch_claims_physical_resource_key
        UNIQUE (cluster_identity, namespace, deployment_uid);

INSERT INTO public.accordlock_schema_migrations (version, name)
VALUES (6, '0006_physical_resource_reservations')
ON CONFLICT (version) DO NOTHING;

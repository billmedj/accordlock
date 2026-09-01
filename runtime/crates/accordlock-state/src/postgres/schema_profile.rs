use postgres::Transaction;

use crate::StateError;

use super::migration_checksum;

// PostgreSQL preserves the same enforced objects while allowing catalog
// decompilation details to vary across supported PostgreSQL 17 builds. Keep
// every explicitly accepted representation exact: an unknown rendering still
// fails closed instead of being normalized away.
const CONTROL_SCHEMA_PROFILES_BY_SERVER_VERSION: &[(i32, &str)] = &[
    // PostgreSQL 17.4 on Windows. Both exact catalog renderings have been
    // observed for the supported schema, including the repository's fresh
    // project-local cluster initialized with the C locale.
    (
        170_004,
        "sha256:6955bdb6f22eda58b94019a63e0b13e97443483fcf8c3324724c9e01fd6154ea",
    ),
    (
        170_004,
        "sha256:71b32cf28dbb4f7b3057304da0d59373bfa11521112688bcfc5c8b550562c799",
    ),
    // PostgreSQL 17.11 from the checksum-pinned official Debian image used in CI.
    (
        170_011,
        "sha256:71b32cf28dbb4f7b3057304da0d59373bfa11521112688bcfc5c8b550562c799",
    ),
];

const DISPATCH_ACQUISITION_SCHEMA_PROFILE_SHA256: &str =
    "sha256:524a01ce398a1a7dec8d43ed2d7f67eb613ed5e4fdf159387f39f474e81a3626";

fn control_schema_server_version_is_supported(server_version_num: i32) -> bool {
    CONTROL_SCHEMA_PROFILES_BY_SERVER_VERSION
        .iter()
        .any(|(version, _)| *version == server_version_num)
}

fn control_schema_checksum_is_accepted(server_version_num: i32, checksum: &str) -> bool {
    CONTROL_SCHEMA_PROFILES_BY_SERVER_VERSION
        .iter()
        .any(|(version, expected)| *version == server_version_num && *expected == checksum)
}

const DISPATCH_ACQUISITION_SCHEMA_PROFILE_SQL: &str = r#"
SELECT profile_line
  FROM (
        SELECT jsonb_build_array(
                   'table', class.relname, class.relkind::text,
                   class.relpersistence::text, class.relrowsecurity,
                   class.relforcerowsecurity
               )::text COLLATE "C" AS profile_line
          FROM pg_class AS class
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND class.relname IN (
                'accordlock_dispatch_request_identities',
                'accordlock_dispatch_acquisitions',
                'accordlock_dispatch_queue_dispositions',
                'accordlock_dispatch_credential_reviews'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'column', class.relname, attribute.attnum,
                   attribute.attname,
                   format_type(attribute.atttypid, attribute.atttypmod),
                   attribute.attnotnull,
                   COALESCE(coll_namespace.nspname, ''),
                   COALESCE(coll.collname, ''),
                   COALESCE(coll.collprovider::text, ''),
                   COALESCE(coll.collisdeterministic::text, ''),
                   COALESCE(coll.collencoding::text, ''),
                   COALESCE(coll.collcollate, ''),
                   COALESCE(coll.collctype, ''),
                   attribute.attidentity::text,
                   attribute.attgenerated::text,
                   COALESCE(
                       pg_get_expr(default_value.adbin, default_value.adrelid),
                       ''
                   )
               )::text COLLATE "C" AS profile_line
          FROM pg_attribute AS attribute
          JOIN pg_class AS class ON class.oid = attribute.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
          LEFT JOIN pg_collation AS coll ON coll.oid = attribute.attcollation
          LEFT JOIN pg_namespace AS coll_namespace
            ON coll_namespace.oid = coll.collnamespace
          LEFT JOIN pg_attrdef AS default_value
            ON default_value.adrelid = attribute.attrelid
           AND default_value.adnum = attribute.attnum
         WHERE namespace.nspname = 'public'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND (
                class.relname IN (
                    'accordlock_dispatch_request_identities',
                    'accordlock_dispatch_acquisitions',
                    'accordlock_dispatch_queue_dispositions',
                    'accordlock_dispatch_credential_reviews'
                )
                OR class.relname = 'accordlock_dispatch_claims'
                   AND attribute.attname IN (
                        'attempt_acquisition_id', 'attempt_lease_fence',
                        'attempt_acquired_unix_s', 'attempt_lease_until',
                        'acquisition_binding_version',
                        'credential_review_id',
                        'recovery_safe_after_unix_s',
                        'recovery_retired_unix_s'
                   )
                OR class.relname = 'accordlock_broker_operations'
                   AND attribute.attname IN (
                        'origin_acquisition_id', 'origin_lease_fence',
                        'acquisition_binding_version'
                   )
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'constraint', class.relname, constraint_value.conname,
                   constraint_value.contype::text,
                   constraint_value.convalidated,
                   constraint_value.condeferrable,
                   constraint_value.condeferred,
                   constraint_value.connoinherit,
                   constraint_value.confmatchtype::text,
                   constraint_value.confupdtype::text,
                   constraint_value.confdeltype::text,
                   pg_get_constraintdef(constraint_value.oid, TRUE)
               )::text COLLATE "C" AS profile_line
          FROM pg_constraint AS constraint_value
          JOIN pg_class AS class ON class.oid = constraint_value.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND (
                class.relname IN (
                    'accordlock_dispatch_request_identities',
                    'accordlock_dispatch_acquisitions',
                    'accordlock_dispatch_queue_dispositions',
                    'accordlock_dispatch_credential_reviews'
                )
                OR constraint_value.conname IN (
                    'accordlock_dispatch_claims_acquisition_binding_key',
                    'accordlock_dispatch_claims_attempt_acquisition_fkey',
                    'accordlock_dispatch_claims_credential_review_fkey',
                    'accordlock_dispatch_claims_state_check',
                    'accordlock_dispatch_claims_state_time_check',
                    'accordlock_broker_operations_acquisition_fkey',
                    'accordlock_broker_operations_acquisition_version_check'
                )
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'index', table_class.relname, index_class.relname,
                   index_value.indisvalid, index_value.indisready,
                   index_value.indislive, index_value.indisunique,
                   index_value.indisprimary, index_value.indisexclusion,
                   index_value.indimmediate,
                   pg_get_indexdef(index_class.oid)
               )::text COLLATE "C" AS profile_line
          FROM pg_index AS index_value
          JOIN pg_class AS index_class ON index_class.oid = index_value.indexrelid
          JOIN pg_class AS table_class ON table_class.oid = index_value.indrelid
          JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
         WHERE namespace.nspname = 'public'
           AND (
                table_class.relname IN (
                    'accordlock_dispatch_request_identities',
                    'accordlock_dispatch_acquisitions',
                    'accordlock_dispatch_queue_dispositions',
                    'accordlock_dispatch_credential_reviews'
                )
                OR index_class.relname IN (
                    'accordlock_dispatch_claims_acquisition_binding_key',
                    'accordlock_dispatch_claims_active_physical_resource_key'
                )
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'trigger', relation.relname, trigger_value.tgname,
                   trigger_value.tgenabled::text,
                   pg_get_triggerdef(trigger_value.oid, TRUE)
               )::text COLLATE "C" AS profile_line
          FROM pg_trigger AS trigger_value
          JOIN pg_class AS relation ON relation.oid = trigger_value.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND NOT trigger_value.tgisinternal
           -- Profile the complete user-trigger set on every relation whose
           -- mutation behavior v14 relies on. A later trigger sorts by name
           -- and can rewrite NEW after a guard, so whitelisting only expected
           -- v14 trigger names would leave that drift invisible.
           AND relation.relname IN (
                'accordlock_dispatch_request_identities',
                'accordlock_dispatch_acquisitions',
                'accordlock_dispatch_queue_dispositions',
                'accordlock_dispatch_credential_reviews',
                'accordlock_dispatch_claims',
                'accordlock_broker_operations',
                'accordlock_broker_secret_deletion_observations',
                'accordlock_admission_authorizations',
                'accordlock_terminal_retirements',
                'accordlock_eks_destination_activations',
                'accordlock_grants',
                'accordlock_issued_authorizations',
                'accordlock_consumptions',
                'accordlock_execution_outbox',
                'accordlock_authority_state',
                'accordlock_time_high_water',
                'accordlock_ingress_replay_scopes'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'function', proc.proname,
                   pg_get_function_identity_arguments(proc.oid),
                   pg_get_function_result(proc.oid), language.lanname,
                   proc.provolatile::text, proc.prosecdef, proc.proleakproof,
                   proc.proparallel::text, COALESCE(proc.proconfig::text, ''),
                   proc.prosrc, COALESCE(proc.probin, '')
               )::text COLLATE "C" AS profile_line
          FROM pg_proc AS proc
          JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
          JOIN pg_language AS language ON language.oid = proc.prolang
         WHERE namespace.nspname = 'public'
           AND proc.proname IN (
                'accordlock_reject_dispatch_acquisition_mutation',
                'accordlock_reject_dispatch_disposition_mutation',
                'accordlock_dispatch_frame_commitment',
                'accordlock_dispatch_authority_fact_commitment',
                'accordlock_dispatch_grant_fact_commitment',
                'accordlock_dispatch_outbox_fact_commitment',
                'accordlock_guard_dispatch_request_identity_update',
                'accordlock_check_dispatch_request_identity_child',
                'accordlock_guard_dispatch_claim_v14_insert',
                'accordlock_check_dispatch_claim_acquisition',
                'accordlock_guard_dispatch_acquisition_insert',
                'accordlock_guard_dispatch_claim_v14_update',
                'accordlock_guard_dispatch_queue_disposition_insert',
                'accordlock_check_dispatch_disposition_claim_state',
                'accordlock_check_disposed_claim_disposition',
                'accordlock_guard_broker_acquisition_insert',
                'accordlock_guard_broker_acquisition_update',
                'accordlock_reject_broker_operation_delete',
                'accordlock_guard_dispatch_credential_review_insert',
                'accordlock_guard_dispatch_credential_review_update',
                'accordlock_reject_dispatch_credential_review_delete',
                'accordlock_guard_dispatch_admission_insert',
                'accordlock_guard_dispatch_terminal_insert'
                ,'accordlock_guard_dispatch_grant_source_mutation'
                ,'accordlock_guard_dispatch_authorization_source_mutation'
                ,'accordlock_reject_dispatch_consumption_source_mutation'
                ,'accordlock_reject_dispatch_outbox_source_mutation'
                ,'accordlock_validate_dispatch_authority_source'
                ,'accordlock_guard_dispatch_high_water_mutation'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'sequence', sequence_namespace.nspname,
                   sequence_class.relname, table_class.relname,
                   attribute.attname, attribute.attidentity::text,
                   format_type(attribute.atttypid, attribute.atttypmod),
                   sequence_value.seqincrement, sequence_value.seqmin,
                   sequence_value.seqmax, sequence_value.seqstart,
                   sequence_value.seqcache, sequence_value.seqcycle
               )::text COLLATE "C" AS profile_line
          FROM pg_attribute AS attribute
          JOIN pg_class AS table_class ON table_class.oid = attribute.attrelid
          JOIN pg_namespace AS table_namespace
            ON table_namespace.oid = table_class.relnamespace
          JOIN pg_class AS sequence_class
            ON sequence_class.oid = pg_get_serial_sequence(
                'public.accordlock_dispatch_acquisitions', 'lease_fence'
            )::regclass
          JOIN pg_namespace AS sequence_namespace
            ON sequence_namespace.oid = sequence_class.relnamespace
          JOIN pg_sequence AS sequence_value
            ON sequence_value.seqrelid = sequence_class.oid
         WHERE table_namespace.nspname = 'public'
           AND table_class.relname = 'accordlock_dispatch_acquisitions'
           AND attribute.attname = 'lease_fence'
           AND NOT attribute.attisdropped
       ) AS profile
 ORDER BY profile_line
"#;

// Keep every field in a JSON array so the profile is unambiguous even when a
// function body contains newlines or a PostgreSQL identifier contains a
// separator. jsonb's textual representation is deterministic for arrays.
const CONTROL_SCHEMA_PROFILE_SQL: &str = r#"
SELECT profile_line
  FROM (
        SELECT jsonb_build_array(
                   'table', class.relname, class.relkind::text,
                   class.relpersistence::text, class.relrowsecurity,
                   class.relforcerowsecurity
               )::text COLLATE "C" AS profile_line
          FROM pg_class AS class
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND class.relname IN (
                'accordlock_control_submissions',
                'accordlock_control_status',
                'accordlock_control_events',
                'accordlock_control_evaluations',
                'accordlock_control_decisions',
                'accordlock_control_work_claims',
                'accordlock_control_work_queue',
                'accordlock_control_work_finalizations',
                'accordlock_control_issuances',
                'accordlock_control_consumptions',
                'accordlock_control_phase_completions'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'column', class.relname,
                   CASE
                       -- A synthetic v13 -> v12 test downgrade leaves physical
                       -- attisdropped slots before migration 0013 adds these
                       -- columns again. Column order is not part of their
                       -- payload contract; every meaningful attribute below
                       -- remains fingerprinted.
                       WHEN class.relname = 'accordlock_issued_authorizations'
                       THEN 0
                       ELSE attribute.attnum
                   END,
                   attribute.attname,
                   format_type(attribute.atttypid, attribute.atttypmod),
                   attribute.attnotnull,
                   COALESCE(coll_namespace.nspname, ''),
                   COALESCE(coll.collname, ''),
                   COALESCE(coll.collprovider::text, ''),
                   COALESCE(coll.collisdeterministic::text, ''),
                   COALESCE(coll.collencoding::text, ''),
                   COALESCE(coll.collcollate, ''),
                   COALESCE(coll.collctype, ''),
                   attribute.attidentity::text,
                   attribute.attgenerated::text,
                   COALESCE(
                       pg_get_expr(default_value.adbin, default_value.adrelid),
                       ''
                   )
               )::text COLLATE "C" AS profile_line
          FROM pg_attribute AS attribute
          JOIN pg_class AS class ON class.oid = attribute.attrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
          LEFT JOIN pg_collation AS coll ON coll.oid = attribute.attcollation
          LEFT JOIN pg_namespace AS coll_namespace
            ON coll_namespace.oid = coll.collnamespace
          LEFT JOIN pg_attrdef AS default_value
            ON default_value.adrelid = attribute.attrelid
           AND default_value.adnum = attribute.attnum
         WHERE namespace.nspname = 'public'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND (
                class.relname IN (
                    'accordlock_control_submissions',
                    'accordlock_control_status',
                    'accordlock_control_events',
                    'accordlock_control_evaluations',
                    'accordlock_control_decisions',
                    'accordlock_control_work_claims',
                    'accordlock_control_work_queue',
                    'accordlock_control_work_finalizations',
                    'accordlock_control_issuances',
                    'accordlock_control_consumptions',
                    'accordlock_control_phase_completions'
                )
                OR class.relname = 'accordlock_issued_authorizations'
                   AND attribute.attname IN ('request_id', 'evaluation_nonce')
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'constraint', class.relname, constraint_value.conname,
                   constraint_value.contype::text,
                   constraint_value.convalidated,
                   constraint_value.condeferrable,
                   constraint_value.condeferred,
                   constraint_value.connoinherit,
                   pg_get_constraintdef(constraint_value.oid, TRUE)
               )::text COLLATE "C" AS profile_line
          FROM pg_constraint AS constraint_value
          JOIN pg_class AS class ON class.oid = constraint_value.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public'
           AND (
                class.relname IN (
                    'accordlock_control_submissions',
                    'accordlock_control_status',
                    'accordlock_control_events',
                    'accordlock_control_evaluations',
                    'accordlock_control_decisions',
                    'accordlock_control_work_claims',
                    'accordlock_control_work_queue',
                    'accordlock_control_work_finalizations',
                    'accordlock_control_issuances',
                    'accordlock_control_consumptions',
                    'accordlock_control_phase_completions'
                )
                OR constraint_value.conname IN (
                    'accordlock_ingress_replay_nonces_control_lineage_key',
                    'accordlock_issued_authorizations_control_lineage_ids_check',
                    'accordlock_issued_authorizations_control_hash_key',
                    'accordlock_issued_authorizations_control_grant_hash_key',
                    'accordlock_execution_outbox_full_identity_key',
                    'accordlock_consumptions_control_exact_key',
                    'accordlock_execution_outbox_control_deadline_key'
                )
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'index', table_class.relname, index_class.relname,
                   index_value.indisvalid, index_value.indisready,
                   index_value.indislive, index_value.indisunique,
                   index_value.indisprimary, index_value.indisexclusion,
                   index_value.indimmediate,
                   pg_get_indexdef(index_class.oid)
               )::text COLLATE "C" AS profile_line
          FROM pg_index AS index_value
          JOIN pg_class AS index_class ON index_class.oid = index_value.indexrelid
          JOIN pg_class AS table_class ON table_class.oid = index_value.indrelid
          JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
         WHERE namespace.nspname = 'public'
           AND (
                table_class.relname IN (
                    'accordlock_control_submissions',
                    'accordlock_control_status',
                    'accordlock_control_events',
                    'accordlock_control_evaluations',
                    'accordlock_control_decisions',
                    'accordlock_control_work_claims',
                    'accordlock_control_work_queue',
                    'accordlock_control_work_finalizations',
                    'accordlock_control_issuances',
                    'accordlock_control_consumptions',
                    'accordlock_control_phase_completions'
                )
                OR index_class.relname IN (
                    'accordlock_ingress_replay_nonces_control_lineage_key',
                    'accordlock_issued_authorizations_control_hash_key',
                    'accordlock_issued_authorizations_control_grant_hash_key',
                    'accordlock_execution_outbox_full_identity_key',
                    'accordlock_consumptions_control_exact_key',
                    'accordlock_execution_outbox_control_deadline_key'
                )
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'trigger', relation.relname, trigger_value.tgname,
                   trigger_value.tgenabled::text,
                   pg_get_triggerdef(trigger_value.oid, TRUE)
               )::text COLLATE "C" AS profile_line
          FROM pg_trigger AS trigger_value
          JOIN pg_class AS relation ON relation.oid = trigger_value.tgrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND NOT trigger_value.tgisinternal
           AND relation.relname IN (
                'accordlock_control_submissions',
                'accordlock_control_status',
                'accordlock_control_events',
                'accordlock_control_evaluations',
                'accordlock_control_decisions',
                'accordlock_control_work_claims',
                'accordlock_control_work_queue',
                'accordlock_control_work_finalizations',
                'accordlock_control_issuances',
                'accordlock_control_consumptions',
                'accordlock_control_phase_completions'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'function', proc.proname,
                   pg_get_function_identity_arguments(proc.oid),
                   pg_get_function_result(proc.oid), language.lanname,
                   proc.provolatile::text, proc.prosecdef, proc.proleakproof,
                   proc.proparallel::text, COALESCE(proc.proconfig::text, ''),
                   proc.prosrc, COALESCE(proc.probin, '')
               )::text COLLATE "C" AS profile_line
          FROM pg_proc AS proc
          JOIN pg_namespace AS namespace ON namespace.oid = proc.pronamespace
          JOIN pg_language AS language ON language.oid = proc.prolang
         WHERE namespace.nspname = 'public'
           AND proc.proname IN (
                'accordlock_check_control_status_event',
                'accordlock_check_control_event_chain',
                'accordlock_check_control_terminal_exclusion',
                'accordlock_check_control_event_artifact',
                'accordlock_check_control_artifact_lease',
                'accordlock_check_control_queue_transition',
                'accordlock_reject_control_history_mutation'
           )
        UNION ALL
        SELECT jsonb_build_array(
                   'sequence', sequence_namespace.nspname,
                   sequence_class.relname, table_class.relname,
                   attribute.attname, attribute.attidentity::text,
                   format_type(attribute.atttypid, attribute.atttypmod),
                   sequence_value.seqincrement, sequence_value.seqmin,
                   sequence_value.seqmax, sequence_value.seqstart,
                   sequence_value.seqcache, sequence_value.seqcycle
               )::text COLLATE "C" AS profile_line
          FROM pg_attribute AS attribute
          JOIN pg_class AS table_class ON table_class.oid = attribute.attrelid
          JOIN pg_namespace AS table_namespace
            ON table_namespace.oid = table_class.relnamespace
          JOIN pg_class AS sequence_class
            ON sequence_class.oid = pg_get_serial_sequence(
                'public.accordlock_control_work_claims', 'fence'
            )::regclass
          JOIN pg_namespace AS sequence_namespace
            ON sequence_namespace.oid = sequence_class.relnamespace
          JOIN pg_sequence AS sequence_value
            ON sequence_value.seqrelid = sequence_class.oid
         WHERE table_namespace.nspname = 'public'
           AND table_class.relname = 'accordlock_control_work_claims'
           AND attribute.attname = 'fence'
           AND NOT attribute.attisdropped
       ) AS profile
 ORDER BY profile_line
"#;

pub(super) fn validate_control_schema(transaction: &mut Transaction<'_>) -> Result<(), StateError> {
    let server_version_num: i32 = transaction
        .query_one(
            "SELECT current_setting('server_version_num')::integer AS server_version_num",
            &[],
        )?
        .get("server_version_num");
    if !control_schema_server_version_is_supported(server_version_num) {
        return Err(StateError::SchemaMismatch(format!(
            "unsupported PostgreSQL server_version_num for durable-control schema profile: \
             {server_version_num}"
        )));
    }
    let lines: Vec<String> = transaction
        .query(CONTROL_SCHEMA_PROFILE_SQL, &[])?
        .into_iter()
        .map(|row| row.get("profile_line"))
        .collect();
    let checksum = migration_checksum(&lines.join("\n"));
    if !control_schema_checksum_is_accepted(server_version_num, &checksum) {
        return Err(StateError::SchemaMismatch(format!(
            "durable-control schema profile differs: {checksum}"
        )));
    }

    let fence_runtime = transaction.query_one(
        "SELECT sequence.last_value, sequence.is_called,
                (SELECT max(fence)
                   FROM public.accordlock_control_work_claims) AS max_fence
           FROM public.accordlock_control_work_claims_fence_seq AS sequence",
        &[],
    )?;
    let last_value: i64 = fence_runtime.get("last_value");
    let is_called: bool = fence_runtime.get("is_called");
    let max_fence: Option<i64> = fence_runtime.get("max_fence");
    if last_value < 1 || max_fence.is_some_and(|maximum| !is_called || last_value < maximum) {
        return Err(StateError::SchemaMismatch(
            "durable-control fence sequence is behind durable claim state".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_dispatch_acquisition_schema(
    transaction: &mut Transaction<'_>,
) -> Result<(), StateError> {
    let lines: Vec<String> = transaction
        .query(DISPATCH_ACQUISITION_SCHEMA_PROFILE_SQL, &[])?
        .into_iter()
        .map(|row| row.get("profile_line"))
        .collect();
    let checksum = migration_checksum(&lines.join("\n"));
    if checksum != DISPATCH_ACQUISITION_SCHEMA_PROFILE_SHA256 {
        return Err(StateError::SchemaMismatch(format!(
            "durable-dispatch-acquisition schema profile differs: {checksum}"
        )));
    }

    let fence_runtime = transaction.query_one(
        "SELECT sequence.last_value, sequence.is_called,
                (SELECT max(lease_fence)
                   FROM public.accordlock_dispatch_acquisitions) AS max_fence
           FROM public.accordlock_dispatch_acquisitions_lease_fence_seq AS sequence",
        &[],
    )?;
    let last_value: i64 = fence_runtime.get("last_value");
    let is_called: bool = fence_runtime.get("is_called");
    let max_fence: Option<i64> = fence_runtime.get("max_fence");
    if last_value < 1 || max_fence.is_some_and(|maximum| !is_called || last_value < maximum) {
        return Err(StateError::SchemaMismatch(
            "dispatch acquisition fence sequence is behind durable lease state".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{control_schema_checksum_is_accepted, control_schema_server_version_is_supported};

    #[test]
    fn control_schema_fingerprints_are_bound_to_exact_server_versions() {
        let windows_existing =
            "sha256:6955bdb6f22eda58b94019a63e0b13e97443483fcf8c3324724c9e01fd6154ea";
        let fresh_or_debian =
            "sha256:71b32cf28dbb4f7b3057304da0d59373bfa11521112688bcfc5c8b550562c799";
        assert!(control_schema_checksum_is_accepted(
            170_004,
            windows_existing
        ));
        assert!(control_schema_checksum_is_accepted(
            170_004,
            fresh_or_debian
        ));
        assert!(control_schema_checksum_is_accepted(
            170_011,
            fresh_or_debian
        ));
        assert!(!control_schema_checksum_is_accepted(
            170_011,
            windows_existing
        ));
        assert!(!control_schema_checksum_is_accepted(
            170_004,
            "sha256:unknown"
        ));
        assert!(control_schema_server_version_is_supported(170_004));
        assert!(control_schema_server_version_is_supported(170_011));
        assert!(!control_schema_server_version_is_supported(170_010));
        assert!(!control_schema_server_version_is_supported(180_000));
    }
}

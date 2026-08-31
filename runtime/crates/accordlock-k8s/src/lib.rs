//! Exact local Kubernetes mutation profile for `DEPLOY_EKS_IMAGE_V1`.

use std::collections::BTreeSet;

use accordlock_protocol::{CanonicalEncode, DeploymentTemplate, Digest32};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

const TRANSACTION_ANNOTATION: &str = "accordlock.io/transaction-id";
const AUTHORIZATION_ANNOTATION: &str = "accordlock.io/authorization-id";
const OPERATION_ANNOTATION: &str = "accordlock.io/operation-hash";
const DEPLOYMENT_REVISION_ANNOTATION: &str = "deployment.kubernetes.io/revision";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPatch {
    pub operation_hash: Digest32,
    pub patch: Value,
    /// Commitment to the fixed native Kubernetes PATCH adapter and its exact
    /// request. No caller-supplied shell command participates in this value.
    pub execution_command_commitment: Digest32,
    pub final_wire_commitment: Digest32,
}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("deployment object is missing required field {0}")]
    MissingField(String),
    #[error("deployment precondition failed for {0}")]
    Precondition(String),
    #[error("observed Kubernetes object changed unauthorized path {0}")]
    UnauthorizedDelta(String),
    #[error("expected authorized path was not set to its bound value: {0}")]
    AuthorizedValueMismatch(String),
    #[error("template canonicalization failed: {0}")]
    Canonical(String),
    #[error("provider body serialization failed: {0}")]
    Serialization(String),
    #[error("deployment template cannot be executed: {0}")]
    InvalidTemplate(String),
}

/// Builds the exact JSON Patch and its non-self-referential wire commitment.
///
/// # Errors
///
/// Returns [`ProjectionError`] when the template cannot be canonically encoded
/// or the provider body cannot be serialized.
pub fn prepare_patch(
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
) -> Result<PreparedPatch, ProjectionError> {
    validate_executable_template(template)?;
    let operation_hash = operation_hash(template, transaction_id, authorization_id)?;
    let annotation_base = "/metadata/annotations/";
    let transaction_path = format!(
        "{annotation_base}{}",
        escape_pointer(TRANSACTION_ANNOTATION)
    );
    let authorization_path = format!(
        "{annotation_base}{}",
        escape_pointer(AUTHORIZATION_ANNOTATION)
    );
    let operation_path = format!("{annotation_base}{}", escape_pointer(OPERATION_ANNOTATION));
    let container_base = format!(
        "/spec/template/spec/containers/{}",
        template.container_index
    );

    let patch = Value::Array(vec![
        json!({"op":"test","path":"/metadata/uid","value":template.deployment_uid}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":template.resource_version}),
        json!({"op":"test","path":format!("{container_base}/name"),"value":template.container}),
        json!({"op":"test","path":format!("{container_base}/image"),"value":image_reference(&template.image_repository, template.prior_image_digest)}),
        annotation_test(
            &transaction_path,
            required_prior_annotation(
                TRANSACTION_ANNOTATION,
                template.prior_transaction_annotation.as_deref(),
            )?,
        ),
        annotation_test(
            &authorization_path,
            required_prior_annotation(
                AUTHORIZATION_ANNOTATION,
                template.prior_authorization_annotation.as_deref(),
            )?,
        ),
        annotation_test(
            &operation_path,
            required_prior_annotation(
                OPERATION_ANNOTATION,
                template.prior_operation_hash_annotation.as_deref(),
            )?,
        ),
        json!({"op":"replace","path":format!("{container_base}/image"),"value":image_reference(&template.image_repository, template.image_digest)}),
        annotation_write(&transaction_path, &transaction_id.to_string()),
        annotation_write(&authorization_path, &authorization_id.to_string()),
        annotation_write(&operation_path, &operation_hash.to_string()),
    ]);

    let wire_body = serialize_patch_body(&patch)?;
    let provider_path = format!(
        "/apis/apps/v1/namespaces/{}/deployments/{}",
        template.namespace, template.deployment
    );
    let execution_command_commitment = native_execution_command_commitment(
        "PATCH",
        &provider_path,
        "application/json-patch+json",
        &wire_body,
    );
    let final_wire_commitment = wire_commitment(
        "PATCH",
        &provider_path,
        "application/json-patch+json",
        &wire_body,
    );
    Ok(PreparedPatch {
        operation_hash,
        patch,
        execution_command_commitment,
        final_wire_commitment,
    })
}

fn annotation_test(path: &str, prior: &str) -> Value {
    json!({"op":"test","path":path,"value":prior})
}

fn annotation_write(path: &str, value: &str) -> Value {
    json!({"op":"replace", "path":path, "value":value})
}

fn required_prior_annotation<'a>(
    key: &str,
    value: Option<&'a str>,
) -> Result<&'a str, ProjectionError> {
    value.ok_or_else(|| {
        ProjectionError::InvalidTemplate(format!(
            "reserved annotation {key:?} must be pre-provisioned"
        ))
    })
}

fn validate_executable_template(template: &DeploymentTemplate) -> Result<(), ProjectionError> {
    if template.operation != "DEPLOY_EKS_IMAGE_V1" {
        return Err(ProjectionError::InvalidTemplate(
            "operation is not DEPLOY_EKS_IMAGE_V1".to_owned(),
        ));
    }
    validate_dns_label("namespace", &template.namespace)?;
    validate_dns_subdomain("deployment", &template.deployment)?;
    validate_dns_label("container", &template.container)?;
    if template.deployment_uid.trim().is_empty() {
        return Err(ProjectionError::InvalidTemplate(
            "deployment UID is empty".to_owned(),
        ));
    }
    if template.resource_version.trim().is_empty() {
        return Err(ProjectionError::InvalidTemplate(
            "resourceVersion is empty".to_owned(),
        ));
    }
    validate_image_repository(&template.image_repository)?;
    for (key, value) in [
        (
            TRANSACTION_ANNOTATION,
            template.prior_transaction_annotation.as_deref(),
        ),
        (
            AUTHORIZATION_ANNOTATION,
            template.prior_authorization_annotation.as_deref(),
        ),
        (
            OPERATION_ANNOTATION,
            template.prior_operation_hash_annotation.as_deref(),
        ),
    ] {
        let _ = required_prior_annotation(key, value)?;
    }
    Ok(())
}

fn validate_image_repository(repository: &str) -> Result<(), ProjectionError> {
    if repository.is_empty()
        || repository.len() > 255
        || !repository.is_ascii()
        || repository.trim() != repository
        || repository.contains('@')
    {
        return Err(invalid_image_repository());
    }

    let components: Vec<_> = repository.split('/').collect();
    if components.iter().any(|component| component.is_empty()) {
        return Err(invalid_image_repository());
    }
    let first_is_registry = components.len() > 1
        && (components[0].contains('.')
            || components[0].contains(':')
            || components[0] == "localhost");
    let path_start = usize::from(first_is_registry);
    if first_is_registry {
        validate_registry_component(components[0])?;
    }
    if components[path_start..]
        .iter()
        .any(|component| !is_repository_path_component(component))
    {
        return Err(invalid_image_repository());
    }
    Ok(())
}

fn validate_registry_component(registry: &str) -> Result<(), ProjectionError> {
    let host = match registry.split_once(':') {
        Some((host, port)) => {
            if port.is_empty()
                || port.contains(':')
                || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid_image_repository());
            }
            let Ok(port_number) = port.parse::<u16>() else {
                return Err(invalid_image_repository());
            };
            if port_number == 0 {
                return Err(invalid_image_repository());
            }
            host
        }
        None => registry,
    };
    if host.is_empty()
        || host.len() > 253
        || host
            .split('.')
            .any(|label| validate_dns_label("image registry", label).is_err())
    {
        return Err(invalid_image_repository());
    }
    Ok(())
}

fn is_repository_path_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut index = 0;
    if !consume_ascii_lowercase_or_digit(bytes, &mut index) {
        return false;
    }
    while index < bytes.len() {
        match bytes[index] {
            b'.' => index += 1,
            b'_' => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                }
            }
            b'-' => {
                while bytes.get(index) == Some(&b'-') {
                    index += 1;
                }
            }
            _ => return false,
        }
        if !consume_ascii_lowercase_or_digit(bytes, &mut index) {
            return false;
        }
    }
    true
}

fn consume_ascii_lowercase_or_digit(bytes: &[u8], index: &mut usize) -> bool {
    let start = *index;
    while bytes
        .get(*index)
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        *index += 1;
    }
    *index != start
}

fn invalid_image_repository() -> ProjectionError {
    ProjectionError::InvalidTemplate(
        "image repository is outside the conservative OCI/Docker name grammar".to_owned(),
    )
}

fn validate_dns_label(field: &str, value: &str) -> Result<(), ProjectionError> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(ProjectionError::InvalidTemplate(format!(
            "{field} is not a DNS label"
        )));
    }
    Ok(())
}

fn validate_dns_subdomain(field: &str, value: &str) -> Result<(), ProjectionError> {
    if value.is_empty()
        || value.len() > 253
        || value
            .split('.')
            .any(|label| validate_dns_label(field, label).is_err())
    {
        return Err(ProjectionError::InvalidTemplate(format!(
            "{field} is not a DNS subdomain"
        )));
    }
    Ok(())
}

fn operation_hash(
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
) -> Result<Digest32, ProjectionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"accordlock:v1:deploy-operation\0");
    hasher.update(
        template
            .canonical_bytes()
            .map_err(|error| ProjectionError::Canonical(error.to_string()))?,
    );
    hasher.update(transaction_id.as_bytes());
    hasher.update(authorization_id.as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&hasher.finalize());
    Ok(Digest32::from_bytes(output))
}

fn wire_commitment(method: &str, path: &str, content_type: &str, body: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(b"accordlock:v1:provider-wire\0");
    for value in [method, path, content_type] {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(body);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&hasher.finalize());
    Digest32::from_bytes(output)
}

fn native_execution_command_commitment(
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(b"accordlock:v1:k8s-native-patch-command\0");
    for value in [
        "accordlock-k8s-native-client/v1",
        method,
        path,
        content_type,
    ] {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(body);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&hasher.finalize());
    Digest32::from_bytes(output)
}

fn serialize_patch_body(patch: &Value) -> Result<Vec<u8>, ProjectionError> {
    serde_json::to_vec(patch).map_err(|error| ProjectionError::Serialization(error.to_string()))
}

/// Returns the exact compact JSON bytes committed by [`PreparedPatch`].
///
/// The returned body has no trailing newline and is intended for an
/// `application/json-patch+json` request. Callers must first rederive and
/// compare the complete [`PreparedPatch`] from the signed template.
///
/// # Errors
///
/// Returns [`ProjectionError`] if the stored JSON value cannot be serialized.
pub fn patch_wire_body(prepared: &PreparedPatch) -> Result<Vec<u8>, ProjectionError> {
    serialize_patch_body(&prepared.patch)
}

/// Checks all state assumptions bound into the deployment template.
///
/// # Errors
///
/// Returns [`ProjectionError`] when a required field is absent or differs from
/// the value bound into the authorization template.
pub fn validate_preconditions(
    current: &Value,
    template: &DeploymentTemplate,
) -> Result<(), ProjectionError> {
    validate_executable_template(template)?;
    require_string(current, "/apiVersion", "apps/v1")?;
    require_string(current, "/kind", "Deployment")?;
    require_string(current, "/metadata/name", &template.deployment)?;
    require_string(current, "/metadata/namespace", &template.namespace)?;
    require_string(current, "/metadata/uid", &template.deployment_uid)?;
    require_string(
        current,
        "/metadata/resourceVersion",
        &template.resource_version,
    )?;
    require_string(
        current,
        &format!(
            "/spec/template/spec/containers/{}/name",
            template.container_index
        ),
        &template.container,
    )?;
    require_string(
        current,
        &format!(
            "/spec/template/spec/containers/{}/image",
            template.container_index
        ),
        &image_reference(&template.image_repository, template.prior_image_digest),
    )?;
    require_optional_annotation(
        current,
        TRANSACTION_ANNOTATION,
        template.prior_transaction_annotation.as_deref(),
    )?;
    require_optional_annotation(
        current,
        AUTHORIZATION_ANNOTATION,
        template.prior_authorization_annotation.as_deref(),
    )?;
    require_optional_annotation(
        current,
        OPERATION_ANNOTATION,
        template.prior_operation_hash_annotation.as_deref(),
    )?;
    Ok(())
}

/// Verifies a server-side dry-run candidate before persistence.
///
/// # Errors
///
/// Returns [`ProjectionError`] when a precondition fails, an unauthorized path
/// changes, or an authorized path does not contain its bound final value.
pub fn validate_admission_candidate(
    old: &Value,
    candidate: &Value,
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Result<(), ProjectionError> {
    validate_effect_projection(
        old,
        candidate,
        template,
        transaction_id,
        authorization_id,
        operation_hash,
    )
}

/// Verifies the persisted API-server response after the JSON Patch.
///
/// This performs the same desired-state projection as
/// [`validate_admission_candidate`] and additionally requires a new
/// `resourceVersion` plus one Deployment generation increment.
///
/// # Errors
///
/// Returns [`ProjectionError`] when the candidate projection or required
/// persistence transition is invalid.
pub fn validate_authorized_delta(
    old: &Value,
    persisted_response: &Value,
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Result<(), ProjectionError> {
    validate_effect_projection(
        old,
        persisted_response,
        template,
        transaction_id,
        authorization_id,
        operation_hash,
    )?;
    validate_server_transition(old, persisted_response)
}

fn validate_effect_projection(
    old: &Value,
    observed: &Value,
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Result<(), ProjectionError> {
    validate_preconditions(old, template)?;
    require_string(observed, "/metadata/uid", &template.deployment_uid)?;

    let image_path = format!(
        "/spec/template/spec/containers/{}/image",
        template.container_index
    );
    let allowed: BTreeSet<String> = [
        image_path.clone(),
        format!(
            "/metadata/annotations/{}",
            escape_pointer(TRANSACTION_ANNOTATION)
        ),
        format!(
            "/metadata/annotations/{}",
            escape_pointer(AUTHORIZATION_ANNOTATION)
        ),
        format!(
            "/metadata/annotations/{}",
            escape_pointer(OPERATION_ANNOTATION)
        ),
    ]
    .into_iter()
    .collect();

    let old_projection = authorized_projection(old.clone());
    let new_projection = authorized_projection(observed.clone());
    let mut changed = BTreeSet::new();
    collect_changed_paths("", &old_projection, &new_projection, &mut changed);
    for path in &changed {
        if !allowed.contains(path) {
            return Err(ProjectionError::UnauthorizedDelta(path.clone()));
        }
    }

    require_string(
        observed,
        &image_path,
        &image_reference(&template.image_repository, template.image_digest),
    )?;
    require_annotation(
        observed,
        TRANSACTION_ANNOTATION,
        &transaction_id.to_string(),
    )?;
    require_annotation(
        observed,
        AUTHORIZATION_ANNOTATION,
        &authorization_id.to_string(),
    )?;
    require_annotation(observed, OPERATION_ANNOTATION, &operation_hash.to_string())?;
    Ok(())
}

/// Validates the eventual Deployment after the controller has updated only its
/// declared bookkeeping fields.
///
/// The persisted response must already have passed
/// [`validate_authorized_delta`]. This check authorizations changes only to
/// `status`, `metadata.resourceVersion`, `metadata.managedFields`, and the
/// Deployment controller revision
/// annotation. All desired-state fields, deletion state, identity, image, and
/// `AccordLock` annotations remain exact. Deployment generation must remain equal to
/// the persisted response because controller reconciliation is not a spec
/// mutation.
///
/// # Errors
///
/// Returns [`ProjectionError`] for any non-controller delta or lost bound
/// value.
pub fn validate_eventual_controller_projection(
    persisted_response: &Value,
    eventual: &Value,
    template: &DeploymentTemplate,
    transaction_id: Uuid,
    authorization_id: Uuid,
    operation_hash: Digest32,
) -> Result<(), ProjectionError> {
    require_string(eventual, "/apiVersion", "apps/v1")?;
    require_string(eventual, "/kind", "Deployment")?;
    require_string(eventual, "/metadata/name", &template.deployment)?;
    require_string(eventual, "/metadata/namespace", &template.namespace)?;
    require_string(eventual, "/metadata/uid", &template.deployment_uid)?;
    let persisted_generation = required_u64(persisted_response, "/metadata/generation")?;
    let eventual_generation = required_u64(eventual, "/metadata/generation")?;
    if eventual_generation != persisted_generation {
        return Err(ProjectionError::UnauthorizedDelta(
            "/metadata/generation".to_owned(),
        ));
    }
    if required_string(eventual, "/metadata/resourceVersion")?.is_empty() {
        return Err(ProjectionError::Precondition(
            "/metadata/resourceVersion".to_owned(),
        ));
    }

    let old_projection = eventual_projection(persisted_response.clone());
    let new_projection = eventual_projection(eventual.clone());
    let mut changed = BTreeSet::new();
    collect_changed_paths("", &old_projection, &new_projection, &mut changed);
    if let Some(path) = changed.into_iter().next() {
        return Err(ProjectionError::UnauthorizedDelta(path));
    }

    let image_path = format!(
        "/spec/template/spec/containers/{}/image",
        template.container_index
    );
    require_string(
        eventual,
        &image_path,
        &image_reference(&template.image_repository, template.image_digest),
    )?;
    require_annotation(
        eventual,
        TRANSACTION_ANNOTATION,
        &transaction_id.to_string(),
    )?;
    require_annotation(
        eventual,
        AUTHORIZATION_ANNOTATION,
        &authorization_id.to_string(),
    )?;
    require_annotation(eventual, OPERATION_ANNOTATION, &operation_hash.to_string())?;
    Ok(())
}

/// Verifies a local projection of the active Pods selected by the eventual
/// Deployment.
///
/// Terminating Pods are ignored. The Deployment status must have observed the
/// current generation and report every desired replica updated, ready, and
/// available. The number of remaining Pods must equal that replica count, all
/// must be Running and Ready, share one template hash, and have a `ReplicaSet`
/// controller owner. Containers are compared exactly, which detects Pod
/// admission sidecars and mutations to image, command, environment, mounts,
/// resources, probes, or security context. The complete Pod spec is compared
/// after removing only a scheduler-assigned `nodeName` when the template did
/// not bind one, plus the two standard 300-second `NoExecute` tolerations.
///
/// This compatibility function does not observe `ReplicaSet` objects and therefore
/// cannot prove that a Pod is controlled by this exact Deployment. It is
/// insufficient for an ownership proof at the provider integration boundary.
/// New integrations must use [`validate_rollout_ownership_strict`] with
/// exhaustive Pod and `ReplicaSet` snapshots.
///
/// # Errors
///
/// Returns [`ProjectionError`] when the Pod list is malformed, the active count
/// differs, labels do not satisfy the selector, or a workload field differs.
pub fn validate_rollout_pods(
    eventual_deployment: &Value,
    observed_pods: &Value,
) -> Result<(), ProjectionError> {
    require_string(observed_pods, "/apiVersion", "v1")?;
    require_string(observed_pods, "/kind", "List")?;
    let desired_replicas = required_u64(eventual_deployment, "/spec/replicas")?;
    validate_deployment_rollout_status(eventual_deployment, desired_replicas)?;
    let namespace = required_string(eventual_deployment, "/metadata/namespace")?;
    let template_spec = eventual_deployment
        .pointer("/spec/template/spec")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField("/spec/template/spec".to_owned()))?;
    let selector = eventual_deployment
        .pointer("/spec/selector/matchLabels")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField("/spec/selector/matchLabels".to_owned()))?;
    let items = observed_pods
        .pointer("/items")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField("/items".to_owned()))?;
    let active: Vec<_> = items
        .iter()
        .filter(|pod| {
            pod.pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
        })
        .collect();
    let active_count = u64::try_from(active.len())
        .map_err(|_| ProjectionError::Precondition("active Pod count exceeds u64".to_owned()))?;
    if active_count != desired_replicas {
        return Err(ProjectionError::Precondition(format!(
            "active Pod count {active_count} differs from desired replicas {desired_replicas}"
        )));
    }

    let mut pod_template_hashes = BTreeSet::new();
    for (index, pod) in active.into_iter().enumerate() {
        pod_template_hashes.insert(validate_active_pod_metadata(
            pod, index, namespace, selector,
        )?);
        let pod_spec = pod
            .pointer("/spec")
            .and_then(Value::as_object)
            .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/spec")))?;
        let template_projection = pod_spec_projection(template_spec, false, false)?;
        let observed_projection =
            pod_spec_projection(pod_spec, true, !template_spec.contains_key("nodeName"))?;
        if template_projection != observed_projection {
            let mut changed = BTreeSet::new();
            collect_changed_paths(
                &format!("/items/{index}/spec"),
                &template_projection,
                &observed_projection,
                &mut changed,
            );
            return Err(ProjectionError::UnauthorizedDelta(
                changed
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| format!("/items/{index}/spec")),
            ));
        }
    }
    if desired_replicas != 0 && pod_template_hashes.len() != 1 {
        return Err(ProjectionError::Precondition(
            "active Pods do not share one pod-template-hash".to_owned(),
        ));
    }
    Ok(())
}

struct StrictReplicaSet<'a> {
    name: &'a str,
    uid: &'a str,
    template_hash: &'a str,
    template_labels: &'a serde_json::Map<String, Value>,
    template_spec: &'a serde_json::Map<String, Value>,
}

/// Verifies the complete Deployment -> `ReplicaSet` -> Pod controller chain.
///
/// `observed_replica_sets` and `observed_pods` must be exhaustive snapshots for
/// the target Deployment selector. Every `ReplicaSet` in the supplied list must
/// be owned by the exact Deployment name and UID. Historical `ReplicaSet` objects are
/// accepted only when both their desired and observed replica counts are zero.
/// Exactly one `ReplicaSet` must reproduce the current Deployment Pod template,
/// report the desired ready state, and carry one internally consistent
/// `pod-template-hash`. Every supplied Pod must be non-terminating, controlled
/// by that exact `ReplicaSet` name and UID, and retain its template hash, labels,
/// Pod spec, Running phase, and Ready condition.
///
/// The hash is checked as a controller linkage value across `ReplicaSet`
/// metadata, selector, template, and Pods. This function deliberately does not
/// claim to recompute Kubernetes' version-dependent `DeepHashObject` result.
///
/// # Errors
///
/// Returns [`ProjectionError`] for malformed or duplicate identities,
/// ambiguous current `ReplicaSet` objects, foreign controller owners, non-zero old
/// workloads, terminating Pods, template-hash mismatches, or workload drift.
#[allow(clippy::too_many_lines)]
pub fn validate_rollout_ownership_strict(
    eventual_deployment: &Value,
    observed_replica_sets: &Value,
    observed_pods: &Value,
) -> Result<(), ProjectionError> {
    require_string(eventual_deployment, "/apiVersion", "apps/v1")?;
    require_string(eventual_deployment, "/kind", "Deployment")?;
    let deployment_name = required_non_empty_string(eventual_deployment, "/metadata/name")?;
    let deployment_namespace =
        required_non_empty_string(eventual_deployment, "/metadata/namespace")?;
    let deployment_uid = required_non_empty_string(eventual_deployment, "/metadata/uid")?;
    require_not_terminating(eventual_deployment, "/metadata/deletionTimestamp")?;

    let desired_replicas = required_u64(eventual_deployment, "/spec/replicas")?;
    validate_deployment_rollout_status(eventual_deployment, desired_replicas)?;
    let deployment_selector = strict_match_labels(eventual_deployment, "/spec/selector")?;
    let deployment_template = eventual_deployment
        .pointer("/spec/template")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField("/spec/template".to_owned()))?;
    let deployment_template_labels = deployment_template
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("labels"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProjectionError::MissingField("/spec/template/metadata/labels".to_owned())
        })?;
    if deployment_template_labels.contains_key("pod-template-hash") {
        return Err(ProjectionError::Precondition(
            "/spec/template/metadata/labels/pod-template-hash is controller-reserved".to_owned(),
        ));
    }
    let deployment_template_spec = deployment_template
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField("/spec/template/spec".to_owned()))?;
    let deployment_template_projection = normalized_controller_template(deployment_template)?;

    require_string(observed_replica_sets, "/apiVersion", "v1")?;
    require_string(observed_replica_sets, "/kind", "List")?;
    let replica_sets = observed_replica_sets
        .pointer("/items")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField("/items".to_owned()))?;
    if replica_sets.is_empty() {
        return Err(ProjectionError::Precondition(
            "ReplicaSet snapshot is empty".to_owned(),
        ));
    }

    let mut replica_set_names = BTreeSet::new();
    let mut replica_set_uids = BTreeSet::new();
    let mut replica_set_hashes = BTreeSet::new();
    let mut current_replica_set = None;

    for (index, replica_set) in replica_sets.iter().enumerate() {
        require_string(replica_set, "/apiVersion", "apps/v1")?;
        require_string(replica_set, "/kind", "ReplicaSet")?;
        require_string(replica_set, "/metadata/namespace", deployment_namespace)?;
        let replica_set_name = required_non_empty_string(replica_set, "/metadata/name")?;
        let replica_set_uid = required_non_empty_string(replica_set, "/metadata/uid")?;
        if !replica_set_names.insert(replica_set_name.to_owned())
            || !replica_set_uids.insert(replica_set_uid.to_owned())
        {
            return Err(ProjectionError::Precondition(format!(
                "/items/{index} duplicates a ReplicaSet name or UID"
            )));
        }
        require_not_terminating(replica_set, "/metadata/deletionTimestamp")?;
        validate_strict_controller_owner(
            replica_set,
            &format!("/items/{index}"),
            "Deployment",
            deployment_name,
            deployment_uid,
        )?;

        let replica_set_selector = strict_match_labels(replica_set, "/spec/selector")?;
        let replica_set_template = replica_set
            .pointer("/spec/template")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProjectionError::MissingField(format!("/items/{index}/spec/template"))
            })?;
        let replica_set_template_labels = replica_set_template
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("labels"))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProjectionError::MissingField(format!(
                    "/items/{index}/spec/template/metadata/labels"
                ))
            })?;
        let replica_set_template_spec = replica_set_template
            .get("spec")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProjectionError::MissingField(format!("/items/{index}/spec/template/spec"))
            })?;
        let template_hash = validate_replica_set_template_hash(
            replica_set,
            replica_set_selector,
            replica_set_template_labels,
            index,
        )?;
        if !replica_set_hashes.insert(template_hash.to_owned()) {
            return Err(ProjectionError::Precondition(format!(
                "/items/{index} duplicates a pod-template-hash"
            )));
        }
        validate_replica_set_selector(
            replica_set_selector,
            deployment_selector,
            template_hash,
            index,
        )?;

        let template_is_current =
            normalized_controller_template(replica_set_template)? == deployment_template_projection;
        if template_is_current {
            validate_replica_set_rollout_status(replica_set, desired_replicas, index)?;
            if current_replica_set.is_some() {
                return Err(ProjectionError::Precondition(
                    "multiple ReplicaSets reproduce the current Deployment template".to_owned(),
                ));
            }
            current_replica_set = Some(StrictReplicaSet {
                name: replica_set_name,
                uid: replica_set_uid,
                template_hash,
                template_labels: replica_set_template_labels,
                template_spec: replica_set_template_spec,
            });
        } else {
            validate_replica_set_rollout_status(replica_set, 0, index)?;
        }
    }

    let current_replica_set = current_replica_set.ok_or_else(|| {
        ProjectionError::Precondition(
            "no ReplicaSet reproduces the current Deployment template".to_owned(),
        )
    })?;
    debug_assert_eq!(
        current_replica_set.template_spec, deployment_template_spec,
        "normalized current template comparison includes the Pod spec"
    );

    require_string(observed_pods, "/apiVersion", "v1")?;
    require_string(observed_pods, "/kind", "List")?;
    let pods = observed_pods
        .pointer("/items")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField("/items".to_owned()))?;
    for pod in pods {
        require_not_terminating(pod, "/metadata/deletionTimestamp")?;
    }
    let pod_count = u64::try_from(pods.len())
        .map_err(|_| ProjectionError::Precondition("Pod count exceeds u64".to_owned()))?;
    if pod_count != desired_replicas {
        return Err(ProjectionError::Precondition(format!(
            "Pod count {pod_count} differs from desired replicas {desired_replicas}"
        )));
    }

    let mut pod_names = BTreeSet::new();
    let mut pod_uids = BTreeSet::new();
    for (index, pod) in pods.iter().enumerate() {
        require_string(pod, "/apiVersion", "v1")?;
        require_string(pod, "/kind", "Pod")?;
        require_string(pod, "/metadata/namespace", deployment_namespace)?;
        let pod_name = required_non_empty_string(pod, "/metadata/name")?;
        let pod_uid = required_non_empty_string(pod, "/metadata/uid")?;
        if !pod_names.insert(pod_name.to_owned()) || !pod_uids.insert(pod_uid.to_owned()) {
            return Err(ProjectionError::Precondition(format!(
                "/items/{index} duplicates a Pod name or UID"
            )));
        }
        validate_strict_controller_owner(
            pod,
            &format!("/items/{index}"),
            "ReplicaSet",
            current_replica_set.name,
            current_replica_set.uid,
        )?;
        validate_strict_pod_metadata(
            pod,
            index,
            deployment_selector,
            current_replica_set.template_labels,
            current_replica_set.template_hash,
        )?;

        let pod_spec = pod
            .pointer("/spec")
            .and_then(Value::as_object)
            .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/spec")))?;
        let template_projection =
            pod_spec_projection(current_replica_set.template_spec, false, false)?;
        let observed_projection = pod_spec_projection(
            pod_spec,
            true,
            !current_replica_set.template_spec.contains_key("nodeName"),
        )?;
        if template_projection != observed_projection {
            let mut changed = BTreeSet::new();
            collect_changed_paths(
                &format!("/items/{index}/spec"),
                &template_projection,
                &observed_projection,
                &mut changed,
            );
            return Err(ProjectionError::UnauthorizedDelta(
                changed
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| format!("/items/{index}/spec")),
            ));
        }
        validate_running_ready_pod(pod, index)?;
    }
    Ok(())
}

fn strict_match_labels<'a>(
    value: &'a Value,
    selector_pointer: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProjectionError> {
    let selector = value
        .pointer(selector_pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField(selector_pointer.to_owned()))?;
    if selector.len() != 1 || !selector.contains_key("matchLabels") {
        return Err(ProjectionError::Precondition(format!(
            "{selector_pointer} is outside the strict matchLabels-only profile"
        )));
    }
    selector
        .get("matchLabels")
        .and_then(Value::as_object)
        .filter(|labels| !labels.is_empty())
        .ok_or_else(|| ProjectionError::MissingField(format!("{selector_pointer}/matchLabels")))
}

fn normalized_controller_template(
    template: &serde_json::Map<String, Value>,
) -> Result<Value, ProjectionError> {
    let mut normalized = template.clone();
    let labels = normalized
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("labels"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| ProjectionError::MissingField("template metadata labels".to_owned()))?;
    labels.remove("pod-template-hash");
    Ok(Value::Object(normalized))
}

fn validate_replica_set_template_hash<'a>(
    replica_set: &'a Value,
    selector: &'a serde_json::Map<String, Value>,
    template_labels: &'a serde_json::Map<String, Value>,
    index: usize,
) -> Result<&'a str, ProjectionError> {
    let metadata_hash =
        required_non_empty_string(replica_set, "/metadata/labels/pod-template-hash")?;
    let selector_hash = selector
        .get("pod-template-hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let template_hash = template_labels
        .get("pod-template-hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if selector_hash != Some(metadata_hash) || template_hash != Some(metadata_hash) {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/pod-template-hash linkage"
        )));
    }
    Ok(metadata_hash)
}

fn validate_replica_set_selector(
    replica_set_selector: &serde_json::Map<String, Value>,
    deployment_selector: &serde_json::Map<String, Value>,
    template_hash: &str,
    index: usize,
) -> Result<(), ProjectionError> {
    let mut expected = deployment_selector.clone();
    expected.insert(
        "pod-template-hash".to_owned(),
        Value::String(template_hash.to_owned()),
    );
    if replica_set_selector != &expected {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/spec/selector/matchLabels"
        )));
    }
    Ok(())
}

fn validate_replica_set_rollout_status(
    replica_set: &Value,
    expected_replicas: u64,
    index: usize,
) -> Result<(), ProjectionError> {
    if required_u64(replica_set, "/spec/replicas")? != expected_replicas {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/spec/replicas"
        )));
    }
    let generation = required_u64(replica_set, "/metadata/generation")?;
    if required_u64(replica_set, "/status/observedGeneration")? != generation {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/status/observedGeneration"
        )));
    }
    for field in [
        "replicas",
        "fullyLabeledReplicas",
        "readyReplicas",
        "availableReplicas",
    ] {
        if optional_u64_or_zero(replica_set, &format!("/status/{field}"))? != expected_replicas {
            return Err(ProjectionError::Precondition(format!(
                "/items/{index}/status/{field}"
            )));
        }
    }
    Ok(())
}

fn validate_strict_controller_owner(
    value: &Value,
    object_path: &str,
    expected_kind: &str,
    expected_name: &str,
    expected_uid: &str,
) -> Result<(), ProjectionError> {
    let owner_path = format!("{object_path}/metadata/ownerReferences");
    let owners = value
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField(owner_path.clone()))?;
    if owners.len() != 1 {
        return Err(ProjectionError::Precondition(owner_path));
    }
    let owner = &owners[0];
    let exact = owner.get("apiVersion").and_then(Value::as_str) == Some("apps/v1")
        && owner.get("kind").and_then(Value::as_str) == Some(expected_kind)
        && owner.get("name").and_then(Value::as_str) == Some(expected_name)
        && owner.get("uid").and_then(Value::as_str) == Some(expected_uid)
        && owner.get("controller").and_then(Value::as_bool) == Some(true);
    if !exact || expected_name.is_empty() || expected_uid.is_empty() {
        return Err(ProjectionError::Precondition(format!(
            "{object_path}/metadata/ownerReferences/0"
        )));
    }
    Ok(())
}

fn validate_strict_pod_metadata(
    pod: &Value,
    index: usize,
    deployment_selector: &serde_json::Map<String, Value>,
    replica_set_template_labels: &serde_json::Map<String, Value>,
    expected_template_hash: &str,
) -> Result<(), ProjectionError> {
    let labels = pod
        .pointer("/metadata/labels")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/metadata/labels")))?;
    if labels != replica_set_template_labels {
        return Err(ProjectionError::AuthorizedValueMismatch(format!(
            "/items/{index}/metadata/labels"
        )));
    }
    if labels.get("pod-template-hash").and_then(Value::as_str) != Some(expected_template_hash) {
        return Err(ProjectionError::AuthorizedValueMismatch(format!(
            "/items/{index}/metadata/labels/pod-template-hash"
        )));
    }
    for (key, expected) in deployment_selector {
        if labels.get(key) != Some(expected) {
            return Err(ProjectionError::AuthorizedValueMismatch(format!(
                "/items/{index}/metadata/labels/{}",
                escape_pointer(key)
            )));
        }
    }
    Ok(())
}

fn validate_running_ready_pod(pod: &Value, index: usize) -> Result<(), ProjectionError> {
    require_string(pod, "/status/phase", "Running")?;
    let ready_conditions: Vec<_> = pod
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/status/conditions")))?
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Ready"))
        .collect();
    if ready_conditions.len() != 1
        || ready_conditions[0].get("status").and_then(Value::as_str) != Some("True")
    {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/status/conditions/Ready"
        )));
    }
    Ok(())
}

fn validate_deployment_rollout_status(
    deployment: &Value,
    desired_replicas: u64,
) -> Result<(), ProjectionError> {
    let generation = required_u64(deployment, "/metadata/generation")?;
    if required_u64(deployment, "/status/observedGeneration")? != generation {
        return Err(ProjectionError::Precondition(
            "/status/observedGeneration".to_owned(),
        ));
    }
    for field in [
        "replicas",
        "updatedReplicas",
        "readyReplicas",
        "availableReplicas",
    ] {
        if optional_u64_or_zero(deployment, &format!("/status/{field}"))? != desired_replicas {
            return Err(ProjectionError::Precondition(format!("/status/{field}")));
        }
    }
    if optional_u64_or_zero(deployment, "/status/unavailableReplicas")? != 0 {
        return Err(ProjectionError::Precondition(
            "/status/unavailableReplicas".to_owned(),
        ));
    }
    Ok(())
}

fn validate_active_pod_metadata(
    pod: &Value,
    index: usize,
    namespace: &str,
    selector: &serde_json::Map<String, Value>,
) -> Result<String, ProjectionError> {
    require_string(pod, "/apiVersion", "v1")?;
    require_string(pod, "/kind", "Pod")?;
    require_string(pod, "/metadata/namespace", namespace)?;
    let labels = pod
        .pointer("/metadata/labels")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/metadata/labels")))?;
    for (key, expected) in selector {
        if labels.get(key) != Some(expected) {
            return Err(ProjectionError::AuthorizedValueMismatch(format!(
                "/items/{index}/metadata/labels/{}",
                escape_pointer(key)
            )));
        }
    }
    let pod_template_hash = labels
        .get("pod-template-hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProjectionError::MissingField(format!(
                "/items/{index}/metadata/labels/pod-template-hash"
            ))
        })?;
    validate_pod_controller_owner(pod, index)?;
    require_string(pod, "/status/phase", "Running")?;
    let ready_conditions: Vec<_> = pod
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::MissingField(format!("/items/{index}/status/conditions")))?
        .iter()
        .filter(|condition| condition.get("type").and_then(Value::as_str) == Some("Ready"))
        .collect();
    if ready_conditions.len() != 1
        || ready_conditions[0].get("status").and_then(Value::as_str) != Some("True")
    {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/status/conditions/Ready"
        )));
    }
    Ok(pod_template_hash.to_owned())
}

fn validate_pod_controller_owner(pod: &Value, index: usize) -> Result<(), ProjectionError> {
    let owners = pod
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProjectionError::MissingField(format!("/items/{index}/metadata/ownerReferences"))
        })?;
    let controllers: Vec<_> = owners
        .iter()
        .filter(|owner| owner.get("controller").and_then(Value::as_bool) == Some(true))
        .collect();
    if controllers.len() != 1
        || controllers[0].get("apiVersion").and_then(Value::as_str) != Some("apps/v1")
        || controllers[0].get("kind").and_then(Value::as_str) != Some("ReplicaSet")
        || controllers[0]
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || controllers[0]
            .get("uid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(ProjectionError::Precondition(format!(
            "/items/{index}/metadata/ownerReferences"
        )));
    }
    Ok(())
}

fn pod_spec_projection(
    spec: &serde_json::Map<String, Value>,
    observed_pod: bool,
    remove_scheduled_node_name: bool,
) -> Result<Value, ProjectionError> {
    let mut projection = spec.clone();
    if observed_pod && remove_scheduled_node_name {
        projection.remove("nodeName");
    }
    let remove_empty_tolerations = if let Some(value) = projection.get_mut("tolerations") {
        let values = value
            .as_array_mut()
            .ok_or_else(|| ProjectionError::MissingField("/spec/tolerations".to_owned()))?;
        if observed_pod {
            values.retain(|toleration| !is_standard_runtime_toleration(toleration));
        }
        values.is_empty()
    } else {
        false
    };
    if remove_empty_tolerations {
        projection.remove("tolerations");
    }
    Ok(Value::Object(projection))
}

fn is_standard_runtime_toleration(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 4
        || object.get("effect").and_then(Value::as_str) != Some("NoExecute")
        || object.get("operator").and_then(Value::as_str) != Some("Exists")
        || object.get("tolerationSeconds").and_then(Value::as_u64) != Some(300)
    {
        return false;
    }
    matches!(
        object.get("key").and_then(Value::as_str),
        Some("node.kubernetes.io/not-ready" | "node.kubernetes.io/unreachable")
    )
}

fn validate_server_transition(old: &Value, new: &Value) -> Result<(), ProjectionError> {
    let old_resource_version = required_string(old, "/metadata/resourceVersion")?;
    let new_resource_version = required_string(new, "/metadata/resourceVersion")?;
    if new_resource_version.is_empty() || old_resource_version == new_resource_version {
        return Err(ProjectionError::Precondition(
            "/metadata/resourceVersion transition".to_owned(),
        ));
    }
    let old_generation = required_u64(old, "/metadata/generation")?;
    let new_generation = required_u64(new, "/metadata/generation")?;
    if old_generation.checked_add(1) != Some(new_generation) {
        return Err(ProjectionError::Precondition(
            "/metadata/generation transition".to_owned(),
        ));
    }
    Ok(())
}

fn authorized_projection(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut()
        && let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut)
    {
        for field in ["resourceVersion", "generation", "managedFields"] {
            metadata.remove(field);
        }
    }
    value
}

fn eventual_projection(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("status");
        if let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut) {
            for field in ["resourceVersion", "managedFields"] {
                metadata.remove(field);
            }
            if let Some(annotations) = metadata
                .get_mut("annotations")
                .and_then(Value::as_object_mut)
            {
                annotations.remove(DEPLOYMENT_REVISION_ANNOTATION);
            }
        }
    }
    value
}

fn collect_changed_paths(prefix: &str, old: &Value, new: &Value, output: &mut BTreeSet<String>) {
    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            let keys: BTreeSet<_> = old_map.keys().chain(new_map.keys()).collect();
            for key in keys {
                let path = format!("{prefix}/{}", escape_pointer(key));
                match (old_map.get(key), new_map.get(key)) {
                    (Some(old), Some(new)) => collect_changed_paths(&path, old, new, output),
                    _ => {
                        output.insert(path);
                    }
                }
            }
        }
        (Value::Array(old_values), Value::Array(new_values)) => {
            let length = old_values.len().max(new_values.len());
            for index in 0..length {
                let path = format!("{prefix}/{index}");
                match (old_values.get(index), new_values.get(index)) {
                    (Some(old), Some(new)) => collect_changed_paths(&path, old, new, output),
                    _ => {
                        output.insert(path);
                    }
                }
            }
        }
        _ if old != new => {
            output.insert(prefix.to_owned());
        }
        _ => {}
    }
}

fn require_string(value: &Value, pointer: &str, expected: &str) -> Result<(), ProjectionError> {
    let actual = required_string(value, pointer)?;
    if actual != expected {
        return Err(ProjectionError::Precondition(pointer.to_owned()));
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ProjectionError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| ProjectionError::MissingField(pointer.to_owned()))
}

fn required_non_empty_string<'a>(
    value: &'a Value,
    pointer: &str,
) -> Result<&'a str, ProjectionError> {
    let actual = required_string(value, pointer)?;
    if actual.trim().is_empty() {
        return Err(ProjectionError::Precondition(pointer.to_owned()));
    }
    Ok(actual)
}

fn require_not_terminating(value: &Value, pointer: &str) -> Result<(), ProjectionError> {
    if value.pointer(pointer).is_some_and(|value| !value.is_null()) {
        return Err(ProjectionError::Precondition(pointer.to_owned()));
    }
    Ok(())
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, ProjectionError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProjectionError::MissingField(pointer.to_owned()))
}

fn optional_u64_or_zero(value: &Value, pointer: &str) -> Result<u64, ProjectionError> {
    match value.pointer(pointer) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| ProjectionError::MissingField(pointer.to_owned())),
    }
}

fn require_annotation(value: &Value, key: &str, expected: &str) -> Result<(), ProjectionError> {
    let pointer = format!("/metadata/annotations/{}", escape_pointer(key));
    let actual = value.pointer(&pointer).and_then(Value::as_str);
    if actual != Some(expected) {
        return Err(ProjectionError::AuthorizedValueMismatch(pointer));
    }
    Ok(())
}

fn require_optional_annotation(
    value: &Value,
    key: &str,
    expected: Option<&str>,
) -> Result<(), ProjectionError> {
    let pointer = format!("/metadata/annotations/{}", escape_pointer(key));
    let actual = value.pointer(&pointer).and_then(Value::as_str);
    if actual != expected {
        return Err(ProjectionError::Precondition(pointer));
    }
    Ok(())
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn image_reference(repository: &str, digest: Digest32) -> String {
    format!("{repository}@{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> DeploymentTemplate {
        DeploymentTemplate {
            operation: "DEPLOY_EKS_IMAGE_V1".to_owned(),
            environment: "prod".to_owned(),
            audience: "accordlock-executor".to_owned(),
            repository: "acme/payments".to_owned(),
            commit_sha: "1".repeat(40),
            image_repository: "acme/payments".to_owned(),
            image_digest: Digest32::from_bytes([0xaa; 32]),
            cluster_identity: "kind://accordlock".to_owned(),
            namespace: "payments-prod".to_owned(),
            deployment: "payments".to_owned(),
            deployment_uid: "11111111-2222-4333-8444-555555555555".to_owned(),
            container: "app".to_owned(),
            container_index: 0,
            prior_image_digest: Digest32::from_bytes([0xcc; 32]),
            resource_version: "1001".to_owned(),
            prior_projection_hash: Digest32::from_bytes([0xdd; 32]),
            prior_transaction_annotation: Some("unset".to_owned()),
            prior_authorization_annotation: Some("unset".to_owned()),
            prior_operation_hash_annotation: Some("unset".to_owned()),
        }
    }

    fn deployment() -> Value {
        json!({
            "apiVersion":"apps/v1",
            "kind":"Deployment",
            "metadata":{
                "name":"payments",
                "namespace":"payments-prod",
                "uid":"11111111-2222-4333-8444-555555555555",
                "resourceVersion":"1001",
                "generation":1,
                "creationTimestamp":"2026-08-16T00:00:00Z",
                "annotations":{
                    "accordlock.io/transaction-id":"unset",
                    "accordlock.io/authorization-id":"unset",
                    "accordlock.io/operation-hash":"unset"
                }
            },
            "spec":{"replicas":2,"template":{"metadata":{"labels":{"app":"payments"}},"spec":{
                "serviceAccountName":"payments-runtime",
                "containers":[{"name":"app","image":format!("acme/payments@sha256:{}", "cc".repeat(32)),"env":[]}]
            }}},
            "status":{"availableReplicas":2}
        })
    }

    fn authorized_after(
        template: &DeploymentTemplate,
        transaction_id: Uuid,
        authorization_id: Uuid,
        operation_hash: Digest32,
    ) -> Result<Value, &'static str> {
        let mut value = deployment();
        value["spec"]["template"]["spec"]["containers"][0]["image"] = Value::String(
            image_reference(&template.image_repository, template.image_digest),
        );
        let annotations = value["metadata"]["annotations"]
            .as_object_mut()
            .ok_or("annotations not object")?;
        annotations.insert(
            TRANSACTION_ANNOTATION.to_owned(),
            Value::String(transaction_id.to_string()),
        );
        annotations.insert(
            AUTHORIZATION_ANNOTATION.to_owned(),
            Value::String(authorization_id.to_string()),
        );
        annotations.insert(
            OPERATION_ANNOTATION.to_owned(),
            Value::String(operation_hash.to_string()),
        );
        value["metadata"]["resourceVersion"] = Value::String("1002".to_owned());
        value["metadata"]["generation"] = json!(2);
        Ok(value)
    }

    #[test]
    fn exact_image_and_annotations_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let after = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        validate_authorized_delta(
            &deployment(),
            &after,
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        Ok(())
    }

    #[test]
    fn admission_sidecar_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let mut after = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        let containers = after["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or("containers not array")?;
        containers.push(json!({"name":"sidecar","image":"sha256:evil"}));
        let result = validate_authorized_delta(
            &deployment(),
            &after,
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        );
        assert!(matches!(result, Err(ProjectionError::UnauthorizedDelta(_))));
        Ok(())
    }

    #[test]
    fn admission_service_account_change_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let mut after = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        after["spec"]["template"]["spec"]["serviceAccountName"] =
            Value::String("elevated".to_owned());
        let result = validate_authorized_delta(
            &deployment(),
            &after,
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        );
        assert!(matches!(result, Err(ProjectionError::UnauthorizedDelta(_))));
        Ok(())
    }

    #[test]
    fn operation_hash_is_not_self_referential() -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let first = prepare_patch(&template, transaction_id, authorization_id)?;
        let second = prepare_patch(&template, transaction_id, authorization_id)?;
        assert_eq!(first, second);
        assert_ne!(first.operation_hash, first.final_wire_commitment);
        assert_ne!(
            first.execution_command_commitment,
            first.final_wire_commitment
        );
        Ok(())
    }

    #[test]
    fn native_command_commitment_binds_the_exact_provider_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let prepared = prepare_patch(
            &template,
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
        )?;
        let body = patch_wire_body(&prepared)?;
        let expected = native_execution_command_commitment(
            "PATCH",
            "/apis/apps/v1/namespaces/payments-prod/deployments/payments",
            "application/json-patch+json",
            &body,
        );
        assert_eq!(prepared.execution_command_commitment, expected);

        let changed = native_execution_command_commitment(
            "PATCH",
            "/apis/apps/v1/namespaces/payments-prod/deployments/other",
            "application/json-patch+json",
            &body,
        );
        assert_ne!(prepared.execution_command_commitment, changed);
        Ok(())
    }

    #[test]
    fn patch_uses_a_digest_pinned_kubernetes_image_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let prepared = prepare_patch(
            &template,
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
        )?;
        let operations = prepared.patch.as_array().ok_or("patch is not an array")?;
        let replacement = operations
            .iter()
            .find(|operation| {
                operation.get("op").and_then(Value::as_str) == Some("replace")
                    && operation.get("path").and_then(Value::as_str)
                        == Some("/spec/template/spec/containers/0/image")
            })
            .ok_or("image replacement is missing")?;
        assert_eq!(
            replacement.get("value").and_then(Value::as_str),
            Some(format!("acme/payments@sha256:{}", "aa".repeat(32)).as_str())
        );
        Ok(())
    }

    #[test]
    fn wire_body_is_the_exact_body_committed_by_the_prepared_patch()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let body = patch_wire_body(&prepared)?;
        assert_eq!(body, serde_json::to_vec(&prepared.patch)?);
        assert!(!body.ends_with(b"\n"));
        let expected = wire_commitment(
            "PATCH",
            "/apis/apps/v1/namespaces/payments-prod/deployments/payments",
            "application/json-patch+json",
            &body,
        );
        assert_eq!(prepared.final_wire_commitment, expected);
        Ok(())
    }

    #[test]
    fn reserved_annotation_pointer_tokens_are_rfc6901_escaped()
    -> Result<(), Box<dyn std::error::Error>> {
        let prepared = prepare_patch(
            &template(),
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
        )?;
        let paths: Vec<_> = prepared
            .patch
            .as_array()
            .ok_or("patch is not an array")?
            .iter()
            .filter_map(|operation| operation.get("path").and_then(Value::as_str))
            .collect();
        assert!(paths.contains(&"/metadata/annotations/accordlock.io~1transaction-id"));
        assert!(paths.contains(&"/metadata/annotations/accordlock.io~1authorization-id"));
        assert!(paths.contains(&"/metadata/annotations/accordlock.io~1operation-hash"));
        assert!(!paths.iter().any(|path| path.contains("accordlock.io/")));
        Ok(())
    }

    #[test]
    fn absent_reserved_annotation_cannot_be_encoded_as_a_safe_patch_precondition() {
        let mut template = template();
        template.prior_authorization_annotation = None;
        assert!(matches!(
            prepare_patch(
                &template,
                Uuid::from_bytes([1; 16]),
                Uuid::from_bytes([2; 16])
            ),
            Err(ProjectionError::InvalidTemplate(_))
        ));
    }

    #[test]
    fn target_identity_is_an_explicit_precondition() {
        let mut wrong = deployment();
        wrong["metadata"]["namespace"] = Value::String("other".to_owned());
        assert!(matches!(
            validate_preconditions(&wrong, &template()),
            Err(ProjectionError::Precondition(path)) if path == "/metadata/namespace"
        ));
    }

    #[test]
    fn unchanged_resource_version_is_not_a_persisted_patch_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let mut after = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        after["metadata"]["resourceVersion"] = Value::String("1001".to_owned());
        assert!(matches!(
            validate_authorized_delta(
                &deployment(),
                &after,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::Precondition(path)) if path == "/metadata/resourceVersion transition"
        ));
        Ok(())
    }

    #[test]
    fn dry_run_candidate_is_checked_without_claiming_persistence()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let mut candidate = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        candidate["metadata"]["resourceVersion"] = Value::String("1001".to_owned());
        candidate["metadata"]["generation"] = json!(1);
        validate_admission_candidate(
            &deployment(),
            &candidate,
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;

        candidate["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or("containers not array")?
            .push(json!({"name":"injected","image":"attacker.invalid/sidecar:latest"}));
        assert!(matches!(
            validate_admission_candidate(
                &deployment(),
                &candidate,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::UnauthorizedDelta(_))
        ));
        Ok(())
    }

    #[test]
    fn post_admission_status_or_deletion_changes_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let after = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;

        let mut status_changed = after.clone();
        status_changed["status"] = json!({"availableReplicas":0});
        assert!(matches!(
            validate_authorized_delta(
                &deployment(),
                &status_changed,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::UnauthorizedDelta(path)) if path.starts_with("/status")
        ));

        let mut deleting = after;
        deleting["metadata"]["deletionTimestamp"] =
            Value::String("2026-08-16T00:01:00Z".to_owned());
        assert!(matches!(
            validate_authorized_delta(
                &deployment(),
                &deleting,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::UnauthorizedDelta(path)) if path == "/metadata/deletionTimestamp"
        ));
        Ok(())
    }

    #[test]
    fn eventual_projection_allows_only_declared_controller_bookkeeping()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = template();
        let transaction_id = Uuid::from_bytes([1; 16]);
        let authorization_id = Uuid::from_bytes([2; 16]);
        let prepared = prepare_patch(&template, transaction_id, authorization_id)?;
        let post_admission = authorized_after(
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;
        let mut eventual = post_admission.clone();
        eventual["metadata"]["resourceVersion"] = Value::String("1009".to_owned());
        eventual["metadata"]["managedFields"] = json!([{"manager":"kube-controller-manager"}]);
        eventual["metadata"]["annotations"][DEPLOYMENT_REVISION_ANNOTATION] =
            Value::String("2".to_owned());
        eventual["status"] = json!({"availableReplicas":2,"observedGeneration":2});
        validate_eventual_controller_projection(
            &post_admission,
            &eventual,
            &template,
            transaction_id,
            authorization_id,
            prepared.operation_hash,
        )?;

        let mut generation_drift = eventual.clone();
        generation_drift["metadata"]["generation"] = json!(3);
        assert!(matches!(
            validate_eventual_controller_projection(
                &post_admission,
                &generation_drift,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::UnauthorizedDelta(path)) if path == "/metadata/generation"
        ));

        eventual["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .ok_or("containers not array")?
            .push(json!({"name":"injected","image":"attacker.invalid/sidecar:latest"}));
        assert!(matches!(
            validate_eventual_controller_projection(
                &post_admission,
                &eventual,
                &template,
                transaction_id,
                authorization_id,
                prepared.operation_hash,
            ),
            Err(ProjectionError::UnauthorizedDelta(_))
        ));
        Ok(())
    }

    #[test]
    fn malformed_image_repository_is_rejected_before_patch_construction() {
        for repository in [
            "acme/payments@attacker",
            "acme/payments:latest",
            "Acme/payments",
            "acme//payments",
            "acme/payments.",
            "registry.invalid:0/payments",
            "registry.invalid:70000/payments",
        ] {
            let mut template = template();
            template.image_repository = repository.to_owned();
            assert!(matches!(
                prepare_patch(
                    &template,
                    Uuid::from_bytes([1; 16]),
                    Uuid::from_bytes([2; 16])
                ),
                Err(ProjectionError::InvalidTemplate(_))
            ));
        }

        let mut template = template();
        template.image_repository = "registry.example:5000/acme/payments_v2".to_owned();
        assert!(
            prepare_patch(
                &template,
                Uuid::from_bytes([1; 16]),
                Uuid::from_bytes([2; 16])
            )
            .is_ok()
        );
    }

    #[test]
    fn rollout_pod_projection_rejects_pod_admission_sidecars()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut eventual = deployment();
        eventual["spec"]["replicas"] = json!(1);
        eventual["spec"]["selector"] = json!({"matchLabels":{"app":"payments"}});
        eventual["spec"]["template"]["spec"]["automountServiceAccountToken"] = json!(false);
        eventual["status"] = json!({
            "observedGeneration":1,
            "replicas":1,
            "updatedReplicas":1,
            "readyReplicas":1,
            "availableReplicas":1
        });
        let expected_spec = eventual["spec"]["template"]["spec"].clone();
        let pod = json!({
            "apiVersion":"v1",
            "kind":"Pod",
            "metadata":{
                "name":"payments-abc",
                "namespace":"payments-prod",
                "labels":{"app":"payments","pod-template-hash":"abc"},
                "ownerReferences":[{
                    "apiVersion":"apps/v1",
                    "kind":"ReplicaSet",
                    "name":"payments-abc",
                    "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "controller":true
                }]
            },
            "spec":expected_spec,
            "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}
        });
        let pods = json!({"apiVersion":"v1","kind":"List","items":[pod]});
        validate_rollout_pods(&eventual, &pods)?;

        let mut injected = pods;
        injected["items"][0]["spec"]["containers"]
            .as_array_mut()
            .ok_or("Pod containers not array")?
            .push(json!({"name":"injected","image":"attacker.invalid/sidecar:latest"}));
        assert!(matches!(
            validate_rollout_pods(&eventual, &injected),
            Err(ProjectionError::UnauthorizedDelta(path)) if path.starts_with("/items/0/spec/containers")
        ));

        let mut unready = injected;
        unready["items"][0]["spec"]["containers"] =
            eventual["spec"]["template"]["spec"]["containers"].clone();
        unready["items"][0]["status"]["conditions"][0]["status"] =
            Value::String("False".to_owned());
        assert!(matches!(
            validate_rollout_pods(&eventual, &unready),
            Err(ProjectionError::Precondition(path)) if path.contains("Ready")
        ));
        Ok(())
    }

    #[test]
    fn rollout_pod_projection_ignores_terminating_old_pods_but_not_active_count_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut eventual = deployment();
        eventual["spec"]["replicas"] = json!(1);
        eventual["spec"]["selector"] = json!({"matchLabels":{"app":"payments"}});
        eventual["status"] = json!({
            "observedGeneration":1,
            "replicas":1,
            "updatedReplicas":1,
            "readyReplicas":1,
            "availableReplicas":1
        });
        let expected_spec = eventual["spec"]["template"]["spec"].clone();
        let active = json!({
            "apiVersion":"v1",
            "kind":"Pod",
            "metadata":{
                "namespace":"payments-prod",
                "labels":{"app":"payments","pod-template-hash":"abc"},
                "ownerReferences":[{
                    "apiVersion":"apps/v1",
                    "kind":"ReplicaSet",
                    "name":"payments-abc",
                    "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "controller":true
                }]
            },
            "spec":expected_spec,
            "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}
        });
        let mut terminating = active.clone();
        terminating["metadata"]["deletionTimestamp"] =
            Value::String("2026-08-16T00:02:00Z".to_owned());
        let pods = json!({
            "apiVersion":"v1",
            "kind":"List",
            "items":[active.clone(),terminating]
        });
        validate_rollout_pods(&eventual, &pods)?;

        let duplicate = json!({
            "apiVersion":"v1",
            "kind":"List",
            "items":[active.clone(),active]
        });
        assert!(matches!(
            validate_rollout_pods(&eventual, &duplicate),
            Err(ProjectionError::Precondition(_))
        ));
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn strict_rollout_fixture() -> (Value, Value, Value) {
        let mut eventual = deployment();
        eventual["spec"]["replicas"] = json!(1);
        eventual["spec"]["selector"] = json!({"matchLabels":{"app":"payments"}});
        eventual["spec"]["template"]["spec"]["automountServiceAccountToken"] = json!(false);
        eventual["status"] = json!({
            "observedGeneration":1,
            "replicas":1,
            "updatedReplicas":1,
            "readyReplicas":1,
            "availableReplicas":1
        });

        let mut current_template = eventual["spec"]["template"].clone();
        current_template["metadata"]["labels"]["pod-template-hash"] =
            Value::String("new-hash".to_owned());
        let current_replica_set = json!({
            "apiVersion":"apps/v1",
            "kind":"ReplicaSet",
            "metadata":{
                "name":"payments-new-hash",
                "namespace":"payments-prod",
                "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "generation":3,
                "labels":{"app":"payments","pod-template-hash":"new-hash"},
                "ownerReferences":[{
                    "apiVersion":"apps/v1",
                    "kind":"Deployment",
                    "name":"payments",
                    "uid":"11111111-2222-4333-8444-555555555555",
                    "controller":true
                }]
            },
            "spec":{
                "replicas":1,
                "selector":{"matchLabels":{"app":"payments","pod-template-hash":"new-hash"}},
                "template":current_template
            },
            "status":{
                "observedGeneration":3,
                "replicas":1,
                "fullyLabeledReplicas":1,
                "readyReplicas":1,
                "availableReplicas":1
            }
        });

        let mut historical_template = eventual["spec"]["template"].clone();
        historical_template["metadata"]["labels"]["pod-template-hash"] =
            Value::String("old-hash".to_owned());
        historical_template["spec"]["containers"][0]["image"] = Value::String(
            "acme/payments@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        );
        let historical_replica_set = json!({
            "apiVersion":"apps/v1",
            "kind":"ReplicaSet",
            "metadata":{
                "name":"payments-old-hash",
                "namespace":"payments-prod",
                "uid":"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
                "generation":4,
                "labels":{"app":"payments","pod-template-hash":"old-hash"},
                "ownerReferences":[{
                    "apiVersion":"apps/v1",
                    "kind":"Deployment",
                    "name":"payments",
                    "uid":"11111111-2222-4333-8444-555555555555",
                    "controller":true
                }]
            },
            "spec":{
                "replicas":0,
                "selector":{"matchLabels":{"app":"payments","pod-template-hash":"old-hash"}},
                "template":historical_template
            },
            "status":{
                "observedGeneration":4,
                "replicas":0,
                "fullyLabeledReplicas":0,
                "readyReplicas":0,
                "availableReplicas":0
            }
        });
        let replica_sets = json!({
            "apiVersion":"v1",
            "kind":"List",
            "items":[current_replica_set, historical_replica_set]
        });

        let pod = json!({
            "apiVersion":"v1",
            "kind":"Pod",
            "metadata":{
                "name":"payments-new-hash-abcde",
                "namespace":"payments-prod",
                "uid":"cccccccc-dddd-4eee-8fff-000000000000",
                "labels":{"app":"payments","pod-template-hash":"new-hash"},
                "ownerReferences":[{
                    "apiVersion":"apps/v1",
                    "kind":"ReplicaSet",
                    "name":"payments-new-hash",
                    "uid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "controller":true
                }]
            },
            "spec":eventual["spec"]["template"]["spec"].clone(),
            "status":{
                "phase":"Running",
                "conditions":[{"type":"Ready","status":"True"}]
            }
        });
        let pods = json!({"apiVersion":"v1","kind":"List","items":[pod]});
        (eventual, replica_sets, pods)
    }

    #[test]
    fn strict_rollout_accepts_exact_chain_and_zero_scale_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let (eventual, replica_sets, pods) = strict_rollout_fixture();
        validate_rollout_ownership_strict(&eventual, &replica_sets, &pods)?;
        Ok(())
    }

    #[test]
    fn strict_rollout_rejects_foreign_evil_replica_set() {
        let (eventual, mut replica_sets, pods) = strict_rollout_fixture();
        replica_sets["items"][1]["metadata"]["ownerReferences"][0]["name"] =
            Value::String("evil-deployment".to_owned());
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::Precondition(path)) if path.contains("ownerReferences")
        ));
    }

    #[test]
    fn strict_rollout_rejects_wrong_deployment_owner_uid() {
        let (eventual, mut replica_sets, pods) = strict_rollout_fixture();
        replica_sets["items"][0]["metadata"]["ownerReferences"][0]["uid"] =
            Value::String("99999999-8888-4777-8666-555555555555".to_owned());
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::Precondition(path)) if path.contains("ownerReferences")
        ));
    }

    #[test]
    fn strict_rollout_rejects_template_hash_mismatch() {
        let (eventual, replica_sets, mut pods) = strict_rollout_fixture();
        pods["items"][0]["metadata"]["labels"]["pod-template-hash"] =
            Value::String("old-hash".to_owned());
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::AuthorizedValueMismatch(path)) if path.contains("labels")
        ));
    }

    #[test]
    fn strict_rollout_rejects_terminating_old_pod() -> Result<(), Box<dyn std::error::Error>> {
        let (eventual, replica_sets, mut pods) = strict_rollout_fixture();
        let mut old_pod = pods["items"][0].clone();
        old_pod["metadata"]["name"] = Value::String("payments-old-hash-abcde".to_owned());
        old_pod["metadata"]["uid"] =
            Value::String("dddddddd-eeee-4fff-8000-111111111111".to_owned());
        old_pod["metadata"]["labels"]["pod-template-hash"] = Value::String("old-hash".to_owned());
        old_pod["metadata"]["ownerReferences"][0]["name"] =
            Value::String("payments-old-hash".to_owned());
        old_pod["metadata"]["ownerReferences"][0]["uid"] =
            Value::String("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff".to_owned());
        old_pod["metadata"]["deletionTimestamp"] = Value::String("2026-08-16T00:02:00Z".to_owned());
        pods["items"]
            .as_array_mut()
            .ok_or("items is not an array")?
            .push(old_pod);
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::Precondition(path)) if path == "/metadata/deletionTimestamp"
        ));
        Ok(())
    }

    #[test]
    fn strict_rollout_rejects_duplicate_owner_and_replica_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let (eventual, replica_sets, mut pods) = strict_rollout_fixture();
        let duplicate_owner = pods["items"][0]["metadata"]["ownerReferences"][0].clone();
        pods["items"][0]["metadata"]["ownerReferences"]
            .as_array_mut()
            .ok_or("ownerReferences is not an array")?
            .push(duplicate_owner);
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::Precondition(path)) if path.contains("ownerReferences")
        ));

        let (eventual, mut replica_sets, pods) = strict_rollout_fixture();
        let duplicate_replica_set = replica_sets["items"][0].clone();
        replica_sets["items"]
            .as_array_mut()
            .ok_or("items is not an array")?
            .push(duplicate_replica_set);
        assert!(matches!(
            validate_rollout_ownership_strict(&eventual, &replica_sets, &pods),
            Err(ProjectionError::Precondition(path)) if path.contains("duplicates a ReplicaSet")
        ));
        Ok(())
    }
}

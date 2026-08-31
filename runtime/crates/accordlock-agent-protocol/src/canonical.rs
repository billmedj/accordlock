use std::convert::Infallible;

use accordlock_protocol::{CanonicalEncode, CanonicalError, Digest32};
use minicbor::Encoder;
use minicbor::encode::Error as EncodeError;
use serde_json::Value;

use crate::model::{
    AuthorizationDecision, ExecutionAuthorization, ExecutionRecord, ExecutionRequest,
    ValidationError, canonical_validation_error,
};

pub const EXECUTION_ARGUMENTS_DOMAIN: &str = "accordlock:v2:execution-arguments";
pub const EXECUTION_REQUEST_DOMAIN: &str = "accordlock:v2:execution-request";
pub const AUTHORIZATION_DECISION_DOMAIN: &str = "accordlock:v4:authorization-decision";
const LEGACY_AUTHORIZATION_DECISION_DOMAIN_V3: &str = "accordlock:v3:authorization-decision";
pub const EXECUTION_AUTHORIZATION_DOMAIN: &str = "accordlock:v2:agent-execution-authorization";
pub const EXECUTION_RECORD_DOMAIN: &str = "accordlock:v2:execution-record";

type VecEncoder = Encoder<Vec<u8>>;
type VecEncodeError = EncodeError<Infallible>;

/// Produces a deterministic, type-preserving CBOR representation of arbitrary
/// JSON tool arguments. Object keys are sorted independently of map insertion
/// order and the traversal is bounded before allocation is trusted.
///
/// # Errors
///
/// Returns [`ValidationError`] when the value exceeds the depth, node, key, or
/// encoded-size profile limits, or if canonical CBOR encoding fails.
pub fn canonical_args_bytes(value: &Value) -> Result<Vec<u8>, ValidationError> {
    let mut budget = ArgumentBudget::default();
    inspect_arguments(value, 0, &mut budget)?;

    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(2)
        .map_err(|error| ValidationError::Canonical(error.to_string()))?;
    encoder
        .str(EXECUTION_ARGUMENTS_DOMAIN)
        .map_err(|error| ValidationError::Canonical(error.to_string()))?;
    encode_json(&mut encoder, value)
        .map_err(|error| ValidationError::Canonical(error.to_string()))?;
    let bytes = encoder.into_writer();
    if bytes.len() > crate::MAX_CANONICAL_ARGUMENT_BYTES {
        return Err(ValidationError::CanonicalArgumentsTooLarge);
    }
    Ok(bytes)
}

/// SHA-256 commitment to [`canonical_args_bytes`].
///
/// # Errors
///
/// Returns [`ValidationError`] under the same bounded-profile conditions as
/// [`canonical_args_bytes`].
pub fn canonical_args_hash(value: &Value) -> Result<Digest32, ValidationError> {
    Ok(Digest32::sha256(&canonical_args_bytes(value)?))
}

#[derive(Default)]
struct ArgumentBudget {
    nodes: usize,
    text_bytes: usize,
}

fn inspect_arguments(
    value: &Value,
    depth: usize,
    budget: &mut ArgumentBudget,
) -> Result<(), ValidationError> {
    if depth > crate::MAX_CANONICAL_ARGUMENT_DEPTH {
        return Err(ValidationError::CanonicalArgumentsTooDeep);
    }
    budget.nodes = budget
        .nodes
        .checked_add(1)
        .ok_or(ValidationError::CanonicalArgumentsTooManyNodes)?;
    if budget.nodes > crate::MAX_CANONICAL_ARGUMENT_NODES {
        return Err(ValidationError::CanonicalArgumentsTooManyNodes);
    }

    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(text) => add_text_budget(budget, text.len())?,
        Value::Array(values) => {
            for item in values {
                inspect_arguments(item, depth + 1, budget)?;
            }
        }
        Value::Object(values) => {
            for (key, item) in values {
                if key.len() > 1_024 {
                    return Err(ValidationError::CanonicalArgumentKeyTooLong);
                }
                add_text_budget(budget, key.len())?;
                inspect_arguments(item, depth + 1, budget)?;
            }
        }
    }

    if budget.text_bytes > crate::MAX_CANONICAL_ARGUMENT_BYTES {
        return Err(ValidationError::CanonicalArgumentsTooLarge);
    }
    Ok(())
}

fn add_text_budget(budget: &mut ArgumentBudget, bytes: usize) -> Result<(), ValidationError> {
    budget.text_bytes = budget
        .text_bytes
        .checked_add(bytes)
        .ok_or(ValidationError::CanonicalArgumentsTooLarge)?;
    Ok(())
}

fn encode_json(encoder: &mut VecEncoder, value: &Value) -> Result<(), VecEncodeError> {
    match value {
        Value::Null => {
            encoder.array(1)?;
            encoder.u8(0)?;
        }
        Value::Bool(value) => {
            encoder.array(2)?;
            encoder.u8(1)?;
            encoder.bool(*value)?;
        }
        Value::Number(value) => {
            encoder.array(2)?;
            encoder.u8(2)?;
            encoder.str(&value.to_string())?;
        }
        Value::String(value) => {
            encoder.array(2)?;
            encoder.u8(3)?;
            encoder.str(value)?;
        }
        Value::Array(values) => {
            encoder.array(3)?;
            encoder.u8(4)?;
            encoder.array(u64::try_from(values.len()).unwrap_or(u64::MAX))?;
            for item in values {
                encode_json(encoder, item)?;
            }
        }
        Value::Object(values) => {
            encoder.array(3)?;
            encoder.u8(5)?;
            encoder.array(u64::try_from(values.len()).unwrap_or(u64::MAX))?;
            let mut ordered = values.iter().collect::<Vec<_>>();
            ordered.sort_unstable_by(|left, right| left.0.cmp(right.0));
            for (key, item) in ordered {
                encoder.array(2)?;
                encoder.str(key)?;
                encode_json(encoder, item)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_bindings(
    encoder: &mut VecEncoder,
    session_id: &str,
    run_id: &str,
    tool_call_id: &str,
    workspace: &str,
    extension: &str,
    tool: &str,
    canonical_args_hash: Digest32,
    policy_epoch: u64,
    task_policy_hash: Digest32,
) -> Result<(), VecEncodeError> {
    encoder.str(session_id)?;
    encoder.str(run_id)?;
    encoder.str(tool_call_id)?;
    encoder.str(workspace)?;
    encoder.str(extension)?;
    encoder.str(tool)?;
    encoder.bytes(canonical_args_hash.as_bytes())?;
    encoder.u64(policy_epoch)?;
    encoder.bytes(task_policy_hash.as_bytes())?;
    Ok(())
}

fn finish(result: Result<Vec<u8>, VecEncodeError>) -> Result<Vec<u8>, CanonicalError> {
    result.map_err(|error| CanonicalError::Encode(error.to_string()))
}

impl CanonicalEncode for ExecutionRequest {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| canonical_validation_error())?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(14)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_id.as_bytes())?;
            encode_bindings(
                &mut encoder,
                &self.session_id,
                &self.run_id,
                &self.tool_call_id,
                &self.workspace,
                &self.extension,
                &self.tool,
                self.canonical_args_hash,
                self.policy_epoch,
                self.task_policy_hash,
            )?;
            encoder.i64(self.created_at)?;
            encoder.i64(self.expires_at)?;
            encoder.str(EXECUTION_REQUEST_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for AuthorizationDecision {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| canonical_validation_error())?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            let current = self.schema_version == crate::AUTHORIZATION_DECISION_SCHEMA_VERSION;
            encoder.array(if current { 20 } else { 19 })?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encode_bindings(
                &mut encoder,
                &self.session_id,
                &self.run_id,
                &self.tool_call_id,
                &self.workspace,
                &self.extension,
                &self.tool,
                self.canonical_args_hash,
                self.policy_epoch,
                self.task_policy_hash,
            )?;
            encoder.bytes(self.policy_decision_hash.as_bytes())?;
            encoder.array(
                u64::try_from(self.conformance_evaluation_hashes.len()).unwrap_or(u64::MAX),
            )?;
            for hash in &self.conformance_evaluation_hashes {
                encoder.bytes(hash.as_bytes())?;
            }
            if current {
                encoder.bytes(self.intent_evaluation_hash.as_bytes())?;
            }
            encoder.u8(self.outcome.code())?;
            encoder.str(&self.reason_code)?;
            if let Some(hash) = self.approval_evidence_hash {
                encoder.bytes(hash.as_bytes())?;
            } else {
                encoder.null()?;
            }
            encoder.i64(self.decided_at)?;
            encoder.i64(self.expires_at)?;
            encoder.str(if current {
                AUTHORIZATION_DECISION_DOMAIN
            } else {
                LEGACY_AUTHORIZATION_DECISION_DOMAIN_V3
            })?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ExecutionAuthorization {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| canonical_validation_error())?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(17)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.authorization_id.as_bytes())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.authorization_decision_hash.as_bytes())?;
            encode_bindings(
                &mut encoder,
                &self.session_id,
                &self.run_id,
                &self.tool_call_id,
                &self.workspace,
                &self.extension,
                &self.tool,
                self.canonical_args_hash,
                self.policy_epoch,
                self.task_policy_hash,
            )?;
            encoder.i64(self.issued_at)?;
            encoder.i64(self.not_before)?;
            encoder.i64(self.expires_at)?;
            encoder.str(EXECUTION_AUTHORIZATION_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

impl CanonicalEncode for ExecutionRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        self.validate().map_err(|_| canonical_validation_error())?;
        finish((|| {
            let mut encoder = Encoder::new(Vec::new());
            encoder.array(19)?;
            encoder.u16(self.schema_version)?;
            encoder.bytes(self.record_id.as_bytes())?;
            encoder.bytes(self.authorization_id.as_bytes())?;
            encoder.bytes(self.request_hash.as_bytes())?;
            encoder.bytes(self.authorization_hash.as_bytes())?;
            encode_bindings(
                &mut encoder,
                &self.session_id,
                &self.run_id,
                &self.tool_call_id,
                &self.workspace,
                &self.extension,
                &self.tool,
                self.canonical_args_hash,
                self.policy_epoch,
                self.task_policy_hash,
            )?;
            encoder.i64(self.consumed_at)?;
            encoder.i64(self.completed_at)?;
            encoder.u8(self.outcome.code())?;
            encoder.bytes(self.result_hash.as_bytes())?;
            encoder.str(EXECUTION_RECORD_DOMAIN)?;
            Ok(encoder.into_writer())
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_type_domains_are_pairwise_distinct() {
        let domains = [
            EXECUTION_ARGUMENTS_DOMAIN,
            EXECUTION_REQUEST_DOMAIN,
            AUTHORIZATION_DECISION_DOMAIN,
            EXECUTION_AUTHORIZATION_DOMAIN,
            EXECUTION_RECORD_DOMAIN,
            accordlock_protocol::EXECUTION_AUTHORIZATION_DOMAIN,
        ];
        for (index, domain) in domains.iter().enumerate() {
            assert!(
                domains[..index].iter().all(|prior| prior != domain),
                "canonical domain is reused: {domain}"
            );
        }
    }
}

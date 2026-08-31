use accordlock_agent_protocol::Digest32;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::model::WireValidationError;

pub(crate) const EXECUTION_OBSERVATION_DOMAIN: &[u8] =
    b"accordlock:v2:agent-execution-observation\0";

pub(crate) fn canonical_json_bytes<T: Serialize + ?Sized>(
    input: &T,
) -> Result<Vec<u8>, WireValidationError> {
    let value = serde_json::to_value(input).map_err(|_| WireValidationError::CanonicalJson)?;
    serde_json::to_vec(&sort_json(value)).map_err(|_| WireValidationError::CanonicalJson)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sort_json(value)))
                    .collect(),
            )
        }
        scalar => scalar,
    }
}

pub(crate) fn goose_digest<T: Serialize + ?Sized>(
    input: &T,
) -> Result<String, WireValidationError> {
    canonical_json_bytes(input).map(|bytes| digest_bytes(&bytes).to_string())
}

pub(crate) fn domain_digest<T: Serialize + ?Sized>(
    domain: &[u8],
    input: &T,
) -> Result<String, WireValidationError> {
    let canonical = canonical_json_bytes(input)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    Ok(Digest32::from_bytes(bytes).to_string())
}

pub(crate) fn digest_bytes(input: &[u8]) -> Digest32 {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&Sha256::digest(input));
    Digest32::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recursively_sorted_json_matches_goose_profile() {
        let left = json!({"z": 1, "a": {"y": 2, "b": 3}});
        let right = json!({"a": {"b": 3, "y": 2}, "z": 1});
        assert_eq!(canonical_json_bytes(&left), canonical_json_bytes(&right));
        assert_eq!(goose_digest(&left), goose_digest(&right));
        assert_eq!(
            domain_digest(EXECUTION_OBSERVATION_DOMAIN, &left),
            domain_digest(EXECUTION_OBSERVATION_DOMAIN, &right)
        );
        assert_ne!(
            goose_digest(&left),
            domain_digest(EXECUTION_OBSERVATION_DOMAIN, &left)
        );
    }
}

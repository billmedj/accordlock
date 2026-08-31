use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use uuid::Uuid;

const MAX_JWT_SEGMENT_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct JwtExpectation<'a> {
    pub subject: &'a str,
    pub audience: &'a str,
    pub namespace: &'a str,
    pub service_account: &'a str,
    pub service_account_uid: &'a str,
    pub secret_name: &'a str,
    pub secret_uid: &'a str,
    pub expiration: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JwtClaims {
    pub not_before: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub credential_authorization_id: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JwtError {
    InvalidCompactForm,
    InvalidEncoding,
    InvalidHeader,
    InvalidClaims,
    BindingMismatch,
}

pub(crate) fn validate_bound_token(
    token: &[u8],
    expected: JwtExpectation<'_>,
) -> Result<JwtClaims, JwtError> {
    let mut segments = token.split(|byte| *byte == b'.');
    let header_segment = segments.next().ok_or(JwtError::InvalidCompactForm)?;
    let payload_segment = segments.next().ok_or(JwtError::InvalidCompactForm)?;
    let signature_segment = segments.next().ok_or(JwtError::InvalidCompactForm)?;
    if segments.next().is_some()
        || header_segment.is_empty()
        || payload_segment.is_empty()
        || signature_segment.is_empty()
        || header_segment.len() > MAX_JWT_SEGMENT_BYTES
        || payload_segment.len() > MAX_JWT_SEGMENT_BYTES
        || signature_segment.len() > MAX_JWT_SEGMENT_BYTES
    {
        return Err(JwtError::InvalidCompactForm);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| JwtError::InvalidEncoding)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| JwtError::InvalidEncoding)?;
    if header_bytes.len() > MAX_JWT_SEGMENT_BYTES || payload_bytes.len() > MAX_JWT_SEGMENT_BYTES {
        return Err(JwtError::InvalidEncoding);
    }
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        .ok_or(JwtError::InvalidHeader)?;
    if algorithm.len() > 128 || header.as_object().is_none() {
        return Err(JwtError::InvalidHeader);
    }
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::InvalidClaims)?;
    let object = payload.as_object().ok_or(JwtError::InvalidClaims)?;
    require_string(object.get("sub"), expected.subject)?;
    require_exact_audience(object.get("aud"), expected.audience)?;
    let expires_at = require_integer(object.get("exp"))?;
    let not_before = require_integer(object.get("nbf"))?;
    let issued_at = require_integer(object.get("iat"))?;
    let credential_authorization_id = require_canonical_uuid(object.get("authorization_id"))?;
    if expires_at != expected.expiration || not_before > issued_at || issued_at >= expires_at {
        return Err(JwtError::BindingMismatch);
    }

    let kubernetes = object
        .get("kubernetes.io")
        .and_then(Value::as_object)
        .ok_or(JwtError::InvalidClaims)?;
    require_string(kubernetes.get("namespace"), expected.namespace)?;
    let service_account = kubernetes
        .get("serviceaccount")
        .and_then(Value::as_object)
        .ok_or(JwtError::InvalidClaims)?;
    require_string(service_account.get("name"), expected.service_account)?;
    require_string(service_account.get("uid"), expected.service_account_uid)?;
    let secret = kubernetes
        .get("secret")
        .and_then(Value::as_object)
        .ok_or(JwtError::InvalidClaims)?;
    require_string(secret.get("name"), expected.secret_name)?;
    require_string(secret.get("uid"), expected.secret_uid)?;
    Ok(JwtClaims {
        not_before,
        issued_at,
        expires_at,
        credential_authorization_id,
    })
}

fn require_canonical_uuid(value: Option<&Value>) -> Result<Uuid, JwtError> {
    let encoded = value
        .and_then(Value::as_str)
        .ok_or(JwtError::InvalidClaims)?;
    let parsed = Uuid::parse_str(encoded).map_err(|_| JwtError::InvalidClaims)?;
    if parsed.is_nil() || encoded != parsed.to_string() {
        return Err(JwtError::InvalidClaims);
    }
    Ok(parsed)
}

fn require_string(value: Option<&Value>, expected: &str) -> Result<(), JwtError> {
    if value.and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(JwtError::BindingMismatch)
    }
}

fn require_exact_audience(value: Option<&Value>, expected: &str) -> Result<(), JwtError> {
    match value {
        Some(Value::String(candidate)) if candidate == expected => Ok(()),
        Some(Value::Array(candidates))
            if candidates.len() == 1 && candidates[0].as_str() == Some(expected) =>
        {
            Ok(())
        }
        _ => Err(JwtError::BindingMismatch),
    }
}

fn require_integer(value: Option<&Value>) -> Result<i64, JwtError> {
    value.and_then(Value::as_i64).ok_or(JwtError::InvalidClaims)
}

pub(crate) fn parse_rfc3339_utc(value: &str) -> Result<i64, JwtError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 30
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().ok_or(JwtError::InvalidClaims)? != b'Z'
    {
        return Err(JwtError::InvalidClaims);
    }
    let year = decimal(&bytes[0..4])?;
    let month = decimal(&bytes[5..7])?;
    let day = decimal(&bytes[8..10])?;
    let hour = decimal(&bytes[11..13])?;
    let minute = decimal(&bytes[14..16])?;
    let second = decimal(&bytes[17..19])?;
    let between = &bytes[19..bytes.len() - 1];
    if !between.is_empty()
        && (between[0] != b'.'
            || between.len() == 1
            || between.len() > 10
            || !between[1..].iter().all(u8::is_ascii_digit))
    {
        return Err(JwtError::InvalidClaims);
    }
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(JwtError::InvalidClaims);
    }
    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or(JwtError::InvalidClaims)
}

fn decimal(bytes: &[u8]) -> Result<i64, JwtError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(JwtError::InvalidClaims);
    }
    bytes.iter().try_fold(0_i64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|current| current.checked_add(i64::from(byte - b'0')))
            .ok_or(JwtError::InvalidClaims)
    })
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = adjusted_year / 400;
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn token(mut payload: Value) -> Vec<u8> {
        if payload.get("exp").is_none() {
            payload["exp"] = json!(1_700_000_100_i64);
        }
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap_or_default());
        format!("{header}.{body}.signature").into_bytes()
    }

    fn expectation<'a>() -> JwtExpectation<'a> {
        JwtExpectation {
            subject: "system:serviceaccount:payments:accordlock-attempt",
            audience: "accordlock-executor",
            namespace: "payments",
            service_account: "accordlock-attempt",
            service_account_uid: "sa-uid",
            secret_name: "accordlock-00000000000000000000000000000001",
            secret_uid: "secret-uid",
            expiration: 1_700_000_100,
        }
    }

    #[test]
    fn validates_exact_secret_bound_claims() {
        let payload = json!({
            "sub":"system:serviceaccount:payments:accordlock-attempt",
            "aud":["accordlock-executor"],
            "exp":1_700_000_100_i64,
            "nbf":1_700_000_000_i64,
            "iat":1_700_000_000_i64,
            "authorization_id":"7ee52be0-9045-4653-aa5e-0da57b8dccdc",
            "kubernetes.io":{
                "namespace":"payments",
                "serviceaccount":{"name":"accordlock-attempt","uid":"sa-uid"},
                "secret":{"name":"accordlock-00000000000000000000000000000001","uid":"secret-uid"}
            }
        });
        assert_eq!(
            validate_bound_token(&token(payload), expectation()),
            Ok(JwtClaims {
                not_before: 1_700_000_000,
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_100,
                credential_authorization_id: Uuid::parse_str(
                    "7ee52be0-9045-4653-aa5e-0da57b8dccdc"
                )
                .unwrap_or_default(),
            })
        );
    }

    #[test]
    fn rejects_wrong_secret_even_after_tokenreview_would_authenticate() {
        let payload = json!({
            "sub":"system:serviceaccount:payments:accordlock-attempt",
            "aud":"accordlock-executor",
            "exp":1_700_000_100_i64,
            "nbf":1_700_000_000_i64,
            "iat":1_700_000_000_i64,
            "authorization_id":"7ee52be0-9045-4653-aa5e-0da57b8dccdc",
            "kubernetes.io":{
                "namespace":"payments",
                "serviceaccount":{"name":"accordlock-attempt","uid":"sa-uid"},
                "secret":{"name":"attacker","uid":"secret-uid"}
            }
        });
        assert_eq!(
            validate_bound_token(&token(payload), expectation()),
            Err(JwtError::BindingMismatch)
        );
    }

    #[test]
    fn parses_go_style_utc_rfc3339() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(
            parse_rfc3339_utc("2000-02-29T12:34:56.123456789Z"),
            Ok(951_827_696)
        );
        assert_eq!(
            parse_rfc3339_utc("2023-02-29T00:00:00Z"),
            Err(JwtError::InvalidClaims)
        );
        assert_eq!(
            parse_rfc3339_utc("2024-01-01T00:00:00+00:00"),
            Err(JwtError::InvalidClaims)
        );
    }
}

//! AccordLock-only provider credential storage.
//!
//! OAuth credentials use dedicated keyring entries instead of the shared
//! provider-secret entry. Windows Credential Manager limits each password to
//! 2,560 bytes after UTF-16 encoding, so serialized credentials are base64
//! encoded and split into bounded ASCII chunks.

use std::sync::{LazyLock, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_VERSION: u8 = 1;
const CHUNK_ASCII_LIMIT: usize = 1_000;
const MAX_CHUNK_COUNT: usize = 1_024;
const SERVICE_PREFIX: &str = "accordlock.oauth";
const MANIFEST_ENTRY: &str = "manifest";

static VAULT_OPERATION_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CredentialManifest {
    version: u8,
    key: String,
    generation: String,
    chunk_count: usize,
    sha256: String,
}

#[derive(Debug, Clone)]
struct EncodedCredential {
    manifest: CredentialManifest,
    chunks: Vec<String>,
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid provider credential vault key")
    }
    Ok(())
}

fn validate_generation(generation: &str) -> Result<()> {
    if generation.is_empty()
        || generation.len() > 128
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid provider credential vault generation")
    }
    Ok(())
}

fn service_name(key: &str) -> String {
    format!("{SERVICE_PREFIX}.{}", key.to_ascii_lowercase())
}

fn chunk_entry_name(generation: &str, index: usize) -> String {
    format!("chunk.{generation}.{index:04}")
}

fn entry(key: &str, name: &str) -> Result<Entry> {
    Entry::new(&service_name(key), name)
        .with_context(|| format!("failed to open operating-system credential vault entry: {key}"))
}

fn digest_base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn encode_serialized(key: &str, generation: &str, serialized: &[u8]) -> Result<EncodedCredential> {
    validate_key(key)?;
    validate_generation(generation)?;

    let encoded = URL_SAFE_NO_PAD.encode(serialized);
    let chunks = encoded
        .as_bytes()
        .chunks(CHUNK_ASCII_LIMIT)
        .map(|chunk| {
            String::from_utf8(chunk.to_vec()).expect("base64 credential chunks are always ASCII")
        })
        .collect::<Vec<_>>();

    if chunks.is_empty() || chunks.len() > MAX_CHUNK_COUNT {
        bail!("provider credential is too large for the operating-system vault")
    }

    let manifest = CredentialManifest {
        version: MANIFEST_VERSION,
        key: key.to_string(),
        generation: generation.to_string(),
        chunk_count: chunks.len(),
        sha256: digest_base64(serialized),
    };
    let manifest_size = serde_json::to_string(&manifest)?.len();
    if manifest_size > CHUNK_ASCII_LIMIT {
        bail!("provider credential manifest is too large for the operating-system vault")
    }

    Ok(EncodedCredential { manifest, chunks })
}

fn validate_manifest<'a>(key: &str, manifest: &'a CredentialManifest) -> Result<&'a str> {
    if manifest.version != MANIFEST_VERSION {
        bail!(
            "unsupported provider credential manifest version: {}",
            manifest.version
        )
    }
    if manifest.key != key {
        bail!("provider credential manifest key mismatch")
    }
    validate_generation(&manifest.generation)?;
    if manifest.chunk_count == 0 || manifest.chunk_count > MAX_CHUNK_COUNT {
        bail!("invalid provider credential chunk count")
    }
    Ok(&manifest.generation)
}

fn decode_serialized(
    key: &str,
    manifest: &CredentialManifest,
    chunks: &[String],
) -> Result<Vec<u8>> {
    validate_manifest(key, manifest)?;
    if chunks.len() != manifest.chunk_count {
        bail!("provider credential chunk count does not match its manifest")
    }
    if chunks
        .iter()
        .any(|chunk| chunk.is_empty() || chunk.len() > CHUNK_ASCII_LIMIT || !chunk.is_ascii())
    {
        bail!("provider credential contains an invalid vault chunk")
    }

    let encoded = chunks.concat();
    let serialized = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("provider credential contains invalid base64 data")?;
    if digest_base64(&serialized) != manifest.sha256 {
        bail!("provider credential failed its vault integrity check")
    }
    Ok(serialized)
}

fn parse_manifest(key: &str, raw: &str) -> Result<CredentialManifest> {
    let manifest: CredentialManifest = serde_json::from_str(raw)
        .with_context(|| format!("invalid provider credential manifest in the vault: {key}"))?;
    validate_manifest(key, &manifest)?;
    Ok(manifest)
}

fn read_manifest(key: &str) -> Result<Option<CredentialManifest>> {
    let manifest_entry = entry(key, MANIFEST_ENTRY)?;
    match manifest_entry.get_password() {
        Ok(raw) => parse_manifest(key, &raw).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!("failed to read provider credential manifest from the vault: {key}")
        }),
    }
}

fn read_serialized(key: &str) -> Result<Option<Vec<u8>>> {
    let Some(manifest) = read_manifest(key)? else {
        return Ok(None);
    };

    let mut chunks = Vec::with_capacity(manifest.chunk_count);
    for index in 0..manifest.chunk_count {
        let name = chunk_entry_name(&manifest.generation, index);
        let chunk = entry(key, &name)?.get_password().with_context(|| {
            format!("failed to read provider credential chunk from the vault: {key}")
        })?;
        chunks.push(chunk);
    }
    decode_serialized(key, &manifest, &chunks).map(Some)
}

fn delete_entry_if_present(key: &str, name: &str) -> Result<()> {
    match entry(key, name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!("failed to delete provider credential entry from the vault: {key}")
        }),
    }
}

fn delete_generation(key: &str, manifest: &CredentialManifest) -> Result<()> {
    let mut first_error = None;
    for index in 0..manifest.chunk_count {
        let name = chunk_entry_name(&manifest.generation, index);
        if let Err(error) = delete_entry_if_present(key, &name) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Load a structured OAuth credential from its dedicated OS-vault entries.
///
/// A genuinely missing manifest is `Ok(None)`. Vault availability, manifest,
/// chunk, decoding, and integrity failures remain errors so callers cannot
/// silently start a new OAuth flow.
pub(crate) fn load<T: DeserializeOwned>(key: &str) -> Result<Option<T>> {
    validate_key(key)?;
    let _guard = VAULT_OPERATION_MUTEX
        .lock()
        .map_err(|_| anyhow!("provider credential vault operation mutex is poisoned"))?;
    read_serialized(key)?
        .map(|serialized| {
            serde_json::from_slice(&serialized)
                .with_context(|| format!("invalid structured credential in the vault: {key}"))
        })
        .transpose()
}

/// Store a structured OAuth credential in generation-scoped OS-vault entries.
pub(crate) fn save<T: Serialize>(key: &str, value: &T) -> Result<()> {
    validate_key(key)?;
    let serialized = serde_json::to_vec(value)?;
    let generation = nanoid::nanoid!(24);
    let encoded = encode_serialized(key, &generation, &serialized)?;
    let manifest_password = serde_json::to_string(&encoded.manifest)?;

    let _guard = VAULT_OPERATION_MUTEX
        .lock()
        .map_err(|_| anyhow!("provider credential vault operation mutex is poisoned"))?;
    let previous_manifest = read_manifest(key)?;

    for (index, chunk) in encoded.chunks.iter().enumerate() {
        let name = chunk_entry_name(&encoded.manifest.generation, index);
        let chunk_entry = match entry(key, &name) {
            Ok(chunk_entry) => chunk_entry,
            Err(error) => {
                let _ = delete_generation(key, &encoded.manifest);
                return Err(error);
            }
        };
        if let Err(error) = chunk_entry.set_password(chunk) {
            let _ = delete_generation(key, &encoded.manifest);
            return Err(error).with_context(|| {
                format!("failed to store provider credential chunk in the vault: {key}")
            });
        }
    }

    let manifest_entry = match entry(key, MANIFEST_ENTRY) {
        Ok(manifest_entry) => manifest_entry,
        Err(error) => {
            let _ = delete_generation(key, &encoded.manifest);
            return Err(error);
        }
    };
    if let Err(error) = manifest_entry.set_password(&manifest_password) {
        let _ = delete_generation(key, &encoded.manifest);
        return Err(error).with_context(|| {
            format!("failed to store provider credential manifest in the vault: {key}")
        });
    }

    if let Some(previous_manifest) = previous_manifest {
        if previous_manifest.generation != encoded.manifest.generation {
            if let Err(error) = delete_generation(key, &previous_manifest) {
                tracing::warn!(
                    "Failed to remove superseded provider credential generation for {}: {}",
                    key,
                    error
                );
            }
        }
    }
    Ok(())
}

/// Remove a structured OAuth credential and all chunks bound by its manifest.
pub(crate) fn delete(key: &str) -> Result<()> {
    validate_key(key)?;
    let _guard = VAULT_OPERATION_MUTEX
        .lock()
        .map_err(|_| anyhow!("provider credential vault operation mutex is poisoned"))?;
    let Some(manifest) = read_manifest(key)? else {
        return Ok(());
    };

    delete_generation(key, &manifest)?;
    delete_entry_if_present(key, MANIFEST_ENTRY)
}

/// Check whether a complete, integrity-valid OAuth credential exists.
pub(crate) fn contains(key: &str) -> Result<bool> {
    validate_key(key)?;
    let _guard = VAULT_OPERATION_MUTEX
        .lock()
        .map_err(|_| anyhow!("provider credential vault operation mutex is poisoned"))?;
    Ok(read_serialized(key)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Fixture {
        access_token: String,
        refresh_token: String,
    }

    #[test]
    fn codec_chunks_and_reassembles_large_credentials_with_bounded_ascii_entries() {
        let fixture = Fixture {
            access_token: "a".repeat(3_000),
            refresh_token: "r".repeat(2_000),
        };
        let serialized = serde_json::to_vec(&fixture).unwrap();
        let encoded =
            encode_serialized("FIXTURE_OAUTH_TOKEN_CACHE", "generation-1", &serialized).unwrap();

        assert!(encoded.chunks.len() > 1);
        assert!(encoded
            .chunks
            .iter()
            .all(|chunk| chunk.is_ascii() && chunk.len() <= CHUNK_ASCII_LIMIT));
        assert_eq!(encoded.manifest.chunk_count, encoded.chunks.len());
        assert_eq!(encoded.manifest.sha256, digest_base64(&serialized));

        let reassembled = decode_serialized(
            "FIXTURE_OAUTH_TOKEN_CACHE",
            &encoded.manifest,
            &encoded.chunks,
        )
        .unwrap();
        let decoded: Fixture = serde_json::from_slice(&reassembled).unwrap();
        assert_eq!(decoded, fixture);
    }

    #[test]
    fn codec_rejects_tampered_chunks_and_manifest_binding_changes() {
        let serialized = serde_json::to_vec(&Fixture {
            access_token: "access".repeat(300),
            refresh_token: "refresh".repeat(300),
        })
        .unwrap();
        let encoded =
            encode_serialized("FIXTURE_OAUTH_TOKEN_CACHE", "generation-2", &serialized).unwrap();

        let mut tampered_chunks = encoded.chunks.clone();
        tampered_chunks[0].replace_range(0..1, "A");
        assert!(decode_serialized(
            "FIXTURE_OAUTH_TOKEN_CACHE",
            &encoded.manifest,
            &tampered_chunks
        )
        .is_err());

        let mut rebound_manifest = encoded.manifest.clone();
        rebound_manifest.key = "OTHER_OAUTH_TOKEN_CACHE".to_string();
        assert!(decode_serialized(
            "FIXTURE_OAUTH_TOKEN_CACHE",
            &rebound_manifest,
            &encoded.chunks
        )
        .is_err());
    }
}

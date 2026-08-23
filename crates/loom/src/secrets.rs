//! Project secret store: AES-256-GCM at rest, write-only reads.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::project::validate_project_name;
use crate::{LoomError, PersistentLoomStore, read_bounded, write_atomic};

const MAX_SECRETS_BYTES: u64 = 1024 * 1024;
const MAX_SECRETS: usize = 4096;
const MAX_KEY_LEN: usize = 128;
const MAX_VALUE_LEN: usize = 16 * 1024;
const NONCE_LEN: usize = 12;

/// One named variable, secret or plain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRecord {
    /// Project that owns the value.
    pub project: String,
    /// Environment (`staging`, `production`, `legacy`, or empty for all).
    #[serde(default)]
    pub environment: String,
    /// Variable name.
    pub key: String,
    /// True when the value is a secret (write-only on read).
    pub secret: bool,
    /// Ciphertext (hex) when `secret`, else plaintext.
    pub value: String,
}

/// Public view of a secret: values of secrets are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretView {
    /// Project.
    pub project: String,
    /// Environment.
    pub environment: String,
    /// Key.
    pub key: String,
    /// Whether the stored value is a secret.
    pub secret: bool,
    /// Plain value, or `None` for secrets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Upsert body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretUpsert {
    /// Project.
    pub project: String,
    /// Environment. Empty means all environments.
    #[serde(default)]
    pub environment: String,
    /// Key.
    pub key: String,
    /// Value (plaintext). Encrypted when `secret` is true.
    pub value: String,
    /// Treat as a secret.
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSecrets {
    schema_version: String,
    records: Vec<SecretRecord>,
}

/// AES-256-GCM secret store. The key is SHA-256 of `LOOM_SECRETS_KEY`.
#[derive(Debug, Clone)]
pub struct SecretStore {
    store: PersistentLoomStore,
    key: [u8; 32],
    configured: bool,
}

impl SecretStore {
    /// Opens the store. An empty `secrets_key` can list plaintext vars but
    /// refuses to persist secrets.
    #[must_use]
    pub fn new(store: PersistentLoomStore, secrets_key: &str) -> Self {
        let mut key = [0_u8; 32];
        let configured = !secrets_key.is_empty();
        if configured {
            key.copy_from_slice(Sha256::digest(secrets_key.as_bytes()).as_slice());
        }
        Self {
            store,
            key,
            configured,
        }
    }

    /// Lists secrets for a project. Secret values are omitted.
    ///
    /// # Errors
    ///
    /// Returns for lock or I/O failure.
    pub fn list(&self, project: &str) -> Result<Vec<SecretView>, LoomError> {
        Ok(self
            .load()?
            .into_values()
            .filter(|record| record.project == project)
            .map(|record| SecretView {
                project: record.project,
                environment: record.environment,
                key: record.key,
                secret: record.secret,
                value: (!record.secret).then_some(record.value),
            })
            .collect())
    }

    /// Decrypts inject-ready env for a project + environment.
    ///
    /// # Errors
    ///
    /// Returns for lock, I/O, or decrypt failure.
    pub fn inject(
        &self,
        project: &str,
        environment: &str,
    ) -> Result<BTreeMap<String, String>, LoomError> {
        let mut env = BTreeMap::new();
        for record in self.load()?.into_values() {
            if record.project != project {
                continue;
            }
            if !record.environment.is_empty() && record.environment != environment {
                continue;
            }
            let value = if record.secret {
                decrypt(&self.key, &record.value)?
            } else {
                record.value
            };
            env.insert(record.key, value);
        }
        Ok(env)
    }

    /// Creates or replaces one variable.
    ///
    /// # Errors
    ///
    /// Returns for invalid names, a missing secrets key, bounds, or I/O failure.
    pub fn upsert(&self, request: SecretUpsert) -> Result<SecretView, LoomError> {
        validate_project_name(&request.project)?;
        validate_key(&request.key)?;
        if request.value.len() > MAX_VALUE_LEN {
            return Err(LoomError::ResourceLimit);
        }
        if request.secret && !self.configured {
            return Err(LoomError::InvalidControl);
        }
        let stored = if request.secret {
            encrypt(&self.key, &request.value)?
        } else {
            request.value.clone()
        };
        let record = SecretRecord {
            project: request.project.clone(),
            environment: request.environment.clone(),
            key: request.key.clone(),
            secret: request.secret,
            value: stored,
        };
        let lock = self.store.exclusive_lock()?;
        let mut records = self.load()?;
        records.insert(record_key(&record), record.clone());
        if records.len() > MAX_SECRETS {
            return Err(LoomError::ResourceLimit);
        }
        self.write(&records)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(SecretView {
            project: request.project,
            environment: request.environment,
            key: request.key,
            secret: request.secret,
            value: (!request.secret).then_some(request.value),
        })
    }

    fn path(&self) -> PathBuf {
        self.store.root.join("secrets.json")
    }

    fn load(&self) -> Result<BTreeMap<String, SecretRecord>, LoomError> {
        let path = self.path();
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = read_bounded(&path, MAX_SECRETS_BYTES)?;
        let persisted: PersistedSecrets =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(persisted
            .records
            .into_iter()
            .map(|record| (record_key(&record), record))
            .collect())
    }

    fn write(&self, records: &BTreeMap<String, SecretRecord>) -> Result<(), LoomError> {
        let persisted = PersistedSecrets {
            schema_version: "v1".to_owned(),
            records: records.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        write_atomic(&self.store.root, &self.path(), &bytes, 0o600)
    }
}

fn record_key(record: &SecretRecord) -> String {
    format!("{}:{}:{}", record.project, record.environment, record.key)
}

fn validate_key(key: &str) -> Result<(), LoomError> {
    if (1..=MAX_KEY_LEN).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(LoomError::InvalidControl)
    }
}

fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, LoomError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = nonce_from_uuid();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| LoomError::StorageUnavailable)?;
    let mut packed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);
    Ok(crate::hex_digest(&packed))
}

fn decrypt(key: &[u8; 32], ciphertext_hex: &str) -> Result<String, LoomError> {
    let bytes = decode_hex(ciphertext_hex)?;
    if bytes.len() <= NONCE_LEN {
        return Err(LoomError::CorruptState);
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LoomError::CorruptState)?;
    String::from_utf8(plain).map_err(|_| LoomError::CorruptState)
}

fn nonce_from_uuid() -> [u8; NONCE_LEN] {
    let uuid = Uuid::now_v7();
    let bytes = uuid.as_bytes();
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[..NONCE_LEN]);
    nonce
}

fn decode_hex(value: &str) -> Result<Vec<u8>, LoomError> {
    if !value.len().is_multiple_of(2) {
        return Err(LoomError::CorruptState);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| LoomError::CorruptState)
        })
        .collect()
}

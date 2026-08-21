//! Scoped access tokens minted by the owner for workspaces, runners, and agents.
//!
//! The owner token stays all-powerful (except deploy). Scoped tokens narrow a
//! bearer to a repository set and a capability set so Grid can hand each
//! workspace, runner, or review agent its own revocable credential. Secrets
//! are stored only as SHA-256 hashes in `tokens.json` under the store lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::auth::AccessToken;
use crate::{LoomError, PersistentLoomStore, validate_repository};

const MAX_TOKEN_BYTES: u64 = 1024 * 1024;
const MAX_TOKENS: usize = 10_000;
const MAX_TOKEN_REPOSITORIES: usize = 64;

/// Prefix of every scoped-token secret.
pub const SCOPED_TOKEN_PREFIX: &str = "lt_";

/// Capability granted to a scoped token on its repository set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenPerm {
    /// Git gateway reads and writes within the writable-ref rules.
    Git,
    /// Feature create, read, and candidate submission on bound repositories.
    Features,
    /// Release and CI evidence reads.
    Evidence,
    /// Review lifecycle writes without candidate, patch-apply, or promotion authority.
    Review,
    /// Event stream reads.
    Events,
}

/// Durable scoped-token record. The secret is stored only as a hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedToken {
    /// Durable token identifier.
    pub id: String,
    /// Owner-facing label (workspace id, runner job, agent name).
    pub name: String,
    /// Lowercase hex SHA-256 of the bearer secret.
    pub secret_sha256: String,
    /// Repository namespaces this token may touch.
    pub repositories: BTreeSet<String>,
    /// Capabilities granted on those repositories.
    pub perms: BTreeSet<TokenPerm>,
    /// Optional feature binding for an automated review job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_id: Option<String>,
    /// Optional review binding for an automated review job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
    /// Unix seconds after which the token stops resolving, if bounded.
    pub expires_at: Option<u64>,
    /// Unix seconds at mint time.
    pub created_at: u64,
}

impl ScopedToken {
    /// True when the token is expired at `now` (unix seconds).
    #[must_use]
    pub fn expired_at(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|deadline| now >= deadline)
    }
}

/// Owner request to mint one scoped token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMint {
    /// Owner-facing label.
    pub name: String,
    /// Repository namespaces the token may touch.
    pub repositories: Vec<String>,
    /// Capabilities granted on those repositories.
    pub perms: Vec<TokenPerm>,
    /// Bind a review token to one feature. Must be paired with `review_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_id: Option<String>,
    /// Bind a review token to one review. Must be paired with `feature_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
    /// Optional unix-seconds expiry.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Mint result: the durable record plus the secret, shown exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintedToken {
    /// Durable record as persisted (hash only).
    pub token: ScopedToken,
    /// Bearer secret. Never persisted in plaintext.
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTokens {
    schema_version: String,
    tokens: Vec<ScopedToken>,
}

/// Durable scoped-token catalog stored beside the Loom CAS.
#[derive(Debug, Clone)]
pub struct TokenStore {
    store: PersistentLoomStore,
}

impl TokenStore {
    /// Opens the token catalog inside an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Mints a scoped token and persists its hash.
    ///
    /// # Errors
    ///
    /// Returns for invalid names, repositories, perms, expiry, or I/O failure.
    pub fn mint(&self, request: &TokenMint) -> Result<MintedToken, LoomError> {
        let record = validate_mint(request)?;
        let secret = format!(
            "{SCOPED_TOKEN_PREFIX}{}{}",
            Uuid::now_v7().simple(),
            Uuid::now_v7().simple()
        );
        let token = ScopedToken {
            secret_sha256: sha256_hex(secret.as_bytes()),
            ..record
        };
        let lock = self.store.exclusive_lock()?;
        let mut tokens = self.load()?;
        if tokens.len() >= MAX_TOKENS {
            return Err(LoomError::ResourceLimit);
        }
        tokens.insert(token.id.clone(), token.clone());
        self.write(&tokens)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(MintedToken { token, secret })
    }

    /// Lists tokens newest-id first. Secrets are hashes only.
    ///
    /// # Errors
    ///
    /// Returns for durable I/O failure.
    pub fn list(&self) -> Result<Vec<ScopedToken>, LoomError> {
        let lock = self.store.shared_lock()?;
        let mut tokens = self.load()?.into_values().collect::<Vec<_>>();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        tokens.sort_by(|left, right| right.id.cmp(&left.id));
        Ok(tokens)
    }

    /// Revokes one token by id. Resolution stops immediately.
    ///
    /// # Errors
    ///
    /// Returns `UnknownToken` when the id is absent.
    pub fn revoke(&self, id: &str) -> Result<ScopedToken, LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut tokens = self.load()?;
        let removed = tokens
            .remove(id)
            .ok_or_else(|| LoomError::UnknownToken { id: id.to_owned() })?;
        self.write(&tokens)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(removed)
    }

    /// Resolves a presented secret to its live token, if any.
    ///
    /// Expired tokens never resolve. Comparison is by SHA-256 hash in
    /// constant time per record.
    ///
    /// # Errors
    ///
    /// Returns for durable I/O failure.
    pub fn resolve(&self, presented: &str) -> Result<Option<ScopedToken>, LoomError> {
        if presented.is_empty() {
            return Ok(None);
        }
        let digest = sha256_hex(presented.as_bytes());
        let lock = self.store.shared_lock()?;
        let tokens = self.load()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        let now = unix_now();
        Ok(tokens.into_values().find(|token| {
            bool::from(token.secret_sha256.as_bytes().ct_eq(digest.as_bytes()))
                && !token.expired_at(now)
        }))
    }

    fn load(&self) -> Result<BTreeMap<String, ScopedToken>, LoomError> {
        let path = self.store.root.join("tokens.json");
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = crate::read_bounded(&path, MAX_TOKEN_BYTES)?;
        let persisted: PersistedTokens =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" || persisted.tokens.len() > MAX_TOKENS {
            return Err(LoomError::CorruptState);
        }
        let mut tokens = BTreeMap::new();
        for token in persisted.tokens {
            if tokens.insert(token.id.clone(), token).is_some() {
                return Err(LoomError::CorruptState);
            }
        }
        Ok(tokens)
    }

    fn write(&self, tokens: &BTreeMap<String, ScopedToken>) -> Result<(), LoomError> {
        let persisted = PersistedTokens {
            schema_version: "v1".to_owned(),
            tokens: tokens.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_TOKEN_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        crate::write_atomic(
            &self.store.root,
            &self.store.root.join("tokens.json"),
            &bytes,
            0o600,
        )
    }
}

/// Authenticated caller resolved from a presented bearer credential.
#[derive(Debug, Clone)]
pub enum Principal {
    /// The owner token: unrestricted except deploy.
    Owner,
    /// A scoped token minted by the owner.
    Scoped(ScopedToken),
}

impl Principal {
    /// True when this principal holds `perm` over every listed repository.
    pub fn allows<'a>(
        &self,
        perm: TokenPerm,
        repositories: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        match self {
            Self::Owner => true,
            Self::Scoped(token) => {
                token.perms.contains(&perm)
                    && repositories
                        .into_iter()
                        .all(|repository| token.repositories.contains(repository))
            }
        }
    }

    /// True when this principal may use `perm` for this exact feature.
    ///
    /// Unbound workspace tokens retain repository-scoped behavior. Automated
    /// review tokens carry a feature/review binding and cannot use their
    /// short-lived capability against another feature in the same repository.
    pub fn allows_feature<'a>(
        &self,
        perm: TokenPerm,
        repositories: impl IntoIterator<Item = &'a str>,
        feature_id: &str,
    ) -> bool {
        match self {
            Self::Owner => true,
            Self::Scoped(token) => {
                token
                    .feature_id
                    .as_deref()
                    .is_none_or(|bound| bound == feature_id)
                    && token.perms.contains(&perm)
                    && repositories
                        .into_iter()
                        .all(|repository| token.repositories.contains(repository))
            }
        }
    }

    /// True when this principal may mutate this exact review.
    pub fn allows_review<'a>(
        &self,
        repositories: impl IntoIterator<Item = &'a str>,
        feature_id: &str,
        review_id: &str,
    ) -> bool {
        match self {
            Self::Owner => true,
            Self::Scoped(token) => {
                self.allows_feature(TokenPerm::Review, repositories, feature_id)
                    && token
                        .review_id
                        .as_deref()
                        .is_none_or(|bound| bound == review_id)
            }
        }
    }

    /// Exact automated-review binding, when present.
    #[must_use]
    pub fn review_binding(&self) -> Option<(&str, &str)> {
        match self {
            Self::Scoped(token) => token.feature_id.as_deref().zip(token.review_id.as_deref()),
            Self::Owner => None,
        }
    }

    /// True for the owner principal.
    #[must_use]
    pub const fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }
}

/// Resolves presented credentials against the owner token and the catalog.
#[derive(Debug, Clone)]
pub struct Authority {
    owner: AccessToken,
    tokens: TokenStore,
}

impl Authority {
    /// Creates an authority over one owner token and one token catalog.
    #[must_use]
    pub const fn new(owner: AccessToken, tokens: TokenStore) -> Self {
        Self { owner, tokens }
    }

    /// Scoped-token catalog for owner mint/list/revoke handlers.
    #[must_use]
    pub const fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    /// Resolves a presented secret. Storage failures fail closed to `None`.
    #[must_use]
    pub fn resolve(&self, presented: &str) -> Option<Principal> {
        if self.owner.matches(presented) {
            return Some(Principal::Owner);
        }
        match self.tokens.resolve(presented) {
            Ok(Some(token)) => Some(Principal::Scoped(token)),
            Ok(None) | Err(_) => None,
        }
    }
}

fn validate_mint(request: &TokenMint) -> Result<ScopedToken, LoomError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(LoomError::InvalidToken);
    }
    if request.repositories.is_empty() || request.repositories.len() > MAX_TOKEN_REPOSITORIES {
        return Err(LoomError::InvalidToken);
    }
    let mut repositories = BTreeSet::new();
    for repository in &request.repositories {
        validate_repository(repository)?;
        repositories.insert(repository.clone());
    }
    if request.perms.is_empty() {
        return Err(LoomError::InvalidToken);
    }
    match (&request.feature_id, &request.review_id) {
        (None, None) => {}
        (Some(feature_id), Some(review_id))
            if request.perms.contains(&TokenPerm::Review)
                && valid_binding_id(feature_id)
                && valid_binding_id(review_id) => {}
        _ => return Err(LoomError::InvalidToken),
    }
    let created_at = unix_now();
    if let Some(expires_at) = request.expires_at
        && expires_at <= created_at
    {
        return Err(LoomError::InvalidToken);
    }
    Ok(ScopedToken {
        id: Uuid::now_v7().to_string(),
        name: name.to_owned(),
        secret_sha256: String::new(),
        repositories,
        perms: request.perms.iter().copied().collect(),
        feature_id: request.feature_id.clone(),
        review_id: request.review_id.clone(),
        expires_at: request.expires_at,
        created_at,
    })
}

fn valid_binding_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex_digest(Sha256::digest(bytes).as_slice())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

//! Bearer-token authority for the standalone Loom server.

use std::collections::BTreeSet;

use base64ct::{Base64, Encoding as _};
use subtle::ConstantTimeEq;

use crate::NamespaceGrant;

/// Owner token that authorizes every repository on this Loom.
#[derive(Debug, Clone)]
pub struct AccessToken {
    secret: String,
}

impl AccessToken {
    /// Creates a token from an owner-supplied secret.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Constant-time compare against a presented bearer value.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        if self.secret.is_empty() || presented.is_empty() {
            return false;
        }
        bool::from(self.secret.as_bytes().ct_eq(presented.as_bytes()))
    }

    /// Grant covering one repository after a successful token match.
    #[must_use]
    pub fn grant_for(&self, repository: impl Into<String>) -> NamespaceGrant {
        NamespaceGrant::new(BTreeSet::from([repository.into()]))
    }

    /// Unrestricted grant used by owner RPC after authentication.
    #[must_use]
    pub fn owner_grant(repositories: impl IntoIterator<Item = String>) -> NamespaceGrant {
        NamespaceGrant::new(repositories.into_iter().collect())
    }
}

/// Extracts a Bearer token from an Authorization header value.
#[must_use]
pub fn bearer_token(header: &str) -> Option<&str> {
    header
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
}

/// Extracts the password of a Basic Authorization header value.
///
/// Git credential helpers speak HTTP Basic: the password carries a Loom
/// bearer secret and the username is ignored.
#[must_use]
pub fn basic_password(header: &str) -> Option<String> {
    let encoded = header.strip_prefix("Basic ").map(str::trim)?;
    let decoded = Base64::decode_vec(encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (_, password) = text.split_once(':')?;
    if password.is_empty() {
        None
    } else {
        Some(password.to_owned())
    }
}

/// Extracts a presented secret from either Bearer or Basic authorization.
#[must_use]
pub fn presented_secret(header: &str) -> Option<String> {
    bearer_token(header)
        .map(str::to_owned)
        .or_else(|| basic_password(header))
}

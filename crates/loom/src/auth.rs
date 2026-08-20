//! Bearer-token authority for the standalone Loom server.

use std::collections::BTreeSet;

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

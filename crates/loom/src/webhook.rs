//! Outbound signed HTTP webhooks.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::LoomError;
use crate::events::Event;

/// One outbound webhook endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookEndpoint {
    /// Durable id.
    pub id: String,
    /// HTTPS URL.
    pub url: String,
    /// HMAC secret (hex of SHA-256 of the owner-supplied secret).
    pub secret_sha256: String,
    /// Event kinds to deliver. Empty means the default set.
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// Create body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCreate {
    /// HTTPS URL.
    pub url: String,
    /// Shared secret (shown never again).
    pub secret: String,
    /// Optional kind filter.
    #[serde(default)]
    pub kinds: Vec<String>,
}

impl WebhookCreate {
    /// Validates and hashes the secret.
    ///
    /// # Errors
    ///
    /// Returns for an empty URL or secret.
    pub fn into_endpoint(self) -> Result<WebhookEndpoint, LoomError> {
        if !self.url.starts_with("https://") && !self.url.starts_with("http://127.0.0.1") {
            return Err(LoomError::InvalidControl);
        }
        if self.secret.is_empty() {
            return Err(LoomError::InvalidControl);
        }
        Ok(WebhookEndpoint {
            id: format!("wh_{}", Uuid::now_v7()),
            url: self.url,
            secret_sha256: crate::hex_digest(Sha256::digest(self.secret.as_bytes()).as_slice()),
            kinds: self.kinds,
        })
    }
}

/// HMAC-SHA256 hex over the event JSON using the raw secret.
#[must_use]
pub fn sign(secret: &str, body: &[u8]) -> String {
    crate::hex_digest(&hmac_sha256(secret.as_bytes(), body))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(Sha256::digest(key).as_slice());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = block;
    let mut opad = block;
    for byte in &mut ipad {
        *byte ^= 0x36;
    }
    for byte in &mut opad {
        *byte ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner.finalize());
    let digest = outer.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// True when this hook should receive `event`.
#[must_use]
pub fn matches(hook: &WebhookEndpoint, event: &Event) -> bool {
    if hook.kinds.is_empty() {
        return matches!(
            event.kind.as_str(),
            "push.received"
                | "feature.created"
                | "feature.approved"
                | "feature.auto_approved"
                | "feature.accepted"
                | "feature.rejected"
                | "refs.moved"
                | "deploy.applied"
        );
    }
    hook.kinds.iter().any(|kind| kind == &event.kind)
}

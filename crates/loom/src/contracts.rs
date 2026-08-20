//! Standalone Loom contracts. No Grid, Nero, Kiln, or Restate types.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One or more contract validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("contract validation failed")]
pub struct ValidationError {
    violations: Vec<String>,
}

impl ValidationError {
    fn from_violations(violations: Vec<String>) -> Result<(), Self> {
        if violations.is_empty() {
            Ok(())
        } else {
            Err(Self { violations })
        }
    }

    /// Stable human-readable violations.
    #[must_use]
    pub fn violations(&self) -> &[String] {
        &self.violations
    }
}

/// A repository revision pinned by a lowercase SHA-256 object identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRevision {
    /// Loom repository namespace.
    pub repository: String,
    /// Immutable 64-character hexadecimal revision identifier.
    pub revision: String,
}

impl RepositoryRevision {
    /// Constructs and validates an immutable repository revision.
    ///
    /// # Errors
    ///
    /// Returns when the repository is empty or the revision is not SHA-256.
    pub fn new(
        repository: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let value = Self {
            repository: repository.into(),
            revision: revision.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates repository and revision syntax.
    ///
    /// # Errors
    ///
    /// Returns every repository and digest syntax violation.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut violations = Vec::new();
        if !safe_artifact_identifier(&self.repository) {
            violations.push(
                "repository name must be 1-128 ASCII letters, digits, dots, dashes, or underscores"
                    .to_owned(),
            );
        }
        if !is_sha256_hex(&self.revision) {
            violations
                .push("revision must be a 64-character lowercase hexadecimal digest".to_owned());
        }
        ValidationError::from_violations(violations)
    }
}

/// Immutable digest for an object, artifact, or evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    /// Digest algorithm. Only SHA-256 is admitted.
    pub algorithm: String,
    /// Lowercase hexadecimal digest value.
    pub value: String,
}

impl ArtifactDigest {
    /// Creates a validated SHA-256 artifact digest.
    ///
    /// # Errors
    ///
    /// Returns when the value is not lowercase SHA-256 hexadecimal.
    pub fn sha256(value: impl Into<String>) -> Result<Self, ValidationError> {
        let digest = Self {
            algorithm: "sha256".to_owned(),
            value: value.into(),
        };
        digest.validate()?;
        Ok(digest)
    }

    /// Validates the digest algorithm and value.
    ///
    /// # Errors
    ///
    /// Returns every unsupported algorithm and digest syntax violation.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut violations = Vec::new();
        if self.algorithm != "sha256" {
            violations.push("only sha256 artifacts are admitted".to_owned());
        }
        if !is_sha256_hex(&self.value) {
            violations
                .push("artifact digest must be 64 lowercase hexadecimal characters".to_owned());
        }
        ValidationError::from_violations(violations)
    }
}

/// Immutable base and candidate head binding for one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    /// Approved base revision.
    pub base: RepositoryRevision,
    /// Candidate revision, populated after execution.
    pub head: Option<RepositoryRevision>,
    /// Protected symbolic destination ref.
    pub target_ref: String,
}

impl RepositoryBinding {
    /// Creates a binding before candidate execution has produced a head.
    #[must_use]
    pub fn new(base: RepositoryRevision, target_ref: String) -> Self {
        Self {
            base,
            head: None,
            target_ref,
        }
    }

    /// Pins the immutable candidate head.
    #[must_use]
    pub fn with_head(mut self, head: RepositoryRevision) -> Self {
        self.head = Some(head);
        self
    }
}

/// Validates the symbolic ref grammar used by features and protected refs.
///
/// # Errors
///
/// Returns when a ref cannot be resolved or promoted by Loom.
pub fn validate_repository_ref(ref_name: &str) -> Result<(), ValidationError> {
    if ref_name.starts_with("refs/")
        && !ref_name.contains("..")
        && !ref_name.ends_with('/')
        && !ref_name
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        Ok(())
    } else {
        Err(ValidationError {
            violations: vec!["target refs must use Loom's protected refs grammar".to_owned()],
        })
    }
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn safe_artifact_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

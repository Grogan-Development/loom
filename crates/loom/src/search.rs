//! CAS code search and compare/tree/blob reads.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::contracts::RepositoryRevision;
use crate::{LoomError, NamespaceGrant, PersistentLoomStore, validate_repository};

/// One search hit.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    /// Repository.
    pub repository: String,
    /// Path.
    pub path: String,
    /// 1-based line.
    pub line: u32,
    /// Matching line text, truncated.
    pub text: String,
}

/// File listing entry.
#[derive(Debug, Clone, Serialize)]
pub struct TreeEntry {
    /// Path.
    pub path: String,
    /// Byte length.
    pub size: usize,
}

/// Searches one revision for `query` (substring, case-sensitive, bounded).
///
/// # Errors
///
/// Returns for authorization, missing revision, or I/O failure.
pub fn search(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    revision: &RepositoryRevision,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchHit>, LoomError> {
    if query.is_empty() || query.len() > 256 {
        return Err(LoomError::InvalidControl);
    }
    let files = store.materialize(grant, revision)?;
    let mut hits = Vec::new();
    for (path, bytes) in files {
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if line.contains(query) {
                hits.push(SearchHit {
                    repository: revision.repository.clone(),
                    path: path.clone(),
                    line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    text: line.chars().take(240).collect(),
                });
                if hits.len() >= limit {
                    return Ok(hits);
                }
            }
        }
    }
    Ok(hits)
}

/// Lists paths in a revision.
///
/// # Errors
///
/// Returns for authorization or missing revision.
pub fn tree(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    revision: &RepositoryRevision,
) -> Result<Vec<TreeEntry>, LoomError> {
    let files = store.materialize(grant, revision)?;
    let mut entries = files
        .into_iter()
        .map(|(path, bytes)| TreeEntry {
            path,
            size: bytes.len(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

/// Reads one blob.
///
/// # Errors
///
/// Returns for authorization, missing revision, or missing path.
pub fn blob(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    revision: &RepositoryRevision,
    path: &str,
) -> Result<Vec<u8>, LoomError> {
    crate::validate_path(path)?;
    let files = store.materialize(grant, revision)?;
    files
        .get(path)
        .cloned()
        .ok_or_else(|| LoomError::InvalidPath {
            path: path.to_owned(),
        })
}

/// Compare two revisions: added/removed/changed paths.
///
/// # Errors
///
/// Returns for authorization or missing revisions.
pub fn compare(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    base: &RepositoryRevision,
    head: &RepositoryRevision,
) -> Result<BTreeMap<String, String>, LoomError> {
    validate_repository(&base.repository)?;
    let base_files = store.materialize(grant, base)?;
    let head_files = store.materialize(grant, head)?;
    let mut delta = BTreeMap::new();
    let paths = base_files
        .keys()
        .chain(head_files.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for path in paths {
        match (base_files.get(&path), head_files.get(&path)) {
            (None, Some(_)) => {
                delta.insert(path, "added".to_owned());
            }
            (Some(_), None) => {
                delta.insert(path, "removed".to_owned());
            }
            (Some(left), Some(right)) if left != right => {
                delta.insert(path, "changed".to_owned());
            }
            _ => {}
        }
    }
    Ok(delta)
}

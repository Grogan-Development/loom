//! Git remote import into the catalog + CAS.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::catalog::{RepoCatalog, RepoEntry};
use crate::contracts::RepositoryRevision;
use crate::git::GitBridge;
use crate::project::validate_project_name;
use crate::{LoomError, NamespaceGrant, PersistentLoomStore, validate_repository};

/// Import request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// Project name.
    pub project: String,
    /// Repo name (second segment).
    pub name: String,
    /// Optional git URL. Empty means create an empty repo.
    #[serde(default)]
    pub git_url: String,
    /// Optional shallow depth.
    #[serde(default)]
    pub depth: Option<u32>,
}

/// Import result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportResult {
    /// Catalog name `project/name`.
    pub repo: String,
    /// Native revision of the imported HEAD.
    pub revision: String,
    /// True when history was snapshotted (`import.partial_history`).
    pub partial_history: bool,
}

/// Runs import: catalog upsert, optional git fetch, CAS commit, bootstrap later.
///
/// # Errors
///
/// Returns for invalid names, git failure, or storage failure.
pub fn import(
    store: &PersistentLoomStore,
    catalog: &RepoCatalog,
    git: Option<&GitBridge>,
    workdir: &Path,
    request: &ImportRequest,
) -> Result<ImportResult, LoomError> {
    validate_project_name(&request.project)?;
    validate_project_name(&request.name)?;
    let repo = format!("{}/{}", request.project, request.name);
    validate_repository(&repo)?;
    catalog.upsert(RepoEntry::minimal(&repo))?;
    let grant = NamespaceGrant::new([repo.clone()].into_iter().collect());
    if request.git_url.is_empty() {
        let revision = store.commit(&grant, &repo, None, BTreeMap::new())?;
        return Ok(ImportResult {
            repo,
            revision: revision.revision,
            partial_history: false,
        });
    }
    let clone_dir = workdir.join(crate::repository_storage_name(&repo));
    let _ = std::fs::remove_dir_all(&clone_dir);
    std::fs::create_dir_all(&clone_dir).map_err(|_| LoomError::StorageUnavailable)?;
    git_clone(&request.git_url, &clone_dir, request.depth)?;
    let files = read_tree(&clone_dir)?;
    let revision = commit_files(store, git, &grant, &repo, &clone_dir, &files)?;
    Ok(ImportResult {
        repo,
        revision: revision.revision,
        partial_history: request.depth.is_some(),
    })
}

fn git_clone(url: &str, dest: &Path, depth: Option<u32>) -> Result<(), LoomError> {
    if !url.starts_with("https://") {
        return Err(LoomError::InvalidControl);
    }
    let mut command = Command::new("git");
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.arg("-c").arg("core.symlinks=false");
    command.arg("clone");
    if let Some(depth) = depth {
        command.arg("--depth").arg(depth.to_string());
    }
    command
        .arg("--")
        .arg(url)
        .arg(dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command.status().map_err(|_| LoomError::OriginUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(LoomError::OriginUnavailable)
    }
}

fn read_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, LoomError> {
    let mut files = BTreeMap::new();
    read_tree_inner(root, root, &mut files, 0)?;
    Ok(files)
}

/// Test helper: walk a tree the same way import does.
///
/// # Errors
///
/// Returns [`LoomError::InvalidPath`] when a symlink is present.
pub fn read_tree_for_test(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, LoomError> {
    read_tree(root)
}

fn read_tree_inner(
    root: &Path,
    current: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    depth: u32,
) -> Result<(), LoomError> {
    if depth > 16 || files.len() > 10_000 {
        return Err(LoomError::ResourceLimit);
    }
    let entries = std::fs::read_dir(current).map_err(|_| LoomError::StorageUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| LoomError::StorageUnavailable)?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| LoomError::StorageUnavailable)?;
        if file_type.is_symlink() {
            return Err(LoomError::InvalidPath {
                path: path.display().to_string(),
            });
        }
        if file_type.is_dir() {
            read_tree_inner(root, &path, files, depth + 1)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| LoomError::InvalidPath {
                    path: path.display().to_string(),
                })?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = std::fs::read(&path).map_err(|_| LoomError::StorageUnavailable)?;
            files.insert(rel, bytes);
        }
    }
    Ok(())
}

fn commit_files(
    store: &PersistentLoomStore,
    _git: Option<&GitBridge>,
    grant: &NamespaceGrant,
    repo: &str,
    _clone: &Path,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<RepositoryRevision, LoomError> {
    store.commit(grant, repo, None, files.clone())
}

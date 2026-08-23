//! Backup and restore of CAS + control + secrets metadata.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{LoomError, PersistentLoomStore};

/// Files copied into a backup tarball (relative to `LOOM_ROOT`).
const BACKUP_ENTRIES: &[&str] = &[
    "objects",
    "snapshots",
    "graphs",
    "refs.json",
    "repos.json",
    "features.json",
    "tokens.json",
    "ci-jobs.json",
    "control.json",
    "secrets.json",
    "events",
    "git-mappings",
    "origin-releases.json",
];

/// Writes a gzip tar of the control + CAS files to `destination`.
///
/// # Errors
///
/// Returns when tar fails or the destination cannot be created.
pub fn backup(store: &PersistentLoomStore, destination: &Path) -> Result<PathBuf, LoomError> {
    let mut command = Command::new("tar");
    command
        .arg("-czf")
        .arg(destination)
        .arg("-C")
        .arg(&store.root);
    for entry in BACKUP_ENTRIES {
        let path = store.root.join(entry);
        if path.exists() {
            command.arg(entry);
        }
    }
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|_| LoomError::StorageUnavailable)?;
    if status.success() {
        Ok(destination.to_path_buf())
    } else {
        Err(LoomError::StorageUnavailable)
    }
}

/// Extracts a backup tarball into `LOOM_ROOT`.
///
/// # Errors
///
/// Returns when tar fails.
pub fn restore(store: &PersistentLoomStore, archive: &Path) -> Result<(), LoomError> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&store.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|_| LoomError::StorageUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(LoomError::StorageUnavailable)
    }
}

/// Writes a tiny backup without spawning tar (tests).
///
/// # Errors
///
/// Returns for I/O failure.
pub fn backup_files(store: &PersistentLoomStore, destination: &Path) -> Result<(), LoomError> {
    let mut blob = Vec::new();
    for entry in BACKUP_ENTRIES {
        let path = store.root.join(entry);
        if path.is_file() {
            let bytes = crate::read_bounded(&path, 8 * 1024 * 1024)?;
            writeln!(&mut blob, "{entry} {}", bytes.len())
                .map_err(|_| LoomError::StorageUnavailable)?;
            blob.extend_from_slice(&bytes);
        }
    }
    std::fs::write(destination, blob).map_err(|_| LoomError::StorageUnavailable)
}

//! Durable append-only Loom event log and live broadcast.
//!
//! `push.received` is emitted from `git.rs` once a pre-receive batch has
//! fully completed its CAS import (durable log only; the import runs in the
//! hook process, outside this process's live broadcast). Feature acceptance
//! emits `refs.moved` after a successful protected-ref CAS, and
//! `deploy.applied` follows a successful release apply.
//!
//! Known kinds: `push.received`, `feature.created`, `feature.approved`,
//! `feature.auto_approved`, `feature.accepted`, `feature.rejected`, `candidate.submitted`,
//! `ci.started`, `ci.finished`, `insights.ready`, `review.started`,
//! `review.finding`, `review.completed`, `comment.added`, `refs.moved`,
//! `refs.bootstrapped`, `deploy.applied`.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{LoomError, PersistentLoomStore, ensure_private_directory, read_bounded, write_atomic};

const MAX_EVENT_LOG_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENT_LINE_BYTES: usize = 256 * 1024;
const BROADCAST_LAG: usize = 256;
/// Default catch-up page used by `GET /v1/events`.
pub const DEFAULT_CATCH_UP: usize = 200;
/// Hard catch-up cap used by `GET /v1/events` and [`EventLog::since`].
pub const MAX_CATCH_UP: usize = 1000;

/// One durable event in the append-only Loom log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Monotonic identifier (`evt_` plus a UUID v7).
    pub id: String,
    /// Unix timestamp in seconds.
    pub ts: u64,
    /// Event kind (see module documentation).
    pub kind: String,
    /// Repository namespaces this event is scoped to.
    pub repos: Vec<String>,
    /// Kind-specific JSON body.
    pub payload: serde_json::Value,
}

/// Durable JSONL event log plus an in-process live tail.
#[derive(Clone)]
pub struct EventLog {
    store: PersistentLoomStore,
    live: broadcast::Sender<Event>,
}

impl EventLog {
    /// Opens the event log inside an existing Loom dataset.
    #[must_use]
    pub fn new(store: PersistentLoomStore) -> Self {
        let (live, _) = broadcast::channel(BROADCAST_LAG);
        Self { store, live }
    }

    /// Appends one event, persists it, and notifies live tails.
    ///
    /// # Errors
    ///
    /// Returns for an invalid kind, an invalid repository namespace, a line or
    /// log that exceeds its bound, serialization failure, or durable I/O failure.
    pub fn emit(
        &self,
        kind: &str,
        repos: impl IntoIterator<Item = impl Into<String>>,
        payload: serde_json::Value,
    ) -> Result<Event, LoomError> {
        validate_kind(kind)?;
        let mut names = Vec::new();
        for repository in repos {
            let repository = repository.into();
            crate::validate_repository(&repository)?;
            if !names.contains(&repository) {
                names.push(repository);
            }
        }
        let event = Event {
            id: format!("evt_{}", Uuid::now_v7()),
            ts: unix_now(),
            kind: kind.to_owned(),
            repos: names,
            payload,
        };
        let line = serde_json::to_vec(&event).map_err(|_| LoomError::Serialization)?;
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        let directory = self.events_dir();
        let log_path = self.log_path();
        let seq_path = directory.join("seq");
        let lock = self.store.exclusive_lock()?;
        ensure_private_directory(&directory)?;
        let existing = if log_path.exists() {
            fs::metadata(&log_path)
                .map_err(|_| LoomError::StorageUnavailable)?
                .len()
        } else {
            0
        };
        let next_len = existing
            .checked_add(line.len() as u64)
            .and_then(|length| length.checked_add(1))
            .ok_or(LoomError::ResourceLimit)?;
        if next_len > MAX_EVENT_LOG_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|_| LoomError::StorageUnavailable)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| LoomError::StorageUnavailable)?;
        file.write_all(&line)
            .map_err(|_| LoomError::StorageUnavailable)?;
        file.write_all(b"\n")
            .map_err(|_| LoomError::StorageUnavailable)?;
        file.sync_all().map_err(|_| LoomError::StorageUnavailable)?;
        write_atomic(&directory, &seq_path, event.id.as_bytes(), 0o600)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        let _ = self.live.send(event.clone());
        Ok(event)
    }

    /// Returns durable events after `after`, in append order, up to `limit`.
    ///
    /// `limit` is clamped to [`MAX_CATCH_UP`]. When `after` is `None`, the
    /// oldest events are returned so a subscriber can walk the log forward.
    ///
    /// # Errors
    ///
    /// Returns for corrupt JSONL, an oversized log, or durable I/O failure.
    pub fn since(&self, after: Option<&str>, limit: usize) -> Result<Vec<Event>, LoomError> {
        let limit = limit.min(MAX_CATCH_UP);
        let lock = self.store.shared_lock()?;
        let events = self.load_all()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(events
            .into_iter()
            .filter(|event| after.is_none_or(|cursor| event.id.as_str() > cursor))
            .take(limit)
            .collect())
    }

    /// Subscribes to events emitted after this call.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.live.subscribe()
    }

    fn load_all(&self) -> Result<Vec<Event>, LoomError> {
        let path = self.log_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = read_bounded(&path, MAX_EVENT_LOG_BYTES)?;
        let mut events = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_slice(line).map_err(|_| LoomError::CorruptState)?;
            events.push(event);
        }
        Ok(events)
    }

    fn events_dir(&self) -> PathBuf {
        self.store.root.join("events")
    }

    fn log_path(&self) -> PathBuf {
        self.events_dir().join("log.jsonl")
    }
}

fn validate_kind(kind: &str) -> Result<(), LoomError> {
    if (1..=64).contains(&kind.len())
        && kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Ok(())
    } else {
        Err(LoomError::InvalidSourceCommit)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

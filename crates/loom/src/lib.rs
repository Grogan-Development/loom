//! Loom content-addressed source, refs, atomic promotion, features, and CI.

pub mod auth;
pub mod ci;
pub mod contracts;
pub mod features;
pub mod git;
pub mod server;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::contracts::{
    ArtifactDigest, RepositoryBinding, RepositoryRevision, validate_repository_ref,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Loom storage and ref failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoomError {
    /// Principal cannot access the repository namespace.
    #[error("repository namespace denied: {repository}")]
    NamespaceDenied {
        /// Requested namespace.
        repository: String,
    },
    /// Base or head revision does not exist in the repository.
    #[error("unknown repository revision: {repository}@{revision}")]
    UnknownRevision {
        /// Repository namespace.
        repository: String,
        /// Requested digest.
        revision: String,
    },
    /// Source path is absolute or escapes the materialization root.
    #[error("invalid source path: {path}")]
    InvalidPath {
        /// Rejected path.
        path: String,
    },
    /// Protected ref syntax is invalid.
    #[error("invalid protected ref: {ref_name}")]
    InvalidRef {
        /// Rejected ref.
        ref_name: String,
    },
    /// Expected ref base did not match the current revision.
    #[error("protected ref compare-and-swap conflict: {repository}/{ref_name}")]
    RefConflict {
        /// Repository namespace.
        repository: String,
        /// Protected ref.
        ref_name: String,
    },
    /// A promotion batch targeted the same ref twice.
    #[error("duplicate protected ref in atomic update: {repository}/{ref_name}")]
    DuplicateRef {
        /// Repository namespace.
        repository: String,
        /// Protected ref.
        ref_name: String,
    },
    /// Canonical revision input could not be serialized.
    #[error("revision serialization failed")]
    Serialization,
    /// Persistent root path is relative, traversing, or otherwise unsafe.
    #[error("Loom persistent root is invalid")]
    InvalidRoot,
    /// Persistent state is not private to the Loom service identity.
    #[error("Loom persistent root permissions are unsafe")]
    UnsafeRootPermissions,
    /// Bounded durable file I/O failed.
    #[error("Loom persistent storage is unavailable")]
    StorageUnavailable,
    /// Stored object, snapshot, or ref state failed its digest or schema contract.
    #[error("Loom persistent state is corrupt")]
    CorruptState,
    /// One commit exceeded the bounded source-file or snapshot limits.
    #[error("Loom commit exceeds resource limits")]
    ResourceLimit,
    /// Repository namespace cannot be safely mapped into durable storage.
    #[error("invalid repository namespace: {repository}")]
    InvalidRepository {
        /// Rejected repository namespace.
        repository: String,
    },
    /// Plaintext Loom RPC may bind only to loopback behind the Data VM mTLS proxy.
    #[error("Loom RPC bind must be loopback")]
    InvalidRpcBind,
    /// Revision-scoped software graph does not satisfy the bounded v1 contract.
    #[error("software graph is invalid")]
    InvalidSoftwareGraph,
    /// A different immutable graph was already admitted for this exact revision.
    #[error("software graph already exists for {repository}@{revision}")]
    GraphConflict {
        /// Repository namespace.
        repository: String,
        /// Immutable source revision.
        revision: String,
    },
    /// A native source-commit request failed its version, ordering, digest, or resource contract.
    #[error("native source commit is invalid")]
    InvalidSourceCommit,
    /// A native source-commit request targeted one path more than once.
    #[error("duplicate native source mutation: {path}")]
    DuplicateSourceMutation {
        /// Conflicting repository-relative path.
        path: String,
    },
    /// A native source-commit request attempted to delete a path absent from its exact base.
    #[error("native source deletion is absent from the base: {path}")]
    SourceDeletionAbsent {
        /// Missing repository-relative path.
        path: String,
    },
    /// A native source commit would represent one path as both an entry and a directory.
    #[error("native source path conflicts with an ancestor entry: {path}")]
    SourcePathConflict {
        /// Repository-relative path whose ancestor is already a source entry.
        path: String,
    },
}

/// Repository namespace set attached to one authorized request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceGrant {
    repositories: BTreeSet<String>,
}

impl NamespaceGrant {
    /// Creates an immutable namespace grant.
    #[must_use]
    pub const fn new(repositories: BTreeSet<String>) -> Self {
        Self { repositories }
    }

    fn permits(&self, repository: &str) -> bool {
        self.repositories.contains(repository)
    }
}

/// One protected ref compare-and-swap update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasUpdate {
    /// Repository namespace.
    pub repository: String,
    /// Protected ref name.
    pub ref_name: String,
    /// Required current revision.
    pub expected: RepositoryRevision,
    /// New immutable revision.
    pub head: RepositoryRevision,
}

impl RefCasUpdate {
    /// Creates a ref compare-and-swap update.
    #[must_use]
    pub fn new(
        repository: impl Into<String>,
        ref_name: impl Into<String>,
        expected: RepositoryRevision,
        head: RepositoryRevision,
    ) -> Self {
        Self {
            repository: repository.into(),
            ref_name: ref_name.into(),
            expected,
            head,
        }
    }
}

/// Source entry semantics preserved across native materialization and Git projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFileMode {
    /// Ordinary non-executable file.
    Regular,
    /// Executable regular file.
    Executable,
    /// Symbolic-link target stored as source bytes.
    Symlink,
}

/// One digest-verified materialized source entry including filesystem semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedSourceFile {
    /// Exact source bytes or symbolic-link target.
    pub contents: Vec<u8>,
    /// Filesystem mode required when constructing a workspace.
    pub mode: SourceFileMode,
}

/// One digest-bound source file carried over the private Loom RPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMaterializationFile {
    /// Valid relative repository path.
    pub path: String,
    /// Exact file semantics.
    pub mode: SourceFileMode,
    /// Digest verified by Loom and rechecked by the guest materializer.
    pub digest: ArtifactDigest,
    /// Standard base64 source bytes or symlink target.
    pub contents_base64: String,
}

/// Bounded immutable revision materialization for one workspace repository binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMaterialization {
    /// Contract schema version.
    pub schema_version: String,
    /// Exact repository revision reconstructed from CAS.
    pub revision: RepositoryRevision,
    /// Sorted, unique source entries.
    pub files: Vec<SourceMaterializationFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum SnapshotEntry {
    Legacy(ArtifactDigest),
    Mode {
        digest: ArtifactDigest,
        mode: SourceFileMode,
    },
}

impl SnapshotEntry {
    const fn digest(&self) -> &ArtifactDigest {
        match self {
            Self::Legacy(digest) | Self::Mode { digest, .. } => digest,
        }
    }

    const fn mode(&self) -> SourceFileMode {
        match self {
            Self::Legacy(_)
            | Self::Mode {
                mode: SourceFileMode::Regular,
                ..
            } => SourceFileMode::Regular,
            Self::Mode { mode, .. } => *mode,
        }
    }
}

pub(crate) struct PendingSourceFile {
    pub(crate) contents: Vec<u8>,
    pub(crate) mode: SourceFileMode,
}

type Snapshot = BTreeMap<String, SnapshotEntry>;
type RefKey = (String, String);

/// In-memory Loom domain store for pure domain tests and disposable adapters.
#[derive(Debug, Default)]
pub struct LoomStore {
    objects: BTreeMap<ArtifactDigest, Vec<u8>>,
    snapshots: BTreeMap<RepositoryRevision, Snapshot>,
    refs: BTreeMap<RefKey, RepositoryRevision>,
}

const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GRAPH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GRAPH_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES_PER_COMMIT: usize = 10_000;
const MAX_GRAPH_NODES: usize = 100_000;
const MAX_GRAPH_EDGES: usize = 500_000;
const MAX_MATERIALIZATION_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCE_COMMIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_COMMIT_REQUEST_BYTES: usize = 24 * 1024 * 1024;
const MAX_SOURCE_COMMIT_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_RPC_RESPONSE_BYTES: usize = 96 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRef {
    repository: String,
    ref_name: String,
    revision: RepositoryRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRefs {
    schema_version: String,
    refs: Vec<PersistedRef>,
}

/// Restart-safe Loom CAS and protected-ref store intended for a private ZFS dataset.
#[derive(Debug, Clone)]
pub struct PersistentLoomStore {
    root: PathBuf,
    objects: PathBuf,
    snapshots: PathBuf,
    graphs: PathBuf,
    refs: PathBuf,
    lock: PathBuf,
}

/// One revision-scoped software entity emitted by an admitted analyzer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareNode {
    /// Stable analyzer-defined identity within this graph.
    pub id: String,
    /// Versioned entity class such as `rust_crate` or `service`.
    pub kind: String,
    /// Repository-relative source location.
    pub path: String,
    /// Human-readable entity name.
    pub label: String,
}

/// One directed relationship between two nodes in the same immutable graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareEdge {
    /// Existing source node identity.
    pub source: String,
    /// Existing target node identity.
    pub target: String,
    /// Versioned relationship class such as `depends_on`.
    pub kind: String,
}

/// Complete software graph pinned to one reachable Loom revision and analyzer artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareGraph {
    /// Graph schema version.
    pub schema_version: String,
    /// Exact source revision described by this graph.
    pub revision: RepositoryRevision,
    /// Admitted analyzer image or binary digest.
    pub analyzer_digest: ArtifactDigest,
    /// Unique software entities.
    pub nodes: Vec<SoftwareNode>,
    /// Directed relationships whose endpoints are present in `nodes`.
    pub edges: Vec<SoftwareEdge>,
}

/// Private RPC request for candidate source reachability and protected-ref readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRevisionCheck {
    /// Exact Gate 1 repository bindings with immutable candidate heads.
    pub repositories: Vec<RepositoryBinding>,
}

/// Bounded fail-closed source readiness result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRevisionStatus {
    /// True only when every base/head is reachable and every protected ref remains at its base.
    pub ready: bool,
    /// Stable unique source-readiness failures.
    pub failures: Vec<String>,
}

/// Private Loom readiness response backed by a verified persistent-state read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoomHealth {
    /// Health contract version.
    pub schema_version: String,
    /// True only after the durable ref manifest and storage permissions are revalidated.
    pub persistent_state_ready: bool,
}

/// Private RPC request for one atomic multi-repository ref promotion or rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicRefRequest {
    /// Complete compare-and-swap batch.
    pub updates: Vec<RefCasUpdate>,
}

/// Atomic ref result including read-back and the exact reverse compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicRefResult {
    /// Reverse CAS to restore the exact prior ref manifest.
    pub rollback: Vec<RefCasUpdate>,
    /// True only when every promoted ref was read back at its requested head.
    pub read_back: bool,
}

/// Private RPC request for one exact revision-scoped software graph read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareGraphRead {
    /// Reachable revision whose admitted graph is requested.
    pub revision: RepositoryRevision,
}

/// Private RPC request for one exact immutable source materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMaterializationRead {
    /// Reachable repository revision to reconstruct from CAS.
    pub revision: RepositoryRevision,
}

/// One ordered native source mutation applied to an exact immutable base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceCommitMutation {
    /// Creates or completely replaces one source entry.
    Upsert {
        /// Valid repository-relative path.
        path: String,
        /// Exact regular, executable, or symbolic-link semantics.
        mode: SourceFileMode,
        /// SHA-256 digest of the decoded source bytes.
        digest: ArtifactDigest,
        /// Standard base64 source bytes or symbolic-link target.
        contents_base64: String,
    },
    /// Removes one path that must exist in the exact base revision.
    Delete {
        /// Valid repository-relative path.
        path: String,
    },
}

impl SourceCommitMutation {
    fn path(&self) -> &str {
        match self {
            Self::Upsert { path, .. } | Self::Delete { path } => path,
        }
    }
}

/// Versioned bounded request for one native Loom source commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCommitRequest {
    /// Contract schema version. MVP accepts only `v1`.
    pub schema_version: String,
    /// Existing immutable revision whose repository is the complete authority boundary.
    pub base: RepositoryRevision,
    /// Non-empty mutations in strictly increasing path order.
    pub mutations: Vec<SourceCommitMutation>,
}

/// Digest-bound result for one atomically visible native source commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCommitResult {
    /// Contract schema version.
    pub schema_version: String,
    /// SHA-256 digest of the exact versioned request acknowledged by Loom.
    pub request_digest: ArtifactDigest,
    /// Exact immutable base accepted by Loom.
    pub base: RepositoryRevision,
    /// Deterministic immutable revision produced from the base and mutations.
    pub head: RepositoryRevision,
    /// Number of mutations accepted into the new revision.
    pub mutation_count: u32,
}

#[derive(Debug)]
enum DecodedSourceMutation {
    Upsert {
        path: String,
        mode: SourceFileMode,
        digest: ArtifactDigest,
        contents: Vec<u8>,
    },
    Delete {
        path: String,
    },
}

/// Bounded private Loom RPC client failures.
#[derive(Debug, Error)]
pub enum LoomRpcError {
    /// Endpoint is not HTTPS outside explicit loopback tests.
    #[error("Loom RPC endpoint is invalid")]
    InvalidEndpoint,
    /// Source commit request failed local version, path, ordering, base64, digest, or bounds checks.
    #[error("Loom RPC request contract is invalid")]
    InvalidRequest,
    /// Private RPC transport failed.
    #[error("Loom RPC transport failed")]
    Transport,
    /// Loom rejected the requested operation.
    #[error("Loom RPC returned HTTP {0}")]
    RemoteStatus(u16),
    /// Response exceeded the product-state bound.
    #[error("Loom RPC response exceeded its limit")]
    ResponseTooLarge,
    /// Response did not match the versioned RPC contract.
    #[error("Loom RPC response contract is invalid")]
    InvalidResponse,
}

/// Mutual-TLS-ready Control-to-Data Loom RPC client.
#[derive(Clone)]
pub struct LoomRpcClient {
    endpoint: reqwest::Url,
    client: reqwest::Client,
}

impl fmt::Debug for LoomRpcClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoomRpcClient")
            .field("endpoint", &self.endpoint)
            .field("client", &"[CONFIGURED]")
            .finish()
    }
}

impl LoomRpcClient {
    /// Creates a client using an already hardened mutual-TLS HTTP client.
    ///
    /// # Errors
    ///
    /// Returns when the endpoint contains credentials, query state, or unsafe cleartext transport.
    pub fn new(endpoint: &str, client: reqwest::Client) -> Result<Self, LoomRpcError> {
        let mut endpoint =
            reqwest::Url::parse(endpoint).map_err(|_| LoomRpcError::InvalidEndpoint)?;
        let loopback_http = endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        if (endpoint.scheme() != "https" && !loopback_http)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(LoomRpcError::InvalidEndpoint);
        }
        endpoint.set_path("/");
        Ok(Self { endpoint, client })
    }

    /// Revalidates Loom's private service and persistent ref state.
    ///
    /// # Errors
    ///
    /// Returns for transport, status, size, or response-contract failures.
    pub async fn health(&self) -> Result<LoomHealth, LoomRpcError> {
        let response = self
            .client
            .get(self.url("loom/v1/health")?)
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let health: LoomHealth = decode_rpc(response).await?;
        if health.schema_version != "v1" || !health.persistent_state_ready {
            return Err(LoomRpcError::InvalidResponse);
        }
        Ok(health)
    }

    /// Verifies candidate revisions are reachable and protected refs remain at Gate 1 bases.
    ///
    /// # Errors
    ///
    /// Returns for transport, status, size, or response-contract failures.
    pub async fn verify_candidate(
        &self,
        repositories: &[RepositoryBinding],
    ) -> Result<CandidateRevisionStatus, LoomRpcError> {
        let response = self
            .client
            .post(self.url("loom/v1/candidates/verify")?)
            .json(&CandidateRevisionCheck {
                repositories: repositories.to_vec(),
            })
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        decode_rpc(response).await
    }

    /// Executes one atomic protected-ref CAS and returns its exact rollback.
    ///
    /// # Errors
    ///
    /// Returns for transport, conflict/status, size, or response-contract failures.
    pub async fn compare_and_swap(
        &self,
        updates: &[RefCasUpdate],
    ) -> Result<AtomicRefResult, LoomRpcError> {
        let response = self
            .client
            .post(self.url("loom/v1/refs/cas")?)
            .json(&AtomicRefRequest {
                updates: updates.to_vec(),
            })
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let result: AtomicRefResult = decode_rpc(response).await?;
        let expected_rollback = updates
            .iter()
            .map(|update| RefCasUpdate {
                repository: update.repository.clone(),
                ref_name: update.ref_name.clone(),
                expected: update.head.clone(),
                head: update.expected.clone(),
            })
            .collect::<Vec<_>>();
        if !result.read_back || result.rollback != expected_rollback {
            return Err(LoomRpcError::InvalidResponse);
        }
        Ok(result)
    }

    /// Admits one immutable software graph through the private Loom boundary.
    ///
    /// # Errors
    ///
    /// Returns for transport, authorization/status, size, or an acknowledgement mismatch.
    pub async fn ingest_software_graph(&self, graph: &SoftwareGraph) -> Result<(), LoomRpcError> {
        let response = self
            .client
            .post(self.url("loom/v1/graphs/ingest")?)
            .json(graph)
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let admitted: SoftwareGraph = decode_rpc(response).await?;
        if admitted != *graph {
            return Err(LoomRpcError::InvalidResponse);
        }
        Ok(())
    }

    /// Reads one immutable revision-scoped software graph.
    ///
    /// # Errors
    ///
    /// Returns for transport, authorization/status, size, or a mismatched response.
    pub async fn software_graph(
        &self,
        revision: &RepositoryRevision,
    ) -> Result<SoftwareGraph, LoomRpcError> {
        let response = self
            .client
            .post(self.url("loom/v1/graphs/read")?)
            .json(&SoftwareGraphRead {
                revision: revision.clone(),
            })
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let graph: SoftwareGraph = decode_rpc(response).await?;
        if graph.revision != *revision {
            return Err(LoomRpcError::InvalidResponse);
        }
        Ok(graph)
    }

    /// Reconstructs one exact repository revision with digest and mode read-back.
    ///
    /// # Errors
    ///
    /// Returns for transport, authorization/status, bounds, base64, digest, or path mismatch.
    pub async fn source_materialization(
        &self,
        revision: &RepositoryRevision,
    ) -> Result<SourceMaterialization, LoomRpcError> {
        let response = self
            .client
            .post(self.url("loom/v1/source/materialize")?)
            .json(&SourceMaterializationRead {
                revision: revision.clone(),
            })
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let materialization: SourceMaterialization = decode_rpc(response).await?;
        validate_materialization(revision, &materialization)?;
        Ok(materialization)
    }

    /// Atomically commits one sorted native source mutation set from an exact immutable base.
    ///
    /// # Errors
    ///
    /// Returns before transport for invalid requests, or for transport, status, size, and strict
    /// response-binding failures.
    pub async fn commit_source(
        &self,
        request: &SourceCommitRequest,
    ) -> Result<SourceCommitResult, LoomRpcError> {
        let (expected_digest, _) =
            validate_source_commit_request(request).map_err(|_| LoomRpcError::InvalidRequest)?;
        let response = self
            .client
            .post(self.url("loom/v1/source/commit")?)
            .json(request)
            .send()
            .await
            .map_err(|_| LoomRpcError::Transport)?;
        let result: SourceCommitResult =
            decode_rpc_bounded(response, MAX_SOURCE_COMMIT_RESPONSE_BYTES).await?;
        let mutation_count =
            u32::try_from(request.mutations.len()).map_err(|_| LoomRpcError::InvalidResponse)?;
        if result.schema_version != "v1"
            || result.request_digest != expected_digest
            || result.base != request.base
            || result.head.repository != request.base.repository
            || result.head.validate().is_err()
            || result.mutation_count != mutation_count
        {
            return Err(LoomRpcError::InvalidResponse);
        }
        Ok(result)
    }

    fn url(&self, path: &str) -> Result<reqwest::Url, LoomRpcError> {
        self.endpoint
            .join(path)
            .map_err(|_| LoomRpcError::InvalidEndpoint)
    }
}

async fn decode_rpc<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, LoomRpcError> {
    decode_rpc_bounded(response, MAX_RPC_RESPONSE_BYTES).await
}

async fn decode_rpc_bounded<T: for<'de> Deserialize<'de>>(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<T, LoomRpcError> {
    if !response.status().is_success() {
        return Err(LoomRpcError::RemoteStatus(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(LoomRpcError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| LoomRpcError::Transport)?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(LoomRpcError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| LoomRpcError::InvalidResponse)
}

fn validate_materialization(
    expected: &RepositoryRevision,
    materialization: &SourceMaterialization,
) -> Result<(), LoomRpcError> {
    if materialization.schema_version != "v1"
        || materialization.revision != *expected
        || materialization.files.len() > MAX_FILES_PER_COMMIT
    {
        return Err(LoomRpcError::InvalidResponse);
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_usize;
    for file in &materialization.files {
        if validate_path(&file.path).is_err()
            || previous.is_some_and(|previous| previous >= file.path.as_str())
        {
            return Err(LoomRpcError::InvalidResponse);
        }
        let contents =
            Base64::decode_vec(&file.contents_base64).map_err(|_| LoomRpcError::InvalidResponse)?;
        total = total
            .checked_add(contents.len())
            .ok_or(LoomRpcError::ResponseTooLarge)?;
        if total > MAX_MATERIALIZATION_SOURCE_BYTES || digest_bytes(&contents) != file.digest {
            return Err(LoomRpcError::InvalidResponse);
        }
        previous = Some(&file.path);
    }
    Ok(())
}

fn validate_source_commit_request(
    request: &SourceCommitRequest,
) -> Result<(ArtifactDigest, Vec<DecodedSourceMutation>), LoomError> {
    if request.schema_version != "v1"
        || request.base.validate().is_err()
        || validate_repository(&request.base.repository).is_err()
        || request.mutations.is_empty()
    {
        return Err(LoomError::InvalidSourceCommit);
    }
    if request.mutations.len() > MAX_FILES_PER_COMMIT {
        return Err(LoomError::ResourceLimit);
    }
    let mut previous: Option<&str> = None;
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0_usize;
    let mut decoded = Vec::with_capacity(request.mutations.len());
    for mutation in &request.mutations {
        let path = mutation.path();
        if validate_path(path).is_err() {
            return Err(LoomError::InvalidSourceCommit);
        }
        if !seen.insert(path) {
            return Err(LoomError::DuplicateSourceMutation {
                path: path.to_owned(),
            });
        }
        if previous.is_some_and(|previous| previous >= path) {
            return Err(LoomError::InvalidSourceCommit);
        }
        match mutation {
            SourceCommitMutation::Upsert {
                path,
                mode,
                digest,
                contents_base64,
            } => {
                if digest.validate().is_err() {
                    return Err(LoomError::InvalidSourceCommit);
                }
                let contents = Base64::decode_vec(contents_base64)
                    .map_err(|_| LoomError::InvalidSourceCommit)?;
                if contents.len() as u64 > MAX_SOURCE_FILE_BYTES {
                    return Err(LoomError::ResourceLimit);
                }
                total_bytes = total_bytes
                    .checked_add(contents.len())
                    .ok_or(LoomError::ResourceLimit)?;
                if total_bytes > MAX_SOURCE_COMMIT_BYTES {
                    return Err(LoomError::ResourceLimit);
                }
                if digest_bytes(&contents) != *digest {
                    return Err(LoomError::InvalidSourceCommit);
                }
                decoded.push(DecodedSourceMutation::Upsert {
                    path: path.clone(),
                    mode: *mode,
                    digest: digest.clone(),
                    contents,
                });
            }
            SourceCommitMutation::Delete { path } => {
                decoded.push(DecodedSourceMutation::Delete { path: path.clone() });
            }
        }
        previous = Some(path);
    }
    let encoded = serde_json::to_vec(request).map_err(|_| LoomError::Serialization)?;
    if encoded.len() > MAX_SOURCE_COMMIT_REQUEST_BYTES {
        return Err(LoomError::ResourceLimit);
    }
    Ok((digest_bytes(&encoded), decoded))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcErrorBody {
    code: String,
    message: String,
}

/// Loopback-only Loom RPC handler placed behind the Data VM mutual-TLS boundary.
#[derive(Debug, Clone)]
pub struct LoomRpc {
    store: Arc<PersistentLoomStore>,
}

/// Validated loopback-only Loom RPC server.
#[derive(Debug, Clone)]
pub struct LoomServer {
    bind: SocketAddr,
    rpc: LoomRpc,
}

impl LoomServer {
    /// Opens persistent state and validates the plaintext listener remains loopback-only.
    ///
    /// # Errors
    ///
    /// Returns for a non-loopback bind or any persistent Loom initialization failure.
    pub fn new(bind: SocketAddr, root: impl AsRef<Path>) -> Result<Self, LoomError> {
        Ok(Self {
            bind,
            rpc: LoomRpc::new(PersistentLoomStore::open(root)?),
        })
    }

    /// Validated listener address.
    #[must_use]
    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Consumes the server and builds its bounded private routes.
    pub fn router(self) -> Router {
        self.rpc.router()
    }
}

impl LoomRpc {
    /// Creates a private handler over one persistent Loom store.
    #[must_use]
    pub fn new(store: PersistentLoomStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// Builds the bounded private RPC routes.
    pub fn router(self) -> Router {
        Router::new()
            .route("/loom/v1/health", get(rpc_health))
            .route("/loom/v1/candidates/verify", post(rpc_verify_candidate))
            .route("/loom/v1/refs/cas", post(rpc_compare_and_swap))
            .route("/loom/v1/graphs/ingest", post(rpc_ingest_software_graph))
            .route("/loom/v1/graphs/read", post(rpc_read_software_graph))
            .route("/loom/v1/source/materialize", post(rpc_materialize_source))
            .route("/loom/v1/source/commit", post(rpc_commit_source))
            .layer(DefaultBodyLimit::max(
                MAX_GRAPH_REQUEST_BYTES.max(MAX_SOURCE_COMMIT_REQUEST_BYTES),
            ))
            .with_state(self.store)
    }
}

async fn rpc_commit_source(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(request): Json<SourceCommitRequest>,
) -> Response {
    let grant = NamespaceGrant::new(BTreeSet::from([request.base.repository.clone()]));
    match store.commit_source_changes(&grant, &request) {
        Ok(result) => (StatusCode::CREATED, Json(result)).into_response(),
        Err(LoomError::UnknownRevision { .. }) => rpc_error(
            StatusCode::NOT_FOUND,
            "loom.source_base_unavailable",
            "the exact source base is unavailable",
        ),
        Err(LoomError::SourceDeletionAbsent { .. }) => rpc_error(
            StatusCode::CONFLICT,
            "loom.source_delete_conflict",
            "a deleted source path is absent from the exact base",
        ),
        Err(LoomError::ResourceLimit) => rpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "loom.source_commit_too_large",
            "the native source commit exceeds its bound",
        ),
        Err(_) => rpc_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "loom.source_commit_invalid",
            "the native source commit is invalid",
        ),
    }
}

async fn rpc_materialize_source(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(request): Json<SourceMaterializationRead>,
) -> Response {
    if request.revision.validate().is_err() {
        return rpc_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "loom.revision_invalid",
            "source revision is invalid",
        );
    }
    let grant = NamespaceGrant::new(BTreeSet::from([request.revision.repository.clone()]));
    let source = match store.materialize_source(&grant, &request.revision) {
        Ok(source) => source,
        Err(LoomError::UnknownRevision { .. }) => {
            return rpc_error(
                StatusCode::NOT_FOUND,
                "loom.revision_unavailable",
                "source revision is unavailable",
            );
        }
        Err(_) => {
            return rpc_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "loom.materialization_invalid",
                "source revision could not be materialized",
            );
        }
    };
    let total = source.values().try_fold(0_usize, |total, file| {
        total.checked_add(file.contents.len())
    });
    if total.is_none_or(|total| total > MAX_MATERIALIZATION_SOURCE_BYTES) {
        return rpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "loom.materialization_too_large",
            "source materialization exceeds its bound",
        );
    }
    Json(SourceMaterialization {
        schema_version: "v1".to_owned(),
        revision: request.revision,
        files: source
            .into_iter()
            .map(|(path, file)| SourceMaterializationFile {
                path,
                mode: file.mode,
                digest: digest_bytes(&file.contents),
                contents_base64: Base64::encode_string(&file.contents),
            })
            .collect(),
    })
    .into_response()
}

async fn rpc_health(State(store): State<Arc<PersistentLoomStore>>) -> Response {
    match store.health() {
        Ok(()) => Json(LoomHealth {
            schema_version: "v1".to_owned(),
            persistent_state_ready: true,
        })
        .into_response(),
        Err(_) => rpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "loom.persistent_state_unavailable",
            "Loom persistent state could not be revalidated",
        ),
    }
}

async fn rpc_verify_candidate(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(request): Json<CandidateRevisionCheck>,
) -> Response {
    if request.repositories.is_empty() || request.repositories.len() > 128 {
        return rpc_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "loom.bindings_invalid",
            "candidate repository bindings are invalid",
        );
    }
    let repositories = request
        .repositories
        .iter()
        .map(|binding| binding.base.repository.clone())
        .collect::<BTreeSet<_>>();
    let grant = NamespaceGrant::new(repositories);
    let mut failures = BTreeSet::new();
    for binding in request.repositories {
        let Some(head) = binding.head else {
            failures.insert("loom.head_missing".to_owned());
            continue;
        };
        if store.has_revision(&grant, &binding.base).is_err()
            || store.has_revision(&grant, &head).is_err()
        {
            failures.insert("loom.revision_unavailable".to_owned());
            continue;
        }
        if store
            .resolve_ref(&grant, &binding.base.repository, &binding.target_ref)
            .as_ref()
            != Ok(&binding.base)
        {
            failures.insert("loom.ref_not_at_base".to_owned());
        }
    }
    let failures = failures.into_iter().collect::<Vec<_>>();
    Json(CandidateRevisionStatus {
        ready: failures.is_empty(),
        failures,
    })
    .into_response()
}

async fn rpc_compare_and_swap(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(request): Json<AtomicRefRequest>,
) -> Response {
    let grant = NamespaceGrant::new(
        request
            .updates
            .iter()
            .map(|update| update.repository.clone())
            .collect(),
    );
    match store.compare_and_swap_refs(&grant, &request.updates) {
        Ok(rollback) => Json(AtomicRefResult {
            rollback,
            read_back: true,
        })
        .into_response(),
        Err(LoomError::RefConflict { .. }) => rpc_error(
            StatusCode::CONFLICT,
            "loom.ref_conflict",
            "one or more protected refs changed before the atomic update",
        ),
        Err(_) => rpc_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "loom.atomic_update_invalid",
            "the atomic protected-ref update is invalid",
        ),
    }
}

async fn rpc_ingest_software_graph(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(graph): Json<SoftwareGraph>,
) -> Response {
    let grant = NamespaceGrant::new(BTreeSet::from([graph.revision.repository.clone()]));
    match store.ingest_software_graph(&grant, graph.clone()) {
        Ok(()) => (StatusCode::CREATED, Json(graph)).into_response(),
        Err(LoomError::GraphConflict { .. }) => rpc_error(
            StatusCode::CONFLICT,
            "loom.graph_conflict",
            "a different graph is already admitted for this revision",
        ),
        Err(_) => rpc_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "loom.graph_invalid",
            "the revision-scoped software graph is invalid or unavailable",
        ),
    }
}

async fn rpc_read_software_graph(
    State(store): State<Arc<PersistentLoomStore>>,
    Json(request): Json<SoftwareGraphRead>,
) -> Response {
    let grant = NamespaceGrant::new(BTreeSet::from([request.revision.repository.clone()]));
    match store.software_graph(&grant, &request.revision) {
        Ok(graph) => Json(graph).into_response(),
        Err(_) => rpc_error(
            StatusCode::NOT_FOUND,
            "loom.graph_unavailable",
            "no admitted software graph exists for this exact revision",
        ),
    }
}

fn rpc_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(RpcErrorBody {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
    )
        .into_response()
}

impl PersistentLoomStore {
    /// Opens or initializes one owner-private persistent Loom dataset.
    ///
    /// # Errors
    ///
    /// Returns for unsafe paths or permissions, malformed durable state, or bounded I/O failure.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LoomError> {
        let root = root.as_ref();
        if !safe_absolute_path(root) {
            return Err(LoomError::InvalidRoot);
        }
        if root.exists() {
            validate_private_directory(root)?;
        } else {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root)
                .map_err(|_| LoomError::StorageUnavailable)?;
        }
        let objects = root.join("objects");
        let snapshots = root.join("snapshots");
        let graphs = root.join("graphs");
        ensure_private_directory(&objects)?;
        ensure_private_directory(&snapshots)?;
        ensure_private_directory(&graphs)?;
        let refs = root.join("refs.json");
        let lock = root.join("store.lock");
        let store = Self {
            root: root.to_path_buf(),
            objects,
            snapshots,
            graphs,
            refs,
            lock,
        };
        let lock_file = store.lock_file()?;
        lock_file
            .lock()
            .map_err(|_| LoomError::StorageUnavailable)?;
        if store.refs.exists() {
            store.load_refs()?;
        } else {
            store.write_refs(&BTreeMap::new())?;
        }
        File::unlock(&lock_file).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(store)
    }

    /// Revalidates the owner-private dataset and durable ref manifest without mutating state.
    ///
    /// # Errors
    ///
    /// Returns when permissions, locking, or the durable ref manifest are unavailable or corrupt.
    pub fn health(&self) -> Result<(), LoomError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.objects)?;
        validate_private_directory(&self.snapshots)?;
        validate_private_directory(&self.graphs)?;
        let lock = self.shared_lock()?;
        self.load_refs()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    /// Creates an immutable durable revision from a base plus complete-file replacements.
    ///
    /// # Errors
    ///
    /// Returns for authorization, unknown bases, unsafe paths, bounds, corruption, or I/O failure.
    pub fn commit(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        base: Option<&RepositoryRevision>,
        changes: BTreeMap<String, Vec<u8>>,
    ) -> Result<RepositoryRevision, LoomError> {
        self.commit_source(
            grant,
            repository,
            base,
            changes
                .into_iter()
                .map(|(path, contents)| {
                    (
                        path,
                        PendingSourceFile {
                            contents,
                            mode: SourceFileMode::Regular,
                        },
                    )
                })
                .collect(),
            false,
        )
    }

    /// Atomically exposes one deterministic native source revision from an exact immutable base.
    ///
    /// All mutations, decoded bytes, deletion preconditions, and snapshot bounds are validated
    /// before any new revision becomes reachable. Exact retries return the same request digest and
    /// head revision, including after process restart.
    ///
    /// # Errors
    ///
    /// Returns for denied or unknown bases, invalid/duplicate mutations, absent deletions,
    /// unsupported bounds, corrupt state, or durable storage failure.
    pub fn commit_source_changes(
        &self,
        grant: &NamespaceGrant,
        request: &SourceCommitRequest,
    ) -> Result<SourceCommitResult, LoomError> {
        authorize(grant, &request.base.repository)?;
        let (request_digest, mutations) = validate_source_commit_request(request)?;
        let lock = self.exclusive_lock()?;
        let mut snapshot = self.load_snapshot(&request.base)?;
        let mut objects = Vec::new();
        for mutation in mutations {
            match mutation {
                DecodedSourceMutation::Upsert {
                    path,
                    mode,
                    digest,
                    contents,
                } => {
                    snapshot.insert(
                        path,
                        SnapshotEntry::Mode {
                            digest: digest.clone(),
                            mode,
                        },
                    );
                    objects.push((digest, contents));
                }
                DecodedSourceMutation::Delete { path } => {
                    if snapshot.remove(&path).is_none() {
                        return Err(LoomError::SourceDeletionAbsent { path });
                    }
                }
            }
        }
        validate_snapshot_path_conflicts(&snapshot)?;
        if snapshot.len() > MAX_FILES_PER_COMMIT {
            return Err(LoomError::ResourceLimit);
        }
        let snapshot_bytes = serde_json::to_vec(&snapshot).map_err(|_| LoomError::Serialization)?;
        if snapshot_bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        let head = revision_for(&request.base.repository, &snapshot)?;
        for (digest, contents) in objects {
            self.store_object(&digest, &contents)?;
        }
        self.store_snapshot(&head, &snapshot)?;
        if self.load_snapshot(&head)? != snapshot {
            return Err(LoomError::CorruptState);
        }
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(SourceCommitResult {
            schema_version: "v1".to_owned(),
            request_digest,
            base: request.base.clone(),
            head,
            mutation_count: u32::try_from(request.mutations.len())
                .map_err(|_| LoomError::ResourceLimit)?,
        })
    }

    pub(crate) fn commit_git_source(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        files: BTreeMap<String, PendingSourceFile>,
    ) -> Result<RepositoryRevision, LoomError> {
        self.commit_source(grant, repository, None, files, true)
    }

    fn commit_source(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        base: Option<&RepositoryRevision>,
        changes: BTreeMap<String, PendingSourceFile>,
        preserve_modes: bool,
    ) -> Result<RepositoryRevision, LoomError> {
        authorize(grant, repository)?;
        validate_repository(repository)?;
        if changes.len() > MAX_FILES_PER_COMMIT
            || changes
                .values()
                .any(|source| source.contents.len() as u64 > MAX_SOURCE_FILE_BYTES)
        {
            return Err(LoomError::ResourceLimit);
        }
        let lock = self.exclusive_lock()?;
        let mut snapshot = match base {
            Some(revision) => {
                if revision.repository != repository {
                    return Err(unknown_revision(revision));
                }
                self.load_snapshot(revision)?
            }
            None => BTreeMap::new(),
        };
        for (path, source) in changes {
            validate_path(&path)?;
            let digest = digest_bytes(&source.contents);
            self.store_object(&digest, &source.contents)?;
            let entry = if preserve_modes {
                SnapshotEntry::Mode {
                    digest,
                    mode: source.mode,
                }
            } else {
                SnapshotEntry::Legacy(digest)
            };
            snapshot.insert(path, entry);
        }
        if snapshot.len() > MAX_FILES_PER_COMMIT {
            return Err(LoomError::ResourceLimit);
        }
        let revision = revision_for(repository, &snapshot)?;
        self.store_snapshot(&revision, &snapshot)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(revision)
    }

    /// Reconstructs and digest-verifies one durable revision.
    ///
    /// # Errors
    ///
    /// Returns for authorization, missing state, corruption, resource limits, or I/O failure.
    pub fn materialize(
        &self,
        grant: &NamespaceGrant,
        revision: &RepositoryRevision,
    ) -> Result<BTreeMap<String, Vec<u8>>, LoomError> {
        self.materialize_source(grant, revision).map(|source| {
            source
                .into_iter()
                .map(|(path, source)| (path, source.contents))
                .collect()
        })
    }

    /// Reconstructs one digest-verified source revision with exact file modes.
    ///
    /// # Errors
    ///
    /// Returns for authorization, missing state, corruption, resource limits, or I/O failure.
    pub fn materialize_source(
        &self,
        grant: &NamespaceGrant,
        revision: &RepositoryRevision,
    ) -> Result<BTreeMap<String, MaterializedSourceFile>, LoomError> {
        authorize(grant, &revision.repository)?;
        let lock = self.shared_lock()?;
        let snapshot = self.load_snapshot(revision)?;
        let materialized = snapshot
            .into_iter()
            .map(|(path, entry)| {
                let bytes = read_bounded(
                    self.object_path(entry.digest()).as_path(),
                    MAX_SOURCE_FILE_BYTES,
                )?;
                if digest_bytes(&bytes) != *entry.digest() {
                    return Err(LoomError::CorruptState);
                }
                Ok((
                    path,
                    MaterializedSourceFile {
                        contents: bytes,
                        mode: entry.mode(),
                    },
                ))
            })
            .collect();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        materialized
    }

    /// Verifies one revision manifest exists and still hashes to its immutable identifier.
    ///
    /// # Errors
    ///
    /// Returns for denied namespaces, missing revisions, corruption, or I/O failure.
    pub fn has_revision(
        &self,
        grant: &NamespaceGrant,
        revision: &RepositoryRevision,
    ) -> Result<(), LoomError> {
        authorize(grant, &revision.repository)?;
        let lock = self.shared_lock()?;
        self.load_snapshot(revision)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    /// Admits one complete immutable software graph for a reachable source revision.
    ///
    /// The analyzer digest, nodes, and edges are all part of the immutable value. An exact replay
    /// is idempotent; a different value for the same source revision fails closed.
    ///
    /// # Errors
    ///
    /// Returns for namespace denial, an unknown revision, invalid graph structure, conflict,
    /// corruption, resource limits, or bounded storage failure.
    pub fn ingest_software_graph(
        &self,
        grant: &NamespaceGrant,
        graph: SoftwareGraph,
    ) -> Result<(), LoomError> {
        authorize(grant, &graph.revision.repository)?;
        validate_software_graph(&graph)?;
        let lock = self.exclusive_lock()?;
        self.ensure_persistent_revision(&graph.revision.repository, &graph.revision)?;
        let directory = self.graphs.join(&graph.revision.repository);
        ensure_private_directory(&directory)?;
        let path = directory.join(format!("{}.json", graph.revision.revision));
        let bytes = serde_json::to_vec(&graph).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_GRAPH_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        if path.exists() {
            let existing = read_bounded(&path, MAX_GRAPH_BYTES)?;
            File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(LoomError::GraphConflict {
                    repository: graph.revision.repository,
                    revision: graph.revision.revision,
                })
            };
        }
        write_atomic(&directory, &path, &bytes, 0o600)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    /// Reads and validates the immutable software graph for one exact source revision.
    ///
    /// # Errors
    ///
    /// Returns for namespace denial, an unknown revision or graph, corruption, resource bounds,
    /// or storage failure.
    pub fn software_graph(
        &self,
        grant: &NamespaceGrant,
        revision: &RepositoryRevision,
    ) -> Result<SoftwareGraph, LoomError> {
        authorize(grant, &revision.repository)?;
        let lock = self.shared_lock()?;
        self.ensure_persistent_revision(&revision.repository, revision)?;
        let path = self
            .graphs
            .join(&revision.repository)
            .join(format!("{}.json", revision.revision));
        let bytes = read_bounded(&path, MAX_GRAPH_BYTES)?;
        let graph: SoftwareGraph =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if graph.revision != *revision || validate_software_graph(&graph).is_err() {
            return Err(LoomError::CorruptState);
        }
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(graph)
    }

    /// Creates a durable protected ref at a known immutable revision.
    ///
    /// # Errors
    ///
    /// Returns for authorization, syntax, unknown revisions, conflicts, corruption, or I/O.
    pub fn create_ref(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        ref_name: &str,
        revision: &RepositoryRevision,
    ) -> Result<(), LoomError> {
        authorize(grant, repository)?;
        validate_repository(repository)?;
        validate_ref(ref_name)?;
        let lock = self.exclusive_lock()?;
        self.ensure_persistent_revision(repository, revision)?;
        let mut refs = self.load_refs()?;
        let key = (repository.to_owned(), ref_name.to_owned());
        if refs.contains_key(&key) {
            return Err(LoomError::RefConflict {
                repository: repository.to_owned(),
                ref_name: ref_name.to_owned(),
            });
        }
        refs.insert(key, revision.clone());
        self.write_refs(&refs)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    /// Resolves one durable protected ref under namespace authorization.
    ///
    /// # Errors
    ///
    /// Returns for authorization, syntax, unknown refs, corruption, or I/O failure.
    pub fn resolve_ref(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        ref_name: &str,
    ) -> Result<RepositoryRevision, LoomError> {
        authorize(grant, repository)?;
        validate_repository(repository)?;
        validate_ref(ref_name)?;
        let lock = self.shared_lock()?;
        let revision = self
            .load_refs()?
            .get(&(repository.to_owned(), ref_name.to_owned()))
            .cloned()
            .ok_or_else(|| LoomError::RefConflict {
                repository: repository.to_owned(),
                ref_name: ref_name.to_owned(),
            })?;
        self.ensure_persistent_revision(repository, &revision)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(revision)
    }

    /// Returns a stable copy of every protected ref for one authorized Git projection.
    pub(crate) fn protected_refs_for_repository(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
    ) -> Result<BTreeMap<String, RepositoryRevision>, LoomError> {
        authorize(grant, repository)?;
        validate_repository(repository)?;
        let lock = self.shared_lock()?;
        let refs = self
            .load_refs()?
            .into_iter()
            .filter_map(|((entry_repository, ref_name), revision)| {
                (entry_repository == repository).then_some((ref_name, revision))
            })
            .collect();
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(refs)
    }

    /// Atomically commits one multi-repository protected-ref manifest and returns its rollback.
    ///
    /// # Errors
    ///
    /// Returns before the atomic rename for any denied, invalid, duplicate, unknown, or stale ref.
    pub fn compare_and_swap_refs(
        &self,
        grant: &NamespaceGrant,
        updates: &[RefCasUpdate],
    ) -> Result<Vec<RefCasUpdate>, LoomError> {
        if updates.is_empty() || updates.len() > MAX_FILES_PER_COMMIT {
            return Err(LoomError::ResourceLimit);
        }
        let lock = self.exclusive_lock()?;
        let mut refs = self.load_refs()?;
        let mut seen = BTreeSet::new();
        let mut all_expected = true;
        let mut all_heads = true;
        for update in updates {
            authorize(grant, &update.repository)?;
            validate_repository(&update.repository)?;
            validate_ref(&update.ref_name)?;
            let key = (update.repository.clone(), update.ref_name.clone());
            if !seen.insert(key.clone()) {
                return Err(LoomError::DuplicateRef {
                    repository: update.repository.clone(),
                    ref_name: update.ref_name.clone(),
                });
            }
            self.ensure_persistent_revision(&update.repository, &update.expected)?;
            self.ensure_persistent_revision(&update.repository, &update.head)?;
            let current = refs.get(&key);
            all_expected &= current == Some(&update.expected);
            all_heads &= current == Some(&update.head);
            if current != Some(&update.expected) && current != Some(&update.head) {
                return Err(LoomError::RefConflict {
                    repository: update.repository.clone(),
                    ref_name: update.ref_name.clone(),
                });
            }
        }
        if !all_expected && !all_heads {
            return Err(LoomError::RefConflict {
                repository: updates[0].repository.clone(),
                ref_name: updates[0].ref_name.clone(),
            });
        }
        let rollback = updates
            .iter()
            .map(|update| RefCasUpdate {
                repository: update.repository.clone(),
                ref_name: update.ref_name.clone(),
                expected: update.head.clone(),
                head: update.expected.clone(),
            })
            .collect::<Vec<_>>();
        if all_heads {
            File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
            return Ok(rollback);
        }
        for update in updates {
            refs.insert(
                (update.repository.clone(), update.ref_name.clone()),
                update.head.clone(),
            );
        }
        self.write_refs(&refs)?;
        let readback = self.load_refs()?;
        if updates.iter().any(|update| {
            readback.get(&(update.repository.clone(), update.ref_name.clone()))
                != Some(&update.head)
        }) {
            return Err(LoomError::CorruptState);
        }
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        Ok(rollback)
    }

    fn store_object(&self, digest: &ArtifactDigest, bytes: &[u8]) -> Result<(), LoomError> {
        let path = self.object_path(digest);
        if path.exists() {
            let existing = read_bounded(&path, MAX_SOURCE_FILE_BYTES)?;
            return if digest_bytes(&existing) == *digest {
                Ok(())
            } else {
                Err(LoomError::CorruptState)
            };
        }
        write_atomic(&self.objects, &path, bytes, 0o600)
    }

    fn store_snapshot(
        &self,
        revision: &RepositoryRevision,
        snapshot: &Snapshot,
    ) -> Result<(), LoomError> {
        let directory = self.snapshots.join(&revision.repository);
        ensure_private_directory(&directory)?;
        let path = directory.join(format!("{}.json", revision.revision));
        let bytes = serde_json::to_vec(snapshot).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        if path.exists() {
            return if read_bounded(&path, MAX_SNAPSHOT_BYTES)? == bytes {
                Ok(())
            } else {
                Err(LoomError::CorruptState)
            };
        }
        write_atomic(&directory, &path, &bytes, 0o600)
    }

    fn load_snapshot(&self, revision: &RepositoryRevision) -> Result<Snapshot, LoomError> {
        validate_repository(&revision.repository)?;
        let path = self
            .snapshots
            .join(&revision.repository)
            .join(format!("{}.json", revision.revision));
        let bytes = read_bounded(&path, MAX_SNAPSHOT_BYTES).map_err(|error| match error {
            LoomError::StorageUnavailable if !path.exists() => unknown_revision(revision),
            other => other,
        })?;
        let snapshot: Snapshot =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if snapshot.len() > MAX_FILES_PER_COMMIT
            || snapshot.iter().any(|(path, entry)| {
                validate_path(path).is_err() || entry.digest().validate().is_err()
            })
            || revision_for(&revision.repository, &snapshot).as_ref() != Ok(revision)
        {
            return Err(LoomError::CorruptState);
        }
        Ok(snapshot)
    }

    fn load_refs(&self) -> Result<BTreeMap<RefKey, RepositoryRevision>, LoomError> {
        let bytes = read_bounded(&self.refs, MAX_SNAPSHOT_BYTES)?;
        let persisted: PersistedRefs =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" || persisted.refs.len() > MAX_FILES_PER_COMMIT {
            return Err(LoomError::CorruptState);
        }
        let mut refs = BTreeMap::new();
        for entry in persisted.refs {
            if validate_repository(&entry.repository).is_err()
                || validate_ref(&entry.ref_name).is_err()
                || entry.revision.repository != entry.repository
                || refs
                    .insert((entry.repository, entry.ref_name), entry.revision)
                    .is_some()
            {
                return Err(LoomError::CorruptState);
            }
        }
        Ok(refs)
    }

    fn write_refs(&self, refs: &BTreeMap<RefKey, RepositoryRevision>) -> Result<(), LoomError> {
        let persisted = PersistedRefs {
            schema_version: "v1".to_owned(),
            refs: refs
                .iter()
                .map(|((repository, ref_name), revision)| PersistedRef {
                    repository: repository.clone(),
                    ref_name: ref_name.clone(),
                    revision: revision.clone(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        write_atomic(&self.root, &self.refs, &bytes, 0o600)
    }

    fn ensure_persistent_revision(
        &self,
        repository: &str,
        revision: &RepositoryRevision,
    ) -> Result<(), LoomError> {
        if revision.repository != repository {
            return Err(unknown_revision(revision));
        }
        self.load_snapshot(revision).map(|_| ())
    }

    fn object_path(&self, digest: &ArtifactDigest) -> PathBuf {
        self.objects.join(&digest.value)
    }

    fn lock_file(&self) -> Result<File, LoomError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&self.lock)
            .map_err(|_| LoomError::StorageUnavailable)?;
        let metadata = file.metadata().map_err(|_| LoomError::StorageUnavailable)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(LoomError::UnsafeRootPermissions);
        }
        Ok(file)
    }

    fn exclusive_lock(&self) -> Result<File, LoomError> {
        let file = self.lock_file()?;
        file.lock().map_err(|_| LoomError::StorageUnavailable)?;
        Ok(file)
    }

    fn shared_lock(&self) -> Result<File, LoomError> {
        let file = self.lock_file()?;
        file.lock_shared()
            .map_err(|_| LoomError::StorageUnavailable)?;
        Ok(file)
    }
}

impl LoomStore {
    /// Creates an empty Loom store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            refs: BTreeMap::new(),
        }
    }

    /// Creates an immutable revision from a base plus complete-file replacements.
    ///
    /// # Errors
    ///
    /// Returns for denied namespaces, unknown bases, unsafe paths, or serialization failures.
    pub fn commit(
        &mut self,
        grant: &NamespaceGrant,
        repository: &str,
        base: Option<&RepositoryRevision>,
        changes: BTreeMap<String, Vec<u8>>,
    ) -> Result<RepositoryRevision, LoomError> {
        authorize(grant, repository)?;
        let mut snapshot = match base {
            Some(revision) => {
                if revision.repository != repository {
                    return Err(unknown_revision(revision));
                }
                self.snapshots
                    .get(revision)
                    .cloned()
                    .ok_or_else(|| unknown_revision(revision))?
            }
            None => BTreeMap::new(),
        };
        for (path, contents) in changes {
            validate_path(&path)?;
            let digest = digest_bytes(&contents);
            self.objects.entry(digest.clone()).or_insert(contents);
            snapshot.insert(path, SnapshotEntry::Legacy(digest));
        }
        let revision = revision_for(repository, &snapshot)?;
        self.snapshots.entry(revision.clone()).or_insert(snapshot);
        Ok(revision)
    }

    /// Reconstructs one immutable revision without exposing internal object mutation.
    ///
    /// # Errors
    ///
    /// Returns for a denied namespace, unknown revision, or missing CAS object.
    pub fn materialize(
        &self,
        grant: &NamespaceGrant,
        revision: &RepositoryRevision,
    ) -> Result<BTreeMap<String, Vec<u8>>, LoomError> {
        authorize(grant, &revision.repository)?;
        let snapshot = self
            .snapshots
            .get(revision)
            .ok_or_else(|| unknown_revision(revision))?;
        snapshot
            .iter()
            .map(|(path, entry)| {
                let bytes = self
                    .objects
                    .get(entry.digest())
                    .cloned()
                    .ok_or_else(|| unknown_revision(revision))?;
                Ok((path.clone(), bytes))
            })
            .collect()
    }

    /// Number of deduplicated content objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Creates a protected ref at a known immutable revision.
    ///
    /// # Errors
    ///
    /// Returns for authorization, ref syntax, revision existence, or ref conflicts.
    pub fn create_ref(
        &mut self,
        grant: &NamespaceGrant,
        repository: &str,
        ref_name: &str,
        revision: &RepositoryRevision,
    ) -> Result<(), LoomError> {
        authorize(grant, repository)?;
        validate_ref(ref_name)?;
        self.ensure_revision(repository, revision)?;
        let key = (repository.to_owned(), ref_name.to_owned());
        if self.refs.contains_key(&key) {
            return Err(LoomError::RefConflict {
                repository: repository.to_owned(),
                ref_name: ref_name.to_owned(),
            });
        }
        self.refs.insert(key, revision.clone());
        Ok(())
    }

    /// Resolves a protected ref under namespace authorization.
    ///
    /// # Errors
    ///
    /// Returns for authorization, ref syntax, or an unknown ref.
    pub fn resolve_ref(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        ref_name: &str,
    ) -> Result<RepositoryRevision, LoomError> {
        authorize(grant, repository)?;
        validate_ref(ref_name)?;
        self.refs
            .get(&(repository.to_owned(), ref_name.to_owned()))
            .cloned()
            .ok_or_else(|| LoomError::RefConflict {
                repository: repository.to_owned(),
                ref_name: ref_name.to_owned(),
            })
    }

    /// Atomically validates and updates every repository ref in one candidate.
    ///
    /// The returned updates are a ready-to-execute rollback compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns before mutation for any authorization, revision, duplicate, or CAS conflict.
    pub fn compare_and_swap_refs(
        &mut self,
        grant: &NamespaceGrant,
        updates: &[RefCasUpdate],
    ) -> Result<Vec<RefCasUpdate>, LoomError> {
        let mut seen = BTreeSet::new();
        for update in updates {
            authorize(grant, &update.repository)?;
            validate_ref(&update.ref_name)?;
            let key = (update.repository.clone(), update.ref_name.clone());
            if !seen.insert(key.clone()) {
                return Err(LoomError::DuplicateRef {
                    repository: update.repository.clone(),
                    ref_name: update.ref_name.clone(),
                });
            }
            self.ensure_revision(&update.repository, &update.expected)?;
            self.ensure_revision(&update.repository, &update.head)?;
            if self.refs.get(&key) != Some(&update.expected) {
                return Err(LoomError::RefConflict {
                    repository: update.repository.clone(),
                    ref_name: update.ref_name.clone(),
                });
            }
        }
        for update in updates {
            self.refs.insert(
                (update.repository.clone(), update.ref_name.clone()),
                update.head.clone(),
            );
        }
        Ok(updates
            .iter()
            .map(|update| RefCasUpdate {
                repository: update.repository.clone(),
                ref_name: update.ref_name.clone(),
                expected: update.head.clone(),
                head: update.expected.clone(),
            })
            .collect())
    }

    fn ensure_revision(
        &self,
        repository: &str,
        revision: &RepositoryRevision,
    ) -> Result<(), LoomError> {
        if revision.repository != repository || !self.snapshots.contains_key(revision) {
            return Err(unknown_revision(revision));
        }
        Ok(())
    }
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn validate_private_directory(path: &Path) -> Result<(), LoomError> {
    let metadata = fs::metadata(path).map_err(|_| LoomError::StorageUnavailable)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(LoomError::UnsafeRootPermissions);
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), LoomError> {
    if path.exists() {
        return validate_private_directory(path);
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| LoomError::StorageUnavailable)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, LoomError> {
    let metadata = fs::metadata(path).map_err(|_| LoomError::StorageUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > maximum
    {
        return Err(LoomError::CorruptState);
    }
    let file = File::open(path).map_err(|_| LoomError::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LoomError::StorageUnavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(LoomError::ResourceLimit);
    }
    Ok(bytes)
}

fn write_atomic(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), LoomError> {
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(LoomError::StorageUnavailable)?;
    let temporary = directory.join(format!(".{file_name}.next"));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|_| LoomError::StorageUnavailable)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| LoomError::StorageUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| LoomError::StorageUnavailable)?;
    file.sync_all().map_err(|_| LoomError::StorageUnavailable)?;
    fs::rename(&temporary, destination).map_err(|_| LoomError::StorageUnavailable)?;
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| LoomError::StorageUnavailable)
}

fn authorize(grant: &NamespaceGrant, repository: &str) -> Result<(), LoomError> {
    if grant.permits(repository) {
        Ok(())
    } else {
        Err(LoomError::NamespaceDenied {
            repository: repository.to_owned(),
        })
    }
}

fn validate_repository(repository: &str) -> Result<(), LoomError> {
    if (1..=128).contains(&repository.len())
        && repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(LoomError::InvalidRepository {
            repository: repository.to_owned(),
        })
    }
}

fn validate_path(path: &str) -> Result<(), LoomError> {
    let value = Path::new(path);
    let mut normalized = PathBuf::new();
    for component in value.components() {
        if let Component::Normal(component) = component {
            normalized.push(component);
        }
    }
    let valid = !path.is_empty()
        && !value.is_absolute()
        && normalized.as_os_str().as_encoded_bytes() == path.as_bytes()
        && value
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(LoomError::InvalidPath {
            path: path.to_owned(),
        })
    }
}

fn validate_snapshot_path_conflicts(snapshot: &Snapshot) -> Result<(), LoomError> {
    for path in snapshot.keys() {
        if path
            .match_indices('/')
            .any(|(separator, _)| snapshot.contains_key(&path[..separator]))
        {
            return Err(LoomError::SourcePathConflict { path: path.clone() });
        }
    }
    Ok(())
}

fn validate_ref(ref_name: &str) -> Result<(), LoomError> {
    if validate_repository_ref(ref_name).is_ok() {
        Ok(())
    } else {
        Err(LoomError::InvalidRef {
            ref_name: ref_name.to_owned(),
        })
    }
}

fn validate_software_graph(graph: &SoftwareGraph) -> Result<(), LoomError> {
    validate_repository(&graph.revision.repository).map_err(|_| LoomError::InvalidSoftwareGraph)?;
    graph
        .analyzer_digest
        .validate()
        .map_err(|_| LoomError::InvalidSoftwareGraph)?;
    if graph.schema_version != "v1"
        || graph.nodes.is_empty()
        || graph.nodes.len() > MAX_GRAPH_NODES
        || graph.edges.len() > MAX_GRAPH_EDGES
    {
        return Err(LoomError::InvalidSoftwareGraph);
    }
    let mut node_ids = BTreeSet::new();
    for node in &graph.nodes {
        if !valid_graph_token(&node.id, 256)
            || !valid_graph_token(&node.kind, 128)
            || node.label.trim().is_empty()
            || node.label.len() > 512
            || validate_path(&node.path).is_err()
            || !node_ids.insert(node.id.as_str())
        {
            return Err(LoomError::InvalidSoftwareGraph);
        }
    }
    let mut edges = BTreeSet::new();
    for edge in &graph.edges {
        if !node_ids.contains(edge.source.as_str())
            || !node_ids.contains(edge.target.as_str())
            || !valid_graph_token(&edge.kind, 128)
            || !edges.insert((
                edge.source.as_str(),
                edge.target.as_str(),
                edge.kind.as_str(),
            ))
        {
            return Err(LoomError::InvalidSoftwareGraph);
        }
    }
    Ok(())
}

fn valid_graph_token(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn unknown_revision(revision: &RepositoryRevision) -> LoomError {
    LoomError::UnknownRevision {
        repository: revision.repository.clone(),
        revision: revision.revision.clone(),
    }
}

fn digest_bytes(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest {
        algorithm: "sha256".to_owned(),
        value: hex_digest(Sha256::digest(bytes).as_slice()),
    }
}

fn revision_for(repository: &str, snapshot: &Snapshot) -> Result<RepositoryRevision, LoomError> {
    #[derive(Serialize)]
    struct RevisionInput<'a> {
        repository: &'a str,
        snapshot: &'a Snapshot,
    }
    let encoded = serde_json::to_vec(&RevisionInput {
        repository,
        snapshot,
    })
    .map_err(|_| LoomError::Serialization)?;
    RepositoryRevision::new(repository, hex_digest(Sha256::digest(encoded).as_slice()))
        .map_err(|_| LoomError::Serialization)
}

fn hex_digest(bytes: &[u8]) -> String {
    let alphabet = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(alphabet[usize::from(byte >> 4)]),
                char::from(alphabet[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

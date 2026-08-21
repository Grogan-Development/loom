//! Insights pre-flight: digest-cached static analysis before any review agent.
//!
//! Produces a content-addressed bundle (diffstat, toolchain, LSP delta,
//! code-graph delta, blast radius, hotspots) from base vs head materializations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ci::CiEngine;
use crate::contracts::{ArtifactDigest, RepositoryBinding, RepositoryRevision};
use crate::features::{Candidate, Feature, candidate_source_key};
use crate::{
    LoomError, NamespaceGrant, PersistentLoomStore, SoftwareEdge, SoftwareGraph, SoftwareNode,
    digest_bytes, read_bounded, valid_graph_token, validate_path, write_atomic,
};

const MAX_INSIGHTS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOBS: usize = 10_000;
const MAX_HUNKS: usize = 256;
const MAX_HOTSPOTS: usize = 8;
const MAX_BLAST: usize = 256;
const MAX_GRAPH_FILE_BYTES: usize = 1024 * 1024;
const MAX_LINE_DIFF_LINES: usize = 10_000;
const ANALYZER_SEED: &[u8] = b"loom-insights-v1";
const LSP_TIMEOUT: Duration = Duration::from_secs(10);

/// Digest-bound pointer from a candidate to a persisted insights bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightsRef {
    /// SHA-256 of the canonical bundle body (without the digest field).
    pub digest: ArtifactDigest,
    /// Durable insights job identifier.
    pub job_id: String,
}

/// Digest-cached pre-flight analysis for one candidate source key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightsBundle {
    /// Bundle schema version. MVP is `v1`.
    pub schema_version: String,
    /// SHA-256 of the canonical JSON without this field.
    pub digest: ArtifactDigest,
    /// Canonical `repo:base:head` cache key.
    pub source_key: String,
    /// Per-repository analysis.
    pub repos: Vec<RepoInsights>,
    /// Advisory failure recorded when analysis could not fully complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Static analysis for one repository binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoInsights {
    /// Repository namespace.
    pub repository: String,
    /// Base revision hex.
    pub base: String,
    /// Head revision hex.
    pub head: String,
    /// Detected toolchain: `cargo`, `go`, `node`, or `unknown`.
    pub toolchain: String,
    /// File-level diff between materializations.
    pub diffstat: DiffStat,
    /// Best-effort LSP diagnostic delta.
    pub diagnostics_delta: DiagnosticsDelta,
    /// Added/removed graph nodes and edge counts.
    pub graph_delta: GraphDelta,
    /// One-hop neighbors of changed graph nodes.
    pub blast_radius: Vec<String>,
    /// Highest-churn changed paths, bounded.
    pub hotspots: Vec<String>,
}

/// File-level and hunk-level diff between two trees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffStat {
    /// Paths present only in head.
    pub files_added: u32,
    /// Paths present only in base.
    pub files_removed: u32,
    /// Paths present in both with different bytes.
    pub files_changed: u32,
    /// Bounded per-path line counts (max 256).
    pub hunks: Vec<FileHunk>,
}

/// Line add/delete counts for one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHunk {
    /// Repository-relative path.
    pub path: String,
    /// Lines added (head not in base).
    pub added: u32,
    /// Lines removed (base not in head).
    pub removed: u32,
}

/// Introduced vs fixed diagnostics, or a skip reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsDelta {
    /// Diagnostics present on head and absent on base.
    pub introduced: Vec<Diagnostic>,
    /// Diagnostics present on base and absent on head.
    pub fixed: Vec<Diagnostic>,
    /// Why LSP was not applied (`lsp: skipped`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// One file-scoped diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Repository-relative path.
    pub path: String,
    /// 1-based line, or 0 when unknown.
    pub line: u32,
    /// Analyzer severity (`error`, `warning`, …).
    pub severity: String,
    /// Human-readable message, bounded.
    pub message: String,
}

/// Graph membership delta between base and head analyzers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDelta {
    /// Node ids present only on head.
    pub nodes_added: Vec<String>,
    /// Node ids present only on base.
    pub nodes_removed: Vec<String>,
    /// Directed edges present only on head.
    pub edges_added: u32,
    /// Directed edges present only on base.
    pub edges_removed: u32,
}

/// Durable insights job keyed by candidate source digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsightsJob {
    /// Durable job identifier.
    pub id: String,
    /// Feature that requested the job.
    pub feature_id: String,
    /// Canonical source key (repo:base:head…).
    pub source_key: String,
    /// Digest of the persisted bundle.
    pub digest: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedJobs {
    schema_version: String,
    jobs: Vec<InsightsJob>,
}

#[derive(Serialize)]
struct BundleFingerprint<'a> {
    schema_version: &'a str,
    source_key: &'a str,
    repos: &'a [RepoInsights],
    #[serde(skip_serializing_if = "Option::is_none")]
    error: &'a Option<String>,
}

/// Digest-cached insights runner rooted in the Loom dataset.
#[derive(Debug, Clone)]
pub struct InsightsEngine {
    store: PersistentLoomStore,
}

impl InsightsEngine {
    /// Creates an insights engine over an existing Loom dataset.
    #[must_use]
    pub const fn new(store: PersistentLoomStore) -> Self {
        Self { store }
    }

    /// Runs or replays pre-flight analysis for one candidate source key.
    ///
    /// Analysis failures are advisory: they are recorded on the bundle rather
    /// than failing the candidate pipeline.
    ///
    /// # Errors
    ///
    /// Returns when the candidate is not ready or durable storage fails.
    pub fn run(
        &self,
        feature_id: &str,
        bindings: &[RepositoryBinding],
    ) -> Result<InsightsBundle, LoomError> {
        let source_key = candidate_source_key(bindings).ok_or(LoomError::InvalidSourceCommit)?;
        let status = CiEngine::new(self.store.clone()).verify(bindings);
        if !status.ready {
            return Err(LoomError::UnknownRevision {
                repository: bindings.first().map_or_else(
                    || "unknown".to_owned(),
                    |binding| binding.base.repository.clone(),
                ),
                revision: status.failures.join(","),
            });
        }
        if let Some(cached) = self.cached(&source_key)? {
            return Ok(cached);
        }
        let (repos, error) = match self.analyze_bindings(bindings) {
            Ok(repos) => (repos, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let bundle = seal_bundle(source_key.clone(), repos, error);
        let job = InsightsJob {
            id: Uuid::now_v7().to_string(),
            feature_id: feature_id.to_owned(),
            source_key,
            digest: bundle.digest.clone(),
        };
        self.persist(&job, &bundle)?;
        Ok(bundle)
    }

    /// Pointer from a completed bundle back to its durable job.
    ///
    /// # Errors
    ///
    /// Returns when the job catalog cannot be read or the digest is unknown.
    pub fn ref_for(&self, bundle: &InsightsBundle) -> Result<InsightsRef, LoomError> {
        let job = self
            .load_jobs()?
            .into_values()
            .find(|job| job.digest == bundle.digest)
            .ok_or_else(|| unknown_insights(&bundle.digest.value))?;
        Ok(InsightsRef {
            digest: bundle.digest.clone(),
            job_id: job.id,
        })
    }

    /// Loads a persisted bundle by digest.
    ///
    /// # Errors
    ///
    /// Returns when the object is missing, corrupt, or unreadable.
    pub fn load_bundle(&self, digest: &ArtifactDigest) -> Result<InsightsBundle, LoomError> {
        let lock = self.store.shared_lock()?;
        let path = self.bundle_path(digest);
        let bytes = read_bounded(&path, MAX_INSIGHTS_BYTES)?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        let bundle: InsightsBundle =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if bundle.schema_version != "v1" || bundle.digest != *digest {
            return Err(LoomError::CorruptState);
        }
        Ok(bundle)
    }

    /// Resolves the insights bundle attached to a feature candidate.
    ///
    /// # Errors
    ///
    /// Returns when the feature has no candidate or no persisted insights.
    pub fn bundle_for_feature(&self, feature: &Feature) -> Result<InsightsBundle, LoomError> {
        let candidate = feature
            .candidate
            .as_ref()
            .ok_or_else(|| unknown_insights("missing-candidate"))?;
        if let Some(insights) = &candidate.insights {
            return self.load_bundle(&insights.digest);
        }
        let source_key = candidate_source_key(&candidate.repositories)
            .ok_or_else(|| unknown_insights("missing-source-key"))?;
        self.cached(&source_key)?
            .ok_or_else(|| unknown_insights(&source_key))
    }

    /// Attaches a completed insights pointer onto a CI candidate.
    pub fn attach_to_candidate(candidate: &mut Candidate, insights: InsightsRef) {
        candidate.insights = Some(insights);
    }

    fn analyze_bindings(
        &self,
        bindings: &[RepositoryBinding],
    ) -> Result<Vec<RepoInsights>, LoomError> {
        let grant = NamespaceGrant::new(
            bindings
                .iter()
                .map(|binding| binding.base.repository.clone())
                .collect(),
        );
        let mut repos = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let head = binding
                .head
                .as_ref()
                .ok_or(LoomError::InvalidSourceCommit)?;
            let base_files = self.store.materialize(&grant, &binding.base)?;
            let head_files = self.store.materialize(&grant, head)?;
            let (mut repo, base_graph, head_graph) = analyze_trees(
                &binding.base.repository,
                &binding.base.revision,
                &head.revision,
                &base_files,
                &head_files,
            );
            repo.graph_delta = ingest_and_delta(&self.store, &grant, &base_graph, &head_graph)?;
            repo.blast_radius = blast_from_graphs(
                &self.store,
                &grant,
                &binding.base,
                head,
                &repo.graph_delta,
                &repo.diffstat,
            );
            repos.push(repo);
        }
        Ok(repos)
    }

    fn cached(&self, source_key: &str) -> Result<Option<InsightsBundle>, LoomError> {
        let lock = self.store.shared_lock()?;
        let jobs = self.load_jobs()?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)?;
        let Some(job) = jobs.values().find(|job| job.source_key == source_key) else {
            return Ok(None);
        };
        match self.load_bundle(&job.digest) {
            Ok(bundle) => Ok(Some(bundle)),
            Err(LoomError::StorageUnavailable | LoomError::CorruptState) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn persist(&self, job: &InsightsJob, bundle: &InsightsBundle) -> Result<(), LoomError> {
        let lock = self.store.exclusive_lock()?;
        let mut jobs = self.load_jobs()?;
        jobs.insert(job.id.clone(), job.clone());
        if jobs.len() > MAX_JOBS {
            return Err(LoomError::ResourceLimit);
        }
        let persisted = PersistedJobs {
            schema_version: "v1".to_owned(),
            jobs: jobs.into_values().collect(),
        };
        let job_bytes = serde_json::to_vec(&persisted).map_err(|_| LoomError::Serialization)?;
        if job_bytes.len() as u64 > MAX_INSIGHTS_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        write_atomic(
            &self.store.root,
            &self.store.root.join("insights-jobs.json"),
            &job_bytes,
            0o600,
        )?;
        let directory = self.store.root.join("insights");
        ensure_insights_directory(&directory)?;
        let bundle_bytes = serde_json::to_vec(bundle).map_err(|_| LoomError::Serialization)?;
        if bundle_bytes.len() as u64 > MAX_INSIGHTS_BYTES {
            return Err(LoomError::ResourceLimit);
        }
        write_atomic(
            &directory,
            &self.bundle_path(&bundle.digest),
            &bundle_bytes,
            0o600,
        )?;
        File::unlock(&lock).map_err(|_| LoomError::StorageUnavailable)
    }

    fn load_jobs(&self) -> Result<BTreeMap<String, InsightsJob>, LoomError> {
        let path = self.store.root.join("insights-jobs.json");
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = read_bounded(&path, MAX_INSIGHTS_BYTES)?;
        let persisted: PersistedJobs =
            serde_json::from_slice(&bytes).map_err(|_| LoomError::CorruptState)?;
        if persisted.schema_version != "v1" {
            return Err(LoomError::CorruptState);
        }
        Ok(persisted
            .jobs
            .into_iter()
            .map(|job| (job.id.clone(), job))
            .collect())
    }

    fn bundle_path(&self, digest: &ArtifactDigest) -> PathBuf {
        self.store
            .root
            .join("insights")
            .join(format!("{}.json", digest.value))
    }
}

/// Walks a materialized tree on disk into a path → bytes map.
///
/// # Errors
///
/// Returns when the root cannot be read or a path is unsafe.
pub fn read_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, LoomError> {
    let mut files = BTreeMap::new();
    collect_tree(root, root, &mut files)?;
    Ok(files)
}

/// Analyzes two in-memory trees without touching Loom storage.
#[must_use]
pub fn analyze_trees(
    repository: &str,
    base_revision: &str,
    head_revision: &str,
    base_files: &BTreeMap<String, Vec<u8>>,
    head_files: &BTreeMap<String, Vec<u8>>,
) -> (RepoInsights, SoftwareGraph, SoftwareGraph) {
    let toolchain = detect_toolchain(head_files, base_files);
    let diffstat = diff_trees(base_files, head_files);
    let hotspots = hotspots_from(&diffstat);
    let changed = changed_paths(&diffstat);
    let diagnostics_delta = lsp_delta(&toolchain, base_files, head_files, &changed);
    let base_graph =
        extract_software_graph(placeholder_revision(repository, base_revision), base_files);
    let head_graph =
        extract_software_graph(placeholder_revision(repository, head_revision), head_files);
    let graph_delta = graph_delta(&base_graph, &head_graph);
    let blast_radius = blast_radius(&base_graph, &head_graph, &graph_delta, &changed);
    (
        RepoInsights {
            repository: repository.to_owned(),
            base: base_revision.to_owned(),
            head: head_revision.to_owned(),
            toolchain,
            diffstat,
            diagnostics_delta,
            graph_delta,
            blast_radius,
            hotspots,
        },
        base_graph,
        head_graph,
    )
}

/// Extracts a deterministic v1 software graph from one materialized tree.
#[must_use]
pub fn extract_software_graph(
    revision: RepositoryRevision,
    files: &BTreeMap<String, Vec<u8>>,
) -> SoftwareGraph {
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for (path, contents) in files {
        if validate_path(path).is_err() || contents.len() > MAX_GRAPH_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::str::from_utf8(contents) else {
            continue;
        };
        let language = language_for(path);
        if language == Language::Unknown {
            continue;
        }
        let file_id = graph_token(&format!("file:{path}"));
        if file_id.is_empty() {
            continue;
        }
        nodes.insert(SoftwareNode {
            id: file_id.clone(),
            kind: "file".to_owned(),
            path: path.clone(),
            label: file_label(path),
        });
        for symbol in extract_symbols(language, path, text) {
            if !nodes.iter().any(|node| node.id == symbol.node.id) {
                edges.insert(SoftwareEdge {
                    source: file_id.clone(),
                    target: symbol.node.id.clone(),
                    kind: symbol.edge_kind,
                });
                nodes.insert(symbol.node);
            }
        }
    }
    if nodes.is_empty() {
        if let Some(path) = files.keys().find(|path| validate_path(path).is_ok()) {
            nodes.insert(SoftwareNode {
                id: graph_token(&format!("file:{path}")),
                kind: "file".to_owned(),
                path: path.clone(),
                label: file_label(path),
            });
        } else {
            nodes.insert(SoftwareNode {
                id: "file:root".to_owned(),
                kind: "file".to_owned(),
                path: "README.md".to_owned(),
                label: "root".to_owned(),
            });
        }
    }
    SoftwareGraph {
        schema_version: "v1".to_owned(),
        revision,
        analyzer_digest: digest_bytes(ANALYZER_SEED),
        nodes: nodes.into_iter().collect(),
        edges: edges.into_iter().collect(),
    }
}

fn ingest_and_delta(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    base_graph: &SoftwareGraph,
    head_graph: &SoftwareGraph,
) -> Result<GraphDelta, LoomError> {
    let base = admit_graph(store, grant, base_graph)?;
    let head = admit_graph(store, grant, head_graph)?;
    Ok(graph_delta(&base, &head))
}

fn admit_graph(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    graph: &SoftwareGraph,
) -> Result<SoftwareGraph, LoomError> {
    match store.ingest_software_graph(grant, graph.clone()) {
        Ok(()) => Ok(graph.clone()),
        Err(LoomError::GraphConflict { .. }) => store.software_graph(grant, &graph.revision),
        Err(error) => Err(error),
    }
}

fn blast_from_graphs(
    store: &PersistentLoomStore,
    grant: &NamespaceGrant,
    base: &RepositoryRevision,
    head: &RepositoryRevision,
    delta: &GraphDelta,
    diffstat: &DiffStat,
) -> Vec<String> {
    let base_graph = store.software_graph(grant, base).ok();
    let head_graph = store.software_graph(grant, head).ok();
    let Some(head_graph) = head_graph else {
        return Vec::new();
    };
    blast_radius(
        base_graph.as_ref().unwrap_or(&head_graph),
        &head_graph,
        delta,
        &changed_paths(diffstat),
    )
}

fn graph_delta(base: &SoftwareGraph, head: &SoftwareGraph) -> GraphDelta {
    let base_nodes = base
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let head_nodes = head
        .nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let base_edges = edge_keys(base);
    let head_edges = edge_keys(head);
    GraphDelta {
        nodes_added: head_nodes.difference(&base_nodes).cloned().collect(),
        nodes_removed: base_nodes.difference(&head_nodes).cloned().collect(),
        edges_added: u32_count(head_edges.difference(&base_edges).count()),
        edges_removed: u32_count(base_edges.difference(&head_edges).count()),
    }
}

fn blast_radius(
    base: &SoftwareGraph,
    head: &SoftwareGraph,
    delta: &GraphDelta,
    changed_paths: &BTreeSet<String>,
) -> Vec<String> {
    let mut changed = BTreeSet::new();
    changed.extend(delta.nodes_added.iter().cloned());
    changed.extend(delta.nodes_removed.iter().cloned());
    for graph in [base, head] {
        for node in &graph.nodes {
            if changed_paths.contains(&node.path) {
                changed.insert(node.id.clone());
            }
        }
    }
    let mut neighbors = BTreeSet::new();
    for graph in [base, head] {
        for edge in &graph.edges {
            if changed.contains(&edge.source) {
                neighbors.insert(edge.target.clone());
            }
            if changed.contains(&edge.target) {
                neighbors.insert(edge.source.clone());
            }
        }
    }
    for id in &changed {
        neighbors.remove(id);
    }
    neighbors.into_iter().take(MAX_BLAST).collect()
}

fn edge_keys(graph: &SoftwareGraph) -> BTreeSet<(String, String, String)> {
    graph
        .edges
        .iter()
        .map(|edge| (edge.source.clone(), edge.target.clone(), edge.kind.clone()))
        .collect()
}

fn detect_toolchain(
    head_files: &BTreeMap<String, Vec<u8>>,
    base_files: &BTreeMap<String, Vec<u8>>,
) -> String {
    if head_files.contains_key("Cargo.toml") || base_files.contains_key("Cargo.toml") {
        "cargo".to_owned()
    } else if head_files.contains_key("go.mod") || base_files.contains_key("go.mod") {
        "go".to_owned()
    } else if head_files.contains_key("package.json") || base_files.contains_key("package.json") {
        "node".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn diff_trees(
    base_files: &BTreeMap<String, Vec<u8>>,
    head_files: &BTreeMap<String, Vec<u8>>,
) -> DiffStat {
    let mut files_added = 0_u32;
    let mut files_removed = 0_u32;
    let mut files_changed = 0_u32;
    let mut hunks = Vec::new();
    let paths = base_files
        .keys()
        .chain(head_files.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for path in paths {
        let base = base_files.get(&path);
        let head = head_files.get(&path);
        let (added, removed, kind) = match (base, head) {
            (None, Some(head)) => {
                files_added = files_added.saturating_add(1);
                let (added, _) = line_churn(b"", head);
                (added, 0, Some("added"))
            }
            (Some(base), None) => {
                files_removed = files_removed.saturating_add(1);
                let (_, removed) = line_churn(base, b"");
                (0, removed, Some("removed"))
            }
            (Some(base), Some(head)) if base != head => {
                files_changed = files_changed.saturating_add(1);
                let (added, removed) = line_churn(base, head);
                (added, removed, Some("changed"))
            }
            _ => (0, 0, None),
        };
        if kind.is_some() {
            hunks.push(FileHunk {
                path,
                added,
                removed,
            });
        }
    }
    hunks.sort_by(|left, right| left.path.cmp(&right.path));
    hunks.truncate(MAX_HUNKS);
    DiffStat {
        files_added,
        files_removed,
        files_changed,
        hunks,
    }
}

fn line_churn(base: &[u8], head: &[u8]) -> (u32, u32) {
    let Ok(base_text) = std::str::from_utf8(base) else {
        return (u32::from(base != head), 0);
    };
    let Ok(head_text) = std::str::from_utf8(head) else {
        return (1, 0);
    };
    let mut base_counts = BTreeMap::<&str, u32>::new();
    for (index, line) in base_text.lines().enumerate() {
        if index >= MAX_LINE_DIFF_LINES {
            break;
        }
        let count = base_counts.entry(line).or_insert(0);
        *count = count.saturating_add(1);
    }
    let mut added = 0_u32;
    let mut head_counts = BTreeMap::<&str, u32>::new();
    for (index, line) in head_text.lines().enumerate() {
        if index >= MAX_LINE_DIFF_LINES {
            break;
        }
        let count = head_counts.entry(line).or_insert(0);
        *count = count.saturating_add(1);
    }
    for (line, count) in &head_counts {
        let base_count = base_counts.get(line).copied().unwrap_or(0);
        added = added.saturating_add(count.saturating_sub(base_count));
    }
    let mut removed = 0_u32;
    for (line, count) in &base_counts {
        let head_count = head_counts.get(line).copied().unwrap_or(0);
        removed = removed.saturating_add(count.saturating_sub(head_count));
    }
    (added, removed)
}

fn hotspots_from(diffstat: &DiffStat) -> Vec<String> {
    let mut ranked = diffstat
        .hunks
        .iter()
        .map(|hunk| (hunk.added.saturating_add(hunk.removed), hunk.path.clone()))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    ranked
        .into_iter()
        .take(MAX_HOTSPOTS)
        .map(|(_, path)| path)
        .collect()
}

fn changed_paths(diffstat: &DiffStat) -> BTreeSet<String> {
    diffstat
        .hunks
        .iter()
        .map(|hunk| hunk.path.clone())
        .collect()
}

fn lsp_delta(
    toolchain: &str,
    base_files: &BTreeMap<String, Vec<u8>>,
    head_files: &BTreeMap<String, Vec<u8>>,
    changed: &BTreeSet<String>,
) -> DiagnosticsDelta {
    let server = match toolchain {
        "cargo" => "rust-analyzer",
        "go" => "gopls",
        "node" => "typescript-language-server",
        _ => {
            return skipped_diagnostics("lsp: skipped");
        }
    };
    if !language_server_ready(server) {
        return skipped_diagnostics("lsp: skipped");
    }
    match collect_lsp_delta(server, base_files, head_files, changed) {
        Ok(delta) => delta,
        Err(_) => skipped_diagnostics("lsp: skipped"),
    }
}

fn skipped_diagnostics(reason: &str) -> DiagnosticsDelta {
    DiagnosticsDelta {
        introduced: Vec::new(),
        fixed: Vec::new(),
        skipped: Some(reason.to_owned()),
    }
}

fn language_server_ready(server: &str) -> bool {
    if server.contains('/') || server.contains('\\') {
        return false;
    }
    let Ok((ok, _)) = crate::ci::execute_command(
        Path::new("/"),
        &[server.to_owned(), "--version".to_owned()],
        Duration::from_secs(2),
    ) else {
        return false;
    };
    ok
}

fn collect_lsp_delta(
    server: &str,
    base_files: &BTreeMap<String, Vec<u8>>,
    head_files: &BTreeMap<String, Vec<u8>>,
    changed: &BTreeSet<String>,
) -> Result<DiagnosticsDelta, LoomError> {
    let base = collect_lsp(server, base_files, changed)?;
    let head = collect_lsp(server, head_files, changed)?;
    let base_set = base.into_iter().collect::<BTreeSet<_>>();
    let head_set = head.into_iter().collect::<BTreeSet<_>>();
    Ok(DiagnosticsDelta {
        introduced: head_set.difference(&base_set).cloned().collect(),
        fixed: base_set.difference(&head_set).cloned().collect(),
        skipped: None,
    })
}

fn collect_lsp(
    server: &str,
    files: &BTreeMap<String, Vec<u8>>,
    changed: &BTreeSet<String>,
) -> Result<Vec<Diagnostic>, LoomError> {
    let workspace = tempfile::tempdir().map_err(|_| LoomError::StorageUnavailable)?;
    write_changed_tree(workspace.path(), files, changed)?;
    let mut diagnostics = Vec::new();
    for path in changed {
        if !files.contains_key(path) {
            continue;
        }
        let output = match server {
            "gopls" => run_ls(
                workspace.path(),
                &[
                    "gopls".to_owned(),
                    "check".to_owned(),
                    path.replace('/', std::path::MAIN_SEPARATOR_STR),
                ],
            )?,
            "typescript-language-server" => {
                run_ls(
                    workspace.path(),
                    &[
                        "typescript-language-server".to_owned(),
                        "--stdio".to_owned(),
                    ],
                )?;
                String::new()
            }
            "rust-analyzer" => run_ls(
                workspace.path(),
                &["rust-analyzer".to_owned(), "diagnostics".to_owned()],
            )?,
            _ => String::new(),
        };
        diagnostics.extend(parse_diagnostic_lines(path, &output));
    }
    Ok(diagnostics)
}

fn run_ls(cwd: &Path, command: &[String]) -> Result<String, LoomError> {
    crate::ci::execute_command(cwd, command, LSP_TIMEOUT).map(|(_, output)| output)
}

fn parse_diagnostic_lines(path: &str, output: &str) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for line in output.lines().take(64) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let severity = if trimmed.contains("error") {
            "error"
        } else if trimmed.contains("warning") {
            "warning"
        } else {
            continue;
        };
        diagnostics.push(Diagnostic {
            path: path.to_owned(),
            line: 0,
            severity: severity.to_owned(),
            message: trimmed.chars().take(256).collect(),
        });
    }
    diagnostics
}

fn write_changed_tree(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    changed: &BTreeSet<String>,
) -> Result<(), LoomError> {
    for path in changed {
        let Some(contents) = files.get(path) else {
            continue;
        };
        let destination = root.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|_| LoomError::StorageUnavailable)?;
        }
        fs::write(&destination, contents).map_err(|_| LoomError::StorageUnavailable)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Rust,
    Go,
    JavaScript,
    Unknown,
}

struct ExtractedSymbol {
    node: SoftwareNode,
    edge_kind: String,
}

fn language_for(path: &str) -> Language {
    match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
    {
        "rs" => Language::Rust,
        "go" => Language::Go,
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
        _ => Language::Unknown,
    }
}

fn extract_symbols(language: Language, path: &str, text: &str) -> Vec<ExtractedSymbol> {
    match language {
        Language::Rust => extract_rust(path, text),
        Language::Go => extract_go(path, text),
        Language::JavaScript => extract_js(path, text),
        Language::Unknown => Vec::new(),
    }
}

fn extract_rust(path: &str, text: &str) -> Vec<ExtractedSymbol> {
    let mut symbols = Vec::new();
    for line in text.lines() {
        let stripped = strip_visibility(line.trim_start());
        if let Some(name) = keyword_ident(stripped, "fn") {
            symbols.push(symbol_node(path, "fn", &name, "defines"));
        } else if let Some(name) = keyword_ident(stripped, "struct") {
            symbols.push(symbol_node(path, "struct", &name, "defines"));
        } else if let Some(name) = keyword_ident(stripped, "enum") {
            symbols.push(symbol_node(path, "enum", &name, "defines"));
        } else if let Some(name) = keyword_ident(stripped, "mod") {
            symbols.push(symbol_node(path, "mod", &name, "defines"));
        } else if let Some(import) = rust_use(stripped) {
            symbols.push(symbol_node(path, "use", &import, "imports"));
        }
    }
    symbols
}

fn extract_go(path: &str, text: &str) -> Vec<ExtractedSymbol> {
    let mut symbols = Vec::new();
    let mut in_import = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if in_import {
            if trimmed.starts_with(')') {
                in_import = false;
                continue;
            }
            if let Some(import) = go_import_path(trimmed) {
                symbols.push(symbol_node(path, "import", &import, "imports"));
            }
            continue;
        }
        if trimmed == "import (" {
            in_import = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("import ") {
            if let Some(import) = go_import_path(rest) {
                symbols.push(symbol_node(path, "import", &import, "imports"));
            }
        } else if let Some(name) = go_func(trimmed) {
            symbols.push(symbol_node(path, "func", &name, "defines"));
        } else if let Some(name) = keyword_ident(trimmed, "type") {
            symbols.push(symbol_node(path, "type", &name, "defines"));
        }
    }
    symbols
}

fn extract_js(path: &str, text: &str) -> Vec<ExtractedSymbol> {
    let mut symbols = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(name) = js_import(trimmed) {
            symbols.push(symbol_node(path, "import", &name, "imports"));
        } else if let Some(name) =
            keyword_ident(trimmed, "function").or_else(|| keyword_ident(trimmed, "export function"))
        {
            symbols.push(symbol_node(path, "function", &name, "defines"));
        } else if let Some(name) =
            keyword_ident(trimmed, "class").or_else(|| keyword_ident(trimmed, "export class"))
        {
            symbols.push(symbol_node(path, "class", &name, "defines"));
        } else if let Some(name) = js_export(trimmed) {
            symbols.push(symbol_node(path, "export", &name, "defines"));
        }
    }
    symbols
}

fn strip_visibility(line: &str) -> &str {
    let without_pub = match line.strip_prefix("pub") {
        None => line,
        Some(rest) => {
            let rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix('(')
                && let Some(end) = after.find(')')
            {
                after[end.saturating_add(1)..].trim_start()
            } else {
                rest
            }
        }
    };
    without_pub
        .strip_prefix("async")
        .map(str::trim_start)
        .filter(|rest| rest.starts_with("fn") || rest.starts_with("move"))
        .unwrap_or(without_pub)
}

fn keyword_ident(line: &str, keyword: &str) -> Option<String> {
    let rest = line.strip_prefix(keyword)?;
    if !rest.starts_with(|byte: char| byte.is_ascii_whitespace() || byte == '(') {
        return None;
    }
    let rest = rest.trim_start_matches(|byte: char| byte.is_ascii_whitespace() || byte == '(');
    let name = rest
        .split(|byte: char| !byte.is_ascii_alphanumeric() && byte != '_')
        .next()
        .unwrap_or("");
    (!name.is_empty()).then(|| name.to_owned())
}

fn rust_use(line: &str) -> Option<String> {
    let rest = line.strip_prefix("use ")?;
    let token = rest
        .split([';', '{', ' '])
        .next()
        .unwrap_or("")
        .trim_end_matches("::");
    let sanitized = graph_token(token);
    (!sanitized.is_empty()).then_some(sanitized)
}

fn go_func(line: &str) -> Option<String> {
    let rest = line.strip_prefix("func ")?;
    let rest = if rest.starts_with('(') {
        rest.split_once(')')?.1.trim_start()
    } else {
        rest
    };
    let name = rest
        .split(|byte: char| !byte.is_ascii_alphanumeric() && byte != '_')
        .next()
        .unwrap_or("");
    (!name.is_empty()).then(|| name.to_owned())
}

fn go_import_path(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let inner = line.get(start.saturating_add(1)..)?;
    let end = inner.find('"')?;
    let sanitized = graph_token(&inner[..end]);
    (!sanitized.is_empty()).then_some(sanitized)
}

fn js_import(line: &str) -> Option<String> {
    let rest = line.strip_prefix("import ")?;
    if let Some(from) = rest.split(" from ").nth(1) {
        let token = from
            .trim()
            .trim_matches(|byte| matches!(byte, '"' | '\'' | ';' | ' '));
        let sanitized = graph_token(token);
        return (!sanitized.is_empty()).then_some(sanitized);
    }
    let token = rest
        .trim()
        .trim_matches(|byte| matches!(byte, '"' | '\'' | ';' | ' '));
    let sanitized = graph_token(token);
    (!sanitized.is_empty()).then_some(sanitized)
}

fn js_export(line: &str) -> Option<String> {
    let rest = line.strip_prefix("export ")?;
    if rest.starts_with("function") || rest.starts_with("class") {
        return None;
    }
    let name = rest
        .split(|byte: char| !byte.is_ascii_alphanumeric() && byte != '_')
        .find(|part| {
            !part.is_empty() && *part != "default" && *part != "const" && *part != "let"
        })?;
    Some((*name).to_owned())
}

fn symbol_node(path: &str, kind: &str, name: &str, edge_kind: &str) -> ExtractedSymbol {
    let label = if name.is_empty() { kind } else { name };
    let id = graph_token(&format!("{path}:{kind}:{label}"));
    ExtractedSymbol {
        node: SoftwareNode {
            id,
            kind: kind.to_owned(),
            path: path.to_owned(),
            label: label.chars().take(512).collect(),
        },
        edge_kind: edge_kind.to_owned(),
    }
}

fn graph_token(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, '-' | '_' | '.' | ':' | '/') {
                byte
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if valid_graph_token(trimmed, 256) {
        trimmed.to_owned()
    } else {
        trimmed.chars().take(256).collect()
    }
}

fn file_label(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("file")
        .to_owned()
}

fn placeholder_revision(repository: &str, revision: &str) -> RepositoryRevision {
    if let Ok(parsed) = RepositoryRevision::new(repository, revision) {
        return parsed;
    }
    RepositoryRevision {
        repository: repository.to_owned(),
        revision: digest_bytes(revision.as_bytes()).value,
    }
}

/// Builds a v1 insights bundle without persisting it (harness / runner use).
#[must_use]
pub fn seal_standalone(source_key: String, repos: Vec<RepoInsights>) -> InsightsBundle {
    seal_bundle(source_key, repos, None)
}

fn seal_bundle(
    source_key: String,
    repos: Vec<RepoInsights>,
    error: Option<String>,
) -> InsightsBundle {
    let fingerprint = BundleFingerprint {
        schema_version: "v1",
        source_key: &source_key,
        repos: &repos,
        error: &error,
    };
    let encoded =
        serde_json::to_vec(&fingerprint).unwrap_or_else(|_| source_key.as_bytes().to_vec());
    InsightsBundle {
        schema_version: "v1".to_owned(),
        digest: digest_bytes(&encoded),
        source_key,
        repos,
        error,
    }
}

fn collect_tree(
    root: &Path,
    current: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), LoomError> {
    if files.len() > 10_000 {
        return Err(LoomError::ResourceLimit);
    }
    let entries = fs::read_dir(current).map_err(|_| LoomError::StorageUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| LoomError::StorageUnavailable)?;
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|_| LoomError::StorageUnavailable)?;
        if metadata.is_dir() {
            collect_tree(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LoomError::InvalidPath {
                path: path.display().to_string(),
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if validate_path(&relative).is_err() {
            continue;
        }
        let bytes = fs::read(&path).map_err(|_| LoomError::StorageUnavailable)?;
        files.insert(relative, bytes);
    }
    Ok(())
}

fn ensure_insights_directory(path: &Path) -> Result<(), LoomError> {
    if path.exists() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| LoomError::StorageUnavailable)
}

fn u32_count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn unknown_insights(id: &str) -> LoomError {
    LoomError::UnknownRevision {
        repository: "insights".to_owned(),
        revision: id.to_owned(),
    }
}

/// Analyzer digest used for every v1 insights software graph.
#[must_use]
pub fn analyzer_digest() -> ArtifactDigest {
    digest_bytes(ANALYZER_SEED)
}

/// Language server binary name for a detected toolchain, if any.
#[must_use]
pub fn language_server_for(toolchain: &str) -> Option<&'static str> {
    match toolchain {
        "cargo" => Some("rust-analyzer"),
        "go" => Some("gopls"),
        "node" => Some("typescript-language-server"),
        _ => None,
    }
}

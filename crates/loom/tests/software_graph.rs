//! Revision-scoped software graph persistence and validation.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use loom::{
    LoomError, NamespaceGrant, PersistentLoomStore, SoftwareEdge, SoftwareGraph, SoftwareNode,
};

fn graph(revision: loom::contracts::RepositoryRevision) -> SoftwareGraph {
    SoftwareGraph {
        schema_version: "v1".to_owned(),
        revision,
        analyzer_digest: loom::contracts::ArtifactDigest::sha256("a".repeat(64)).unwrap(),
        nodes: vec![
            SoftwareNode {
                id: "crate:grid-loom".to_owned(),
                kind: "rust_crate".to_owned(),
                path: "crates/loom/Cargo.toml".to_owned(),
                label: "grid-loom".to_owned(),
            },
            SoftwareNode {
                id: "crate:grid-contracts".to_owned(),
                kind: "rust_crate".to_owned(),
                path: "crates/grid-contracts/Cargo.toml".to_owned(),
                label: "grid-contracts".to_owned(),
            },
        ],
        edges: vec![SoftwareEdge {
            source: "crate:grid-loom".to_owned(),
            target: "crate:grid-contracts".to_owned(),
            kind: "depends_on".to_owned(),
        }],
    }
}

fn committed_store() -> (
    tempfile::TempDir,
    PersistentLoomStore,
    NamespaceGrant,
    loom::contracts::RepositoryRevision,
) {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let revision = store
        .commit(
            &grant,
            "grid",
            None,
            BTreeMap::from([("Cargo.toml".to_owned(), b"[workspace]".to_vec())]),
        )
        .unwrap();
    (directory, store, grant, revision)
}

#[test]
fn graph_is_revision_scoped_immutable_and_restart_safe() {
    let (directory, store, grant, revision) = committed_store();
    let expected = graph(revision.clone());
    store
        .ingest_software_graph(&grant, expected.clone())
        .unwrap();
    assert_eq!(store.software_graph(&grant, &revision).unwrap(), expected);
    drop(store);

    let restarted = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    assert_eq!(
        restarted.software_graph(&grant, &revision).unwrap(),
        expected
    );
}

#[test]
fn exact_replay_is_idempotent_but_conflicting_graph_is_rejected() {
    let (_directory, store, grant, revision) = committed_store();
    let expected = graph(revision.clone());
    store
        .ingest_software_graph(&grant, expected.clone())
        .unwrap();
    store
        .ingest_software_graph(&grant, expected.clone())
        .unwrap();

    let mut conflicting = expected;
    conflicting.nodes[0].label = "changed".to_owned();
    assert!(matches!(
        store.ingest_software_graph(&grant, conflicting),
        Err(LoomError::GraphConflict { .. })
    ));
}

#[test]
fn ingestion_rejects_unknown_revisions_dangling_edges_and_unsafe_paths() {
    let (_directory, store, grant, revision) = committed_store();

    let mut dangling = graph(revision.clone());
    dangling.edges[0].target = "crate:missing".to_owned();
    assert!(matches!(
        store.ingest_software_graph(&grant, dangling),
        Err(LoomError::InvalidSoftwareGraph)
    ));

    let mut unsafe_path = graph(revision.clone());
    unsafe_path.nodes[0].path = "../Cargo.toml".to_owned();
    assert!(matches!(
        store.ingest_software_graph(&grant, unsafe_path),
        Err(LoomError::InvalidSoftwareGraph)
    ));

    let unknown = loom::contracts::RepositoryRevision::new("grid", "b".repeat(64)).unwrap();
    assert!(matches!(
        store.ingest_software_graph(&grant, graph(unknown)),
        Err(LoomError::UnknownRevision { .. })
    ));
}

#[test]
fn namespace_grants_protect_graph_reads_and_writes() {
    let (_directory, store, grant, revision) = committed_store();
    let denied = NamespaceGrant::new(BTreeSet::from(["grid-control".to_owned()]));
    assert!(matches!(
        store.ingest_software_graph(&denied, graph(revision.clone())),
        Err(LoomError::NamespaceDenied { .. })
    ));
    store
        .ingest_software_graph(&grant, graph(revision.clone()))
        .unwrap();
    assert!(matches!(
        store.software_graph(&denied, &revision),
        Err(LoomError::NamespaceDenied { .. })
    ));
}

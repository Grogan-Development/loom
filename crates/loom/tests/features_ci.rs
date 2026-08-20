//! Feature contracts and lightning CI replace pull requests.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use loom::ci::CiEngine;
use loom::contracts::{RepositoryBinding, RepositoryRevision};
use loom::features::{
    CandidateSubmit, EvidencePolicy, FeatureCreate, FeatureGate, FeatureStore, Scenario,
    promotion_updates,
};
use loom::{NamespaceGrant, PersistentLoomStore};

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

fn store() -> (tempfile::TempDir, PersistentLoomStore, NamespaceGrant) {
    let directory = tempfile::tempdir().unwrap();
    let store = PersistentLoomStore::open(directory.path().join("loom")).unwrap();
    let grant = NamespaceGrant::new(BTreeSet::from(["demo".to_owned()]));
    (directory, store, grant)
}

#[test]
fn feature_two_gate_promote_is_atomic_and_reversible() {
    let (_directory, store, grant) = store();
    let base = store
        .commit(
            &grant,
            "demo",
            None,
            files(&[
                ("README.md", b"# demo\n"),
                (
                    "loom-ci.toml",
                    b"[ci]\ntimeout_seconds = 5\ncommands = [[\"true\"]]\n",
                ),
            ]),
        )
        .unwrap();
    let head = store
        .commit(
            &grant,
            "demo",
            Some(&base),
            files(&[("README.md", b"# demo candidate\n")]),
        )
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();

    let features = FeatureStore::new(store.clone());
    let feature = features
        .create(FeatureCreate {
            title: "ship candidate".to_owned(),
            repositories: vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned())],
            scenarios: vec![Scenario {
                name: "readme exists".to_owned(),
                given: "a repository".to_owned(),
                when: "the candidate is promoted".to_owned(),
                then: "refs/main moves".to_owned(),
            }],
            evidence_policy: EvidencePolicy::minimum(),
        })
        .unwrap();
    assert_eq!(feature.gate, FeatureGate::Draft);
    let feature = features.approve(&feature.id).unwrap();
    assert_eq!(feature.gate, FeatureGate::Approved);

    let bindings =
        vec![RepositoryBinding::new(base.clone(), "refs/main".to_owned()).with_head(head.clone())];
    let ci = CiEngine::new(store.clone());
    let job = ci.run(&feature.id, &bindings).unwrap();
    let candidate = ci.candidate_from_job(&job, bindings.clone()).unwrap();
    features.attach_candidate(&feature.id, candidate).unwrap();

    let updates = promotion_updates(&bindings).unwrap();
    let rollback = store.compare_and_swap_refs(&grant, &updates).unwrap();
    assert_eq!(
        store.resolve_ref(&grant, "demo", "refs/main").unwrap(),
        head
    );
    features.accept(&feature.id, rollback.clone()).unwrap();
    store.compare_and_swap_refs(&grant, &rollback).unwrap();
    assert_eq!(
        store.resolve_ref(&grant, "demo", "refs/main").unwrap(),
        base
    );
}

#[test]
fn lightning_ci_replays_the_same_source_digest() {
    let (_directory, store, grant) = store();
    let base = store
        .commit(
            &grant,
            "demo",
            None,
            files(&[
                ("README.md", b"ok\n"),
                (
                    "loom-ci.toml",
                    b"[ci]\ntimeout_seconds = 5\ncommands = [[\"true\"]]\n",
                ),
            ]),
        )
        .unwrap();
    store
        .create_ref(&grant, "demo", "refs/main", &base)
        .unwrap();
    let head = store
        .commit(
            &grant,
            "demo",
            Some(&base),
            files(&[("README.md", b"ok2\n")]),
        )
        .unwrap();
    let bindings = vec![RepositoryBinding::new(base, "refs/main".to_owned()).with_head(head)];
    let ci = CiEngine::new(store);
    let first = ci.run("feature", &bindings).unwrap();
    let second = ci.run("feature", &bindings).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.status, second.status);
}

#[test]
fn candidate_submit_shape_requires_heads() {
    let revision = RepositoryRevision::new("demo", "a".repeat(64)).unwrap();
    let request = CandidateSubmit {
        repositories: vec![RepositoryBinding::new(revision, "refs/main".to_owned())],
    };
    assert!(request.repositories[0].head.is_none());
}

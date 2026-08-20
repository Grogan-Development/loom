//! Loom storage and promotion properties.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use loom::{LoomError, LoomStore, NamespaceGrant, RefCasUpdate};

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

#[test]
fn cas_deduplicates_and_materialization_is_immutable() {
    let mut loom = LoomStore::new();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let first = loom
        .commit(&grant, "grid", None, files(&[("README.md", b"Grid\n")]))
        .unwrap();
    let second = loom
        .commit(&grant, "grid", Some(&first), BTreeMap::new())
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(loom.object_count(), 1);
    assert_eq!(
        loom.materialize(&grant, &first).unwrap()["README.md"],
        b"Grid\n"
    );

    loom.commit(
        &grant,
        "grid",
        Some(&first),
        files(&[("README.md", b"Grid changed\n")]),
    )
    .unwrap();
    assert_eq!(
        loom.materialize(&grant, &first).unwrap()["README.md"],
        b"Grid\n"
    );
}

#[test]
fn namespace_isolation_fails_closed() {
    let mut loom = LoomStore::new();
    let grid_only = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let result = loom.commit(
        &grid_only,
        "grid-infrastructure",
        None,
        files(&[("README.md", b"infra")]),
    );
    assert!(matches!(result, Err(LoomError::NamespaceDenied { .. })));
}

#[test]
fn protected_ref_compare_and_swap_rejects_races() {
    let mut loom = LoomStore::new();
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let base = loom
        .commit(&grant, "grid", None, files(&[("a", b"one")]))
        .unwrap();
    let head = loom
        .commit(&grant, "grid", Some(&base), files(&[("a", b"two")]))
        .unwrap();
    loom.create_ref(&grant, "grid", "refs/main", &base).unwrap();

    loom.compare_and_swap_refs(
        &grant,
        &[RefCasUpdate::new(
            "grid",
            "refs/main",
            base.clone(),
            head.clone(),
        )],
    )
    .unwrap();
    assert!(matches!(
        loom.compare_and_swap_refs(
            &grant,
            &[RefCasUpdate::new("grid", "refs/main", base, head)]
        ),
        Err(LoomError::RefConflict { .. })
    ));
}

#[test]
fn multi_repository_promotion_is_atomic_and_reversible() {
    let mut loom = LoomStore::new();
    let grant = NamespaceGrant::new(BTreeSet::from([
        "grid".to_owned(),
        "grid-infrastructure".to_owned(),
    ]));
    let grid_base = loom
        .commit(&grant, "grid", None, files(&[("a", b"one")]))
        .unwrap();
    let grid_head = loom
        .commit(&grant, "grid", Some(&grid_base), files(&[("a", b"two")]))
        .unwrap();
    let infra_base = loom
        .commit(&grant, "grid-infrastructure", None, files(&[("b", b"one")]))
        .unwrap();
    let infra_head = loom
        .commit(
            &grant,
            "grid-infrastructure",
            Some(&infra_base),
            files(&[("b", b"two")]),
        )
        .unwrap();
    loom.create_ref(&grant, "grid", "refs/main", &grid_base)
        .unwrap();
    loom.create_ref(&grant, "grid-infrastructure", "refs/main", &infra_base)
        .unwrap();

    let invalid = [
        RefCasUpdate::new("grid", "refs/main", grid_base.clone(), grid_head.clone()),
        RefCasUpdate::new(
            "grid-infrastructure",
            "refs/main",
            grid_base.clone(),
            infra_head.clone(),
        ),
    ];
    assert!(loom.compare_and_swap_refs(&grant, &invalid).is_err());
    assert_eq!(
        loom.resolve_ref(&grant, "grid", "refs/main").unwrap(),
        grid_base
    );

    let promote = [
        RefCasUpdate::new("grid", "refs/main", grid_base.clone(), grid_head.clone()),
        RefCasUpdate::new(
            "grid-infrastructure",
            "refs/main",
            infra_base.clone(),
            infra_head.clone(),
        ),
    ];
    let rollback = loom.compare_and_swap_refs(&grant, &promote).unwrap();
    loom.compare_and_swap_refs(&grant, &rollback).unwrap();
    assert_eq!(
        loom.resolve_ref(&grant, "grid", "refs/main").unwrap(),
        grid_base
    );
    assert_eq!(
        loom.resolve_ref(&grant, "grid-infrastructure", "refs/main")
            .unwrap(),
        infra_base
    );
}

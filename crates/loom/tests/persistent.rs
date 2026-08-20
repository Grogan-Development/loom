//! ZFS-backed Loom persistence, crash recovery, and promotion properties.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use base64ct::{Base64, Encoding as _};
use loom::contracts::ArtifactDigest;
use loom::{
    LoomError, NamespaceGrant, PersistentLoomStore, RefCasUpdate, SourceCommitMutation,
    SourceCommitRequest, SourceFileMode,
};
use sha2::{Digest as _, Sha256};

fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    entries
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), (*bytes).to_vec()))
        .collect()
}

fn digest(bytes: &[u8]) -> ArtifactDigest {
    let value = Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        });
    ArtifactDigest::sha256(value).unwrap()
}

fn upsert(path: &str, mode: SourceFileMode, contents: &[u8]) -> SourceCommitMutation {
    SourceCommitMutation::Upsert {
        path: path.to_owned(),
        mode,
        digest: digest(contents),
        contents_base64: Base64::encode_string(contents),
    }
}

#[test]
fn revisions_refs_atomic_promotion_and_rollback_survive_process_restart() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let grant = NamespaceGrant::new(BTreeSet::from([
        "grid".to_owned(),
        "grid-infrastructure".to_owned(),
    ]));
    let loom = PersistentLoomStore::open(&root).unwrap();
    let grid_base = loom
        .commit(&grant, "grid", None, files(&[("README.md", b"base")]))
        .unwrap();
    let grid_head = loom
        .commit(
            &grant,
            "grid",
            Some(&grid_base),
            files(&[("README.md", b"head")]),
        )
        .unwrap();
    let infra_base = loom
        .commit(
            &grant,
            "grid-infrastructure",
            None,
            files(&[("README.md", b"infra-base")]),
        )
        .unwrap();
    let infra_head = loom
        .commit(
            &grant,
            "grid-infrastructure",
            Some(&infra_base),
            files(&[("README.md", b"infra-head")]),
        )
        .unwrap();
    loom.create_ref(&grant, "grid", "refs/main", &grid_base)
        .unwrap();
    loom.create_ref(&grant, "grid-infrastructure", "refs/main", &infra_base)
        .unwrap();
    drop(loom);

    let restarted = PersistentLoomStore::open(&root).unwrap();
    assert_eq!(
        restarted.materialize(&grant, &grid_base).unwrap()["README.md"],
        b"base"
    );
    let rollback = restarted
        .compare_and_swap_refs(
            &grant,
            &[
                RefCasUpdate::new("grid", "refs/main", grid_base.clone(), grid_head.clone()),
                RefCasUpdate::new(
                    "grid-infrastructure",
                    "refs/main",
                    infra_base.clone(),
                    infra_head.clone(),
                ),
            ],
        )
        .unwrap();
    assert_eq!(
        restarted.resolve_ref(&grant, "grid", "refs/main").unwrap(),
        grid_head
    );
    drop(restarted);

    let restarted = PersistentLoomStore::open(&root).unwrap();
    restarted.compare_and_swap_refs(&grant, &rollback).unwrap();
    assert_eq!(
        restarted.resolve_ref(&grant, "grid", "refs/main").unwrap(),
        grid_base
    );
    assert_eq!(
        restarted
            .resolve_ref(&grant, "grid-infrastructure", "refs/main")
            .unwrap(),
        infra_base
    );
}

#[test]
fn native_source_commit_applies_modes_and_deletions_from_one_exact_base() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let loom = PersistentLoomStore::open(&root).unwrap();
    let base = loom
        .commit(
            &grant,
            "grid",
            None,
            files(&[("README.md", b"base"), ("src/lib.rs", b"pub fn base() {}")]),
        )
        .unwrap();
    let request = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base: base.clone(),
        mutations: vec![
            SourceCommitMutation::Delete {
                path: "README.md".to_owned(),
            },
            upsert("bin/check", SourceFileMode::Executable, b"#!/bin/sh\n"),
            upsert("current", SourceFileMode::Symlink, b"src/lib.rs"),
        ],
    };

    let result = loom.commit_source_changes(&grant, &request).unwrap();
    assert_eq!(result.schema_version, "v1");
    assert_eq!(result.base, base);
    assert_eq!(result.head.repository, "grid");
    assert_eq!(result.mutation_count, 3);
    let source = loom.materialize_source(&grant, &result.head).unwrap();
    assert!(!source.contains_key("README.md"));
    assert_eq!(source["src/lib.rs"].mode, SourceFileMode::Regular);
    assert_eq!(source["bin/check"].mode, SourceFileMode::Executable);
    assert_eq!(source["bin/check"].contents, b"#!/bin/sh\n");
    assert_eq!(source["current"].mode, SourceFileMode::Symlink);
    assert_eq!(source["current"].contents, b"src/lib.rs");
}

#[test]
fn native_source_commit_is_restart_idempotent_and_fails_closed_on_authority_and_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let grid_grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let denied_grant = NamespaceGrant::new(BTreeSet::from(["other".to_owned()]));
    let loom = PersistentLoomStore::open(&root).unwrap();
    let base = loom
        .commit(&grid_grant, "grid", None, files(&[("README.md", b"base")]))
        .unwrap();
    let request = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base: base.clone(),
        mutations: vec![upsert("README.md", SourceFileMode::Regular, b"candidate")],
    };
    assert!(matches!(
        loom.commit_source_changes(&denied_grant, &request),
        Err(LoomError::NamespaceDenied { .. })
    ));
    let first = loom.commit_source_changes(&grid_grant, &request).unwrap();
    drop(loom);
    let restarted = PersistentLoomStore::open(&root).unwrap();
    let replay = restarted
        .commit_source_changes(&grid_grant, &request)
        .unwrap();
    assert_eq!(replay, first);

    let too_many = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base: base.clone(),
        mutations: (0..=10_000)
            .map(|index| SourceCommitMutation::Delete {
                path: format!("deleted/{index:05}"),
            })
            .collect(),
    };
    assert!(matches!(
        restarted.commit_source_changes(&grid_grant, &too_many),
        Err(LoomError::ResourceLimit)
    ));

    let oversized = vec![b'x'; 16 * 1024 * 1024 + 1];
    let too_large = SourceCommitRequest {
        schema_version: "v1".to_owned(),
        base,
        mutations: vec![upsert("large.bin", SourceFileMode::Regular, &oversized)],
    };
    assert!(matches!(
        restarted.commit_source_changes(&grid_grant, &too_large),
        Err(LoomError::ResourceLimit)
    ));
}

#[test]
fn separate_process_handles_serialize_ref_cas_and_reject_stale_writers() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let first = PersistentLoomStore::open(&root).unwrap();
    let base = first
        .commit(&grant, "grid", None, files(&[("a", b"base")]))
        .unwrap();
    let head = first
        .commit(&grant, "grid", Some(&base), files(&[("a", b"head")]))
        .unwrap();
    let competing_head = first
        .commit(&grant, "grid", Some(&base), files(&[("a", b"competing")]))
        .unwrap();
    first
        .create_ref(&grant, "grid", "refs/main", &base)
        .unwrap();
    let second = PersistentLoomStore::open(&root).unwrap();
    first
        .compare_and_swap_refs(
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
        second.compare_and_swap_refs(
            &grant,
            &[RefCasUpdate::new("grid", "refs/main", base, competing_head,)]
        ),
        Err(LoomError::RefConflict { .. })
    ));
}

#[test]
fn replay_after_an_unknown_ack_returns_the_same_exact_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("loom");
    let grant = NamespaceGrant::new(BTreeSet::from(["grid".to_owned()]));
    let loom = PersistentLoomStore::open(&root).unwrap();
    let base = loom
        .commit(&grant, "grid", None, files(&[("a", b"base")]))
        .unwrap();
    let head = loom
        .commit(&grant, "grid", Some(&base), files(&[("a", b"head")]))
        .unwrap();
    loom.create_ref(&grant, "grid", "refs/main", &base).unwrap();
    let request = vec![RefCasUpdate::new(
        "grid",
        "refs/main",
        base.clone(),
        head.clone(),
    )];

    let first = loom.compare_and_swap_refs(&grant, &request).unwrap();
    let replay = loom.compare_and_swap_refs(&grant, &request).unwrap();

    assert_eq!(replay, first);
    assert_eq!(replay[0].expected, head);
    assert_eq!(replay[0].head, base);
}

#[test]
fn persistent_root_permissions_paths_and_cas_corruption_fail_closed() {
    assert!(matches!(
        PersistentLoomStore::open("relative/loom"),
        Err(LoomError::InvalidRoot)
    ));
    let directory = tempfile::tempdir().unwrap();
    let unsafe_root = directory.path().join("unsafe");
    fs::create_dir(&unsafe_root).unwrap();
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        PersistentLoomStore::open(&unsafe_root),
        Err(LoomError::UnsafeRootPermissions)
    ));
}

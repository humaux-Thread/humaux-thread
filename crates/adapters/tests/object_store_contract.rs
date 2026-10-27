//! `adapters::tests::object_store_contract` — G-M17-8 (C-M17-2): the `ObjectStore` contract suite, run against the fs
//!   impl, plus the fs-only confinement cases.
//! Depends-on: crates=[humaux-adapters, uuid]; services=[]; env=[]; modules=[adapters::object_store,
//!   adapters::object_store::fs]
//! Called-by: [cargo-test]
//! Invariants: [`contract_suite` is generic over the port so a later S3 impl reuses it unchanged; it covers round trip,
//!   overwrite, missing keys, idempotent delete, sorted listing at depth, whole-segment prefix matching, delete_prefix
//!   at depth, the key grammar and the temp-prefix shape; every case builds its own random prefixes and the fs store runs
//!   on a unique directory under the OS temp dir that is removed even when an assertion fails]
//! Spec: Baseline §29; §79.1; ADR-0115
//!
//! G-M17-8's injected fault is a `delete_prefix` that skips nested directories: the suite must go red on a derived
//! asset (ADR-0115 D-A keeps pages, embedded images and archive members below the session prefix). The fs-only cases
//! pin the confinement rules: a symlink anywhere on a prefix path or below is refused and never traversed, and staging
//! files are never listed.

use std::io;
use std::path::PathBuf;

use humaux_adapters::object_store::fs::FsObjectStore;
use humaux_adapters::object_store::{
    ObjectKey, ObjectMeta, ObjectPrefix, ObjectStore, temp_prefix,
};
use uuid::Uuid;

/// Objects of one upload session, at depth: the original plus derived pages and archive members.
const SESSION_OBJECTS: [&str; 4] = [
    "original",
    "pages/0001.png",
    "pages/0002.png",
    "archive/inner/a.txt",
];

/// A unique directory under the OS temp dir, removed on drop so a failed assertion cannot leak it.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("humaux-object-store-contract-{}", Uuid::now_v7()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn root(&self) -> PathBuf {
        self.0.join("root")
    }

    fn store(&self) -> FsObjectStore {
        std::fs::create_dir_all(self.root()).unwrap();
        FsObjectStore::new(self.root()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key(text: &str) -> ObjectKey {
    ObjectKey::parse(text).unwrap()
}

fn under(prefix: &ObjectPrefix, rest: &str) -> ObjectKey {
    key(&format!("{}{rest}", prefix.as_str()))
}

fn fresh_prefix() -> ObjectPrefix {
    temp_prefix(Uuid::now_v7(), Uuid::now_v7())
}

/// The sibling session `<session>0` of `session`: a raw string prefix match would swallow it.
fn sibling_session(tenant: Uuid, session: Uuid) -> ObjectPrefix {
    ObjectPrefix::parse(&format!("tmp/{tenant}/{session}0/")).unwrap()
}

fn case_roundtrip<S: ObjectStore>(store: &S) {
    let original = under(&fresh_prefix(), "original");
    store.put(&original, b"hello").unwrap();
    assert_eq!(store.get(&original).unwrap(), Some(b"hello".to_vec()));
    assert_eq!(store.head(&original).unwrap(), Some(ObjectMeta { len: 5 }));
    let empty = under(&fresh_prefix(), "empty");
    store.put(&empty, b"").unwrap();
    assert_eq!(store.get(&empty).unwrap(), Some(Vec::new()));
    assert_eq!(store.head(&empty).unwrap(), Some(ObjectMeta { len: 0 }));
}

fn case_overwrite<S: ObjectStore>(store: &S) {
    let page = under(&fresh_prefix(), "pages/0001.png");
    store.put(&page, b"first").unwrap();
    store.put(&page, b"second, longer").unwrap();
    assert_eq!(store.get(&page).unwrap(), Some(b"second, longer".to_vec()));
    assert_eq!(store.head(&page).unwrap(), Some(ObjectMeta { len: 14 }));
    store.put(&page, b"x").unwrap();
    assert_eq!(store.get(&page).unwrap(), Some(b"x".to_vec()));
    assert_eq!(store.head(&page).unwrap(), Some(ObjectMeta { len: 1 }));
}

fn case_missing<S: ObjectStore>(store: &S) {
    let absent = under(&fresh_prefix(), "never-written");
    assert_eq!(store.get(&absent).unwrap(), None);
    assert_eq!(store.head(&absent).unwrap(), None);
    // The directory part of another key is not an object.
    let prefix = fresh_prefix();
    store.put(&under(&prefix, "dir/leaf"), b"leaf").unwrap();
    assert_eq!(store.get(&under(&prefix, "dir")).unwrap(), None);
    assert_eq!(store.head(&under(&prefix, "dir")).unwrap(), None);
}

fn case_delete_idempotent<S: ObjectStore>(store: &S) {
    let prefix = fresh_prefix();
    let original = under(&prefix, "original");
    let neighbour = under(&prefix, "neighbour");
    let leaf = under(&prefix, "dir/leaf");
    for target in [&original, &neighbour, &leaf] {
        store.put(target, b"data").unwrap();
    }
    store.delete(&original).unwrap();
    assert_eq!(store.get(&original).unwrap(), None);
    store.delete(&original).unwrap();
    store
        .delete(&under(&fresh_prefix(), "never-written"))
        .unwrap();
    // Deleting the directory part of another key removes nothing.
    store.delete(&under(&prefix, "dir")).unwrap();
    assert_eq!(store.get(&neighbour).unwrap(), Some(b"data".to_vec()));
    assert_eq!(store.get(&leaf).unwrap(), Some(b"data".to_vec()));
}

fn case_list_prefix_sorted_at_depth<S: ObjectStore>(store: &S) {
    let (tenant, session) = (Uuid::now_v7(), Uuid::now_v7());
    let prefix = temp_prefix(tenant, session);
    let sibling = sibling_session(tenant, session);
    // Written out of order on purpose.
    for rest in ["pages/0001.png", "original", "archive/inner/a.txt"] {
        store.put(&under(&prefix, rest), rest.as_bytes()).unwrap();
    }
    store.put(&under(&sibling, "original"), b"sibling").unwrap();
    assert_eq!(
        store.list_prefix(&prefix).unwrap(),
        vec![
            under(&prefix, "archive/inner/a.txt"),
            under(&prefix, "original"),
            under(&prefix, "pages/0001.png"),
        ]
    );
    assert_eq!(
        store.list_prefix(&sibling).unwrap(),
        vec![under(&sibling, "original")]
    );
    let pages = ObjectPrefix::parse(&format!("{}pages/", prefix.as_str())).unwrap();
    assert_eq!(
        store.list_prefix(&pages).unwrap(),
        vec![under(&prefix, "pages/0001.png")]
    );
    assert!(store.list_prefix(&fresh_prefix()).unwrap().is_empty());
}

fn case_delete_prefix_at_depth<S: ObjectStore>(store: &S) {
    let (tenant, session) = (Uuid::now_v7(), Uuid::now_v7());
    let prefix = temp_prefix(tenant, session);
    let sibling = sibling_session(tenant, session);
    let other_session = temp_prefix(tenant, Uuid::now_v7());
    for rest in SESSION_OBJECTS {
        store.put(&under(&prefix, rest), rest.as_bytes()).unwrap();
    }
    store.put(&under(&sibling, "original"), b"sibling").unwrap();
    store
        .put(&under(&other_session, "original"), b"other")
        .unwrap();

    assert_eq!(
        store.delete_prefix(&prefix).unwrap(),
        SESSION_OBJECTS.len() as u64
    );
    for rest in SESSION_OBJECTS {
        let survivor = store.get(&under(&prefix, rest)).unwrap();
        assert_eq!(survivor, None, "{rest} survived delete_prefix");
    }
    assert!(store.list_prefix(&prefix).unwrap().is_empty());
    assert_eq!(
        store.get(&under(&sibling, "original")).unwrap(),
        Some(b"sibling".to_vec())
    );
    assert_eq!(
        store.list_prefix(&other_session).unwrap(),
        vec![under(&other_session, "original")]
    );

    assert_eq!(store.delete_prefix(&prefix).unwrap(), 0);
    assert_eq!(store.delete_prefix(&fresh_prefix()).unwrap(), 0);
    store.put(&under(&prefix, "original"), b"again").unwrap();
    assert_eq!(
        store.get(&under(&prefix, "original")).unwrap(),
        Some(b"again".to_vec())
    );
}

fn case_key_grammar() {
    let long_segment = "a".repeat(129);
    let unit = "a".repeat(40);
    let max_key = [unit.as_str(); 25].join("/");
    let over_long = format!("{max_key}b");
    assert_eq!(max_key.len(), 1024);
    assert_eq!(over_long.len(), 1025);
    for bad in [
        "",
        "../x",
        "a/../b",
        "a//b",
        "/a",
        "a/",
        "a/./b",
        ".",
        "..",
        ".hidden",
        "a/.hidden",
        "-lead",
        "_lead",
        "a\\b",
        "a\0b",
        "a b",
        "é",
        long_segment.as_str(),
        over_long.as_str(),
    ] {
        let parsed = ObjectKey::parse(bad);
        assert!(parsed.is_err(), "key {bad:?} must be rejected");
        assert_eq!(parsed.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    let longest_segment = "a".repeat(128);
    for good in [
        "a",
        "a/b",
        "A-b_c.d/E.f",
        "0001.png",
        "tmp/00000000-0000-7000-8000-000000000001/original",
        longest_segment.as_str(),
        max_key.as_str(),
    ] {
        assert_eq!(key(good).as_str(), good);
    }
    for bad in [
        "", "/", "a", "a/b", "a//", "/a/", "../", "a/../", "a/./", ".hidden/", "a\\b/",
    ] {
        let parsed = ObjectPrefix::parse(bad);
        assert!(parsed.is_err(), "prefix {bad:?} must be rejected");
        assert_eq!(parsed.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    for good in ["a/", "tmp/t/s/"] {
        assert_eq!(ObjectPrefix::parse(good).unwrap().as_str(), good);
    }
}

fn case_temp_prefix_shape() {
    let tenant = Uuid::from_u128(0xABCD_EF01_2345_6789_ABCD_EF01_2345_6789);
    let session = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_00AB);
    let prefix = temp_prefix(tenant, session);
    assert_eq!(
        prefix.as_str(),
        "tmp/abcdef01-2345-6789-abcd-ef0123456789/00000000-0000-7000-8000-0000000000ab/"
    );
    assert_eq!(ObjectPrefix::parse(prefix.as_str()).unwrap(), prefix);
}

/// The behaviour every `ObjectStore` implementation must show (G-M17-8).
fn contract_suite<S: ObjectStore>(store: &S) {
    case_roundtrip(store);
    case_overwrite(store);
    case_missing(store);
    case_delete_idempotent(store);
    case_list_prefix_sorted_at_depth(store);
    case_delete_prefix_at_depth(store);
    case_key_grammar();
    case_temp_prefix_shape();
}

#[test]
fn fs_store_passes_the_contract_suite() {
    let scratch = Scratch::new();
    contract_suite(&scratch.store());
}

#[test]
fn new_requires_an_existing_directory() {
    let scratch = Scratch::new();
    let missing = FsObjectStore::new(scratch.0.join("missing")).unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    let file = scratch.0.join("file");
    std::fs::write(&file, b"x").unwrap();
    let not_a_dir = FsObjectStore::new(file).unwrap_err();
    assert_eq!(not_a_dir.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn staging_files_never_appear_in_listings() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let prefix = fresh_prefix();
    let original = under(&prefix, "original");
    store.put(&original, b"data").unwrap();
    let staging = scratch.root().join(".staging");
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    // A crashed put leaves a staged file behind; no listing or purge reaches it.
    std::fs::write(staging.join("leftover"), b"partial").unwrap();
    assert_eq!(store.list_prefix(&prefix).unwrap(), vec![original]);
    assert_eq!(store.delete_prefix(&prefix).unwrap(), 1);
    assert!(staging.join("leftover").exists());
    assert!(ObjectPrefix::parse(".staging/").is_err());
}

#[test]
fn failed_put_leaves_nothing_staged() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let prefix = fresh_prefix();
    let leaf = under(&prefix, "dir/leaf");
    store.put(&leaf, b"leaf").unwrap();
    // `dir` is a directory here, so a file cannot take its place.
    assert!(store.put(&under(&prefix, "dir"), b"x").is_err());
    assert_eq!(
        std::fs::read_dir(scratch.root().join(".staging"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(store.get(&leaf).unwrap(), Some(b"leaf".to_vec()));
}

#[cfg(unix)]
fn assert_refused<T: std::fmt::Debug>(result: io::Result<T>, name: &str) {
    let err = result.expect_err("a symlink must be refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains(name),
        "error must name {name}: {err}"
    );
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_and_nothing_outside_the_root_is_touched() {
    use std::os::unix::fs::symlink;

    let scratch = Scratch::new();
    let store = scratch.store();
    let outside_file = scratch.0.join("outside.txt");
    std::fs::write(&outside_file, b"keep me").unwrap();
    let outside_dir = scratch.0.join("outside-dir");
    std::fs::create_dir(&outside_dir).unwrap();

    let prefix = fresh_prefix();
    let original = under(&prefix, "original");
    store.put(&original, b"orig").unwrap();
    let session_dir = scratch.root().join(prefix.as_str());

    // A symlink to a file outside the root.
    symlink(&outside_file, session_dir.join("escape-file")).unwrap();
    let escape = under(&prefix, "escape-file");
    assert_refused(store.delete_prefix(&prefix), "escape-file");
    assert_refused(store.list_prefix(&prefix), "escape-file");
    assert_refused(store.get(&escape), "escape-file");
    assert_refused(store.head(&escape), "escape-file");
    assert_refused(store.delete(&escape), "escape-file");
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"keep me");
    assert_eq!(store.get(&original).unwrap(), Some(b"orig".to_vec()));
    std::fs::remove_file(session_dir.join("escape-file")).unwrap();

    // A symlink to a directory outside the root, below the prefix.
    std::fs::write(outside_dir.join("inner.txt"), b"keep me too").unwrap();
    symlink(&outside_dir, session_dir.join("escape-dir")).unwrap();
    assert_refused(store.delete_prefix(&prefix), "escape-dir");
    assert_refused(store.list_prefix(&prefix), "escape-dir");
    assert_eq!(
        std::fs::read(outside_dir.join("inner.txt")).unwrap(),
        b"keep me too"
    );
    assert_eq!(store.get(&original).unwrap(), Some(b"orig".to_vec()));

    // A symlink on the path to the prefix itself.
    let (tenant, session) = (Uuid::now_v7(), Uuid::now_v7());
    std::fs::create_dir(outside_dir.join(session.to_string())).unwrap();
    std::fs::write(
        outside_dir.join(session.to_string()).join("original"),
        b"theirs",
    )
    .unwrap();
    symlink(
        &outside_dir,
        scratch.root().join("tmp").join(tenant.to_string()),
    )
    .unwrap();
    let linked = temp_prefix(tenant, session);
    assert_refused(store.delete_prefix(&linked), &tenant.to_string());
    assert_refused(store.list_prefix(&linked), &tenant.to_string());
    let theirs = outside_dir.join(session.to_string()).join("original");
    assert_eq!(std::fs::read(theirs).unwrap(), b"theirs");
}

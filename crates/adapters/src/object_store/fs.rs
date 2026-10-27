//! `adapters::object_store::fs` — C-M17-2 / ADR-0115 D12: the filesystem `ObjectStore` behind the single-node temp store.
//! Depends-on: crates=[uuid]; services=[]; env=[]; modules=[adapters::object_store]
//! Called-by: [tests]
//! Invariants: [every path is the root joined with validated key segments, so no key can name `.staging` or leave the
//!   root; list_prefix and delete_prefix refuse a symlink or special file at any step of the prefix path or below, and
//!   get, head and delete as the final component, with an InvalidData error naming it, and never traverse it;
//!   delete_prefix validates the whole tree before it removes anything; put writes a staged file, syncs it and renames
//!   it over the key, so a reader sees the old bytes or the new, and a failed put leaves no staged file behind]
//! Spec: Baseline §29; ADR-0115
//!
//! D12: the temp store is this implementation on a single node, never backed up; the S3 impl is deferred. It is NOT a
//! WORM sink: write-once is the future audit adapter's job, and this type must not be wired to audit export.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{ObjectKey, ObjectMeta, ObjectPrefix, ObjectStore};

/// Directory under the root that holds in-flight `put` files. A dot-name is never a valid key segment, so no key can
/// collide with it and `list_prefix` never reaches it.
const STAGING_DIR: &str = ".staging";

/// [`ObjectStore`] over a directory tree: key `a/b/c` is the file `<root>/a/b/c`. One existing directory is the root;
/// a key and a longer key that extends it as a directory (`a` and `a/b`) cannot coexist, the second `put` fails.
// ponytail: put/get/head/delete follow symlinked directories above the final path component (only the prefix walkers
// check every step); the root is operator-owned and a symlink inside it is not a supported state; upgrade = step every
// component with symlink_metadata as `prefix_dir` does.
#[derive(Debug, Clone)]
pub struct FsObjectStore {
    root: PathBuf,
}

impl FsObjectStore {
    /// Opens the store at `root`, which must already be a directory; nothing is created here.
    pub fn new(root: PathBuf) -> io::Result<Self> {
        if !fs::metadata(&root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "object store root is not a directory",
            ));
        }
        Ok(Self { root })
    }

    fn key_path(&self, key: &ObjectKey) -> PathBuf {
        self.root.join(key.as_str())
    }

    /// The directory of `prefix`, `None` when it does not exist. Every step is checked without following a symlink.
    fn prefix_dir(&self, prefix: &ObjectPrefix) -> io::Result<Option<PathBuf>> {
        let mut dir = self.root.clone();
        let mut shown = String::new();
        for segment in prefix.as_str().split('/').filter(|s| !s.is_empty()) {
            dir.push(segment);
            shown.push_str(segment);
            shown.push('/');
            match lstat(&dir, &shown)? {
                Some(meta) if meta.is_dir() => {}
                _ => return Ok(None),
            }
        }
        Ok(Some(dir))
    }

    /// Metadata of the regular file at `key`; `None` when nothing, or only a directory, is there.
    fn file_meta(&self, key: &ObjectKey) -> io::Result<Option<fs::Metadata>> {
        Ok(lstat(&self.key_path(key), key.as_str())?.filter(fs::Metadata::is_file))
    }
}

impl ObjectStore for FsObjectStore {
    type Error = io::Error;

    fn put(&self, key: &ObjectKey, bytes: &[u8]) -> io::Result<()> {
        let target = self.key_path(key);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let staging = self.root.join(STAGING_DIR);
        fs::create_dir_all(&staging)?;
        let staged = staging.join(Uuid::now_v7().to_string());
        // ponytail: no directory fsync after rename; temp assets are never backed up (D12), crash = re-upload
        let result = write_synced(&staged, bytes).and_then(|()| fs::rename(&staged, &target));
        if result.is_err() {
            let _ = fs::remove_file(&staged);
        }
        result
    }

    fn get(&self, key: &ObjectKey) -> io::Result<Option<Vec<u8>>> {
        if self.file_meta(key)?.is_none() {
            return Ok(None);
        }
        absent_ok(fs::read(self.key_path(key)))
    }

    fn head(&self, key: &ObjectKey) -> io::Result<Option<ObjectMeta>> {
        Ok(self
            .file_meta(key)?
            .map(|meta| ObjectMeta { len: meta.len() }))
    }

    fn delete(&self, key: &ObjectKey) -> io::Result<()> {
        if self.file_meta(key)?.is_some() {
            absent_ok(fs::remove_file(self.key_path(key)))?;
        }
        Ok(())
    }

    fn delete_prefix(&self, prefix: &ObjectPrefix) -> io::Result<u64> {
        // The listing walks the whole tree first and fails on any symlink, so nothing is removed from a tree we
        // would not fully traverse (ADR-0115 D-G step 6 deletes the live temp prefix).
        let keys = self.list_prefix(prefix)?;
        absent_ok(fs::remove_dir_all(self.root.join(prefix.as_str())))?;
        Ok(keys.len() as u64)
    }

    fn list_prefix(&self, prefix: &ObjectPrefix) -> io::Result<Vec<ObjectKey>> {
        let mut keys = Vec::new();
        if let Some(dir) = self.prefix_dir(prefix)? {
            walk_dir(&dir, prefix.as_str(), &mut keys)?;
        }
        keys.sort();
        Ok(keys)
    }
}

/// Appends the key of every regular file under `dir`; `key_prefix` is the key text of `dir` and ends in `/`.
fn walk_dir(dir: &Path, key_prefix: &str, out: &mut Vec<ObjectKey>) -> io::Result<()> {
    let Some(entries) = absent_ok(fs::read_dir(dir))? else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_data(format!("{key_prefix}: entry name is not UTF-8")))?;
        let key = format!("{key_prefix}{name}");
        let path = entry.path();
        let Some(meta) = lstat(&path, &key)? else {
            continue;
        };
        if meta.is_dir() {
            walk_dir(&path, &format!("{key}/"), out)?;
        } else {
            let parsed = ObjectKey::parse(&key).map_err(|e| {
                invalid_data(format!(
                    "{key}: stored name is not a valid object key ({e})"
                ))
            })?;
            out.push(parsed);
        }
    }
    Ok(())
}

/// Metadata of `path` without following a final symlink; `None` when it is absent. A symlink or special file is an
/// `InvalidData` error naming `shown`, so it is never read, listed or removed through.
fn lstat(path: &Path, shown: &str) -> io::Result<Option<fs::Metadata>> {
    let Some(meta) = absent_ok(fs::symlink_metadata(path))? else {
        return Ok(None);
    };
    if meta.is_file() || meta.is_dir() {
        Ok(Some(meta))
    } else {
        Err(invalid_data(format!(
            "{shown}: symlink or special file inside the store root, refusing to traverse it"
        )))
    }
}

/// Creates `path` exclusively, writes `bytes` and syncs them to disk.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::File::create_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// `Ok(None)` when `result` failed because the path or one of its parents is not there.
fn absent_ok<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

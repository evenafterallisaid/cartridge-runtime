use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use fs4::{FileExt, TryLockError};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const MAX_BLOB_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_BLOB_GC_ROOTS: usize = 100_000;
const BLOB_REFERENCE_PREFIX: &[u8] = b"cartridge-blob-v1\0";
const BLOB_REFERENCE_BYTES: usize = BLOB_REFERENCE_PREFIX.len() + 64 + 8;

static BLOB_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub struct BlobStore {
    root: PathBuf,
    objects: PathBuf,
    temporary: PathBuf,
    lock: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobInfo {
    pub sha256: String,
    pub bytes: u64,
    pub existed: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BlobReference {
    pub sha256: String,
    pub bytes: u64,
}

impl BlobReference {
    pub fn new(sha256: impl Into<String>, bytes: u64) -> Result<Self> {
        let reference = Self {
            sha256: sha256.into(),
            bytes,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoded = Vec::with_capacity(BLOB_REFERENCE_BYTES);
        encoded.extend_from_slice(BLOB_REFERENCE_PREFIX);
        encoded.extend_from_slice(self.sha256.as_bytes());
        encoded.extend_from_slice(&self.bytes.to_be_bytes());
        Ok(encoded)
    }

    pub fn decode(value: &[u8]) -> Result<Option<Self>> {
        if !value.starts_with(BLOB_REFERENCE_PREFIX) {
            return Ok(None);
        }
        if value.len() != BLOB_REFERENCE_BYTES {
            return Err(Error::Corrupt(
                "blob reference has an invalid length".into(),
            ));
        }
        let digest_start = BLOB_REFERENCE_PREFIX.len();
        let digest_end = digest_start + 64;
        let sha256 = std::str::from_utf8(&value[digest_start..digest_end])
            .map_err(|_| Error::Corrupt("blob reference digest is not text".into()))?;
        let bytes = u64::from_be_bytes(
            value[digest_end..]
                .try_into()
                .map_err(|_| Error::Corrupt("blob reference size is invalid".into()))?,
        );
        Self::new(sha256, bytes).map(Some)
    }

    fn validate(&self) -> Result<()> {
        validate_digest(&self.sha256)?;
        if self.bytes > MAX_BLOB_BYTES {
            return Err(Error::Corrupt(format!(
                "blob reference exceeds the {MAX_BLOB_BYTES} byte limit"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BlobGcReport {
    pub retained: usize,
    pub removable: usize,
    pub removable_bytes: u64,
    pub removed: usize,
    pub removed_bytes: u64,
    pub dry_run: bool,
}

impl BlobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if root.exists() {
            reject_symlink(root)?;
        }
        fs::create_dir_all(root)?;
        reject_symlink(root)?;
        set_private_directory_permissions(root)?;
        let root = fs::canonicalize(root)?;
        let objects = root.join("objects");
        if objects.exists() {
            reject_symlink(&objects)?;
        }
        fs::create_dir_all(&objects)?;
        reject_symlink(&objects)?;
        set_private_directory_permissions(&objects)?;
        let temporary = root.join("tmp");
        if temporary.exists() {
            reject_symlink(&temporary)?;
        }
        fs::create_dir_all(&temporary)?;
        reject_symlink(&temporary)?;
        set_private_directory_permissions(&temporary)?;
        let lock = root.join("store.lock");
        if lock.exists() {
            reject_symlink(&lock)?;
        }
        let lock_file = open_lock_file(&lock)?;
        drop(lock_file);
        let store = Self {
            root,
            objects,
            temporary,
            lock,
        };
        let lock_file = store.acquire_lock()?;
        let result = store.remove_abandoned_temporary_files();
        drop(lock_file);
        result?;
        Ok(store)
    }

    pub fn put(&self, input: impl AsRef<Path>) -> Result<BlobInfo> {
        let lock = self.acquire_lock()?;
        let result = self.put_locked(input.as_ref());
        drop(lock);
        result
    }

    fn put_locked(&self, input: &Path) -> Result<BlobInfo> {
        self.validate_layout()?;
        let metadata = fs::metadata(input)?;
        if !metadata.is_file() || metadata.len() > MAX_BLOB_BYTES {
            return Err(Error::Corrupt(format!(
                "blob input exceeds the {MAX_BLOB_BYTES} byte limit"
            )));
        }
        let temporary = PendingFile::new(self.temporary_path());
        let mut source = File::open(input)?;
        let mut target = open_private_new(temporary.path())?;
        let (bytes, sha256) = copy_and_hash(&mut source, &mut target, MAX_BLOB_BYTES)?;
        target.sync_all()?;
        drop(target);
        let final_path = self.object_path(&sha256)?;
        let shard = final_path
            .parent()
            .ok_or_else(|| Error::UnsafePath(final_path.display().to_string()))?;
        fs::create_dir_all(shard)?;
        reject_symlink(shard)?;
        if !fs::canonicalize(shard)?.starts_with(&self.objects) {
            return Err(Error::UnsafePath(shard.display().to_string()));
        }
        set_private_directory_permissions(shard)?;
        if final_path.exists() {
            let existing = self.verify_locked(&sha256)?;
            if existing.bytes != bytes {
                return Err(Error::Corrupt(
                    "blob digest collision has a different size".into(),
                ));
            }
            return Ok(BlobInfo {
                existed: true,
                ..existing
            });
        }
        fs::hard_link(temporary.path(), &final_path)?;
        temporary.remove()?;
        sync_directory(shard)?;
        sync_directory(&self.objects)?;
        Ok(BlobInfo {
            sha256,
            bytes,
            existed: false,
        })
    }

    pub fn verify(&self, sha256: &str) -> Result<BlobInfo> {
        let lock = self.acquire_lock()?;
        let result = self.verify_locked(sha256);
        drop(lock);
        result
    }

    fn verify_locked(&self, sha256: &str) -> Result<BlobInfo> {
        self.validate_layout()?;
        let path = self.object_path(sha256)?;
        reject_symlink(&path)?;
        let shard = path
            .parent()
            .ok_or_else(|| Error::UnsafePath(path.display().to_string()))?;
        reject_symlink(shard)?;
        if !fs::canonicalize(shard)?.starts_with(&self.objects) {
            return Err(Error::UnsafePath(shard.display().to_string()));
        }
        let canonical = fs::canonicalize(&path)?;
        if !canonical.starts_with(&self.objects) {
            return Err(Error::UnsafePath(path.display().to_string()));
        }
        let mut file = File::open(&canonical)?;
        let (bytes, actual) = hash_reader(&mut file, MAX_BLOB_BYTES)?;
        if actual != sha256 {
            return Err(Error::Corrupt(format!(
                "blob {sha256} does not match its content"
            )));
        }
        Ok(BlobInfo {
            sha256: sha256.to_owned(),
            bytes,
            existed: true,
        })
    }

    pub fn materialize(&self, sha256: &str, output: impl AsRef<Path>) -> Result<BlobInfo> {
        let lock = self.acquire_lock()?;
        let result = self.materialize_locked(sha256, output.as_ref());
        drop(lock);
        result
    }

    fn materialize_locked(&self, sha256: &str, output: &Path) -> Result<BlobInfo> {
        let verified = self.verify_locked(sha256)?;
        let source_path = self.object_path(sha256)?;
        let directory = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(directory)?;
        let temporary = PendingFile::new(temporary_path(directory, "materialize"));
        let mut source = File::open(source_path)?;
        let mut target = open_private_new(temporary.path())?;
        let (bytes, actual) = copy_and_hash(&mut source, &mut target, MAX_BLOB_BYTES)?;
        target.sync_all()?;
        drop(target);
        if bytes != verified.bytes || actual != sha256 {
            return Err(Error::Corrupt(
                "blob changed while it was materialized".into(),
            ));
        }
        fs::hard_link(temporary.path(), output)?;
        temporary.remove()?;
        sync_directory(directory)?;
        Ok(verified)
    }

    pub fn gc(&self, retained: &BTreeSet<String>, dry_run: bool) -> Result<BlobGcReport> {
        self.gc_with_references(retained, &BTreeMap::new(), dry_run)
    }

    pub fn gc_with_references(
        &self,
        retained: &BTreeSet<String>,
        references: &BTreeMap<String, u64>,
        dry_run: bool,
    ) -> Result<BlobGcReport> {
        let lock = self.acquire_lock()?;
        let result = self.gc_with_references_locked(retained, references, dry_run);
        drop(lock);
        result
    }

    fn gc_with_references_locked(
        &self,
        retained: &BTreeSet<String>,
        references: &BTreeMap<String, u64>,
        dry_run: bool,
    ) -> Result<BlobGcReport> {
        validate_gc_root_count(retained.len(), references.len())?;
        let mut all_retained = retained.clone();
        for (sha256, expected_bytes) in references {
            let reference = BlobReference::new(sha256, *expected_bytes)?;
            let actual = self.verify_locked(&reference.sha256)?;
            if actual.bytes != reference.bytes {
                return Err(Error::Corrupt(format!(
                    "blob {} has {} bytes; reference declares {}",
                    reference.sha256, actual.bytes, reference.bytes
                )));
            }
            all_retained.insert(reference.sha256);
        }
        self.gc_locked(&all_retained, dry_run)
    }

    fn gc_locked(&self, retained: &BTreeSet<String>, dry_run: bool) -> Result<BlobGcReport> {
        self.validate_layout()?;
        for digest in retained {
            validate_digest(digest)?;
        }
        let mut report = BlobGcReport {
            retained: retained.len(),
            dry_run,
            ..BlobGcReport::default()
        };
        let mut removals = Vec::new();
        for path in self.object_files()? {
            let digest = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| Error::UnsafePath(path.display().to_string()))?;
            if retained.contains(digest) {
                continue;
            }
            let info = self.verify_locked(digest)?;
            report.removable += 1;
            report.removable_bytes = report
                .removable_bytes
                .checked_add(info.bytes)
                .ok_or_else(|| Error::Corrupt("blob garbage collection size overflowed".into()))?;
            removals.push((path, info.bytes));
        }
        if !dry_run {
            for (path, bytes) in removals {
                fs::remove_file(path)?;
                report.removed += 1;
                report.removed_bytes = report
                    .removed_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| Error::Corrupt("blob removal size overflowed".into()))?;
            }
        }
        if !dry_run {
            sync_directory(&self.objects)?;
        }
        Ok(report)
    }

    fn object_path(&self, sha256: &str) -> Result<PathBuf> {
        validate_digest(sha256)?;
        Ok(self.objects.join(&sha256[..2]).join(sha256))
    }

    fn temporary_path(&self) -> PathBuf {
        temporary_path(&self.temporary, "incoming")
    }

    fn validate_layout(&self) -> Result<()> {
        for path in [&self.root, &self.objects, &self.temporary, &self.lock] {
            reject_symlink(path)?;
            let canonical = fs::canonicalize(path)?;
            if path != &self.root && !canonical.starts_with(&self.root) {
                return Err(Error::UnsafePath(path.display().to_string()));
            }
        }
        Ok(())
    }

    fn acquire_lock(&self) -> Result<File> {
        reject_symlink(&self.lock)?;
        let file = open_lock_file(&self.lock)?;
        let deadline = Instant::now() + LOCK_WAIT_TIMEOUT;
        loop {
            match FileExt::try_lock(&file) {
                Ok(()) => return Ok(file),
                Err(TryLockError::Error(error)) => return Err(Error::Io(error)),
                Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                    return Err(Error::LockTimeout {
                        milliseconds: u64::try_from(LOCK_WAIT_TIMEOUT.as_millis())
                            .unwrap_or(u64::MAX),
                    });
                }
                Err(TryLockError::WouldBlock) => thread::sleep(LOCK_RETRY_INTERVAL),
            }
        }
    }

    fn object_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for shard in fs::read_dir(&self.objects)? {
            let shard = shard?;
            if shard.file_type()?.is_symlink() || !shard.file_type()?.is_dir() {
                return Err(Error::UnsafePath(shard.path().display().to_string()));
            }
            let shard_name = shard.file_name();
            let shard_name = shard_name
                .to_str()
                .ok_or_else(|| Error::UnsafePath(shard.path().display().to_string()))?;
            if shard_name.len() != 2 || !shard_name.bytes().all(is_lower_hex) {
                return Err(Error::UnsafePath(shard.path().display().to_string()));
            }
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                if entry.file_type()?.is_symlink() || !entry.file_type()?.is_file() {
                    return Err(Error::UnsafePath(entry.path().display().to_string()));
                }
                let digest = entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| Error::UnsafePath(entry.path().display().to_string()))?
                    .to_owned();
                validate_digest(&digest)?;
                if !digest.starts_with(shard_name) {
                    return Err(Error::UnsafePath(entry.path().display().to_string()));
                }
                files.push(entry.path());
            }
        }
        Ok(files)
    }

    fn remove_abandoned_temporary_files(&self) -> Result<()> {
        self.validate_layout()?;
        for entry in fs::read_dir(&self.temporary)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error::UnsafePath(entry.path().display().to_string()))?;
            if entry.file_type()?.is_symlink()
                || !entry.file_type()?.is_file()
                || !name.starts_with(".cartridge-blob-incoming-")
                || !name.as_bytes().ends_with(b".tmp")
            {
                return Err(Error::UnsafePath(entry.path().display().to_string()));
            }
            fs::remove_file(entry.path())?;
        }
        sync_directory(&self.temporary)?;
        Ok(())
    }
}

struct PendingFile {
    path: PathBuf,
    active: bool,
}

impl PendingFile {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(mut self) -> Result<()> {
        fs::remove_file(&self.path)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn copy_and_hash(source: &mut File, target: &mut File, limit: u64) -> Result<(u64, String)> {
    copy_and_hash_to_writer(source, target, limit)
}

fn hash_reader(source: &mut File, limit: u64) -> Result<(u64, String)> {
    let mut sink = std::io::sink();
    copy_and_hash_to_writer(source, &mut sink, limit)
}

fn copy_and_hash_to_writer(
    source: &mut File,
    target: &mut impl Write,
    limit: u64,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| Error::Corrupt("blob size overflowed".into()))?;
        if total > limit {
            return Err(Error::Corrupt(format!(
                "blob exceeds the {limit} byte limit"
            )));
        }
        target.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return Err(Error::Corrupt(
            "blob digest must be lowercase sha256".into(),
        ));
    }
    Ok(())
}

fn validate_gc_root_count(retained: usize, references: usize) -> Result<()> {
    let root_count = retained
        .checked_add(references)
        .ok_or_else(|| Error::Corrupt("blob root count overflowed".into()))?;
    if root_count > MAX_BLOB_GC_ROOTS {
        return Err(Error::Corrupt(format!(
            "blob garbage collection exceeds the {MAX_BLOB_GC_ROOTS}-root limit"
        )));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::UnsafePath(path.display().to_string()));
    }
    Ok(())
}

fn temporary_path(directory: &Path, label: &str) -> PathBuf {
    let sequence = BLOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".cartridge-blob-{label}-{}-{sequence}.tmp",
        std::process::id()
    ))
}

fn open_private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = fs::metadata(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(directory: &Path) -> Result<()> {
    let _ = fs::metadata(directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_references_have_one_canonical_bounded_encoding() {
        let reference = BlobReference::new("a".repeat(64), 42).unwrap();
        let encoded = reference.encode().unwrap();

        assert_eq!(BlobReference::decode(&encoded).unwrap(), Some(reference));
        assert_eq!(BlobReference::decode(b"ordinary state").unwrap(), None);
        assert!(BlobReference::decode(BLOB_REFERENCE_PREFIX).is_err());
        assert!(BlobReference::new("A".repeat(64), 42).is_err());
        assert!(BlobReference::new("a".repeat(64), MAX_BLOB_BYTES + 1).is_err());
        assert!(validate_gc_root_count(MAX_BLOB_GC_ROOTS, 0).is_ok());
        assert!(validate_gc_root_count(MAX_BLOB_GC_ROOTS, 1).is_err());
        assert!(validate_gc_root_count(usize::MAX, 1).is_err());
    }

    #[test]
    fn blobs_deduplicate_materialize_and_collect() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.bin");
        let output = directory.path().join("output.bin");
        fs::write(&input, b"content").unwrap();
        let store = BlobStore::open(directory.path().join("store")).unwrap();

        let first = store.put(&input).unwrap();
        let second = store.put(&input).unwrap();
        store.materialize(&first.sha256, &output).unwrap();
        let dry_run = store.gc(&BTreeSet::new(), true).unwrap();
        let removed = store.gc(&BTreeSet::new(), false).unwrap();

        assert!(!first.existed);
        assert!(second.existed);
        assert_eq!(fs::read(output).unwrap(), b"content");
        assert_eq!(dry_run.removable, 1);
        assert_eq!(removed.removed, 1);
        assert!(store.verify(&first.sha256).is_err());
    }

    #[test]
    fn artifact_references_are_verified_before_garbage_collection() {
        let directory = tempfile::tempdir().unwrap();
        let retained_input = directory.path().join("retained.bin");
        let removable_input = directory.path().join("removable.bin");
        fs::write(&retained_input, b"retained").unwrap();
        fs::write(&removable_input, b"remove me").unwrap();
        let store = BlobStore::open(directory.path().join("store")).unwrap();
        let retained = store.put(&retained_input).unwrap();
        let removable = store.put(&removable_input).unwrap();

        let wrong_size = BTreeMap::from([(retained.sha256.clone(), retained.bytes + 1)]);
        assert!(
            store
                .gc_with_references(&BTreeSet::new(), &wrong_size, false)
                .is_err()
        );
        store.verify(&retained.sha256).unwrap();
        store.verify(&removable.sha256).unwrap();

        let references = BTreeMap::from([(retained.sha256.clone(), retained.bytes)]);
        let report = store
            .gc_with_references(&BTreeSet::new(), &references, false)
            .unwrap();
        assert_eq!(report.retained, 1);
        assert_eq!(report.removed, 1);
        store.verify(&retained.sha256).unwrap();
        assert!(store.verify(&removable.sha256).is_err());
    }

    #[test]
    fn collection_preflights_every_candidate_before_deleting() {
        let directory = tempfile::tempdir().unwrap();
        let first_input = directory.path().join("first.bin");
        let second_input = directory.path().join("second.bin");
        fs::write(&first_input, b"first").unwrap();
        fs::write(&second_input, b"second").unwrap();
        let store = BlobStore::open(directory.path().join("store")).unwrap();
        let mut objects = [
            store.put(&first_input).unwrap(),
            store.put(&second_input).unwrap(),
        ];
        objects.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        fs::write(store.object_path(&objects[1].sha256).unwrap(), b"corrupt").unwrap();

        assert!(store.gc(&BTreeSet::new(), false).is_err());
        store.verify(&objects[0].sha256).unwrap();
    }

    #[test]
    fn failed_pending_files_are_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pending");
        fs::write(&path, b"partial").unwrap();

        drop(PendingFile::new(path.clone()));

        assert!(!path.exists());
    }

    #[test]
    fn store_lock_wait_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let store = BlobStore::open(directory.path().join("store")).unwrap();
        let held = open_lock_file(&store.lock).unwrap();
        FileExt::lock(&held).unwrap();
        let started = Instant::now();

        let result = store.gc(&BTreeSet::new(), true);

        assert!(matches!(result, Err(Error::LockTimeout { .. })));
        assert!(started.elapsed() < Duration::from_secs(3));
        FileExt::unlock(&held).unwrap();
    }

    #[test]
    fn abandoned_ingest_files_are_removed_on_open() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("store");
        let store = BlobStore::open(&root).unwrap();
        let abandoned = store.temporary_path();
        fs::write(&abandoned, b"partial").unwrap();
        drop(store);

        BlobStore::open(root).unwrap();

        assert!(!abandoned.exists());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_object_directories_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let store = BlobStore::open(directory.path().join("store")).unwrap();
        fs::remove_dir(&store.objects).unwrap();
        symlink(&outside, &store.objects).unwrap();

        assert!(store.gc(&BTreeSet::new(), true).is_err());
    }
}

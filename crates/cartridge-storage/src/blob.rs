use std::{
    collections::BTreeSet,
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
        let lock = self.acquire_lock()?;
        let result = self.gc_locked(retained, dry_run);
        drop(lock);
        result
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
            if !dry_run {
                fs::remove_file(&path)?;
                report.removed += 1;
                report.removed_bytes = report
                    .removed_bytes
                    .checked_add(info.bytes)
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

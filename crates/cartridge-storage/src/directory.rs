use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use fs4::{FileExt, TryLockError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Error, Result, StorageBackend, StorageLimits, StorageSnapshot, StorageUsage, validate_key,
    validate_limits, validate_namespace, validate_prefix,
};

const DISK_FORMAT_VERSION: u32 = 2;
const RETAINED_GENERATIONS: usize = 2;
const MAX_STATE_FILE_BYTES: u64 = 144 * 1024 * 1024;
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct DirectoryStorage {
    root: PathBuf,
}

impl DirectoryStorage {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: fs::canonicalize(root.as_ref())?,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn recover(&self, namespace: &str) -> Result<RecoveryReport> {
        self.with_namespace(namespace, |directory| {
            let mut valid = Vec::new();
            let mut corrupt = Vec::new();
            for (generation, path) in state_files(directory)? {
                match read_state(&path, namespace, generation) {
                    Ok(_) => valid.push((generation, path)),
                    Err(Error::Corrupt(_)) => corrupt.push(path),
                    Err(error) => return Err(error),
                }
            }
            if valid.is_empty() && !corrupt.is_empty() {
                return Err(Error::NoRecoverableState);
            }

            let mut quarantined = Vec::with_capacity(corrupt.len());
            for path in corrupt {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("state");
                let target = unique_path(directory, &format!("corrupt-{name}"), "json");
                fs::rename(&path, &target)?;
                quarantined.push(
                    target
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            let discarded_pending = cleanup_pending(directory)?;
            prune_generations(directory)?;
            sync_directory(directory)?;
            Ok(RecoveryReport {
                valid_generation: valid.iter().map(|(generation, _)| *generation).max(),
                quarantined,
                discarded_pending,
            })
        })
    }

    pub fn export_snapshot(&self, namespace: &str) -> Result<StorageSnapshot> {
        self.with_namespace(namespace, |directory| {
            let state = load_state(directory, namespace)?;
            StorageSnapshot::from_entries(namespace, state.schema, &state.entries)
        })
    }

    pub fn plan_restore(
        &self,
        namespace: &str,
        snapshot: &StorageSnapshot,
        limits: StorageLimits,
    ) -> Result<RestorePlan> {
        let entries = snapshot.entries_for(namespace)?;
        validate_restore_limits(&entries, limits)?;
        self.with_namespace(namespace, |directory| {
            let current = load_state(directory, namespace)?;
            build_restore_plan(
                current.schema,
                &current.entries,
                snapshot.state_schema(),
                &entries,
            )
        })
    }

    pub fn restore(
        &self,
        namespace: &str,
        snapshot: &StorageSnapshot,
        limits: StorageLimits,
    ) -> Result<RestorePlan> {
        let entries = snapshot.entries_for(namespace)?;
        validate_restore_limits(&entries, limits)?;
        self.with_namespace(namespace, |directory| {
            cleanup_pending(directory)?;
            let current = load_state(directory, namespace)?;
            let plan = build_restore_plan(
                current.schema,
                &current.entries,
                snapshot.state_schema(),
                &entries,
            )?;
            if plan.changed() {
                commit_state(
                    directory,
                    namespace,
                    State {
                        generation: current.generation,
                        schema: snapshot.state_schema(),
                        usage: plan.snapshot,
                        entries,
                    },
                )?;
            }
            Ok(plan)
        })
    }

    fn with_namespace<T>(
        &self,
        namespace: &str,
        operation: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        validate_namespace(namespace)?;
        let directory = self.namespace_directory(namespace);
        fs::create_dir_all(&directory)?;
        set_private_directory_permissions(&directory)?;
        let lock_path = directory.join("namespace.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        acquire_lock(&lock)?;
        let result = operation(&directory);
        drop(lock);
        result
    }

    fn namespace_directory(&self, namespace: &str) -> PathBuf {
        self.root
            .join(hex::encode(Sha256::digest(namespace.as_bytes())))
    }
}

fn acquire_lock(file: &File) -> Result<()> {
    let deadline = Instant::now() + LOCK_WAIT_TIMEOUT;
    loop {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::Error(error)) => return Err(Error::Io(error)),
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err(Error::LockTimeout {
                    milliseconds: u64::try_from(LOCK_WAIT_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                });
            }
            Err(TryLockError::WouldBlock) => thread::sleep(LOCK_RETRY_INTERVAL),
        }
    }
}

impl StorageBackend for DirectoryStorage {
    fn prepare(&self, namespace: &str, state_schema: u32) -> Result<()> {
        self.with_namespace(namespace, |directory| {
            cleanup_pending(directory)?;
            let mut state = load_state(directory, namespace)?;
            if state.generation == 0 {
                state.schema = state_schema;
                return commit_state(directory, namespace, state);
            }
            if state.schema != state_schema {
                return Err(Error::SchemaMismatch {
                    expected: state_schema,
                    actual: state.schema,
                });
            }
            Ok(())
        })
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        self.with_namespace(namespace, |directory| {
            Ok(load_state(directory, namespace)?.entries.get(key).cloned())
        })
    }

    fn put(&self, namespace: &str, key: &str, value: &[u8], limits: StorageLimits) -> Result<()> {
        validate_key(key)?;
        validate_limits(limits)?;
        if value.len() > limits.max_value_bytes {
            return Err(Error::ValueTooLarge {
                size: value.len(),
                limit: limits.max_value_bytes,
            });
        }
        self.with_namespace(namespace, |directory| {
            cleanup_pending(directory)?;
            let mut state = load_state(directory, namespace)?;
            let old_size = state.entries.get(key).map_or(0, Vec::len);
            let next_bytes = state
                .usage
                .bytes
                .checked_sub(old_size)
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(Error::QuotaExceeded {
                    size: usize::MAX,
                    limit: limits.max_bytes,
                })?;
            if next_bytes > limits.max_bytes {
                return Err(Error::QuotaExceeded {
                    size: next_bytes,
                    limit: limits.max_bytes,
                });
            }
            if !state.entries.contains_key(key) && state.entries.len() >= limits.max_keys {
                return Err(Error::KeyLimitExceeded {
                    limit: limits.max_keys,
                });
            }
            state.entries.insert(key.to_owned(), value.to_vec());
            state.usage = StorageUsage {
                bytes: next_bytes,
                keys: state.entries.len(),
            };
            commit_state(directory, namespace, state)
        })
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        validate_key(key)?;
        self.with_namespace(namespace, |directory| {
            cleanup_pending(directory)?;
            let mut state = load_state(directory, namespace)?;
            let Some(value) = state.entries.remove(key) else {
                return Ok(false);
            };
            state.usage.bytes -= value.len();
            state.usage.keys = state.entries.len();
            commit_state(directory, namespace, state)?;
            Ok(true)
        })
    }

    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>> {
        validate_prefix(prefix)?;
        self.with_namespace(namespace, |directory| {
            Ok(load_state(directory, namespace)?
                .entries
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect())
        })
    }

    fn usage(&self, namespace: &str) -> Result<StorageUsage> {
        self.with_namespace(namespace, |directory| {
            Ok(load_state(directory, namespace)?.usage)
        })
    }
}

#[derive(Clone, Debug, Default)]
struct State {
    generation: u64,
    schema: u32,
    entries: BTreeMap<String, Vec<u8>>,
    usage: StorageUsage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskPayload {
    format_version: u32,
    namespace: String,
    generation: u64,
    #[serde(default, skip_serializing_if = "is_default")]
    state_schema: u32,
    entries: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskEnvelope {
    payload: DiskPayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryReport {
    pub valid_generation: Option<u64>,
    pub quarantined: Vec<String>,
    pub discarded_pending: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestorePlan {
    pub current_schema: u32,
    pub snapshot_schema: u32,
    pub current: StorageUsage,
    pub snapshot: StorageUsage,
    pub added: usize,
    pub replaced: usize,
    pub removed: usize,
    pub unchanged: usize,
}

impl RestorePlan {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.current_schema != self.snapshot_schema
            || self.added != 0
            || self.replaced != 0
            || self.removed != 0
    }
}

fn load_state(directory: &Path, namespace: &str) -> Result<State> {
    let files = state_files(directory)?;
    let mut latest = State::default();
    for (generation, path) in files {
        let state = read_state(&path, namespace, generation)?;
        if generation >= latest.generation {
            latest = state;
        }
    }
    Ok(latest)
}

fn validate_restore_limits(
    entries: &BTreeMap<String, Vec<u8>>,
    limits: StorageLimits,
) -> Result<()> {
    validate_limits(limits)?;
    let mut bytes = 0usize;
    for value in entries.values() {
        if value.len() > limits.max_value_bytes {
            return Err(Error::ValueTooLarge {
                size: value.len(),
                limit: limits.max_value_bytes,
            });
        }
        bytes = bytes.checked_add(value.len()).ok_or(Error::QuotaExceeded {
            size: usize::MAX,
            limit: limits.max_bytes,
        })?;
    }
    if bytes > limits.max_bytes {
        return Err(Error::QuotaExceeded {
            size: bytes,
            limit: limits.max_bytes,
        });
    }
    if entries.len() > limits.max_keys {
        return Err(Error::KeyLimitExceeded {
            limit: limits.max_keys,
        });
    }
    Ok(())
}

fn build_restore_plan(
    current_schema: u32,
    current: &BTreeMap<String, Vec<u8>>,
    snapshot_schema: u32,
    snapshot: &BTreeMap<String, Vec<u8>>,
) -> Result<RestorePlan> {
    let mut added = 0;
    let mut replaced = 0;
    let mut unchanged = 0;
    for (key, value) in snapshot {
        match current.get(key) {
            None => added += 1,
            Some(current) if current == value => unchanged += 1,
            Some(_) => replaced += 1,
        }
    }
    let removed = current
        .keys()
        .filter(|key| !snapshot.contains_key(*key))
        .count();
    Ok(RestorePlan {
        current_schema,
        snapshot_schema,
        current: state_usage(current)?,
        snapshot: state_usage(snapshot)?,
        added,
        replaced,
        removed,
        unchanged,
    })
}

fn state_usage(entries: &BTreeMap<String, Vec<u8>>) -> Result<StorageUsage> {
    let bytes = entries.values().try_fold(0usize, |total, value| {
        total
            .checked_add(value.len())
            .ok_or_else(|| Error::Corrupt("storage usage overflowed".into()))
    })?;
    Ok(StorageUsage {
        bytes,
        keys: entries.len(),
    })
}

fn read_state(path: &Path, namespace: &str, generation: u64) -> Result<State> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_STATE_FILE_BYTES {
        return Err(Error::Corrupt(format!(
            "{} exceeds the state file size limit",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    let envelope: DiskEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        Error::Corrupt(format!("{} is not valid JSON: {error}", path.display()))
    })?;
    let payload_bytes = serde_json::to_vec(&envelope.payload)?;
    let digest = hex::encode(Sha256::digest(&payload_bytes));
    if envelope.payload_sha256 != digest {
        return Err(Error::Corrupt(format!(
            "{} has a mismatched payload digest",
            path.display()
        )));
    }
    if !matches!(envelope.payload.format_version, 1 | DISK_FORMAT_VERSION)
        || envelope.payload.namespace != namespace
        || envelope.payload.generation != generation
        || (envelope.payload.format_version == 1 && envelope.payload.state_schema != 0)
    {
        return Err(Error::Corrupt(format!(
            "{} has mismatched state identity",
            path.display()
        )));
    }

    let mut entries = BTreeMap::new();
    let mut bytes_used = 0usize;
    for (key, encoded) in envelope.payload.entries {
        validate_key(&key)
            .map_err(|_| Error::Corrupt(format!("{} contains an invalid key", path.display())))?;
        let value = hex::decode(encoded).map_err(|error| {
            Error::Corrupt(format!(
                "{} contains invalid value data: {error}",
                path.display()
            ))
        })?;
        bytes_used = bytes_used
            .checked_add(value.len())
            .ok_or_else(|| Error::Corrupt(format!("{} has overflowing usage", path.display())))?;
        entries.insert(key, value);
    }
    Ok(State {
        generation,
        schema: envelope.payload.state_schema,
        usage: StorageUsage {
            bytes: bytes_used,
            keys: entries.len(),
        },
        entries,
    })
}

fn commit_state(directory: &Path, namespace: &str, mut state: State) -> Result<()> {
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| Error::Corrupt("storage generation overflowed".into()))?;
    let payload = DiskPayload {
        format_version: DISK_FORMAT_VERSION,
        namespace: namespace.to_owned(),
        generation: state.generation,
        state_schema: state.schema,
        entries: state
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), hex::encode(value)))
            .collect(),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let envelope = DiskEnvelope {
        payload,
        payload_sha256: hex::encode(Sha256::digest(&payload_bytes)),
    };
    let encoded = serde_json::to_vec(&envelope)?;
    let final_path = directory.join(state_file_name(state.generation));
    let temporary = unique_path(directory, "pending", "tmp");
    let mut file = open_private_new(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &final_path)?;
    sync_directory(directory)?;
    prune_generations(directory)
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
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

fn state_files(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(generation) = name
            .strip_prefix("state-")
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        let generation = generation
            .parse::<u64>()
            .map_err(|_| Error::Corrupt(format!("unrecognized state file name: {name}")))?;
        files.push((generation, entry.path()));
    }
    files.sort_by_key(|(generation, _)| *generation);
    Ok(files)
}

fn state_file_name(generation: u64) -> String {
    format!("state-{generation:020}.json")
}

fn cleanup_pending(directory: &Path) -> Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if entry.file_type()?.is_file()
            && name.to_str().is_some_and(|name| {
                name.starts_with("pending-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
            })
        {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn prune_generations(directory: &Path) -> Result<()> {
    let files = state_files(directory)?;
    let remove_count = files.len().saturating_sub(RETAINED_GENERATIONS);
    for (_, path) in files.into_iter().take(remove_count) {
        fs::remove_file(path)?;
    }
    sync_directory(directory)
}

fn unique_path(directory: &Path, prefix: &str, extension: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        "{prefix}-{}-{sequence}.{extension}",
        std::process::id()
    ))
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
    use std::{sync::Arc, thread};

    use super::*;

    const LIMITS: StorageLimits = StorageLimits {
        max_bytes: 1024,
        max_keys: 16,
        max_value_bytes: 256,
    };

    #[test]
    fn state_survives_reopening_the_backend() {
        let directory = TestDirectory::new();
        DirectoryStorage::open(directory.path())
            .unwrap()
            .put("dev.example.test", "settings/theme", b"dark", LIMITS)
            .unwrap();

        let reopened = DirectoryStorage::open(directory.path()).unwrap();

        assert_eq!(
            reopened.get("dev.example.test", "settings/theme").unwrap(),
            Some(b"dark".to_vec())
        );
    }

    #[test]
    fn state_schema_survives_reopening_the_backend() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        storage.prepare("dev.example.test", 2).unwrap();
        storage
            .put("dev.example.test", "value", b"kept", LIMITS)
            .unwrap();

        let reopened = DirectoryStorage::open(directory.path()).unwrap();
        reopened.prepare("dev.example.test", 2).unwrap();
        assert_eq!(
            reopened
                .export_snapshot("dev.example.test")
                .unwrap()
                .state_schema(),
            2
        );
        assert!(matches!(
            reopened.prepare("dev.example.test", 3),
            Err(Error::SchemaMismatch {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn durable_v1_generations_remain_compatible_as_schema_zero() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        let namespace = storage.namespace_directory("dev.example.test");
        fs::create_dir_all(&namespace).unwrap();
        let payload = DiskPayload {
            format_version: 1,
            namespace: "dev.example.test".into(),
            generation: 1,
            state_schema: 0,
            entries: BTreeMap::from([("value".into(), hex::encode(b"legacy"))]),
        };
        let envelope = DiskEnvelope {
            payload_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&payload).unwrap())),
            payload,
        };
        fs::write(
            namespace.join(state_file_name(1)),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

        storage.prepare("dev.example.test", 0).unwrap();
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"legacy".to_vec())
        );
        assert!(matches!(
            storage.prepare("dev.example.test", 1),
            Err(Error::SchemaMismatch {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn interrupted_temporary_files_are_ignored() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        storage
            .put("dev.example.test", "value", b"valid", LIMITS)
            .unwrap();
        let namespace = storage.namespace_directory("dev.example.test");
        fs::write(namespace.join("pending-crash.tmp"), b"partial").unwrap();

        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"valid".to_vec())
        );
        storage
            .put("dev.example.test", "other", b"next", LIMITS)
            .unwrap();
        assert!(!namespace.join("pending-crash.tmp").exists());
    }

    #[test]
    fn corrupt_latest_generation_can_be_quarantined() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        storage
            .put("dev.example.test", "value", b"first", LIMITS)
            .unwrap();
        storage
            .put("dev.example.test", "value", b"second", LIMITS)
            .unwrap();
        let namespace = storage.namespace_directory("dev.example.test");
        fs::write(namespace.join(state_file_name(2)), b"corrupt").unwrap();

        assert!(matches!(
            storage.get("dev.example.test", "value"),
            Err(Error::Corrupt(_))
        ));
        let report = storage.recover("dev.example.test").unwrap();

        assert_eq!(report.valid_generation, Some(1));
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"first".to_vec())
        );
    }

    #[test]
    fn concurrent_backend_instances_do_not_lose_updates() {
        let directory = TestDirectory::new();
        let first = Arc::new(DirectoryStorage::open(directory.path()).unwrap());
        let second = Arc::new(DirectoryStorage::open(directory.path()).unwrap());
        let first_thread = {
            let storage = first.clone();
            thread::spawn(move || {
                storage
                    .put("dev.example.test", "first", b"one", LIMITS)
                    .unwrap();
            })
        };
        let second_thread = thread::spawn(move || {
            second
                .put("dev.example.test", "second", b"two", LIMITS)
                .unwrap();
        });

        first_thread.join().unwrap();
        second_thread.join().unwrap();

        assert_eq!(
            first.list("dev.example.test", "").unwrap(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn contended_locks_fail_within_a_fixed_budget() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        let namespace = storage.namespace_directory("dev.example.test");
        fs::create_dir_all(&namespace).unwrap();
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(namespace.join("namespace.lock"))
            .unwrap();
        FileExt::lock(&held).unwrap();
        let started = Instant::now();

        assert!(matches!(
            storage.usage("dev.example.test"),
            Err(Error::LockTimeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn restore_plan_does_not_change_state_until_committed() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        storage
            .put("dev.example.test", "value", b"first", LIMITS)
            .unwrap();
        let snapshot = storage.export_snapshot("dev.example.test").unwrap();
        storage
            .put("dev.example.test", "value", b"second", LIMITS)
            .unwrap();
        storage
            .put("dev.example.test", "extra", b"remove", LIMITS)
            .unwrap();

        let plan = storage
            .plan_restore("dev.example.test", &snapshot, LIMITS)
            .unwrap();

        assert_eq!(plan.replaced, 1);
        assert_eq!(plan.removed, 1);
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"second".to_vec())
        );

        storage
            .restore("dev.example.test", &snapshot, LIMITS)
            .unwrap();
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(storage.get("dev.example.test", "extra").unwrap(), None);
    }

    #[test]
    fn restore_rejects_another_cartridges_snapshot() {
        let directory = TestDirectory::new();
        let storage = DirectoryStorage::open(directory.path()).unwrap();
        storage
            .put("dev.example.first", "value", b"first", LIMITS)
            .unwrap();
        let snapshot = storage.export_snapshot("dev.example.first").unwrap();

        assert!(matches!(
            storage.plan_restore("dev.example.second", &snapshot, LIMITS),
            Err(Error::SnapshotIdentity { .. })
        ));
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cartridge-storage-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}

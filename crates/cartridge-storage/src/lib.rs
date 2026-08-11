mod blob;
mod directory;
mod snapshot;

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Debug,
    sync::RwLock,
};

use serde::Serialize;
use thiserror::Error;

pub use blob::{BlobGcReport, BlobInfo, BlobStore, MAX_BLOB_BYTES};
pub use directory::{
    CapturedState, DirectoryStorage, GenerationEvidence, RecoveryReport, RestorePlan,
};
pub use snapshot::{
    SnapshotComparison, SnapshotDifference, SnapshotEntry, SnapshotStorage, StorageSnapshot,
    StorageSnapshotSummary,
};

pub const MAX_KEY_BYTES: usize = 256;
pub const MAX_STORAGE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_STORAGE_KEYS: usize = 100_000;
pub const MAX_STORAGE_VALUE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TRANSACTION_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRANSACTION_OPERATIONS: usize = 128;

pub trait StorageBackend: Debug + Send + Sync {
    fn prepare(&self, namespace: &str, state_schema: u32, limits: StorageLimits) -> Result<()>;
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&self, namespace: &str, key: &str, value: &[u8], limits: StorageLimits) -> Result<()>;
    fn delete(&self, namespace: &str, key: &str) -> Result<bool>;
    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>>;
    fn usage(&self, namespace: &str) -> Result<StorageUsage>;
    fn revision(&self, namespace: &str) -> Result<u64>;
    fn compare_exchange(
        &self,
        namespace: &str,
        expected_revision: u64,
        key: &str,
        expected: Option<&[u8]>,
        replacement: Option<&[u8]>,
        limits: StorageLimits,
    ) -> Result<StorageTransactionResult>;
    fn apply_batch(
        &self,
        namespace: &str,
        expected_revision: u64,
        mutations: &[StorageMutation],
        limits: StorageLimits,
    ) -> Result<StorageTransactionResult>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLimits {
    pub max_bytes: usize,
    pub max_keys: usize,
    pub max_value_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct StorageUsage {
    pub bytes: usize,
    pub keys: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageMutation {
    pub key: String,
    pub value: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StorageTransactionResult {
    pub applied: bool,
    pub revision: u64,
}

#[derive(Debug, Default)]
pub struct MemoryStorage {
    namespaces: RwLock<BTreeMap<String, Namespace>>,
}

impl MemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn snapshot_state(
        &self,
        namespace: &str,
        limits: StorageLimits,
    ) -> Result<(u64, BTreeMap<String, Vec<u8>>)> {
        validate_namespace(namespace)?;
        validate_limits(limits)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        let (revision, entries) = namespaces.get(namespace).map_or_else(
            || (0, BTreeMap::new()),
            |namespace| (namespace.revision, namespace.entries.clone()),
        );
        validate_entry_limits(&entries, limits)?;
        Ok((revision, entries))
    }

    pub(crate) fn load_namespace(
        &self,
        namespace: &str,
        state_schema: u32,
        revision: u64,
        entries: BTreeMap<String, Vec<u8>>,
        limits: StorageLimits,
    ) -> Result<()> {
        validate_namespace(namespace)?;
        let usage = validate_entry_limits(&entries, limits)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        namespaces.insert(
            namespace.to_owned(),
            Namespace {
                state_schema,
                revision,
                entries,
                bytes: usage.bytes,
            },
        );
        Ok(())
    }
}

impl StorageBackend for MemoryStorage {
    fn prepare(&self, namespace: &str, state_schema: u32, limits: StorageLimits) -> Result<()> {
        validate_namespace(namespace)?;
        validate_limits(limits)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        match namespaces.entry(namespace.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(Namespace {
                    state_schema,
                    ..Namespace::default()
                });
            }
            Entry::Occupied(entry) if entry.get().state_schema != state_schema => {
                return Err(Error::SchemaMismatch {
                    expected: state_schema,
                    actual: entry.get().state_schema,
                });
            }
            Entry::Occupied(_) => {}
        }
        if let Some(namespace) = namespaces.get(namespace) {
            validate_entry_limits(&namespace.entries, limits)?;
        }
        Ok(())
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        Ok(namespaces
            .get(namespace)
            .and_then(|state| state.entries.get(key))
            .cloned())
    }

    fn put(&self, namespace: &str, key: &str, value: &[u8], limits: StorageLimits) -> Result<()> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        validate_limits(limits)?;
        if value.len() > limits.max_value_bytes {
            return Err(Error::ValueTooLarge {
                size: value.len(),
                limit: limits.max_value_bytes,
            });
        }

        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        let state = namespaces.entry(namespace.to_owned()).or_default();
        if state
            .entries
            .get(key)
            .is_some_and(|current| current == value)
        {
            return Ok(());
        }
        let old_size = state.entries.get(key).map_or(0, Vec::len);
        let next_bytes = state
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
        let revision = next_revision(state.revision)?;

        match state.entries.entry(key.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(value.to_vec());
            }
            Entry::Occupied(mut entry) => {
                entry.insert(value.to_vec());
            }
        }
        state.bytes = next_bytes;
        state.revision = revision;
        Ok(())
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        let Some(state) = namespaces.get_mut(namespace) else {
            return Ok(false);
        };
        let Some(value) = state.entries.get(key) else {
            return Ok(false);
        };
        let value_len = value.len();
        let revision = next_revision(state.revision)?;
        state.entries.remove(key);
        state.bytes -= value_len;
        state.revision = revision;
        Ok(true)
    }

    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        let Some(state) = namespaces.get(namespace) else {
            return Ok(Vec::new());
        };
        Ok(state
            .entries
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn usage(&self, namespace: &str) -> Result<StorageUsage> {
        validate_namespace(namespace)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        Ok(namespaces
            .get(namespace)
            .map_or_else(StorageUsage::default, |state| StorageUsage {
                bytes: state.bytes,
                keys: state.entries.len(),
            }))
    }

    fn revision(&self, namespace: &str) -> Result<u64> {
        validate_namespace(namespace)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        Ok(namespaces.get(namespace).map_or(0, |state| state.revision))
    }

    fn compare_exchange(
        &self,
        namespace: &str,
        expected_revision: u64,
        key: &str,
        expected: Option<&[u8]>,
        replacement: Option<&[u8]>,
        limits: StorageLimits,
    ) -> Result<StorageTransactionResult> {
        validate_compare_exchange(key, expected, replacement, limits)?;
        validate_namespace(namespace)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        let state = namespaces.entry(namespace.to_owned()).or_default();
        if state.revision != expected_revision
            || state.entries.get(key).map(Vec::as_slice) != expected
        {
            return Ok(StorageTransactionResult {
                applied: false,
                revision: state.revision,
            });
        }
        let mutations = [StorageMutation {
            key: key.to_owned(),
            value: replacement.map(<[u8]>::to_vec),
        }];
        let mut usage = StorageUsage {
            bytes: state.bytes,
            keys: state.entries.len(),
        };
        let revision = if mutations_change(&state.entries, &mutations) {
            next_revision(state.revision)?
        } else {
            state.revision
        };
        let changed = apply_mutations(&mut state.entries, &mut usage, &mutations, limits)?;
        state.bytes = usage.bytes;
        if changed {
            state.revision = revision;
        }
        Ok(StorageTransactionResult {
            applied: true,
            revision: state.revision,
        })
    }

    fn apply_batch(
        &self,
        namespace: &str,
        expected_revision: u64,
        mutations: &[StorageMutation],
        limits: StorageLimits,
    ) -> Result<StorageTransactionResult> {
        validate_mutations(mutations, limits)?;
        validate_namespace(namespace)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        let state = namespaces.entry(namespace.to_owned()).or_default();
        if state.revision != expected_revision {
            return Ok(StorageTransactionResult {
                applied: false,
                revision: state.revision,
            });
        }
        let mut usage = StorageUsage {
            bytes: state.bytes,
            keys: state.entries.len(),
        };
        let revision = if mutations_change(&state.entries, mutations) {
            next_revision(state.revision)?
        } else {
            state.revision
        };
        let changed = apply_mutations(&mut state.entries, &mut usage, mutations, limits)?;
        state.bytes = usage.bytes;
        if changed {
            state.revision = revision;
        }
        Ok(StorageTransactionResult {
            applied: true,
            revision: state.revision,
        })
    }
}

#[derive(Debug, Default)]
struct Namespace {
    state_schema: u32,
    revision: u64,
    entries: BTreeMap<String, Vec<u8>>,
    bytes: usize,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid storage namespace: {0:?}")]
    InvalidNamespace(String),
    #[error("invalid storage key: {0:?}")]
    InvalidKey(String),
    #[error("invalid storage limits")]
    InvalidLimits,
    #[error("storage value uses {size} bytes; the per-value limit is {limit}")]
    ValueTooLarge { size: usize, limit: usize },
    #[error("storage write would use {size} bytes; the quota is {limit}")]
    QuotaExceeded { size: usize, limit: usize },
    #[error("storage write would exceed the {limit}-key limit")]
    KeyLimitExceeded { limit: usize },
    #[error("storage backend is unavailable")]
    Unavailable,
    #[error("storage data is corrupt: {0}")]
    Corrupt(String),
    #[error("storage has no valid state to recover")]
    NoRecoverableState,
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("snapshot belongs to {actual}; expected {expected}")]
    SnapshotIdentity { expected: String, actual: String },
    #[error("state uses schema {actual}; expected schema {expected}")]
    SchemaMismatch { expected: u32, actual: u32 },
    #[error("durable state changed after the source snapshot was captured")]
    StateChanged,
    #[error("storage lock was not available within {milliseconds} ms")]
    LockTimeout { milliseconds: u64 },
    #[error("storage path is not a private directory or regular file: {0}")]
    UnsafePath(String),
    #[error(
        "storage transaction must contain between 1 and {MAX_TRANSACTION_OPERATIONS} unique operations"
    )]
    InvalidTransaction,
    #[error("storage transaction input uses {size} bytes; the limit is {limit}")]
    TransactionTooLarge { size: usize, limit: usize },
    #[error("storage revision overflowed")]
    RevisionOverflow,
    #[error("state schema transition must increase: {from} -> {to}")]
    InvalidSchemaTransition { from: u32, to: u32 },
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty()
        || namespace.len() > 128
        || !namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
    {
        return Err(Error::InvalidNamespace(namespace.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || key.starts_with('/')
        || key.ends_with('/')
        || !key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
                || byte == b'/'
        })
        || key
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Error::InvalidKey(key.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    validate_key(prefix)
}

pub(crate) fn validate_limits(limits: StorageLimits) -> Result<()> {
    if limits.max_bytes == 0
        || limits.max_keys == 0
        || limits.max_value_bytes == 0
        || limits.max_value_bytes > limits.max_bytes
        || limits.max_bytes > MAX_STORAGE_BYTES
        || limits.max_keys > MAX_STORAGE_KEYS
        || limits.max_value_bytes > MAX_STORAGE_VALUE_BYTES
    {
        return Err(Error::InvalidLimits);
    }
    Ok(())
}

pub(crate) fn validate_entry_limits(
    entries: &BTreeMap<String, Vec<u8>>,
    limits: StorageLimits,
) -> Result<StorageUsage> {
    validate_limits(limits)?;
    if entries.len() > limits.max_keys {
        return Err(Error::KeyLimitExceeded {
            limit: limits.max_keys,
        });
    }
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
    Ok(StorageUsage {
        bytes,
        keys: entries.len(),
    })
}

pub(crate) fn validate_mutations(
    mutations: &[StorageMutation],
    limits: StorageLimits,
) -> Result<()> {
    validate_limits(limits)?;
    if mutations.is_empty() || mutations.len() > MAX_TRANSACTION_OPERATIONS {
        return Err(Error::InvalidTransaction);
    }
    let mut keys = std::collections::BTreeSet::new();
    let mut input_bytes = 0usize;
    for mutation in mutations {
        validate_key(&mutation.key)?;
        if !keys.insert(&mutation.key) {
            return Err(Error::InvalidTransaction);
        }
        input_bytes = input_bytes
            .checked_add(mutation.key.len())
            .and_then(|bytes| {
                mutation
                    .value
                    .as_ref()
                    .map_or(Some(bytes), |value| bytes.checked_add(value.len()))
            })
            .ok_or(Error::TransactionTooLarge {
                size: usize::MAX,
                limit: MAX_TRANSACTION_INPUT_BYTES,
            })?;
        if let Some(value) = &mutation.value {
            if value.len() > limits.max_value_bytes {
                return Err(Error::ValueTooLarge {
                    size: value.len(),
                    limit: limits.max_value_bytes,
                });
            }
        }
    }
    if input_bytes > MAX_TRANSACTION_INPUT_BYTES {
        return Err(Error::TransactionTooLarge {
            size: input_bytes,
            limit: MAX_TRANSACTION_INPUT_BYTES,
        });
    }
    Ok(())
}

pub(crate) fn validate_compare_exchange(
    key: &str,
    expected: Option<&[u8]>,
    replacement: Option<&[u8]>,
    limits: StorageLimits,
) -> Result<()> {
    let input_bytes = key
        .len()
        .checked_add(expected.map_or(0, <[u8]>::len))
        .and_then(|bytes| bytes.checked_add(replacement.map_or(0, <[u8]>::len)))
        .ok_or(Error::TransactionTooLarge {
            size: usize::MAX,
            limit: MAX_TRANSACTION_INPUT_BYTES,
        })?;
    if input_bytes > MAX_TRANSACTION_INPUT_BYTES {
        return Err(Error::TransactionTooLarge {
            size: input_bytes,
            limit: MAX_TRANSACTION_INPUT_BYTES,
        });
    }
    validate_mutations(
        &[StorageMutation {
            key: key.to_owned(),
            value: replacement.map(<[u8]>::to_vec),
        }],
        limits,
    )?;
    if expected.is_some_and(|value| value.len() > limits.max_value_bytes) {
        return Err(Error::ValueTooLarge {
            size: expected.map_or(0, <[u8]>::len),
            limit: limits.max_value_bytes,
        });
    }
    Ok(())
}

pub(crate) fn apply_mutations(
    entries: &mut BTreeMap<String, Vec<u8>>,
    usage: &mut StorageUsage,
    mutations: &[StorageMutation],
    limits: StorageLimits,
) -> Result<bool> {
    let mut removed_bytes = 0usize;
    let mut added_bytes = 0usize;
    let mut removed_keys = 0usize;
    let mut added_keys = 0usize;
    let mut changed = false;
    for mutation in mutations {
        let current = entries.get(&mutation.key);
        if current.map(Vec::as_slice) == mutation.value.as_deref() {
            continue;
        }
        changed = true;
        if let Some(current) = current {
            removed_bytes =
                removed_bytes
                    .checked_add(current.len())
                    .ok_or(Error::QuotaExceeded {
                        size: usize::MAX,
                        limit: limits.max_bytes,
                    })?;
            if mutation.value.is_none() {
                removed_keys += 1;
            }
        } else if mutation.value.is_some() {
            added_keys += 1;
        }
        if let Some(value) = &mutation.value {
            added_bytes = added_bytes
                .checked_add(value.len())
                .ok_or(Error::QuotaExceeded {
                    size: usize::MAX,
                    limit: limits.max_bytes,
                })?;
        }
    }
    let next_bytes = usage
        .bytes
        .checked_sub(removed_bytes)
        .and_then(|bytes| bytes.checked_add(added_bytes))
        .ok_or(Error::QuotaExceeded {
            size: usize::MAX,
            limit: limits.max_bytes,
        })?;
    let next_keys = usage
        .keys
        .checked_sub(removed_keys)
        .and_then(|keys| keys.checked_add(added_keys))
        .ok_or(Error::KeyLimitExceeded {
            limit: limits.max_keys,
        })?;
    if next_bytes > limits.max_bytes {
        return Err(Error::QuotaExceeded {
            size: next_bytes,
            limit: limits.max_bytes,
        });
    }
    if next_keys > limits.max_keys {
        return Err(Error::KeyLimitExceeded {
            limit: limits.max_keys,
        });
    }
    if changed {
        for mutation in mutations {
            if let Some(value) = &mutation.value {
                entries.insert(mutation.key.clone(), value.clone());
            } else {
                entries.remove(&mutation.key);
            }
        }
        *usage = StorageUsage {
            bytes: next_bytes,
            keys: next_keys,
        };
    }
    Ok(changed)
}

pub(crate) fn mutations_change(
    entries: &BTreeMap<String, Vec<u8>>,
    mutations: &[StorageMutation],
) -> bool {
    mutations
        .iter()
        .any(|mutation| entries.get(&mutation.key).map(Vec::as_slice) != mutation.value.as_deref())
}

pub(crate) fn next_revision(revision: u64) -> Result<u64> {
    revision.checked_add(1).ok_or(Error::RevisionOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: StorageLimits = StorageLimits {
        max_bytes: 16,
        max_keys: 2,
        max_value_bytes: 12,
    };

    #[test]
    fn namespaces_are_isolated() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.one", "name", b"one", LIMITS)
            .unwrap();
        storage
            .put("dev.example.two", "name", b"two", LIMITS)
            .unwrap();

        assert_eq!(
            storage.get("dev.example.one", "name").unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            storage.get("dev.example.two", "name").unwrap(),
            Some(b"two".to_vec())
        );
    }

    #[test]
    fn prepared_namespaces_reject_a_different_schema() {
        let storage = MemoryStorage::new();
        storage.prepare("dev.example.test", 2, LIMITS).unwrap();

        assert!(matches!(
            storage.prepare("dev.example.test", 3, LIMITS),
            Err(Error::SchemaMismatch {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn prepare_rejects_existing_state_over_a_lowered_quota() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "value", &[0; 12], LIMITS)
            .unwrap();
        let lower = StorageLimits {
            max_bytes: 8,
            max_keys: 2,
            max_value_bytes: 8,
        };

        assert!(matches!(
            storage.prepare("dev.example.test", 0, lower),
            Err(Error::QuotaExceeded { .. } | Error::ValueTooLarge { .. })
        ));
    }

    #[test]
    fn failed_writes_leave_the_previous_value_intact() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "value", b"valid", LIMITS)
            .unwrap();

        let error = storage
            .put("dev.example.test", "value", &[0; 13], LIMITS)
            .unwrap_err();

        assert!(matches!(error, Error::ValueTooLarge { .. }));
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"valid".to_vec())
        );
    }

    #[test]
    fn key_and_byte_quotas_are_enforced() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "a", &[0; 8], LIMITS)
            .unwrap();
        storage
            .put("dev.example.test", "b", &[0; 8], LIMITS)
            .unwrap();

        assert!(matches!(
            storage.put("dev.example.test", "c", b"x", LIMITS),
            Err(Error::QuotaExceeded { .. } | Error::KeyLimitExceeded { .. })
        ));
        assert_eq!(
            storage.usage("dev.example.test").unwrap(),
            StorageUsage { bytes: 16, keys: 2 }
        );
    }

    #[test]
    fn listing_is_sorted_and_prefix_scoped() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "settings/theme", b"a", LIMITS)
            .unwrap();
        storage
            .put("dev.example.test", "settings/font", b"b", LIMITS)
            .unwrap();

        assert_eq!(
            storage.list("dev.example.test", "settings/").unwrap(),
            vec!["settings/font", "settings/theme"]
        );
    }

    #[test]
    fn deleting_a_value_releases_its_quota() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "temporary", &[0; 12], LIMITS)
            .unwrap();

        assert!(storage.delete("dev.example.test", "temporary").unwrap());
        assert!(!storage.delete("dev.example.test", "temporary").unwrap());
        assert_eq!(
            storage.usage("dev.example.test").unwrap(),
            StorageUsage::default()
        );
    }

    #[test]
    fn replacing_a_value_updates_usage_instead_of_double_counting() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "value", &[0; 12], LIMITS)
            .unwrap();
        storage
            .put("dev.example.test", "value", &[0; 4], LIMITS)
            .unwrap();

        assert_eq!(
            storage.usage("dev.example.test").unwrap(),
            StorageUsage { bytes: 4, keys: 1 }
        );
    }

    #[test]
    fn path_like_escape_keys_are_rejected() {
        let storage = MemoryStorage::new();

        assert!(storage.get("dev.example.test", "../other").is_err());
        assert!(storage.get("dev.example.test", "C:/other").is_err());
        assert!(storage.get("dev.example.test", "a\\b").is_err());
    }

    #[test]
    fn atomic_batches_commit_once_and_fail_without_partial_writes() {
        let storage = MemoryStorage::new();
        storage.prepare("dev.example.test", 2, LIMITS).unwrap();
        let initial = storage.revision("dev.example.test").unwrap();
        let created = storage
            .apply_batch(
                "dev.example.test",
                initial,
                &[
                    StorageMutation {
                        key: "a".into(),
                        value: Some(b"one".to_vec()),
                    },
                    StorageMutation {
                        key: "b".into(),
                        value: Some(b"two".to_vec()),
                    },
                ],
                LIMITS,
            )
            .unwrap();

        assert!(created.applied);
        assert_eq!(created.revision, initial + 1);
        assert_eq!(
            storage.get("dev.example.test", "a").unwrap(),
            Some(b"one".to_vec())
        );
        assert!(matches!(
            storage.apply_batch(
                "dev.example.test",
                created.revision,
                &[
                    StorageMutation {
                        key: "a".into(),
                        value: Some(vec![0; 12]),
                    },
                    StorageMutation {
                        key: "b".into(),
                        value: Some(vec![0; 12]),
                    },
                ],
                LIMITS,
            ),
            Err(Error::QuotaExceeded { .. })
        ));
        assert_eq!(
            storage.revision("dev.example.test").unwrap(),
            created.revision
        );
        assert_eq!(
            storage.get("dev.example.test", "a").unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            storage.get("dev.example.test", "b").unwrap(),
            Some(b"two".to_vec())
        );
    }

    #[test]
    fn revisions_reject_stale_tokens_after_an_aba_change() {
        let storage = MemoryStorage::new();
        storage
            .put("dev.example.test", "value", b"a", LIMITS)
            .unwrap();
        let original = storage.revision("dev.example.test").unwrap();
        let changed = storage
            .compare_exchange(
                "dev.example.test",
                original,
                "value",
                Some(b"a"),
                Some(b"b"),
                LIMITS,
            )
            .unwrap();
        let restored = storage
            .compare_exchange(
                "dev.example.test",
                changed.revision,
                "value",
                Some(b"b"),
                Some(b"a"),
                LIMITS,
            )
            .unwrap();
        let stale = storage
            .compare_exchange(
                "dev.example.test",
                original,
                "value",
                Some(b"a"),
                Some(b"stale"),
                LIMITS,
            )
            .unwrap();

        assert!(changed.applied);
        assert!(restored.applied);
        assert!(!stale.applied);
        assert_eq!(stale.revision, restored.revision);
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"a".to_vec())
        );
    }

    #[test]
    fn transaction_validation_rejects_duplicate_keys_and_keeps_schema() {
        let storage = MemoryStorage::new();
        storage.prepare("dev.example.test", 4, LIMITS).unwrap();
        let revision = storage.revision("dev.example.test").unwrap();
        let duplicate = [
            StorageMutation {
                key: "same".into(),
                value: Some(b"one".to_vec()),
            },
            StorageMutation {
                key: "same".into(),
                value: None,
            },
        ];

        assert!(matches!(
            storage.apply_batch("dev.example.test", revision, &duplicate, LIMITS),
            Err(Error::InvalidTransaction)
        ));
        storage
            .put("dev.example.test", "last", b"value", LIMITS)
            .unwrap();
        assert!(storage.delete("dev.example.test", "last").unwrap());
        storage.prepare("dev.example.test", 4, LIMITS).unwrap();
        assert!(matches!(
            storage.prepare("dev.example.test", 5, LIMITS),
            Err(Error::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn revision_overflow_never_mutates_memory_state() {
        let storage = MemoryStorage::new();
        storage
            .load_namespace(
                "dev.example.test",
                0,
                u64::MAX,
                BTreeMap::from([("value".into(), b"before".to_vec())]),
                LIMITS,
            )
            .unwrap();

        assert!(matches!(
            storage.put("dev.example.test", "value", b"after", LIMITS),
            Err(Error::RevisionOverflow)
        ));
        assert!(matches!(
            storage.apply_batch(
                "dev.example.test",
                u64::MAX,
                &[StorageMutation {
                    key: "value".into(),
                    value: Some(b"batch".to_vec()),
                }],
                LIMITS,
            ),
            Err(Error::RevisionOverflow)
        ));
        assert_eq!(
            storage.get("dev.example.test", "value").unwrap(),
            Some(b"before".to_vec())
        );
        assert_eq!(storage.revision("dev.example.test").unwrap(), u64::MAX);
    }
}

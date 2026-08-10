mod directory;
mod snapshot;

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Debug,
    sync::RwLock,
};

use serde::Serialize;
use thiserror::Error;

pub use directory::{CapturedState, DirectoryStorage, RecoveryReport, RestorePlan};
pub use snapshot::{
    SnapshotComparison, SnapshotDifference, SnapshotEntry, SnapshotStorage, StorageSnapshot,
    StorageSnapshotSummary,
};

pub const MAX_KEY_BYTES: usize = 256;
pub const MAX_STORAGE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_STORAGE_KEYS: usize = 100_000;
pub const MAX_STORAGE_VALUE_BYTES: usize = 8 * 1024 * 1024;

pub trait StorageBackend: Debug + Send + Sync {
    fn prepare(&self, namespace: &str, state_schema: u32, limits: StorageLimits) -> Result<()>;
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;
    fn put(&self, namespace: &str, key: &str, value: &[u8], limits: StorageLimits) -> Result<()>;
    fn delete(&self, namespace: &str, key: &str) -> Result<bool>;
    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>>;
    fn usage(&self, namespace: &str) -> Result<StorageUsage>;
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

#[derive(Debug, Default)]
pub struct MemoryStorage {
    namespaces: RwLock<BTreeMap<String, Namespace>>,
}

impl MemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn snapshot_entries(
        &self,
        namespace: &str,
        limits: StorageLimits,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_limits(limits)?;
        let namespaces = self.namespaces.read().map_err(|_| Error::Unavailable)?;
        let entries = namespaces
            .get(namespace)
            .map_or_else(BTreeMap::new, |namespace| namespace.entries.clone());
        validate_entry_limits(&entries, limits)?;
        Ok(entries)
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

        match state.entries.entry(key.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(value.to_vec());
            }
            Entry::Occupied(mut entry) => {
                entry.insert(value.to_vec());
            }
        }
        state.bytes = next_bytes;
        Ok(())
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let mut namespaces = self.namespaces.write().map_err(|_| Error::Unavailable)?;
        let Some(state) = namespaces.get_mut(namespace) else {
            return Ok(false);
        };
        let Some(value) = state.entries.remove(key) else {
            return Ok(false);
        };
        state.bytes -= value.len();
        if state.entries.is_empty() {
            namespaces.remove(namespace);
        }
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
}

#[derive(Debug, Default)]
struct Namespace {
    state_schema: u32,
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
}

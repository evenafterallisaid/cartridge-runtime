use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Error, MemoryStorage, Result, StorageBackend, StorageLimits, StorageUsage, validate_key,
    validate_limits, validate_namespace,
};

pub const SNAPSHOT_FORMAT_VERSION: u32 = 2;

const MAX_SNAPSHOT_FILE_BYTES: u64 = 144 * 1024 * 1024;

static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSnapshot {
    payload: SnapshotPayload,
    payload_sha256: String,
}

#[derive(Debug)]
pub struct SnapshotStorage {
    cartridge_id: String,
    state_schema: u32,
    storage: MemoryStorage,
}

impl SnapshotStorage {
    pub fn from_snapshot(
        snapshot: &StorageSnapshot,
        cartridge_id: &str,
        limits: StorageLimits,
    ) -> Result<Self> {
        validate_limits(limits)?;
        let entries = snapshot.entries_for(cartridge_id)?;
        let storage = MemoryStorage::new();
        storage.prepare(cartridge_id, snapshot.state_schema())?;
        for (key, value) in entries {
            storage.put(cartridge_id, &key, &value, limits)?;
        }
        Ok(Self {
            cartridge_id: cartridge_id.to_owned(),
            state_schema: snapshot.state_schema(),
            storage,
        })
    }

    pub fn export_snapshot(&self) -> Result<StorageSnapshot> {
        let mut entries = BTreeMap::new();
        for key in self.storage.list(&self.cartridge_id, "")? {
            let value = self
                .storage
                .get(&self.cartridge_id, &key)?
                .ok_or_else(|| Error::Corrupt(format!("snapshot branch lost key {key:?}")))?;
            entries.insert(key, value);
        }
        StorageSnapshot::from_entries(&self.cartridge_id, self.state_schema, &entries)
    }

    fn check_namespace(&self, namespace: &str) -> Result<()> {
        validate_namespace(namespace)?;
        if namespace != self.cartridge_id {
            return Err(Error::SnapshotIdentity {
                expected: self.cartridge_id.clone(),
                actual: namespace.to_owned(),
            });
        }
        Ok(())
    }
}

impl StorageBackend for SnapshotStorage {
    fn prepare(&self, namespace: &str, state_schema: u32) -> Result<()> {
        self.check_namespace(namespace)?;
        if self.state_schema != state_schema {
            return Err(Error::SchemaMismatch {
                expected: state_schema,
                actual: self.state_schema,
            });
        }
        self.storage.prepare(namespace, state_schema)
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        self.check_namespace(namespace)?;
        self.storage.get(namespace, key)
    }

    fn put(&self, namespace: &str, key: &str, value: &[u8], limits: StorageLimits) -> Result<()> {
        self.check_namespace(namespace)?;
        self.storage.put(namespace, key, value, limits)
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        self.check_namespace(namespace)?;
        self.storage.delete(namespace, key)
    }

    fn list(&self, namespace: &str, prefix: &str) -> Result<Vec<String>> {
        self.check_namespace(namespace)?;
        self.storage.list(namespace, prefix)
    }

    fn usage(&self, namespace: &str) -> Result<StorageUsage> {
        self.check_namespace(namespace)?;
        self.storage.usage(namespace)
    }
}

impl StorageSnapshot {
    pub(crate) fn from_entries(
        cartridge_id: &str,
        state_schema: u32,
        entries: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        validate_namespace(cartridge_id)?;
        let payload = SnapshotPayload {
            format_version: SNAPSHOT_FORMAT_VERSION,
            cartridge_id: cartridge_id.to_owned(),
            state_schema,
            entries: entries
                .iter()
                .map(|(key, value)| (key.clone(), hex::encode(value)))
                .collect(),
        };
        let payload_sha256 = payload_digest(&payload)?;
        Ok(Self {
            payload,
            payload_sha256,
        })
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::Corrupt(format!("snapshot is not valid JSON: {error}")))?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
            return Err(Error::Corrupt(format!(
                "{} exceeds the snapshot size limit",
                path.display()
            )));
        }
        Self::from_slice(&fs::read(path)?)
    }

    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }
        let directory = parent.unwrap_or_else(|| Path::new("."));
        let temporary = temporary_path(directory);
        let mut file = open_private_new(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Io(error));
        }
        fs::remove_file(temporary)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !matches!(self.payload.format_version, 1 | SNAPSHOT_FORMAT_VERSION) {
            return Err(Error::Corrupt(format!(
                "unsupported snapshot format {}; expected 1 or {SNAPSHOT_FORMAT_VERSION}",
                self.payload.format_version
            )));
        }
        if self.payload.format_version == 1 && self.payload.state_schema != 0 {
            return Err(Error::Corrupt(
                "snapshot format 1 cannot declare a state schema".into(),
            ));
        }
        validate_namespace(&self.payload.cartridge_id)
            .map_err(|_| Error::Corrupt("snapshot has an invalid cartridge id".into()))?;
        if self.payload_sha256 != payload_digest(&self.payload)? {
            return Err(Error::Corrupt(
                "snapshot payload digest does not match its contents".into(),
            ));
        }
        self.decode_entries().map(|_| ())
    }

    #[must_use]
    pub fn cartridge_id(&self) -> &str {
        &self.payload.cartridge_id
    }

    #[must_use]
    pub fn state_schema(&self) -> u32 {
        self.payload.state_schema
    }

    pub fn summary(&self) -> Result<StorageSnapshotSummary> {
        self.validate()?;
        let entries = self.decode_entries()?;
        let usage = usage(&entries)?;
        Ok(StorageSnapshotSummary {
            format_version: self.payload.format_version,
            cartridge_id: self.payload.cartridge_id.clone(),
            state_schema: self.payload.state_schema,
            entries: usage.keys,
            bytes: usage.bytes,
            payload_sha256: self.payload_sha256.clone(),
        })
    }

    pub fn compare(&self, other: &Self) -> Result<SnapshotComparison> {
        self.validate()?;
        other.validate()?;
        let difference = if self.cartridge_id() != other.cartridge_id() {
            Some(SnapshotDifference::Identity {
                left: self.cartridge_id().to_owned(),
                right: other.cartridge_id().to_owned(),
            })
        } else if self.state_schema() != other.state_schema() {
            Some(SnapshotDifference::Schema {
                left: self.state_schema(),
                right: other.state_schema(),
            })
        } else {
            first_entry_difference(&self.decode_entries()?, &other.decode_entries()?)
        };
        Ok(SnapshotComparison {
            identical: difference.is_none(),
            difference,
        })
    }

    pub(crate) fn entries_for(
        &self,
        expected_cartridge_id: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        self.validate()?;
        if self.cartridge_id() != expected_cartridge_id {
            return Err(Error::SnapshotIdentity {
                expected: expected_cartridge_id.to_owned(),
                actual: self.cartridge_id().to_owned(),
            });
        }
        self.decode_entries()
    }

    fn decode_entries(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut decoded = BTreeMap::new();
        for (key, encoded) in &self.payload.entries {
            validate_key(key)
                .map_err(|_| Error::Corrupt(format!("snapshot contains invalid key {key:?}")))?;
            let value = hex::decode(encoded).map_err(|error| {
                Error::Corrupt(format!("snapshot value for {key:?} is invalid: {error}"))
            })?;
            decoded.insert(key.clone(), value);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayload {
    format_version: u32,
    cartridge_id: String,
    #[serde(default, skip_serializing_if = "is_default")]
    state_schema: u32,
    entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageSnapshotSummary {
    pub format_version: u32,
    pub cartridge_id: String,
    pub state_schema: u32,
    pub entries: usize,
    pub bytes: usize,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SnapshotComparison {
    pub identical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difference: Option<SnapshotDifference>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SnapshotDifference {
    Identity {
        left: String,
        right: String,
    },
    Schema {
        left: u32,
        right: u32,
    },
    Entry {
        key: String,
        left: Option<SnapshotEntry>,
        right: Option<SnapshotEntry>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotEntry {
    pub bytes: usize,
    pub sha256: String,
}

fn payload_digest(payload: &SnapshotPayload) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

fn usage(entries: &BTreeMap<String, Vec<u8>>) -> Result<StorageUsage> {
    let bytes = entries.values().try_fold(0usize, |total, value| {
        total
            .checked_add(value.len())
            .ok_or_else(|| Error::Corrupt("snapshot usage overflowed".into()))
    })?;
    Ok(StorageUsage {
        bytes,
        keys: entries.len(),
    })
}

fn first_entry_difference(
    left: &BTreeMap<String, Vec<u8>>,
    right: &BTreeMap<String, Vec<u8>>,
) -> Option<SnapshotDifference> {
    let keys: BTreeSet<_> = left.keys().chain(right.keys()).collect();
    keys.into_iter().find_map(|key| {
        let left_value = left.get(key);
        let right_value = right.get(key);
        (left_value != right_value).then(|| SnapshotDifference::Entry {
            key: key.clone(),
            left: left_value.map(|value| snapshot_entry(value)),
            right: right_value.map(|value| snapshot_entry(value)),
        })
    })
}

fn snapshot_entry(value: &[u8]) -> SnapshotEntry {
    SnapshotEntry {
        bytes: value.len(),
        sha256: hex::encode(Sha256::digest(value)),
    }
}

fn temporary_path(directory: &Path) -> PathBuf {
    let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".cartridge-snapshot-{}-{sequence}.tmp",
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

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: StorageLimits = StorageLimits {
        max_bytes: 64,
        max_keys: 4,
        max_value_bytes: 32,
    };

    fn snapshot(value: &[u8]) -> StorageSnapshot {
        StorageSnapshot::from_entries(
            "dev.example.test",
            0,
            &BTreeMap::from([("settings/theme".into(), value.to_vec())]),
        )
        .unwrap()
    }

    #[test]
    fn snapshot_round_trips_canonical_data() {
        let snapshot = snapshot(b"dark");
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded = StorageSnapshot::from_slice(&encoded).unwrap();

        assert_eq!(decoded.summary().unwrap(), snapshot.summary().unwrap());
        assert_eq!(
            decoded.entries_for("dev.example.test").unwrap(),
            BTreeMap::from([("settings/theme".into(), b"dark".to_vec())])
        );
    }

    #[test]
    fn changed_snapshot_payloads_are_rejected() {
        let snapshot = snapshot(b"dark");
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["payload"]["entries"]["settings/theme"] = "6c69676874".into();

        assert!(matches!(
            StorageSnapshot::from_slice(&serde_json::to_vec(&value).unwrap()),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn comparison_reports_changed_values_without_exposing_them() {
        let comparison = snapshot(b"dark").compare(&snapshot(b"light")).unwrap();

        assert!(!comparison.identical);
        assert!(matches!(
            comparison.difference,
            Some(SnapshotDifference::Entry { .. })
        ));
    }

    #[test]
    fn comparison_reports_schema_changes_before_entry_changes() {
        let left = StorageSnapshot::from_entries("dev.example.test", 1, &BTreeMap::new()).unwrap();
        let right = StorageSnapshot::from_entries("dev.example.test", 2, &BTreeMap::new()).unwrap();

        assert_eq!(
            left.compare(&right).unwrap().difference,
            Some(SnapshotDifference::Schema { left: 1, right: 2 })
        );
    }

    #[test]
    fn portable_v1_fixture_remains_compatible() {
        let snapshot =
            StorageSnapshot::from_slice(include_bytes!("../tests/fixtures/snapshot-v1.json"))
                .unwrap();

        assert_eq!(
            snapshot.summary().unwrap(),
            StorageSnapshotSummary {
                format_version: 1,
                cartridge_id: "dev.example.test".into(),
                state_schema: 0,
                entries: 1,
                bytes: 4,
                payload_sha256: "3e2cf42a40fed75311308f325de48929568683b15387be177818ed2dd9fa41c7"
                    .into(),
            }
        );
    }

    #[test]
    fn snapshot_branches_export_changes_without_changing_the_source() {
        let source = snapshot(b"dark");
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();

        branch
            .put("dev.example.test", "settings/theme", b"light", LIMITS)
            .unwrap();
        branch
            .put("dev.example.test", "session/count", b"1", LIMITS)
            .unwrap();

        let result = branch.export_snapshot().unwrap();
        assert!(!source.compare(&result).unwrap().identical);
        assert_eq!(
            source.entries_for("dev.example.test").unwrap(),
            BTreeMap::from([("settings/theme".into(), b"dark".to_vec())])
        );
        assert_eq!(result.summary().unwrap().entries, 2);
    }

    #[test]
    fn snapshot_branches_reject_other_namespaces() {
        let branch =
            SnapshotStorage::from_snapshot(&snapshot(b"dark"), "dev.example.test", LIMITS).unwrap();

        assert!(matches!(
            branch.get("dev.example.other", "settings/theme"),
            Err(Error::SnapshotIdentity { .. })
        ));
    }

    #[test]
    fn snapshot_branches_require_the_recorded_schema() {
        let source =
            StorageSnapshot::from_entries("dev.example.test", 2, &BTreeMap::new()).unwrap();
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();

        branch.prepare("dev.example.test", 2).unwrap();
        assert!(matches!(
            branch.prepare("dev.example.test", 3),
            Err(Error::SchemaMismatch {
                expected: 3,
                actual: 2
            })
        ));
    }
}

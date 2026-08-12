use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BlobReference, Error, MAX_STORAGE_BYTES, MAX_STORAGE_KEYS, MAX_STORAGE_VALUE_BYTES,
    MemoryStorage, Result, StorageBackend, StorageLimits, StorageMutation,
    StorageTransactionResult, StorageUsage, validate_key, validate_limits, validate_namespace,
};

pub const SNAPSHOT_FORMAT_VERSION: u32 = 3;

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
        storage.load_namespace(
            cartridge_id,
            snapshot.state_schema(),
            snapshot.state_revision(),
            entries,
            limits,
        )?;
        Ok(Self {
            cartridge_id: cartridge_id.to_owned(),
            state_schema: snapshot.state_schema(),
            storage,
        })
    }

    pub fn export_snapshot(&self) -> Result<StorageSnapshot> {
        self.export_snapshot_with_schema(
            self.state_schema,
            StorageLimits {
                max_bytes: MAX_STORAGE_BYTES,
                max_keys: MAX_STORAGE_KEYS,
                max_value_bytes: MAX_STORAGE_VALUE_BYTES,
            },
        )
    }

    pub fn export_migrated_snapshot(
        &self,
        expected_schema: u32,
        next_schema: u32,
        limits: StorageLimits,
    ) -> Result<StorageSnapshot> {
        if self.state_schema != expected_schema {
            return Err(Error::SchemaMismatch {
                expected: expected_schema,
                actual: self.state_schema,
            });
        }
        if next_schema <= expected_schema {
            return Err(Error::InvalidSchemaTransition {
                from: expected_schema,
                to: next_schema,
            });
        }
        self.export_snapshot_with_schema(next_schema, limits)
    }

    fn export_snapshot_with_schema(
        &self,
        state_schema: u32,
        limits: StorageLimits,
    ) -> Result<StorageSnapshot> {
        let (revision, entries) = self.storage.snapshot_state(&self.cartridge_id, limits)?;
        StorageSnapshot::from_entries_with_revision(
            &self.cartridge_id,
            state_schema,
            revision,
            &entries,
        )
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
    fn prepare(&self, namespace: &str, state_schema: u32, limits: StorageLimits) -> Result<()> {
        self.check_namespace(namespace)?;
        if self.state_schema != state_schema {
            return Err(Error::SchemaMismatch {
                expected: state_schema,
                actual: self.state_schema,
            });
        }
        self.storage.prepare(namespace, state_schema, limits)
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

    fn revision(&self, namespace: &str) -> Result<u64> {
        self.check_namespace(namespace)?;
        self.storage.revision(namespace)
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
        self.check_namespace(namespace)?;
        self.storage.compare_exchange(
            namespace,
            expected_revision,
            key,
            expected,
            replacement,
            limits,
        )
    }

    fn apply_batch(
        &self,
        namespace: &str,
        expected_revision: u64,
        mutations: &[StorageMutation],
        limits: StorageLimits,
    ) -> Result<StorageTransactionResult> {
        self.check_namespace(namespace)?;
        self.storage
            .apply_batch(namespace, expected_revision, mutations, limits)
    }
}

impl StorageSnapshot {
    #[cfg(test)]
    fn from_entries(
        cartridge_id: &str,
        state_schema: u32,
        entries: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        Self::from_entries_with_revision(cartridge_id, state_schema, 0, entries)
    }

    pub(crate) fn from_entries_with_revision(
        cartridge_id: &str,
        state_schema: u32,
        state_revision: u64,
        entries: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        validate_namespace(cartridge_id)?;
        let payload = SnapshotPayload {
            format_version: SNAPSHOT_FORMAT_VERSION,
            cartridge_id: cartridge_id.to_owned(),
            state_schema,
            state_revision,
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
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SNAPSHOT_FILE_BYTES {
            return Err(Error::Corrupt(
                "snapshot exceeds the input size limit".into(),
            ));
        }
        let snapshot: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::Corrupt(format!("snapshot is not valid JSON: {error}")))?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_SNAPSHOT_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SNAPSHOT_FILE_BYTES {
            return Err(Error::Corrupt(format!(
                "{} exceeds the snapshot size limit",
                path.display()
            )));
        }
        Self::from_slice(&bytes)
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
        sync_directory(directory)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !matches!(self.payload.format_version, 1 | 2 | SNAPSHOT_FORMAT_VERSION) {
            return Err(Error::Corrupt(format!(
                "unsupported snapshot format {}; expected 1, 2, or {SNAPSHOT_FORMAT_VERSION}",
                self.payload.format_version
            )));
        }
        if self.payload.format_version == 1 && self.payload.state_schema != 0 {
            return Err(Error::Corrupt(
                "snapshot format 1 cannot declare a state schema".into(),
            ));
        }
        if self.payload.format_version < SNAPSHOT_FORMAT_VERSION && self.payload.state_revision != 0
        {
            return Err(Error::Corrupt(
                "snapshot formats 1 and 2 cannot declare a state revision".into(),
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

    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.payload.state_revision
    }

    pub fn with_state_revision(&self, state_revision: u64) -> Result<Self> {
        self.validate()?;
        Self::from_entries_with_revision(
            self.cartridge_id(),
            self.state_schema(),
            state_revision,
            &self.decode_entries()?,
        )
    }

    pub fn payload_sha256_for_format(&self, format_version: u32) -> Result<String> {
        self.validate()?;
        if !matches!(format_version, 1 | 2 | SNAPSHOT_FORMAT_VERSION) {
            return Err(Error::Corrupt(format!(
                "unsupported snapshot compatibility format {format_version}"
            )));
        }
        if format_version == 1 && self.state_schema() != 0 {
            return Err(Error::Corrupt(
                "snapshot format 1 cannot represent a nonzero schema".into(),
            ));
        }
        let payload = SnapshotPayload {
            format_version,
            cartridge_id: self.cartridge_id().to_owned(),
            state_schema: self.state_schema(),
            state_revision: if format_version >= SNAPSHOT_FORMAT_VERSION {
                self.state_revision()
            } else {
                0
            },
            entries: self.payload.entries.clone(),
        };
        payload_digest(&payload)
    }

    pub fn summary(&self) -> Result<StorageSnapshotSummary> {
        self.validate()?;
        let entries = self.decode_entries()?;
        let usage = usage(&entries)?;
        Ok(StorageSnapshotSummary {
            format_version: self.payload.format_version,
            cartridge_id: self.payload.cartridge_id.clone(),
            state_schema: self.payload.state_schema,
            state_revision: self.payload.state_revision,
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
        } else if self.state_revision() != other.state_revision() {
            Some(SnapshotDifference::Revision {
                left: self.state_revision(),
                right: other.state_revision(),
            })
        } else {
            first_entry_difference(&self.decode_entries()?, &other.decode_entries()?)
        };
        Ok(SnapshotComparison {
            identical: difference.is_none(),
            difference,
        })
    }

    pub fn blob_references(&self) -> Result<BTreeMap<String, u64>> {
        let mut references = BTreeMap::new();
        for value in self.decode_entries()?.values() {
            let Some(reference) = BlobReference::decode(value)? else {
                continue;
            };
            match references.insert(reference.sha256.clone(), reference.bytes) {
                Some(bytes) if bytes != reference.bytes => {
                    return Err(Error::Corrupt(format!(
                        "snapshot has conflicting sizes for blob {}",
                        reference.sha256
                    )));
                }
                _ => {}
            }
        }
        Ok(references)
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
        if self.payload.entries.len() > MAX_STORAGE_KEYS {
            return Err(Error::Corrupt("snapshot contains too many keys".into()));
        }
        let mut decoded = BTreeMap::new();
        let mut bytes = 0usize;
        for (key, encoded) in &self.payload.entries {
            validate_key(key)
                .map_err(|_| Error::Corrupt(format!("snapshot contains invalid key {key:?}")))?;
            if encoded.len() > MAX_STORAGE_VALUE_BYTES.saturating_mul(2) {
                return Err(Error::Corrupt(format!(
                    "snapshot value for {key:?} exceeds the value limit"
                )));
            }
            let value = hex::decode(encoded).map_err(|error| {
                Error::Corrupt(format!("snapshot value for {key:?} is invalid: {error}"))
            })?;
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(|| Error::Corrupt("snapshot usage overflowed".into()))?;
            if bytes > MAX_STORAGE_BYTES {
                return Err(Error::Corrupt(
                    "snapshot exceeds the global storage budget".into(),
                ));
            }
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
    #[serde(default, skip_serializing_if = "is_default")]
    state_revision: u64,
    entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageSnapshotSummary {
    pub format_version: u32,
    pub cartridge_id: String,
    pub state_schema: u32,
    pub state_revision: u64,
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
    Revision {
        left: u64,
        right: u64,
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
                state_revision: 0,
                entries: 1,
                bytes: 4,
                payload_sha256: "3e2cf42a40fed75311308f325de48929568683b15387be177818ed2dd9fa41c7"
                    .into(),
            }
        );
    }

    #[test]
    fn portable_v2_fixture_remains_compatible_with_revision_zero() {
        let snapshot =
            StorageSnapshot::from_slice(include_bytes!("../tests/fixtures/snapshot-v2.json"))
                .unwrap();

        assert_eq!(snapshot.state_schema(), 1);
        assert_eq!(snapshot.state_revision(), 0);
        assert_eq!(snapshot.summary().unwrap().entries, 1);
        assert_eq!(
            snapshot.payload_sha256_for_format(2).unwrap(),
            "2fe93e0109ac40b913c9e48f113fdac2f3e6e517fc8566865381c40867649955"
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
        assert_eq!(source.state_revision(), 0);
        assert_eq!(result.state_revision(), 2);
    }

    #[test]
    fn snapshot_revisions_survive_branch_round_trips_and_affect_comparison() {
        let entries = BTreeMap::from([("settings/theme".into(), b"dark".to_vec())]);
        let source =
            StorageSnapshot::from_entries_with_revision("dev.example.test", 0, 7, &entries)
                .unwrap();
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();
        let exported = branch.export_snapshot().unwrap();
        let older = StorageSnapshot::from_entries_with_revision("dev.example.test", 0, 6, &entries)
            .unwrap();

        assert_eq!(branch.revision("dev.example.test").unwrap(), 7);
        assert_eq!(exported.state_revision(), 7);
        assert_eq!(
            exported.compare(&older).unwrap().difference,
            Some(SnapshotDifference::Revision { left: 7, right: 6 })
        );
    }

    #[test]
    fn snapshots_extract_canonical_blob_references_and_reject_conflicts() {
        let first = BlobReference::new("a".repeat(64), 42)
            .unwrap()
            .encode()
            .unwrap();
        let second = BlobReference::new("b".repeat(64), 7)
            .unwrap()
            .encode()
            .unwrap();
        let snapshot = StorageSnapshot::from_entries(
            "dev.example.test",
            0,
            &BTreeMap::from([
                ("blobs/first".into(), first),
                ("blobs/second".into(), second),
                ("settings/theme".into(), b"dark".to_vec()),
            ]),
        )
        .unwrap();
        assert_eq!(
            snapshot.blob_references().unwrap(),
            BTreeMap::from([("a".repeat(64), 42), ("b".repeat(64), 7)])
        );

        let left = BlobReference::new("c".repeat(64), 1)
            .unwrap()
            .encode()
            .unwrap();
        let right = BlobReference::new("c".repeat(64), 2)
            .unwrap()
            .encode()
            .unwrap();
        let conflicting = StorageSnapshot::from_entries(
            "dev.example.test",
            0,
            &BTreeMap::from([("blobs/left".into(), left), ("blobs/right".into(), right)]),
        )
        .unwrap();
        assert!(conflicting.blob_references().is_err());
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

        branch.prepare("dev.example.test", 2, LIMITS).unwrap();
        assert!(matches!(
            branch.prepare("dev.example.test", 3, LIMITS),
            Err(Error::SchemaMismatch {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn migrated_snapshot_advances_schema_without_mutating_its_source_branch() {
        let source =
            StorageSnapshot::from_entries("dev.example.test", 1, &BTreeMap::new()).unwrap();
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();
        branch
            .put("dev.example.test", "version", b"two", LIMITS)
            .unwrap();

        let migrated = branch.export_migrated_snapshot(1, 2, LIMITS).unwrap();

        assert_eq!(source.state_schema(), 1);
        assert_eq!(branch.export_snapshot().unwrap().state_schema(), 1);
        assert_eq!(migrated.state_schema(), 2);
    }

    #[test]
    fn migrated_snapshot_rejects_non_monotonic_or_mismatched_schemas() {
        let source =
            StorageSnapshot::from_entries("dev.example.test", 1, &BTreeMap::new()).unwrap();
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();

        assert!(matches!(
            branch.export_migrated_snapshot(0, 2, LIMITS),
            Err(Error::SchemaMismatch { .. })
        ));
        assert!(matches!(
            branch.export_migrated_snapshot(1, 1, LIMITS),
            Err(Error::InvalidSchemaTransition { .. })
        ));
    }

    #[test]
    fn migrated_snapshot_revalidates_the_complete_branch_under_one_quota() {
        let source =
            StorageSnapshot::from_entries("dev.example.test", 1, &BTreeMap::new()).unwrap();
        let branch = SnapshotStorage::from_snapshot(&source, "dev.example.test", LIMITS).unwrap();
        branch
            .put("dev.example.test", "value", &[0; 16], LIMITS)
            .unwrap();
        let lower = StorageLimits {
            max_bytes: 8,
            max_keys: LIMITS.max_keys,
            max_value_bytes: 8,
        };

        assert!(matches!(
            branch.export_migrated_snapshot(1, 2, lower),
            Err(Error::ValueTooLarge { .. } | Error::QuotaExceeded { .. })
        ));
    }
}

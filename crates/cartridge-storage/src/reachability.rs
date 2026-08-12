use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BlobReference, Error, MAX_BLOB_GC_ROOTS, Result};

pub const BLOB_REACHABILITY_FORMAT_VERSION: u32 = 1;
pub const MAX_BLOB_REACHABILITY_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_BLOB_REACHABILITY_SOURCES: usize = 256;

static MANIFEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlobReachabilitySourceKind {
    Capsule,
    Snapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReachabilitySource {
    pub kind: BlobReachabilitySourceKind,
    pub sha256: String,
}

impl BlobReachabilitySource {
    pub fn new(kind: BlobReachabilitySourceKind, sha256: impl Into<String>) -> Result<Self> {
        let source = Self {
            kind,
            sha256: sha256.into(),
        };
        validate_sha256(&source.sha256)?;
        Ok(source)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobReachabilityManifest {
    payload: BlobReachabilityPayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BlobReachabilityPayload {
    format_version: u32,
    sources: BTreeSet<BlobReachabilitySource>,
    objects: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobReachabilitySummary {
    pub format_version: u32,
    pub sources: usize,
    pub objects: usize,
    pub bytes: u64,
    pub payload_sha256: String,
}

impl BlobReachabilityManifest {
    pub fn new(
        sources: BTreeSet<BlobReachabilitySource>,
        objects: BTreeMap<String, u64>,
    ) -> Result<Self> {
        let payload = BlobReachabilityPayload {
            format_version: BLOB_REACHABILITY_FORMAT_VERSION,
            sources,
            objects,
        };
        let payload_sha256 = payload_digest(&payload)?;
        let manifest = Self {
            payload,
            payload_sha256,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BLOB_REACHABILITY_DOCUMENT_BYTES {
            return Err(Error::Corrupt(format!(
                "blob reachability manifest exceeds the {MAX_BLOB_REACHABILITY_DOCUMENT_BYTES} byte limit"
            )));
        }
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BLOB_REACHABILITY_DOCUMENT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
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
        let encoded = serde_json::to_vec_pretty(self)?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_BLOB_REACHABILITY_DOCUMENT_BYTES {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Corrupt(format!(
                "blob reachability manifest exceeds the {MAX_BLOB_REACHABILITY_DOCUMENT_BYTES} byte limit"
            )));
        }
        file.write_all(&encoded)?;
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
        if self.payload.format_version != BLOB_REACHABILITY_FORMAT_VERSION {
            return Err(Error::Corrupt(format!(
                "unsupported blob reachability format {}; expected {BLOB_REACHABILITY_FORMAT_VERSION}",
                self.payload.format_version
            )));
        }
        if self.payload.sources.is_empty()
            || self.payload.sources.len() > MAX_BLOB_REACHABILITY_SOURCES
        {
            return Err(Error::Corrupt(format!(
                "blob reachability manifest must contain between 1 and {MAX_BLOB_REACHABILITY_SOURCES} sources"
            )));
        }
        if self.payload.objects.len() > MAX_BLOB_GC_ROOTS {
            return Err(Error::Corrupt(format!(
                "blob reachability manifest exceeds the {MAX_BLOB_GC_ROOTS}-object limit"
            )));
        }
        for source in &self.payload.sources {
            validate_sha256(&source.sha256)?;
        }
        for (sha256, bytes) in &self.payload.objects {
            BlobReference::new(sha256, *bytes)?;
        }
        if self.payload_sha256 != payload_digest(&self.payload)? {
            return Err(Error::Corrupt(
                "blob reachability payload digest does not match its contents".into(),
            ));
        }
        Ok(())
    }

    pub fn summary(&self) -> Result<BlobReachabilitySummary> {
        self.validate()?;
        let bytes = self
            .payload
            .objects
            .values()
            .try_fold(0_u64, |total, bytes| {
                total
                    .checked_add(*bytes)
                    .ok_or_else(|| Error::Corrupt("blob reachability size overflowed".into()))
            })?;
        Ok(BlobReachabilitySummary {
            format_version: self.payload.format_version,
            sources: self.payload.sources.len(),
            objects: self.payload.objects.len(),
            bytes,
            payload_sha256: self.payload_sha256.clone(),
        })
    }

    #[must_use]
    pub fn sources(&self) -> &BTreeSet<BlobReachabilitySource> {
        &self.payload.sources
    }

    #[must_use]
    pub fn objects(&self) -> &BTreeMap<String, u64> {
        &self.payload.objects
    }
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Corrupt(
            "reachability source digest must be lowercase sha256".into(),
        ));
    }
    Ok(())
}

fn payload_digest(payload: &BlobReachabilityPayload) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}

fn temporary_path(directory: &Path) -> std::path::PathBuf {
    let sequence = MANIFEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".cartridge-reachability-{}-{sequence}.tmp",
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

    fn manifest() -> BlobReachabilityManifest {
        BlobReachabilityManifest::new(
            BTreeSet::from([
                BlobReachabilitySource::new(BlobReachabilitySourceKind::Snapshot, "a".repeat(64))
                    .unwrap(),
                BlobReachabilitySource::new(BlobReachabilitySourceKind::Capsule, "b".repeat(64))
                    .unwrap(),
            ]),
            BTreeMap::from([("c".repeat(64), 42), ("d".repeat(64), 7)]),
        )
        .unwrap()
    }

    #[test]
    fn manifests_round_trip_canonical_reachability() {
        let manifest = manifest();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded = BlobReachabilityManifest::from_slice(&encoded).unwrap();

        assert_eq!(decoded, manifest);
        assert_eq!(decoded.summary().unwrap().sources, 2);
        assert_eq!(decoded.summary().unwrap().objects, 2);
        assert_eq!(decoded.summary().unwrap().bytes, 49);
    }

    #[test]
    fn changed_and_oversized_manifests_are_rejected() {
        let mut value = serde_json::to_value(manifest()).unwrap();
        value["payload"]["objects"]["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"] =
            serde_json::json!(43);
        assert!(
            BlobReachabilityManifest::from_slice(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        assert!(
            BlobReachabilityManifest::from_slice(&vec![
                b' ';
                usize::try_from(
                    MAX_BLOB_REACHABILITY_DOCUMENT_BYTES
                )
                .unwrap()
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn manifest_writes_do_not_overwrite_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("roots.json");
        manifest().write_new(&path).unwrap();

        assert!(manifest().write_new(&path).is_err());
        assert_eq!(BlobReachabilityManifest::read(path).unwrap(), manifest());
    }
}

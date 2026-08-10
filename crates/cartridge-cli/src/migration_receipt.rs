use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECEIPT_FORMAT_VERSION: u32 = 1;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    payload: MigrationReceiptPayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceiptPayload {
    pub format_version: u32,
    pub cartridge_id: String,
    pub package_version: String,
    pub component_sha256: String,
    pub source_generation: u64,
    pub target_generation: u64,
    pub source_schema: u32,
    pub target_schema: u32,
    pub source_snapshot_sha256: String,
    pub target_snapshot_sha256: String,
}

impl MigrationReceipt {
    pub fn new(mut payload: MigrationReceiptPayload) -> Result<Self> {
        payload.format_version = RECEIPT_FORMAT_VERSION;
        let payload_sha256 = payload_digest(&payload)?;
        let receipt = Self {
            payload,
            payload_sha256,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(path)
            .with_context(|| format!("could not open receipt {}", path.display()))?
            .take(MAX_RECEIPT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("could not read receipt {}", path.display()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECEIPT_BYTES {
            bail!(
                "migration receipt {} exceeds the {} byte limit",
                path.display(),
                MAX_RECEIPT_BYTES
            );
        }
        Self::from_slice(&bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECEIPT_BYTES {
            bail!("migration receipt exceeds the {MAX_RECEIPT_BYTES} byte limit");
        }
        let receipt: Self = serde_json::from_slice(bytes).context("invalid migration receipt")?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn write_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECEIPT_BYTES {
            bail!("migration receipt exceeds the {MAX_RECEIPT_BYTES} byte limit");
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)?;
        }
        let directory = parent.unwrap_or_else(|| Path::new("."));
        let temporary = temporary_path(directory);
        let mut file = open_private_new(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        fs::remove_file(temporary)?;
        sync_directory(directory)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        let payload = &self.payload;
        if payload.format_version != RECEIPT_FORMAT_VERSION {
            bail!(
                "unsupported migration receipt format {}; expected {RECEIPT_FORMAT_VERSION}",
                payload.format_version
            );
        }
        if !valid_cartridge_id(&payload.cartridge_id) {
            bail!("migration receipt has an invalid cartridge id");
        }
        if payload.package_version.is_empty()
            || payload.package_version.len() > 64
            || !payload
                .package_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        {
            bail!("migration receipt has an invalid package version");
        }
        for (name, digest) in [
            ("component", &payload.component_sha256),
            ("source snapshot", &payload.source_snapshot_sha256),
            ("target snapshot", &payload.target_snapshot_sha256),
        ] {
            if !valid_sha256(digest) {
                bail!("migration receipt has an invalid {name} digest");
            }
        }
        if payload.target_generation
            != payload
                .source_generation
                .checked_add(1)
                .context("migration receipt generation overflowed")?
        {
            bail!("migration receipt target generation must follow its source generation");
        }
        if payload.source_schema >= payload.target_schema {
            bail!("migration receipt must describe an increasing schema transition");
        }
        if self.payload_sha256 != payload_digest(payload)? {
            bail!("migration receipt payload digest does not match its contents");
        }
        Ok(())
    }

    #[must_use]
    pub fn payload(&self) -> &MigrationReceiptPayload {
        &self.payload
    }

    #[must_use]
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }
}

fn payload_digest(payload: &MigrationReceiptPayload) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(payload)?)))
}

fn valid_cartridge_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn temporary_path(directory: &Path) -> PathBuf {
    let sequence = RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".cartridge-migration-receipt-{}-{sequence}.tmp",
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

    fn receipt() -> MigrationReceipt {
        MigrationReceipt::new(MigrationReceiptPayload {
            format_version: 0,
            cartridge_id: "dev.example.migration".into(),
            package_version: "1.2.0".into(),
            component_sha256: "a".repeat(64),
            source_generation: 7,
            target_generation: 8,
            source_schema: 1,
            target_schema: 3,
            source_snapshot_sha256: "b".repeat(64),
            target_snapshot_sha256: "c".repeat(64),
        })
        .unwrap()
    }

    #[test]
    fn receipts_round_trip_canonical_identity() {
        let receipt = receipt();
        let decoded = MigrationReceipt::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();

        assert_eq!(decoded.payload().source_generation, 7);
        assert_eq!(decoded.payload().target_generation, 8);
        assert_eq!(decoded.payload_sha256(), receipt.payload_sha256());
    }

    #[test]
    fn changed_receipt_payloads_are_rejected() {
        let mut value = serde_json::to_value(receipt()).unwrap();
        value["payload"]["target_schema"] = serde_json::json!(4);

        assert!(MigrationReceipt::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn receipts_reject_generation_gaps() {
        let mut payload = receipt().payload().clone();
        payload.target_generation = 10;

        assert!(MigrationReceipt::new(payload).is_err());
    }

    #[test]
    fn oversized_receipts_are_rejected_before_decoding() {
        let oversized = vec![b' '; usize::try_from(MAX_RECEIPT_BYTES).unwrap() + 1];

        assert!(MigrationReceipt::from_slice(&oversized).is_err());
    }
}

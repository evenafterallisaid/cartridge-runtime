use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::{Error, PackageManifest, Result, normalize_relative_path};

const MANIFEST_PATH: &str = "cartridge.toml";
const COMPONENT_PATH: &str = "component.wasm";

#[derive(Clone, Copy, Debug)]
pub struct PackageLimits {
    pub manifest_bytes: u64,
    pub component_bytes: u64,
    pub asset_bytes: u64,
    pub total_bytes: u64,
    pub entries: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            manifest_bytes: 1024 * 1024,
            component_bytes: 64 * 1024 * 1024,
            asset_bytes: 32 * 1024 * 1024,
            total_bytes: 256 * 1024 * 1024,
            entries: 4096,
        }
    }
}

#[derive(Debug)]
pub struct CartridgeArchive {
    pub manifest: PackageManifest,
    pub component: Vec<u8>,
    pub assets: BTreeMap<String, Vec<u8>>,
}

impl CartridgeArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(path, PackageLimits::default())
    }

    pub fn open_with_limits(path: impl AsRef<Path>, limits: PackageLimits) -> Result<Self> {
        let file = File::open(path)?;
        let mut zip = ZipArchive::new(file)?;
        if zip.len() > limits.entries {
            return Err(Error::Archive(format!(
                "archive contains {} entries; maximum is {}",
                zip.len(),
                limits.entries
            )));
        }

        let mut entries = BTreeMap::new();
        let mut total_size = 0_u64;
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index)?;
            if entry.is_dir() {
                continue;
            }
            let name = normalize_relative_path(entry.name())?;
            if entries.contains_key(&name) {
                return Err(Error::Archive(format!("duplicate archive entry: {name}")));
            }

            let limit = match name.as_str() {
                MANIFEST_PATH => limits.manifest_bytes,
                COMPONENT_PATH => limits.component_bytes,
                _ if name.starts_with("assets/") => limits.asset_bytes,
                _ => return Err(Error::Archive(format!("unexpected archive entry: {name}"))),
            };
            if entry.size() > limit {
                return Err(Error::Archive(format!(
                    "archive entry is too large: {name}"
                )));
            }
            let remaining = limits.total_bytes.saturating_sub(total_size);
            if entry.size() > remaining {
                return Err(Error::Archive(
                    "archive exceeds the total uncompressed size limit".into(),
                ));
            }
            let declared_size = entry.size();
            let bytes = read_bounded_entry(&mut entry, declared_size, limit.min(remaining), &name)?;
            total_size =
                total_size
                    .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                        Error::Archive(format!("archive entry is too large: {name}"))
                    })?)
                    .ok_or_else(|| Error::Archive("archive size overflow".into()))?;
            entries.insert(name, bytes);
        }

        let manifest_bytes = entries
            .remove(MANIFEST_PATH)
            .ok_or_else(|| Error::Archive(format!("missing {MANIFEST_PATH}")))?;
        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|_| Error::Manifest("manifest must be UTF-8".into()))?;
        let manifest: PackageManifest = toml::from_str(manifest_text)?;
        manifest.validate()?;

        let component = entries
            .remove(COMPONENT_PATH)
            .ok_or_else(|| Error::Archive(format!("missing {COMPONENT_PATH}")))?;
        verify_component(&manifest, &component)?;

        let assets: BTreeMap<_, _> = entries
            .into_iter()
            .map(|(name, bytes)| {
                let path = name
                    .strip_prefix("assets/")
                    .expect("entry names were checked above")
                    .to_owned();
                (path, bytes)
            })
            .collect();
        verify_assets(&manifest, &assets)?;

        Ok(Self {
            manifest,
            component,
            assets,
        })
    }
}

fn read_bounded_entry(
    reader: &mut impl Read,
    declared_size: u64,
    limit: u64,
    name: &str,
) -> Result<Vec<u8>> {
    let capacity = usize::try_from(declared_size.min(limit))
        .map_err(|_| Error::Archive(format!("archive entry is too large: {name}")))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let actual_size = u64::try_from(bytes.len())
        .map_err(|_| Error::Archive(format!("archive entry is too large: {name}")))?;
    if actual_size > limit {
        return Err(Error::Archive(format!(
            "archive entry exceeded its decompressed size limit: {name}"
        )));
    }
    if actual_size != declared_size {
        return Err(Error::Archive(format!(
            "archive entry size does not match its contents: {name}"
        )));
    }
    Ok(bytes)
}

fn verify_component(manifest: &PackageManifest, component: &[u8]) -> Result<()> {
    if manifest.integrity.component_sha256.is_empty() {
        return Err(Error::Integrity("component digest is missing".into()));
    }
    let actual = hex::encode(Sha256::digest(component));
    if !actual.eq_ignore_ascii_case(&manifest.integrity.component_sha256) {
        return Err(Error::Integrity(format!(
            "component digest mismatch: expected {}, got {actual}",
            manifest.integrity.component_sha256
        )));
    }
    Ok(())
}

fn verify_assets(manifest: &PackageManifest, assets: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if manifest.integrity.assets_sha256.len() != assets.len() {
        return Err(Error::Integrity(format!(
            "asset digest set contains {} entries but the package contains {} assets",
            manifest.integrity.assets_sha256.len(),
            assets.len()
        )));
    }
    for (path, bytes) in assets {
        let expected = manifest
            .integrity
            .assets_sha256
            .get(path)
            .ok_or_else(|| Error::Integrity(format!("asset digest is missing: {path}")))?;
        let actual = hex::encode(Sha256::digest(bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::Integrity(format!(
                "asset digest mismatch for {path}: expected {expected}, got {actual}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CartridgeMetadata, Integrity, Permissions, RuntimeLimits, Services, StateConfig};
    use std::io::{Cursor, Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    #[test]
    fn rejects_a_component_that_changed_after_packing() {
        let original = b"original component";
        let manifest = PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.integrity".into(),
                name: "Integrity".into(),
                version: "0.1.0".into(),
                description: String::new(),
            },
            permissions: Permissions::default(),
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity {
                component_sha256: hex::encode(Sha256::digest(original)),
                assets_sha256: BTreeMap::new(),
            },
        };

        assert!(verify_component(&manifest, original).is_ok());
        assert!(verify_component(&manifest, b"tampered component").is_err());
    }

    #[test]
    fn rejects_an_asset_that_changed_after_packing() {
        let original = b"original asset".to_vec();
        let mut manifest = PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.assets".into(),
                name: "Assets".into(),
                version: "0.1.0".into(),
                description: String::new(),
            },
            permissions: Permissions {
                assets: true,
                ..Permissions::default()
            },
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity::default(),
        };
        manifest
            .integrity
            .assets_sha256
            .insert("message.txt".into(), hex::encode(Sha256::digest(&original)));

        let valid = BTreeMap::from([("message.txt".into(), original)]);
        let tampered = BTreeMap::from([("message.txt".into(), b"changed".to_vec())]);

        assert!(verify_assets(&manifest, &valid).is_ok());
        assert!(verify_assets(&manifest, &tampered).is_err());
    }

    #[test]
    fn bounded_reads_reject_more_data_than_the_declared_size() {
        let mut input = std::io::Cursor::new(vec![0_u8; 1024]);

        assert!(matches!(
            read_bounded_entry(&mut input, 1, 512, "component.wasm"),
            Err(Error::Archive(message)) if message.contains("decompressed size limit")
        ));
    }

    #[test]
    fn bounded_reads_reject_declared_size_mismatches() {
        let mut input = std::io::Cursor::new(vec![0_u8; 16]);

        assert!(matches!(
            read_bounded_entry(&mut input, 1, 512, "component.wasm"),
            Err(Error::Archive(message)) if message.contains("does not match")
        ));
    }

    #[test]
    fn zip_metadata_cannot_hide_inflated_bytes() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                COMPONENT_PATH,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![0_u8; 64 * 1024]).unwrap();
        let mut bytes = writer.finish().unwrap().into_inner();

        let local = bytes
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        bytes[local + 22..local + 26].copy_from_slice(&1_u32.to_le_bytes());
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        bytes[central + 24..central + 28].copy_from_slice(&1_u32.to_le_bytes());

        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut entry = archive.by_index(0).unwrap();
        assert_eq!(entry.size(), 1);
        assert!(matches!(
            read_bounded_entry(&mut entry, 1, 1024, COMPONENT_PATH),
            Err(Error::Archive(message)) if message.contains("decompressed size limit")
        ));
    }
}

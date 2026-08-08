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
            total_size = total_size
                .checked_add(entry.size())
                .ok_or_else(|| Error::Archive("archive size overflow".into()))?;
            if total_size > limits.total_bytes {
                return Err(Error::Archive(
                    "archive exceeds the total uncompressed size limit".into(),
                ));
            }

            let capacity = usize::try_from(entry.size())
                .map_err(|_| Error::Archive(format!("archive entry is too large: {name}")))?;
            let mut bytes = Vec::with_capacity(capacity);
            entry.read_to_end(&mut bytes)?;
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
    use crate::{CartridgeMetadata, Integrity, Permissions, RuntimeLimits, Services};

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
}

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::Path,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::{
    Error, PackageManifest, Result, manifest::asset_integrity_root, normalize_relative_path,
};

const MANIFEST_PATH: &str = "cartridge.toml";
const COMPONENT_PATH: &str = "component.wasm";

#[derive(Clone, Copy, Debug)]
pub struct PackageLimits {
    pub archive_bytes: u64,
    pub manifest_bytes: u64,
    pub component_bytes: u64,
    pub asset_bytes: u64,
    pub total_bytes: u64,
    pub entries: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            archive_bytes: 160 * 1024 * 1024,
            manifest_bytes: 1024 * 1024,
            component_bytes: 32 * 1024 * 1024,
            asset_bytes: 16 * 1024 * 1024,
            total_bytes: 128 * 1024 * 1024,
            entries: 1024,
        }
    }
}

#[derive(Debug)]
pub struct CartridgeArchive {
    pub package_sha256: String,
    pub package_bytes: u64,
    pub manifest: PackageManifest,
    pub component: Vec<u8>,
    pub assets: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssetVerification {
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub assets_root_sha256: String,
}

impl CartridgeArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limits(path, PackageLimits::default())
    }

    pub fn open_with_limits(path: impl AsRef<Path>, limits: PackageLimits) -> Result<Self> {
        let file = File::open(path)?;
        Self::open_reader(file, limits)
    }

    pub fn open_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::open_reader(Cursor::new(bytes), PackageLimits::default())
    }

    fn open_reader(mut reader: impl Read + Seek, limits: PackageLimits) -> Result<Self> {
        let (bytes, package_bytes, package_sha256) =
            package_snapshot(&mut reader, limits.archive_bytes)?;
        let mut zip = ZipArchive::new(Cursor::new(bytes))?;
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
                    .ok_or_else(|| Error::Archive(format!("unexpected archive entry: {name}")))?
                    .to_owned();
                Ok((path, bytes))
            })
            .collect::<Result<_>>()?;
        verify_assets(&manifest, &assets)?;

        Ok(Self {
            package_sha256,
            package_bytes,
            manifest,
            component,
            assets,
        })
    }

    pub fn verify_asset(path: impl AsRef<Path>, asset_path: &str) -> Result<AssetVerification> {
        let limits = PackageLimits::default();
        let requested = normalize_relative_path(asset_path)?;
        let requested_entry = format!("assets/{requested}");
        let file = File::open(path)?;
        let mut zip = ZipArchive::new(file)?;
        let entries = scan_selective_entries(&mut zip, limits, &requested_entry)?;
        let manifest = {
            let mut entry = zip.by_index(entries.manifest)?;
            let declared = entry.size();
            let bytes =
                read_bounded_entry(&mut entry, declared, limits.manifest_bytes, MANIFEST_PATH)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::Manifest("manifest must be UTF-8".into()))?;
            let manifest: PackageManifest = toml::from_str(text)?;
            manifest.validate()?;
            manifest
        };
        let declared_assets: BTreeSet<_> =
            manifest.integrity.assets_sha256.keys().cloned().collect();
        if entries.assets != declared_assets {
            return Err(Error::Integrity(
                "archive asset names do not match the manifest".into(),
            ));
        }
        if manifest.integrity.assets_root_sha256.is_empty() {
            return Err(Error::Integrity(
                "selective asset verification requires an asset integrity root".into(),
            ));
        }
        let expected = manifest
            .integrity
            .assets_sha256
            .get(&requested)
            .ok_or_else(|| Error::Archive(format!("asset not found: {requested}")))?;
        let requested_index = entries
            .requested
            .ok_or_else(|| Error::Archive(format!("asset not found: {requested}")))?;
        let (bytes, sha256) = {
            let mut entry = zip.by_index(requested_index)?;
            let declared = entry.size();
            let bytes =
                read_bounded_entry(&mut entry, declared, limits.asset_bytes, &requested_entry)?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            (declared, sha256)
        };
        if !sha256.eq_ignore_ascii_case(expected) {
            return Err(Error::Integrity(format!(
                "asset digest mismatch for {requested}"
            )));
        }
        Ok(AssetVerification {
            cartridge_id: manifest.cartridge.id,
            cartridge_version: manifest.cartridge.version,
            path: requested,
            bytes,
            sha256,
            assets_root_sha256: manifest.integrity.assets_root_sha256,
        })
    }
}

fn package_snapshot(reader: &mut (impl Read + Seek), limit: u64) -> Result<(Vec<u8>, u64, String)> {
    let package_bytes = reader.seek(SeekFrom::End(0))?;
    if package_bytes == 0 || package_bytes > limit {
        return Err(Error::Archive(format!(
            "archive byte length must be between 1 and {limit}"
        )));
    }
    reader.seek(SeekFrom::Start(0))?;
    let capacity = usize::try_from(package_bytes)
        .map_err(|_| Error::Archive("archive is too large for this platform".into()))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != package_bytes {
        return Err(Error::Archive(
            "archive byte length changed while reading".into(),
        ));
    }
    let package_sha256 = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, package_bytes, package_sha256))
}

struct SelectiveEntries {
    manifest: usize,
    requested: Option<usize>,
    assets: BTreeSet<String>,
}

fn scan_selective_entries(
    zip: &mut ZipArchive<File>,
    limits: PackageLimits,
    requested: &str,
) -> Result<SelectiveEntries> {
    if zip.len() > limits.entries {
        return Err(Error::Archive(format!(
            "archive contains {} entries; maximum is {}",
            zip.len(),
            limits.entries
        )));
    }
    let mut seen = BTreeSet::new();
    let mut assets = BTreeSet::new();
    let mut manifest = None;
    let mut component_found = false;
    let mut requested_index = None;
    let mut total_size = 0_u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let name = normalize_relative_path(entry.name())?;
        if !seen.insert(name.clone()) {
            return Err(Error::Archive(format!("duplicate archive entry: {name}")));
        }
        let limit = match name.as_str() {
            MANIFEST_PATH => {
                manifest = Some(index);
                limits.manifest_bytes
            }
            COMPONENT_PATH => {
                component_found = true;
                limits.component_bytes
            }
            _ if name.starts_with("assets/") => {
                assets.insert(name["assets/".len()..].to_owned());
                if name == requested {
                    requested_index = Some(index);
                }
                limits.asset_bytes
            }
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
    }
    if !component_found {
        return Err(Error::Archive(format!("missing {COMPONENT_PATH}")));
    }
    Ok(SelectiveEntries {
        manifest: manifest.ok_or_else(|| Error::Archive(format!("missing {MANIFEST_PATH}")))?,
        requested: requested_index,
        assets,
    })
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
    if !manifest.integrity.assets_root_sha256.is_empty() {
        let actual = asset_integrity_root(&manifest.integrity.assets_sha256)?;
        if !actual.eq_ignore_ascii_case(&manifest.integrity.assets_root_sha256) {
            return Err(Error::Integrity(
                "asset integrity root does not match the manifest".into(),
            ));
        }
    }
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

    fn package_bytes(component: &[u8]) -> Vec<u8> {
        let manifest = PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.archive".into(),
                name: "Archive".into(),
                version: "0.1.0".into(),
                description: String::new(),
            },
            permissions: Permissions::default(),
            http: cartridge_network::HttpPolicy::default(),
            compatibility: crate::Compatibility::default(),
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity {
                component_sha256: hex::encode(Sha256::digest(component)),
                assets_sha256: BTreeMap::new(),
                assets_root_sha256: String::new(),
            },
        };
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file(MANIFEST_PATH, options).unwrap();
        writer
            .write_all(toml::to_string(&manifest).unwrap().as_bytes())
            .unwrap();
        writer.start_file(COMPONENT_PATH, options).unwrap();
        writer.write_all(component).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn records_the_identity_of_the_exact_package_bytes() {
        let bytes = package_bytes(b"component");
        let expected_digest = hex::encode(Sha256::digest(&bytes));
        let archive = CartridgeArchive::open_bytes(bytes.clone()).unwrap();

        assert_eq!(archive.package_bytes, bytes.len() as u64);
        assert_eq!(archive.package_sha256, expected_digest);
    }

    #[test]
    fn rejects_an_archive_over_the_compressed_size_limit() {
        let limits = PackageLimits {
            archive_bytes: 3,
            ..PackageLimits::default()
        };

        assert!(matches!(
            CartridgeArchive::open_reader(Cursor::new(vec![0_u8; 4]), limits),
            Err(Error::Archive(message)) if message.contains("archive byte length")
        ));
    }

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
            http: cartridge_network::HttpPolicy::default(),
            compatibility: crate::Compatibility::default(),
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity {
                component_sha256: hex::encode(Sha256::digest(original)),
                assets_sha256: BTreeMap::new(),
                assets_root_sha256: String::new(),
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
            http: cartridge_network::HttpPolicy::default(),
            compatibility: crate::Compatibility::default(),
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

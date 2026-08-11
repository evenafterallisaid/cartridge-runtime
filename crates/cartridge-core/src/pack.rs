use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    Error, PackageLimits, PackageManifest, Result, manifest::asset_integrity_root,
    normalize_relative_path,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct PackOptions {
    pub manifest: PathBuf,
    pub component: PathBuf,
    pub assets: Option<PathBuf>,
    pub output: PathBuf,
}

pub fn pack(options: &PackOptions) -> Result<PackageManifest> {
    let limits = PackageLimits::default();
    if options.output.extension().and_then(|value| value.to_str()) != Some("cartridge") {
        return Err(Error::Archive(
            "output file must use the .cartridge extension".into(),
        ));
    }
    let manifest_bytes = read_bounded_file(&options.manifest, limits.manifest_bytes, "manifest")?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| Error::Manifest("manifest must be UTF-8".into()))?;
    let mut manifest: PackageManifest = toml::from_str(manifest_text)?;
    manifest.validate()?;

    let component = read_bounded_file(&options.component, limits.component_bytes, "component")?;
    if component.len() < 8 || &component[..4] != b"\0asm" {
        return Err(Error::Archive(
            "component is not a WebAssembly binary".into(),
        ));
    }
    manifest.integrity.component_sha256 = hex::encode(Sha256::digest(&component));

    let mut total_bytes = u64::try_from(manifest_bytes.len() + component.len())
        .map_err(|_| Error::Archive("package input size overflow".into()))?;
    if total_bytes > limits.total_bytes {
        return Err(Error::Archive(
            "package inputs exceed the total uncompressed size limit".into(),
        ));
    }
    let assets = if let Some(root) = &options.assets {
        collect_assets(root, limits, &mut total_bytes)?
    } else {
        BTreeMap::new()
    };
    if !assets.is_empty() && !manifest.permissions.assets {
        return Err(Error::Manifest(
            "the package contains assets but permissions.assets is false".into(),
        ));
    }
    manifest.integrity.assets_sha256 = assets
        .iter()
        .map(|(path, bytes)| (path.clone(), hex::encode(Sha256::digest(bytes))))
        .collect();
    manifest.integrity.assets_root_sha256 =
        asset_integrity_root(&manifest.integrity.assets_sha256)?;

    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_path(&options.output);
    let result = write_archive(&temporary, &manifest, &component, &assets);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::hard_link(&temporary, &options.output) {
        let _ = fs::remove_file(&temporary);
        return Err(Error::Io(error));
    }
    fs::remove_file(&temporary)?;
    Ok(manifest)
}

fn collect_assets(
    root: &Path,
    limits: PackageLimits,
    total_bytes: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>> {
    if !root.is_dir() {
        return Err(Error::Archive(format!(
            "asset path is not a directory: {}",
            root.display()
        )));
    }

    let mut assets = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| Error::Archive(error.to_string()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        if assets.len() >= limits.entries.saturating_sub(2) {
            return Err(Error::Archive(format!(
                "package contains more than {} asset files",
                limits.entries.saturating_sub(2)
            )));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|error| Error::Archive(error.to_string()))?;
        let path = relative
            .components()
            .map(|part| {
                part.as_os_str().to_str().ok_or_else(|| {
                    Error::Archive(format!(
                        "asset path is not valid UTF-8: {}",
                        entry.path().display()
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        let path = normalize_relative_path(&path)?;
        if assets.contains_key(&path) {
            return Err(Error::Archive(format!("duplicate asset path: {path}")));
        }
        let bytes = read_bounded_file(entry.path(), limits.asset_bytes, "asset")?;
        *total_bytes = total_bytes
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| Error::Archive("package input size overflow".into()))?,
            )
            .ok_or_else(|| Error::Archive("package input size overflow".into()))?;
        if *total_bytes > limits.total_bytes {
            return Err(Error::Archive(
                "package inputs exceed the total uncompressed size limit".into(),
            ));
        }
        assets.insert(path, bytes);
    }
    Ok(assets)
}

fn read_bounded_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    if fs::metadata(path)?.len() > limit {
        return Err(Error::Archive(format!(
            "{label} exceeds the {limit}-byte input limit: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(Error::Archive(format!(
            "{label} exceeded the {limit}-byte input limit while reading: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn write_archive(
    path: &Path,
    manifest: &PackageManifest,
    component: &[u8],
    assets: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    zip.start_file("cartridge.toml", options)?;
    zip.write_all(toml::to_string_pretty(manifest)?.as_bytes())?;
    zip.start_file("component.wasm", options)?;
    zip.write_all(component)?;
    for (name, bytes) in assets {
        zip.start_file(format!("assets/{name}"), options)?;
        zip.write_all(bytes)?;
    }
    zip.finish()?.flush()?;
    Ok(())
}

fn temporary_path(output: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut path = output.as_os_str().to_owned();
    path.push(format!(".{}-{sequence}.tmp", std::process::id()));
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn rejects_non_wasm_component() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("Cartridge.toml");
        let component = directory.path().join("bad.wasm");
        File::create(&manifest)
            .unwrap()
            .write_all(
                br#"format_version = 1
[cartridge]
id = "dev.example.bad"
name = "Bad"
version = "0.1.0"
"#,
            )
            .unwrap();
        File::create(&component)
            .unwrap()
            .write_all(b"not wasm")
            .unwrap();

        let result = pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output: directory.path().join("bad.cartridge"),
        });
        assert!(result.is_err());
    }

    #[test]
    fn packing_does_not_overwrite_an_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("Cartridge.toml");
        let component = directory.path().join("component.wasm");
        let output = directory.path().join("kept.cartridge");
        File::create(&manifest)
            .unwrap()
            .write_all(
                br#"format_version = 1
[cartridge]
id = "dev.example.safe-pack"
name = "Safe Pack"
version = "0.1.0"
"#,
            )
            .unwrap();
        File::create(&component)
            .unwrap()
            .write_all(b"\0asm\x01\0\0\0")
            .unwrap();
        fs::write(&output, b"keep me").unwrap();

        let result = pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output: output.clone(),
        });

        assert!(result.is_err());
        assert_eq!(fs::read(output).unwrap(), b"keep me");
    }

    #[test]
    fn oversized_pack_inputs_are_rejected_before_reading() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("oversized.toml");
        let component = directory.path().join("component.wasm");
        let output = directory.path().join("oversized.cartridge");
        File::create(&manifest)
            .unwrap()
            .set_len(PackageLimits::default().manifest_bytes + 1)
            .unwrap();
        fs::write(&component, b"\0asm\x01\0\0\0").unwrap();

        let error = pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output,
        })
        .unwrap_err();

        assert!(error.to_string().contains("input limit"));
    }

    #[test]
    fn packed_assets_support_selective_verification() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("Cartridge.toml");
        let component = directory.path().join("component.wasm");
        let assets = directory.path().join("assets");
        let output = directory.path().join("assets.cartridge");
        fs::create_dir(&assets).unwrap();
        fs::write(
            &manifest,
            br#"format_version = 1
[cartridge]
id = "dev.example.assets"
name = "Assets"
version = "0.1.0"
[permissions]
assets = true
"#,
        )
        .unwrap();
        fs::write(&component, b"\0asm\x01\0\0\0").unwrap();
        fs::write(assets.join("message.txt"), b"hello").unwrap();

        let packed = pack(&PackOptions {
            manifest,
            component,
            assets: Some(assets),
            output: output.clone(),
        })
        .unwrap();
        let report = crate::CartridgeArchive::verify_asset(&output, "message.txt").unwrap();

        assert!(!packed.integrity.assets_root_sha256.is_empty());
        assert_eq!(report.bytes, 5);
        assert_eq!(report.path, "message.txt");
        assert_eq!(
            report.assets_root_sha256,
            packed.integrity.assets_root_sha256
        );

        let tampered_output = directory.path().join("tampered.cartridge");
        let tampered_assets = BTreeMap::from([("message.txt".into(), b"changed".to_vec())]);
        write_archive(
            &tampered_output,
            &packed,
            b"\0asm\x01\0\0\0",
            &tampered_assets,
        )
        .unwrap();
        assert!(crate::CartridgeArchive::verify_asset(&tampered_output, "message.txt").is_err());
    }
}

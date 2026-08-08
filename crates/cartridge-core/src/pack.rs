use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{Error, PackageManifest, Result, normalize_relative_path};

#[derive(Clone, Debug)]
pub struct PackOptions {
    pub manifest: PathBuf,
    pub component: PathBuf,
    pub assets: Option<PathBuf>,
    pub output: PathBuf,
}

pub fn pack(options: &PackOptions) -> Result<PackageManifest> {
    if options.output.extension().and_then(|value| value.to_str()) != Some("cartridge") {
        return Err(Error::Archive(
            "output file must use the .cartridge extension".into(),
        ));
    }
    let manifest_text = fs::read_to_string(&options.manifest)?;
    let mut manifest: PackageManifest = toml::from_str(&manifest_text)?;
    manifest.validate()?;

    let component = fs::read(&options.component)?;
    if component.len() < 8 || &component[..4] != b"\0asm" {
        return Err(Error::Archive(
            "component is not a WebAssembly binary".into(),
        ));
    }
    manifest.integrity.component_sha256 = hex::encode(Sha256::digest(&component));

    let assets = if let Some(root) = &options.assets {
        collect_assets(root)?
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

    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_path(&options.output);
    let result = write_archive(&temporary, &manifest, &component, &assets);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    fs::rename(&temporary, &options.output)?;
    Ok(manifest)
}

fn collect_assets(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
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
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|error| Error::Archive(error.to_string()))?;
        let path = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let path = normalize_relative_path(&path)?;
        assets.insert(path, fs::read(entry.path())?);
    }
    Ok(assets)
}

fn write_archive(
    path: &Path,
    manifest: &PackageManifest,
    component: &[u8],
    assets: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let file = File::create(path)?;
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
    let mut path = output.as_os_str().to_owned();
    path.push(".tmp");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

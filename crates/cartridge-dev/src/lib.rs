use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use cartridge_core::{PackageManifest, Permissions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROJECT_FORMAT_VERSION: u32 = 1;
pub const MAX_PROJECT_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PROJECT_FILES: usize = 10_000;
pub const MAX_PROJECT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    Rust,
    TinyGo,
    JavaScript,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub format_version: u32,
    pub language: String,
    pub build: Vec<String>,
    pub component: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectReport {
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub language: String,
    pub files: usize,
    pub source_bytes: u64,
    pub asset_bytes: u64,
    pub requested_permissions: Vec<String>,
    pub component: PathBuf,
    pub component_exists: bool,
    pub component_bytes: u64,
    pub fuel_budget: u64,
    pub memory_budget_bytes: usize,
    pub timeout_budget_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReloadDecision {
    Fresh,
    PreserveState,
    Migrate { from: u32, to: u32 },
    Reject { reason: String },
}

pub fn create_project(path: &Path, name: &str, language: Language) -> Result<(), String> {
    validate_project_name(name)?;
    if path.exists() {
        return Err(format!("project path already exists: {}", path.display()));
    }
    fs::create_dir(path).map_err(|error| error.to_string())?;
    write_template(path, name, language)
}

pub fn inspect_project(path: &Path) -> Result<(ProjectConfig, PackageManifest), String> {
    let config_bytes = read_bounded(&path.join("Cartridge.dev.toml"), MAX_PROJECT_FILE_BYTES)?;
    let config: ProjectConfig = toml::from_str(
        std::str::from_utf8(&config_bytes).map_err(|_| "Cartridge.dev.toml is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    validate_config(&config)?;

    let manifest_bytes = read_bounded(&path.join("Cartridge.toml"), MAX_PROJECT_FILE_BYTES)?;
    let manifest: PackageManifest = toml::from_str(
        std::str::from_utf8(&manifest_bytes).map_err(|_| "Cartridge.toml is not UTF-8")?,
    )
    .map_err(|error| error.to_string())?;
    manifest.validate().map_err(|error| error.to_string())?;
    Ok((config, manifest))
}

pub fn profile_project(path: &Path) -> Result<ProjectReport, String> {
    let (config, manifest) = inspect_project(path)?;
    let component = safe_join(path, &config.component)?;
    let mut files = 0usize;
    let mut source_bytes = 0u64;
    let mut asset_bytes = 0u64;
    let mut total_bytes = 0u64;
    visit_project(path, path, &mut |relative, bytes| {
        files = files
            .checked_add(1)
            .ok_or_else(|| "project file count overflow".to_string())?;
        if files > MAX_PROJECT_FILES {
            return Err(format!(
                "project exceeds the {MAX_PROJECT_FILES}-file limit"
            ));
        }
        if relative.starts_with("target/") || relative.starts_with(".git/") {
            return Ok(());
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| "project size overflow".to_string())?;
        if total_bytes > MAX_PROJECT_TOTAL_BYTES {
            return Err(format!(
                "project exceeds the {MAX_PROJECT_TOTAL_BYTES}-byte total limit"
            ));
        }
        if relative.starts_with("assets/") {
            asset_bytes = asset_bytes
                .checked_add(bytes)
                .ok_or_else(|| "asset size overflow".to_string())?;
        } else {
            source_bytes = source_bytes
                .checked_add(bytes)
                .ok_or_else(|| "source size overflow".to_string())?;
        }
        Ok(())
    })?;
    Ok(ProjectReport {
        cartridge_id: manifest.cartridge.id,
        cartridge_version: manifest.cartridge.version,
        language: config.language,
        files,
        source_bytes,
        asset_bytes,
        requested_permissions: permission_names(&manifest.permissions),
        component_exists: component.is_file(),
        component_bytes: component.metadata().map_or(0, |value| value.len()),
        fuel_budget: manifest.runtime.fuel,
        memory_budget_bytes: manifest.runtime.memory_bytes,
        timeout_budget_ms: manifest.runtime.timeout_ms,
        component,
    })
}

#[must_use]
pub fn reload_decision(previous: &PackageManifest, next: &PackageManifest) -> ReloadDecision {
    if previous.cartridge.id != next.cartridge.id {
        return ReloadDecision::Reject {
            reason: "cartridge id changed".into(),
        };
    }
    if !previous.permissions.storage || !next.permissions.storage {
        return ReloadDecision::Fresh;
    }
    if previous.state.schema == next.state.schema {
        return ReloadDecision::PreserveState;
    }
    match next.migration_plan(previous.state.schema) {
        Ok(_) => ReloadDecision::Migrate {
            from: previous.state.schema,
            to: next.state.schema,
        },
        Err(error) => ReloadDecision::Reject {
            reason: error.to_string(),
        },
    }
}

pub fn source_fingerprint(path: &Path) -> Result<String, String> {
    let mut files = BTreeSet::new();
    let mut total_bytes = 0u64;
    visit_project(path, path, &mut |relative, _| {
        if !relative.starts_with("target/") && !relative.starts_with(".git/") {
            files.insert(relative.to_owned());
        }
        Ok(())
    })?;
    let mut digest = Sha256::new();
    for name in &files {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        let bytes = read_bounded(&path.join(name), MAX_PROJECT_FILE_BYTES)?;
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "project size overflow".to_string())?;
        if total_bytes > MAX_PROJECT_TOTAL_BYTES {
            return Err(format!(
                "project exceeds the {MAX_PROJECT_TOTAL_BYTES}-byte total limit"
            ));
        }
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(hex_digest(digest.finalize()))
}

#[must_use]
pub fn manifest_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Cartridge manifest",
        "type": "object",
        "required": ["format_version", "cartridge"],
        "additionalProperties": false,
        "properties": {
            "format_version": {"const": 1},
            "cartridge": {
                "type": "object",
                "required": ["id", "name", "version"],
                "additionalProperties": false,
                "properties": {
                    "id": {"type": "string", "maxLength": 128},
                    "name": {"type": "string", "maxLength": 80},
                    "version": {"type": "string"},
                    "description": {"type": "string", "maxLength": 240}
                }
            },
            "permissions": {"type": "object"},
            "runtime": {"type": "object"},
            "state": {"type": "object"},
            "dependencies": {"type": "array"},
            "services": {"type": "object"},
            "integrity": {"type": "object"}
        }
    })
}

fn write_template(path: &Path, name: &str, language: Language) -> Result<(), String> {
    let id = format!("dev.local.{}", name.replace('_', "-"));
    write_new(
        &path.join("Cartridge.toml"),
        format!(
            "format_version = 1\n\n[cartridge]\nid = \"{id}\"\nname = \"{name}\"\nversion = \"0.1.0\"\ndescription = \"\"\n"
        )
        .as_bytes(),
    )?;
    write_new(&path.join(".gitignore"), b"/target\n/dist\n*.cartridge\n")?;
    match language {
        Language::Rust => write_rust_template(path, name),
        Language::TinyGo => write_tinygo_template(path, name),
        Language::JavaScript => write_javascript_template(path, name),
    }
}

fn write_rust_template(path: &Path, name: &str) -> Result<(), String> {
    fs::create_dir(path.join("src")).map_err(|error| error.to_string())?;
    write_new(
        &path.join("Cartridge.dev.toml"),
        format!(
            "format_version = 1\nlanguage = \"rust\"\nbuild = [\"cargo\", \"build\", \"--release\", \"--target\", \"wasm32-wasip2\"]\ncomponent = \"target/wasm32-wasip2/release/{}.wasm\"\n",
            name.replace('-', "_")
        )
        .as_bytes(),
    )?;
    write_new(
        &path.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nwit-bindgen = \"0.60.0\"\n").as_bytes(),
    )?;
    write_new(
        &path.join("src/lib.rs"),
        b"mod bindings {\n    wit_bindgen::generate!({ path: \"wit\", world: \"cartridge\" });\n\n    use super::CartridgeGuest;\n    export!(CartridgeGuest);\n}\n\nstruct CartridgeGuest;\n\nimpl bindings::Guest for CartridgeGuest {\n    fn run(_args: Vec<String>) -> Result<String, String> {\n        Ok(\"hello from cartridge\".into())\n    }\n}\n",
    )?;
    write_wit(path)
}

fn write_tinygo_template(path: &Path, _name: &str) -> Result<(), String> {
    write_new(&path.join("Cartridge.dev.toml"), b"format_version = 1\nlanguage = \"tinygo\"\nbuild = [\"tinygo\", \"build\", \"-target=wasi\", \"-o\", \"dist/component.wasm\", \".\"]\ncomponent = \"dist/component.wasm\"\n")?;
    write_new(
        &path.join("go.mod"),
        b"module cartridge.local/guest\n\ngo 1.23\n",
    )?;
    write_new(&path.join("main.go"), b"package main\n\nfunc main() {}\n")?;
    write_wit(path)
}

fn write_javascript_template(path: &Path, _name: &str) -> Result<(), String> {
    write_new(&path.join("Cartridge.dev.toml"), b"format_version = 1\nlanguage = \"javascript\"\nbuild = [\"npm\", \"run\", \"build\"]\ncomponent = \"dist/component.wasm\"\n")?;
    write_new(&path.join("package.json"), b"{\n  \"private\": true,\n  \"scripts\": {\n    \"build\": \"jco componentize src/index.js --wit wit/cartridge.wit -o dist/component.wasm\"\n  },\n  \"devDependencies\": {\n    \"@bytecodealliance/componentize-js\": \"^0.19.3\",\n    \"@bytecodealliance/jco\": \"^1.16.1\"\n  }\n}\n")?;
    fs::create_dir(path.join("src")).map_err(|error| error.to_string())?;
    write_new(
        &path.join("src/index.js"),
        b"export const run = (_args) => ({ tag: 'ok', val: 'hello from cartridge' });\n",
    )?;
    write_wit(path)
}

fn write_wit(path: &Path) -> Result<(), String> {
    fs::create_dir(path.join("wit")).map_err(|error| error.to_string())?;
    write_new(
        &path.join("wit/cartridge.wit"),
        include_bytes!("../../../wit/cartridge.wit"),
    )
}

fn validate_project_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("project name must contain between 1 and 64 bytes".into());
    }
    if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) {
        return Err("project name may only contain lowercase letters, digits, '-' and '_'".into());
    }
    Ok(())
}

fn validate_config(config: &ProjectConfig) -> Result<(), String> {
    if config.format_version != PROJECT_FORMAT_VERSION {
        return Err("unsupported developer project format".into());
    }
    if !matches!(config.language.as_str(), "rust" | "tinygo" | "javascript") {
        return Err("language must be rust, tinygo, or javascript".into());
    }
    if config.build.is_empty() || config.build.len() > 32 {
        return Err("build command must contain between 1 and 32 arguments".into());
    }
    if config
        .build
        .iter()
        .any(|arg| arg.len() > 4096 || arg.contains('\0'))
    {
        return Err("build argument is invalid".into());
    }
    safe_relative(&config.component)?;
    Ok(())
}

fn safe_relative(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty() || value.contains('\\') || path.is_absolute() {
        return Err("project path must be a normalized relative path".into());
    }
    if path
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err("project path must not contain traversal components".into());
    }
    Ok(())
}

fn safe_join(root: &Path, value: &str) -> Result<PathBuf, String> {
    safe_relative(value)?;
    Ok(root.join(value))
}

fn permission_names(value: &Permissions) -> Vec<String> {
    [
        ("clock", value.clock),
        ("random", value.random),
        ("assets", value.assets),
        ("storage", value.storage),
        ("graphics", value.graphics),
        ("audio", value.audio),
        ("midi", value.midi),
    ]
    .into_iter()
    .filter(|(_, enabled)| *enabled)
    .map(|(name, _)| name.to_owned())
    .collect()
}

fn visit_project(
    root: &Path,
    current: &Path,
    callback: &mut impl FnMut(&str, u64) -> Result<(), String>,
) -> Result<(), String> {
    let mut pending = vec![current.to_path_buf()];
    let mut entries_seen = 0usize;
    let mut bytes_seen = 0u64;
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or_else(|| "project entry count overflow".to_string())?;
            if entries_seen > MAX_PROJECT_FILES {
                return Err(format!(
                    "project exceeds the {MAX_PROJECT_FILES}-entry limit"
                ));
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() {
                return Err(format!(
                    "project contains a symbolic link: {}",
                    entry.path().display()
                ));
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or_else(|| "project path is not UTF-8".to_string())?
                .replace('\\', "/");
            if kind.is_dir() {
                if relative == "target" || relative == ".git" {
                    continue;
                }
                pending.push(entry.path());
            } else if kind.is_file() {
                let bytes = entry.metadata().map_err(|error| error.to_string())?.len();
                if bytes > MAX_PROJECT_FILE_BYTES {
                    return Err(format!(
                        "project file exceeds the {MAX_PROJECT_FILE_BYTES}-byte limit: {relative}"
                    ));
                }
                bytes_seen = bytes_seen
                    .checked_add(bytes)
                    .ok_or_else(|| "project size overflow".to_string())?;
                if bytes_seen > MAX_PROJECT_TOTAL_BYTES {
                    return Err(format!(
                        "project exceeds the {MAX_PROJECT_TOTAL_BYTES}-byte total limit"
                    ));
                }
                callback(&relative, bytes)?;
            }
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if fs::metadata(path).map_err(|error| error.to_string())?.len() > limit {
        return Err(format!(
            "file exceeds the {limit}-byte limit: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "file exceeded the {limit}-byte limit while reading"
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_inspects_rust_project() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("demo");
        create_project(&project, "demo", Language::Rust).unwrap();
        let report = profile_project(&project).unwrap();
        assert_eq!(report.cartridge_id, "dev.local.demo");
        assert_eq!(report.language, "rust");
        assert!(!report.component_exists);
    }

    #[test]
    fn refuses_to_overwrite_project() {
        let directory = tempfile::tempdir().unwrap();
        assert!(create_project(directory.path(), "demo", Language::Rust).is_err());
    }

    #[test]
    fn state_handoff_requires_identity_and_schema_compatibility() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("demo");
        create_project(&project, "demo", Language::Rust).unwrap();
        let (_, mut old) = inspect_project(&project).unwrap();
        old.permissions.storage = true;
        let mut next = old.clone();
        assert_eq!(reload_decision(&old, &next), ReloadDecision::PreserveState);
        next.state.schema = 1;
        assert!(matches!(
            reload_decision(&old, &next),
            ReloadDecision::Reject { .. }
        ));
    }

    #[test]
    fn component_path_cannot_escape_project() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("demo");
        create_project(&project, "demo", Language::Rust).unwrap();
        fs::write(project.join("Cartridge.dev.toml"), b"format_version = 1\nlanguage = \"rust\"\nbuild = [\"cargo\"]\ncomponent = \"../escape.wasm\"\n").unwrap();
        assert!(inspect_project(&project).is_err());
    }
}

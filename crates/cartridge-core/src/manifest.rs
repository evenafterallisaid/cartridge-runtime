use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const CURRENT_FORMAT_VERSION: u32 = 1;

const DEFAULT_FUEL: u64 = 10_000_000;
const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_MEMORY_BYTES: usize = 1024 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub format_version: u32,
    pub cartridge: CartridgeMetadata,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub runtime: RuntimeLimits,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<CartridgeDependency>,
    #[serde(default, skip_serializing_if = "Services::is_empty")]
    pub services: Services,
    #[serde(default, skip_serializing_if = "Integrity::is_empty")]
    pub integrity: Integrity,
}

impl PackageManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != CURRENT_FORMAT_VERSION {
            return Err(Error::Manifest(format!(
                "unsupported format version {}; expected {}",
                self.format_version, CURRENT_FORMAT_VERSION
            )));
        }

        validate_id(&self.cartridge.id)?;
        if self.cartridge.name.trim().is_empty() || self.cartridge.name.chars().count() > 80 {
            return Err(Error::Manifest(
                "cartridge name must contain between 1 and 80 characters".into(),
            ));
        }
        Version::parse(&self.cartridge.version)
            .map_err(|error| Error::Manifest(format!("version must be valid SemVer: {error}")))?;

        if self.runtime.fuel == 0 {
            return Err(Error::Manifest(
                "runtime fuel must be greater than zero".into(),
            ));
        }
        if !(1024 * 1024..=MAX_MEMORY_BYTES).contains(&self.runtime.memory_bytes) {
            return Err(Error::Manifest(format!(
                "runtime memory_bytes must be between 1 MiB and {} MiB",
                MAX_MEMORY_BYTES / 1024 / 1024
            )));
        }
        if !(1..=MAX_TIMEOUT_MS).contains(&self.runtime.timeout_ms) {
            return Err(Error::Manifest(format!(
                "runtime timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
            )));
        }

        if !self.integrity.component_sha256.is_empty()
            && !is_sha256(&self.integrity.component_sha256)
        {
            return Err(Error::Manifest(
                "integrity.component_sha256 must be a 64-character hexadecimal digest".into(),
            ));
        }
        for (path, digest) in &self.integrity.assets_sha256 {
            crate::normalize_relative_path(path)
                .map_err(|_| Error::Manifest(format!("invalid integrity asset path: {path:?}")))?;
            if !is_sha256(digest) {
                return Err(Error::Manifest(format!(
                    "integrity.assets_sha256 entry for {path:?} must be a 64-character hexadecimal digest"
                )));
            }
        }
        validate_relationships(self)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CartridgeMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Permissions {
    pub clock: bool,
    pub random: bool,
    pub assets: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeLimits {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub timeout_ms: u64,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CartridgeDependency {
    pub alias: String,
    pub cartridge: String,
    pub version: String,
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Services {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<ProvidedService>,
}

impl Services {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.provides.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedService {
    pub name: String,
    pub interface: String,
    #[serde(default)]
    pub visibility: ServiceVisibility,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceVisibility {
    Private,
    #[default]
    Dependency,
    Public,
}

impl fmt::Display for ServiceVisibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Private => "private",
            Self::Dependency => "dependency",
            Self::Public => "public",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Integrity {
    pub component_sha256: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assets_sha256: BTreeMap<String, String>,
}

impl Integrity {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.component_sha256.is_empty() && self.assets_sha256.is_empty()
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_id(id: &str) -> Result<()> {
    if id.len() > 128 || id.split('.').count() < 3 {
        return Err(Error::Manifest(
            "cartridge id must be a reverse-domain identifier such as dev.example.app".into(),
        ));
    }
    if !id.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !segment.starts_with('-')
            && !segment.ends_with('-')
    }) {
        return Err(Error::Manifest(format!("invalid cartridge id: {id}")));
    }
    Ok(())
}

fn validate_relationships(manifest: &PackageManifest) -> Result<()> {
    let mut aliases = BTreeSet::new();
    let mut dependency_ids = BTreeSet::new();
    for dependency in &manifest.dependencies {
        validate_alias(&dependency.alias, "dependency alias")?;
        validate_id(&dependency.cartridge)?;
        if dependency.cartridge == manifest.cartridge.id {
            return Err(Error::Manifest(
                "a cartridge cannot depend on itself".into(),
            ));
        }
        VersionReq::parse(&dependency.version).map_err(|error| {
            Error::Manifest(format!(
                "dependency {} has an invalid version requirement: {error}",
                dependency.alias
            ))
        })?;
        if dependency.interfaces.is_empty() {
            return Err(Error::Manifest(format!(
                "dependency {} must request at least one interface",
                dependency.alias
            )));
        }
        if dependency.reason.chars().count() > 240 {
            return Err(Error::Manifest(format!(
                "dependency {} reason cannot exceed 240 characters",
                dependency.alias
            )));
        }
        if !aliases.insert(&dependency.alias) {
            return Err(Error::Manifest(format!(
                "duplicate dependency alias: {}",
                dependency.alias
            )));
        }
        if !dependency_ids.insert(&dependency.cartridge) {
            return Err(Error::Manifest(format!(
                "duplicate cartridge dependency: {}",
                dependency.cartridge
            )));
        }
        let mut interfaces = BTreeSet::new();
        for interface in &dependency.interfaces {
            validate_interface(interface)?;
            if !interfaces.insert(interface) {
                return Err(Error::Manifest(format!(
                    "dependency {} requests interface {interface} more than once",
                    dependency.alias
                )));
            }
        }
    }

    let mut names = BTreeSet::new();
    let mut interfaces = BTreeSet::new();
    for service in &manifest.services.provides {
        validate_alias(&service.name, "service name")?;
        validate_interface(&service.interface)?;
        if service.description.chars().count() > 240 {
            return Err(Error::Manifest(format!(
                "service {} description cannot exceed 240 characters",
                service.name
            )));
        }
        if !names.insert(&service.name) {
            return Err(Error::Manifest(format!(
                "duplicate provided service name: {}",
                service.name
            )));
        }
        if !interfaces.insert(&service.interface) {
            return Err(Error::Manifest(format!(
                "interface is provided more than once: {}",
                service.interface
            )));
        }
    }
    Ok(())
}

fn validate_alias(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 48
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(Error::Manifest(format!("invalid {field}: {value:?}")));
    }
    Ok(())
}

fn validate_interface(value: &str) -> Result<()> {
    let Some((path, version)) = value.rsplit_once('@') else {
        return Err(Error::Manifest(format!(
            "interface must include a semantic version: {value:?}"
        )));
    };
    Version::parse(version).map_err(|error| {
        Error::Manifest(format!("invalid interface version in {value:?}: {error}"))
    })?;
    let Some((package, interface)) = path.split_once('/') else {
        return Err(Error::Manifest(format!(
            "interface must use namespace:package/interface syntax: {value:?}"
        )));
    };
    let Some((namespace, package)) = package.split_once(':') else {
        return Err(Error::Manifest(format!(
            "interface must use namespace:package/interface syntax: {value:?}"
        )));
    };
    validate_wit_name(namespace, value)?;
    validate_wit_name(package, value)?;
    validate_wit_name(interface, value)
}

fn validate_wit_name(name: &str, full: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        return Err(Error::Manifest(format!(
            "invalid WIT interface reference: {full:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> PackageManifest {
        PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.test".into(),
                name: "Test".into(),
                version: "1.2.3".into(),
                description: String::new(),
            },
            permissions: Permissions::default(),
            runtime: RuntimeLimits::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity::default(),
        }
    }

    #[test]
    fn accepts_valid_manifest() {
        manifest().validate().unwrap();
    }

    #[test]
    fn rejects_ambiguous_id() {
        let mut value = manifest();
        value.cartridge.id = "hello".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_memory() {
        let mut value = manifest();
        value.runtime.memory_bytes = usize::MAX;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_wall_time() {
        let mut value = manifest();
        value.runtime.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn accepts_typed_cartridge_relationships() {
        let mut value = manifest();
        value.dependencies.push(CartridgeDependency {
            alias: "image-codec".into(),
            cartridge: "dev.example.image-codec".into(),
            version: "^1.2".into(),
            interfaces: vec!["example:media/decode@1.0.0".into()],
            optional: false,
            reason: "decodes imported textures".into(),
        });
        value.services.provides.push(ProvidedService {
            name: "thumbnailer".into(),
            interface: "example:media/thumbnail@1.0.0".into(),
            visibility: ServiceVisibility::Dependency,
            description: "creates image previews".into(),
        });

        value.validate().unwrap();
    }

    #[test]
    fn rejects_unversioned_service_interfaces() {
        let mut value = manifest();
        value.services.provides.push(ProvidedService {
            name: "thumbnailer".into(),
            interface: "example:media/thumbnail".into(),
            visibility: ServiceVisibility::Dependency,
            description: String::new(),
        });

        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_implicit_dependency_authority() {
        let mut value = manifest();
        value.dependencies.push(CartridgeDependency {
            alias: "codec".into(),
            cartridge: "dev.example.codec".into(),
            version: "1".into(),
            interfaces: Vec::new(),
            optional: false,
            reason: String::new(),
        });

        assert!(value.validate().is_err());
    }
}

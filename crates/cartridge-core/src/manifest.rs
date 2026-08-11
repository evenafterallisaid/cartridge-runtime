use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const CURRENT_FORMAT_VERSION: u32 = 1;
pub const MIGRATION_PLAN_FORMAT_VERSION: u32 = 1;

const DEFAULT_FUEL: u64 = 10_000_000;
const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_STORAGE_BYTES: usize = 1024 * 1024;
const DEFAULT_STORAGE_KEYS: usize = 1024;
const DEFAULT_STORAGE_VALUE_BYTES: usize = 256 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_FUEL: u64 = 1_000_000_000_000;
const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
const MAX_STORAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STORAGE_KEYS: usize = 100_000;
const MAX_STORAGE_VALUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const MAX_MIGRATIONS: usize = 256;
const MAX_DEPENDENCIES: usize = 128;
const MAX_SERVICES: usize = 128;
const MAX_INTERFACES_PER_DEPENDENCY: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub format_version: u32,
    pub cartridge: CartridgeMetadata,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub runtime: RuntimeLimits,
    #[serde(default, skip_serializing_if = "StateConfig::is_empty")]
    pub state: StateConfig,
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
        validate_human_text(&self.cartridge.name, "cartridge name", 80, false)?;
        validate_human_text(
            &self.cartridge.description,
            "cartridge description",
            240,
            true,
        )?;
        Version::parse(&self.cartridge.version)
            .map_err(|error| Error::Manifest(format!("version must be valid SemVer: {error}")))?;

        if !(1..=MAX_FUEL).contains(&self.runtime.fuel) {
            return Err(Error::Manifest(format!(
                "runtime fuel must be between 1 and {MAX_FUEL}"
            )));
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
        if !(1..=MAX_STORAGE_BYTES).contains(&self.runtime.storage_bytes) {
            return Err(Error::Manifest(format!(
                "runtime storage_bytes must be between 1 and {MAX_STORAGE_BYTES}"
            )));
        }
        if !(1..=MAX_STORAGE_KEYS).contains(&self.runtime.storage_keys) {
            return Err(Error::Manifest(format!(
                "runtime storage_keys must be between 1 and {MAX_STORAGE_KEYS}"
            )));
        }
        if self.runtime.storage_value_bytes == 0
            || self.runtime.storage_value_bytes > self.runtime.storage_bytes
            || self.runtime.storage_value_bytes > MAX_STORAGE_VALUE_BYTES
        {
            return Err(Error::Manifest(format!(
                "runtime storage_value_bytes must be positive, no larger than storage_bytes, and at most {MAX_STORAGE_VALUE_BYTES}"
            )));
        }

        validate_state(self)?;

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
        if !self.integrity.assets_root_sha256.is_empty() {
            if !is_sha256(&self.integrity.assets_root_sha256) {
                return Err(Error::Manifest(
                    "integrity.assets_root_sha256 must be a 64-character hexadecimal digest".into(),
                ));
            }
            let actual = asset_integrity_root(&self.integrity.assets_sha256)?;
            if !actual.eq_ignore_ascii_case(&self.integrity.assets_root_sha256) {
                return Err(Error::Integrity(
                    "asset integrity root does not match the declared asset digests".into(),
                ));
            }
        }
        validate_relationships(self)?;
        Ok(())
    }

    pub fn migration_plan(&self, source_schema: u32) -> Result<MigrationPlan> {
        self.validate()?;
        if source_schema > self.state.schema {
            return Err(Error::Manifest(format!(
                "state schema {source_schema} is newer than package schema {}",
                self.state.schema
            )));
        }

        let migrations: BTreeMap<_, _> = self
            .state
            .migrations
            .iter()
            .map(|migration| (migration.from, migration))
            .collect();
        let mut current = source_schema;
        let mut steps = Vec::new();
        while current < self.state.schema {
            let migration = migrations.get(&current).ok_or_else(|| {
                Error::Manifest(format!(
                    "no migration path from state schema {source_schema} to {}",
                    self.state.schema
                ))
            })?;
            steps.push((*migration).clone());
            current = migration.to;
        }

        Ok(MigrationPlan {
            format_version: MIGRATION_PLAN_FORMAT_VERSION,
            cartridge_id: self.cartridge.id.clone(),
            cartridge_version: self.cartridge.version.clone(),
            component_sha256: self.integrity.component_sha256.clone(),
            source_schema,
            target_schema: self.state.schema,
            steps,
        })
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
#[allow(clippy::struct_excessive_bools)]
pub struct Permissions {
    pub clock: bool,
    pub random: bool,
    pub assets: bool,
    pub storage: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeLimits {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub timeout_ms: u64,
    pub storage_bytes: usize,
    pub storage_keys: usize,
    pub storage_value_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            storage_bytes: DEFAULT_STORAGE_BYTES,
            storage_keys: DEFAULT_STORAGE_KEYS,
            storage_value_bytes: DEFAULT_STORAGE_VALUE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateConfig {
    pub schema: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<StateMigration>,
}

impl StateConfig {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schema == 0 && self.migrations.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateMigration {
    pub name: String,
    pub from: u32,
    pub to: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPlan {
    pub format_version: u32,
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub component_sha256: String,
    pub source_schema: u32,
    pub target_schema: u32,
    pub steps: Vec<StateMigration>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assets_root_sha256: String,
}

impl Integrity {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.component_sha256.is_empty()
            && self.assets_sha256.is_empty()
            && self.assets_root_sha256.is_empty()
    }
}

pub(crate) fn asset_integrity_root(assets: &BTreeMap<String, String>) -> Result<String> {
    let mut nodes = Vec::with_capacity(assets.len());
    for (path, digest) in assets {
        let digest = hex::decode(digest)
            .map_err(|_| Error::Integrity(format!("invalid asset digest for {path:?}")))?;
        if digest.len() != 32 {
            return Err(Error::Integrity(format!(
                "invalid asset digest for {path:?}"
            )));
        }
        let path_length = u64::try_from(path.len())
            .map_err(|_| Error::Integrity("asset path length overflowed".into()))?;
        let mut hasher = Sha256::new();
        hasher.update([0]);
        hasher.update(path_length.to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update(digest);
        nodes.push(hasher.finalize().to_vec());
    }
    if nodes.is_empty() {
        return Ok(hex::encode(Sha256::digest([2])));
    }
    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut hasher = Sha256::new();
            hasher.update([1]);
            hasher.update(left);
            hasher.update(right);
            parents.push(hasher.finalize().to_vec());
        }
        nodes = parents;
    }
    Ok(hex::encode(&nodes[0]))
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
    if manifest.dependencies.len() > MAX_DEPENDENCIES {
        return Err(Error::Manifest(format!(
            "a cartridge cannot declare more than {MAX_DEPENDENCIES} dependencies"
        )));
    }
    if manifest.services.provides.len() > MAX_SERVICES {
        return Err(Error::Manifest(format!(
            "a cartridge cannot provide more than {MAX_SERVICES} services"
        )));
    }
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
        if dependency.interfaces.len() > MAX_INTERFACES_PER_DEPENDENCY {
            return Err(Error::Manifest(format!(
                "dependency {} cannot request more than {MAX_INTERFACES_PER_DEPENDENCY} interfaces",
                dependency.alias
            )));
        }
        validate_human_text(&dependency.reason, "dependency reason", 240, true)?;
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
        validate_human_text(&service.description, "service description", 240, true)?;
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

fn validate_state(manifest: &PackageManifest) -> Result<()> {
    if manifest.state.schema > 0 && !manifest.permissions.storage {
        return Err(Error::Manifest(
            "state schema requires permissions.storage = true".into(),
        ));
    }
    if manifest.state.migrations.len() > MAX_MIGRATIONS {
        return Err(Error::Manifest(format!(
            "state cannot declare more than {MAX_MIGRATIONS} migrations"
        )));
    }

    let mut names = BTreeSet::new();
    let mut sources = BTreeMap::new();
    for migration in &manifest.state.migrations {
        validate_alias(&migration.name, "migration name")?;
        if !names.insert(&migration.name) {
            return Err(Error::Manifest(format!(
                "duplicate migration name: {}",
                migration.name
            )));
        }
        if migration.from >= migration.to {
            return Err(Error::Manifest(format!(
                "migration {} must increase the state schema",
                migration.name
            )));
        }
        if migration.to > manifest.state.schema {
            return Err(Error::Manifest(format!(
                "migration {} targets schema {} beyond package schema {}",
                migration.name, migration.to, manifest.state.schema
            )));
        }
        if sources.insert(migration.from, migration).is_some() {
            return Err(Error::Manifest(format!(
                "more than one migration starts at schema {}",
                migration.from
            )));
        }
    }

    for migration in &manifest.state.migrations {
        let mut current = migration.to;
        while current < manifest.state.schema {
            let next = sources.get(&current).ok_or_else(|| {
                Error::Manifest(format!(
                    "migration {} does not lead to package schema {}",
                    migration.name, manifest.state.schema
                ))
            })?;
            current = next.to;
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

fn validate_human_text(value: &str, field: &str, max: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.trim().is_empty())
        || value.chars().count() > max
        || value.chars().any(char::is_control)
    {
        return Err(Error::Manifest(format!(
            "{field} must contain at most {max} printable characters"
        )));
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
            state: StateConfig::default(),
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
    fn asset_root_binds_paths_and_digests() {
        let mut value = manifest();
        value
            .integrity
            .assets_sha256
            .insert("a.txt".into(), hex::encode(Sha256::digest(b"a")));
        value.integrity.assets_root_sha256 =
            asset_integrity_root(&value.integrity.assets_sha256).unwrap();
        value.validate().unwrap();

        value
            .integrity
            .assets_sha256
            .insert("b.txt".into(), hex::encode(Sha256::digest(b"b")));
        assert!(value.validate().is_err());
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
    fn rejects_unbounded_fuel() {
        let mut value = manifest();
        value.runtime.fuel = u64::MAX;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_wall_time() {
        let mut value = manifest();
        value.runtime.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_terminal_control_characters_in_display_text() {
        let mut value = manifest();
        value.cartridge.name = "trusted\u{1b}[2J".into();

        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_description_and_relationship_counts() {
        let mut value = manifest();
        value.cartridge.description = "x".repeat(241);
        assert!(value.validate().is_err());

        value.cartridge.description.clear();
        value.dependencies = (0..=MAX_DEPENDENCIES)
            .map(|index| CartridgeDependency {
                alias: format!("dependency-{index}"),
                cartridge: format!("dev.example.dependency-{index}"),
                version: "1".into(),
                interfaces: vec!["example:service/run@1.0.0".into()],
                optional: false,
                reason: String::new(),
            })
            .collect();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_a_storage_value_limit_larger_than_the_quota() {
        let mut value = manifest();
        value.runtime.storage_bytes = 8;
        value.runtime.storage_value_bytes = 9;
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

    #[test]
    fn builds_a_deterministic_migration_plan() {
        let mut value = manifest();
        value.permissions.storage = true;
        value.state = StateConfig {
            schema: 3,
            migrations: vec![
                StateMigration {
                    name: "add-profile".into(),
                    from: 0,
                    to: 1,
                },
                StateMigration {
                    name: "split-settings".into(),
                    from: 1,
                    to: 3,
                },
            ],
        };

        let plan = value.migration_plan(0).unwrap();
        assert_eq!(plan.source_schema, 0);
        assert_eq!(plan.target_schema, 3);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].name, "split-settings");
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_migration_graphs() {
        let mut value = manifest();
        value.permissions.storage = true;
        value.state = StateConfig {
            schema: 3,
            migrations: vec![
                StateMigration {
                    name: "first".into(),
                    from: 0,
                    to: 1,
                },
                StateMigration {
                    name: "other".into(),
                    from: 0,
                    to: 2,
                },
            ],
        };

        assert!(value.validate().is_err());

        value.state.migrations.pop();
        assert!(value.validate().is_err());
    }

    #[test]
    fn reports_when_a_supported_migration_path_does_not_start_early_enough() {
        let mut value = manifest();
        value.permissions.storage = true;
        value.state = StateConfig {
            schema: 2,
            migrations: vec![StateMigration {
                name: "upgrade-settings".into(),
                from: 1,
                to: 2,
            }],
        };

        value.validate().unwrap();
        assert!(value.migration_plan(0).is_err());
        assert_eq!(value.migration_plan(1).unwrap().steps.len(), 1);
        assert!(value.migration_plan(2).unwrap().steps.is_empty());
    }
}

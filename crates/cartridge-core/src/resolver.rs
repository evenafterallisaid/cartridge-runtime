use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PackageManifest, ServiceVisibility};

pub const COMPOSITION_LOCK_FORMAT_VERSION: u32 = 1;
const MAX_LOCKED_PACKAGES: usize = 128;
const MAX_LOCKED_PACKAGE_BYTES: u64 = 160 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionPlan {
    pub resolved: Vec<ResolvedDependency>,
    pub unavailable_optional: Vec<UnavailableDependency>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDependency {
    pub alias: String,
    pub cartridge: String,
    pub version: String,
    pub interfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableDependency {
    pub alias: String,
    pub cartridge: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("invalid manifest in dependency set: {0}")]
    InvalidManifest(String),
    #[error("candidate set contains duplicate package {cartridge} {version}")]
    DuplicateCandidate { cartridge: String, version: String },
    #[error("required dependency {alias} ({cartridge} {version}) could not be resolved: {reason}")]
    RequiredUnavailable {
        alias: String,
        cartridge: String,
        version: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub cartridge_id: String,
    pub version: String,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub component_sha256: String,
    pub assets_root_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionLock {
    pub format_version: u32,
    pub root: LockedPackage,
    pub providers: Vec<LockedPackage>,
    pub plan: ResolutionPlan,
}

impl CompositionLock {
    pub fn new(
        root: LockedPackage,
        mut providers: Vec<LockedPackage>,
        plan: ResolutionPlan,
    ) -> Result<Self, String> {
        providers.sort_by(|left, right| {
            (&left.cartridge_id, &left.version).cmp(&(&right.cartridge_id, &right.version))
        });
        let value = Self {
            format_version: COMPOSITION_LOCK_FORMAT_VERSION,
            root,
            providers,
            plan,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != COMPOSITION_LOCK_FORMAT_VERSION
            || self.providers.len() > MAX_LOCKED_PACKAGES
            || self.plan.resolved.len() > MAX_LOCKED_PACKAGES
            || self.plan.unavailable_optional.len() > MAX_LOCKED_PACKAGES
        {
            return Err("composition lock format or count is invalid".into());
        }
        validate_locked_package(&self.root)?;
        let mut previous = None;
        let mut indexed = BTreeMap::new();
        for provider in &self.providers {
            validate_locked_package(provider)?;
            let key = (provider.cartridge_id.as_str(), provider.version.as_str());
            if previous.is_some_and(|value| value >= key) {
                return Err("composition lock providers are not strictly sorted".into());
            }
            previous = Some(key);
            indexed.insert(key, provider);
        }
        let mut aliases = BTreeSet::new();
        let mut referenced = BTreeSet::new();
        for dependency in &self.plan.resolved {
            if !is_alias(&dependency.alias)
                || !is_cartridge_id(&dependency.cartridge)
                || !is_bounded_text(&dependency.version, 64, false)
                || Version::parse(&dependency.version).is_err()
                || !aliases.insert(dependency.alias.as_str())
                || dependency.interfaces.is_empty()
                || dependency.interfaces.len() > 64
                || dependency
                    .interfaces
                    .iter()
                    .any(|interface| !is_bounded_text(interface, 256, false))
                || !indexed
                    .contains_key(&(dependency.cartridge.as_str(), dependency.version.as_str()))
            {
                return Err("composition lock resolved edge is invalid".into());
            }
            referenced.insert((dependency.cartridge.as_str(), dependency.version.as_str()));
        }
        for dependency in &self.plan.unavailable_optional {
            if !is_alias(&dependency.alias)
                || !is_cartridge_id(&dependency.cartridge)
                || !aliases.insert(dependency.alias.as_str())
                || !is_bounded_text(&dependency.reason, 512, false)
            {
                return Err("composition lock optional edge is invalid".into());
            }
        }
        if indexed.keys().copied().collect::<BTreeSet<_>>() != referenced {
            return Err("composition lock contains an unreferenced provider".into());
        }
        Ok(())
    }
}

pub fn resolve_dependencies(
    root: &PackageManifest,
    candidates: &[PackageManifest],
) -> Result<ResolutionPlan, ResolveError> {
    root.validate()
        .map_err(|error| ResolveError::InvalidManifest(error.to_string()))?;
    for candidate in candidates {
        candidate
            .validate()
            .map_err(|error| ResolveError::InvalidManifest(error.to_string()))?;
    }
    let mut versions = BTreeSet::new();
    for candidate in candidates {
        if !versions.insert((
            candidate.cartridge.id.as_str(),
            candidate.cartridge.version.as_str(),
        )) {
            return Err(ResolveError::DuplicateCandidate {
                cartridge: candidate.cartridge.id.clone(),
                version: candidate.cartridge.version.clone(),
            });
        }
    }

    let mut resolved = Vec::new();
    let mut unavailable_optional = Vec::new();
    for dependency in &root.dependencies {
        let requirement = VersionReq::parse(&dependency.version)
            .map_err(|error| ResolveError::InvalidManifest(error.to_string()))?;
        let mut matching: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate.cartridge.id == dependency.cartridge)
            .filter_map(|candidate| {
                let version = Version::parse(&candidate.cartridge.version).ok()?;
                requirement
                    .matches(&version)
                    .then_some((version, candidate))
            })
            .collect();
        matching.sort_by(|left, right| right.0.cmp(&left.0));

        let provider = matching.into_iter().find(|(_, candidate)| {
            let provided: BTreeSet<_> = candidate
                .services
                .provides
                .iter()
                .filter(|service| service.visibility != ServiceVisibility::Private)
                .map(|service| service.interface.as_str())
                .collect();
            dependency
                .interfaces
                .iter()
                .all(|interface| provided.contains(interface.as_str()))
        });

        if let Some((version, _)) = provider {
            resolved.push(ResolvedDependency {
                alias: dependency.alias.clone(),
                cartridge: dependency.cartridge.clone(),
                version: version.to_string(),
                interfaces: dependency.interfaces.clone(),
            });
            continue;
        }

        let reason = unavailable_reason(dependency, candidates, &requirement);
        if dependency.optional {
            unavailable_optional.push(UnavailableDependency {
                alias: dependency.alias.clone(),
                cartridge: dependency.cartridge.clone(),
                reason,
            });
        } else {
            return Err(ResolveError::RequiredUnavailable {
                alias: dependency.alias.clone(),
                cartridge: dependency.cartridge.clone(),
                version: dependency.version.clone(),
                reason,
            });
        }
    }

    Ok(ResolutionPlan {
        resolved,
        unavailable_optional,
    })
}

fn validate_locked_package(value: &LockedPackage) -> Result<(), String> {
    if !is_cartridge_id(&value.cartridge_id)
        || !is_bounded_text(&value.version, 64, false)
        || Version::parse(&value.version).is_err()
        || value.package_bytes == 0
        || value.package_bytes > MAX_LOCKED_PACKAGE_BYTES
        || !is_digest(&value.package_sha256)
        || !is_digest(&value.component_sha256)
        || (!value.assets_root_sha256.is_empty() && !is_digest(&value.assets_root_sha256))
    {
        return Err("composition lock package identity is invalid".into());
    }
    Ok(())
}

fn is_cartridge_id(value: &str) -> bool {
    value.len() <= 128
        && value.split('.').count() >= 3
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !segment.starts_with('-')
                && !segment.ends_with('-')
        })
}

fn is_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn is_bounded_text(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.chars().count() <= max
        && !value.chars().any(char::is_control)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unavailable_reason(
    dependency: &crate::CartridgeDependency,
    candidates: &[PackageManifest],
    requirement: &VersionReq,
) -> String {
    let matching_id: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.cartridge.id == dependency.cartridge)
        .collect();
    if matching_id.is_empty() {
        return "cartridge is not installed".into();
    }
    let matching_version: Vec<_> = matching_id
        .iter()
        .filter(|candidate| {
            Version::parse(&candidate.cartridge.version)
                .is_ok_and(|version| requirement.matches(&version))
        })
        .collect();
    if matching_version.is_empty() {
        return "installed versions do not satisfy the requested range".into();
    }

    let missing = matching_version
        .iter()
        .map(|candidate| {
            let available: BTreeSet<_> = candidate
                .services
                .provides
                .iter()
                .filter(|service| service.visibility != ServiceVisibility::Private)
                .map(|service| service.interface.as_str())
                .collect();
            dependency
                .interfaces
                .iter()
                .filter(|interface| !available.contains(interface.as_str()))
                .cloned()
                .collect::<Vec<_>>()
        })
        .min_by_key(Vec::len)
        .unwrap_or_else(|| dependency.interfaces.clone());
    format!("compatible versions do not provide: {}", missing.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CartridgeDependency, CartridgeMetadata, Integrity, Permissions, ProvidedService,
        RuntimeLimits, Services, StateConfig,
    };

    #[test]
    fn picks_the_highest_compatible_provider() {
        let mut root = manifest("dev.example.root", "1.0.0");
        root.dependencies.push(dependency(false));
        let old = provider("1.2.0", ServiceVisibility::Dependency);
        let newest = provider("1.9.0", ServiceVisibility::Dependency);
        let incompatible = provider("2.0.0", ServiceVisibility::Dependency);

        let plan = resolve_dependencies(&root, &[old, incompatible, newest]).unwrap();

        assert_eq!(plan.resolved.len(), 1);
        assert_eq!(plan.resolved[0].version, "1.9.0");
    }

    #[test]
    fn private_services_cannot_satisfy_an_external_dependency() {
        let mut root = manifest("dev.example.root", "1.0.0");
        root.dependencies.push(dependency(false));

        let error = resolve_dependencies(&root, &[provider("1.5.0", ServiceVisibility::Private)])
            .unwrap_err();

        assert!(matches!(error, ResolveError::RequiredUnavailable { .. }));
    }

    #[test]
    fn optional_dependencies_remain_visible_in_the_plan() {
        let mut root = manifest("dev.example.root", "1.0.0");
        root.dependencies.push(dependency(true));

        let plan = resolve_dependencies(&root, &[]).unwrap();

        assert!(plan.resolved.is_empty());
        assert_eq!(plan.unavailable_optional.len(), 1);
    }

    #[test]
    fn duplicate_candidate_versions_are_rejected() {
        let mut root = manifest("dev.example.root", "1.0.0");
        root.dependencies.push(dependency(false));
        let candidate = provider("1.5.0", ServiceVisibility::Dependency);

        let error = resolve_dependencies(&root, &[candidate.clone(), candidate]).unwrap_err();

        assert!(matches!(error, ResolveError::DuplicateCandidate { .. }));
    }

    #[test]
    fn composition_locks_bind_exact_packages_and_edges() {
        let provider = LockedPackage {
            cartridge_id: "dev.example.codec".into(),
            version: "1.5.0".into(),
            package_sha256: "a".repeat(64),
            package_bytes: 42,
            component_sha256: "b".repeat(64),
            assets_root_sha256: "c".repeat(64),
        };
        let root = LockedPackage {
            cartridge_id: "dev.example.root".into(),
            version: "1.0.0".into(),
            package_sha256: "d".repeat(64),
            package_bytes: 24,
            component_sha256: "e".repeat(64),
            assets_root_sha256: String::new(),
        };
        let lock = CompositionLock::new(
            root,
            vec![provider],
            ResolutionPlan {
                resolved: vec![ResolvedDependency {
                    alias: "codec".into(),
                    cartridge: "dev.example.codec".into(),
                    version: "1.5.0".into(),
                    interfaces: vec!["example:codec/decode@1.0.0".into()],
                }],
                unavailable_optional: Vec::new(),
            },
        )
        .unwrap();

        assert!(lock.validate().is_ok());
        let mut changed = lock.clone();
        changed.providers[0].package_sha256 = "f".repeat(63);
        assert!(changed.validate().is_err());

        let mut changed = lock;
        changed.plan.resolved[0].alias = "invalid alias".into();
        assert!(changed.validate().is_err());
    }

    fn dependency(optional: bool) -> CartridgeDependency {
        CartridgeDependency {
            alias: "codec".into(),
            cartridge: "dev.example.codec".into(),
            version: "^1.0".into(),
            interfaces: vec!["example:codec/decode@1.0.0".into()],
            optional,
            reason: "decodes media".into(),
        }
    }

    fn provider(version: &str, visibility: ServiceVisibility) -> PackageManifest {
        let mut value = manifest("dev.example.codec", version);
        value.services.provides.push(ProvidedService {
            name: "decoder".into(),
            interface: "example:codec/decode@1.0.0".into(),
            visibility,
            description: String::new(),
        });
        value
    }

    fn manifest(id: &str, version: &str) -> PackageManifest {
        PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: id.into(),
                name: "Test".into(),
                version: version.into(),
                description: String::new(),
            },
            permissions: Permissions::default(),
            http: cartridge_network::HttpPolicy::default(),
            compatibility: crate::Compatibility::default(),
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity::default(),
        }
    }
}

use std::collections::BTreeSet;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PackageManifest, ServiceVisibility};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolutionPlan {
    pub resolved: Vec<ResolvedDependency>,
    pub unavailable_optional: Vec<UnavailableDependency>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolvedDependency {
    pub alias: String,
    pub cartridge: String,
    pub version: String,
    pub interfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnavailableDependency {
    pub alias: String,
    pub cartridge: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("invalid manifest in dependency set: {0}")]
    InvalidManifest(String),
    #[error("required dependency {alias} ({cartridge} {version}) could not be resolved: {reason}")]
    RequiredUnavailable {
        alias: String,
        cartridge: String,
        version: String,
        reason: String,
    },
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

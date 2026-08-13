mod archive;
mod manifest;
mod pack;
mod resolver;

pub use archive::{AssetVerification, CartridgeArchive, PackageLimits};
pub use manifest::{
    CURRENT_FORMAT_VERSION, CartridgeDependency, CartridgeMetadata, Compatibility,
    HOST_API_VERSION, Integrity, MIGRATION_PLAN_FORMAT_VERSION, MigrationPlan, NegotiatedPlatform,
    PackageManifest, Permissions, ProvidedService, RuntimeLimits, ServiceVisibility, Services,
    StateConfig, StateMigration, negotiate_platform,
};
pub use pack::{PackOptions, pack};
pub use resolver::{
    COMPOSITION_LOCK_FORMAT_VERSION, CompositionLock, LockedPackage, MAX_RESOLUTION_CANDIDATES,
    ResolutionPlan, ResolveError, ResolvedDependency, UnavailableDependency, resolve_dependencies,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid cartridge manifest: {0}")]
    Manifest(String),
    #[error("invalid cartridge archive: {0}")]
    Archive(String),
    #[error("package integrity check failed: {0}")]
    Integrity(String),
    #[error("TOML error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn normalize_relative_path(path: &str) -> Result<String> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return Err(Error::Archive(format!("unsafe relative path: {path:?}")));
    }

    let mut normalized = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(':') {
            return Err(Error::Archive(format!("unsafe relative path: {path:?}")));
        }
        normalized.push(part);
    }
    Ok(normalized.join("/"))
}

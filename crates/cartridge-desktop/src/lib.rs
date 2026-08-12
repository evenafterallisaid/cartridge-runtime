mod gpu;

pub use gpu::{
    GPU_PROTOCOL_VERSION, GpuAdapterInfo, GpuBackend, GpuLimits, GraphicsMode, GraphicsPresenter,
    RenderPolicy, ValidatedGpuStream,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use cartridge_core::{CartridgeArchive, Permissions};
use fs4::{FileExt, TryLockError};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LIBRARY_FORMAT_VERSION: u32 = 1;
pub const MAX_LIBRARY_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_INSTALLED_PACKAGES: usize = 10_000;
pub const MAX_LAUNCH_HISTORY: usize = 4096;
pub const MAX_RESOURCE_SAMPLES_PER_LAUNCH: usize = 2048;
pub const SAFE_MODE_CRASH_THRESHOLD: u32 = 3;
pub const MAX_PACKAGE_FILE_BYTES: u64 = 160 * 1024 * 1024;
const LIBRARY_LOCK_ATTEMPTS: usize = 200;
const LIBRARY_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

static INSTALL_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LibraryDocument {
    format_version: u32,
    runtime_channel: String,
    runtime_version: String,
    installed: BTreeMap<String, BTreeMap<String, InstalledVersion>>,
    grants: BTreeMap<String, PersistentGrant>,
    profiles: BTreeMap<String, Profile>,
    history: Vec<LaunchRecord>,
    health: BTreeMap<String, CartridgeHealth>,
}

impl Default for LibraryDocument {
    fn default() -> Self {
        Self {
            format_version: LIBRARY_FORMAT_VERSION,
            runtime_channel: "stable".into(),
            runtime_version: env!("CARGO_PKG_VERSION").into(),
            installed: BTreeMap::new(),
            grants: BTreeMap::new(),
            profiles: BTreeMap::new(),
            history: Vec::new(),
            health: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledVersion {
    pub name: String,
    pub description: String,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub relative_path: String,
    pub requested_permissions: BTreeSet<Capability>,
    pub installed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Clock,
    Random,
    Assets,
    Storage,
    Graphics,
    Audio,
    Midi,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentGrant {
    pub cartridge_id: String,
    pub capabilities: BTreeSet<Capability>,
    pub approved_request_sha256: String,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub cartridges: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchStatus {
    Running,
    Succeeded,
    Failed,
    Terminated,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRecord {
    pub id: u64,
    pub cartridge_id: String,
    pub version: String,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub status: LaunchStatus,
    pub fuel_consumed: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub trace_path: Option<String>,
    #[serde(default)]
    pub resource_samples: Vec<ResourceSample>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSample {
    pub elapsed_ms: u64,
    pub fuel_consumed: u64,
    pub memory_bytes: u64,
    pub audio_underruns: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CartridgeHealth {
    pub consecutive_failures: u32,
    pub safe_mode: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LibraryEntry {
    pub cartridge_id: String,
    pub name: String,
    pub versions: Vec<String>,
    pub safe_mode: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionPreflight {
    pub cartridge_id: String,
    pub version: String,
    pub requested: BTreeSet<Capability>,
    pub granted: BTreeSet<Capability>,
    pub missing: BTreeSet<Capability>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionPrompt {
    pub title: String,
    pub summary: String,
    pub rows: Vec<PermissionRow>,
    pub approve_label: String,
    pub deny_label: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PermissionRow {
    pub capability: Capability,
    pub label: &'static str,
    pub description: &'static str,
}

pub struct Library {
    root: PathBuf,
    document: LibraryDocument,
    session_grants: BTreeMap<String, BTreeSet<Capability>>,
    _lock: File,
}

impl Library {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(root.join("packages")).map_err(|error| error.to_string())?;
        fs::create_dir_all(root.join("recovery")).map_err(|error| error.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("library.lock"))
            .map_err(|error| error.to_string())?;
        acquire_library_lock(&lock)?;
        let document_path = root.join("library.json");
        recover_library_document(&root, &document_path)?;
        let document = if document_path.exists() {
            if let Ok(document) = read_document(&document_path) {
                document
            } else {
                quarantine_broken_document(&root, &document_path)?;
                LibraryDocument::default()
            }
        } else {
            LibraryDocument::default()
        };
        validate_document(&document)?;
        let mut library = Self {
            root,
            document,
            session_grants: BTreeMap::new(),
            _lock: lock,
        };
        library.recover_interrupted_launches()?;
        library.save()?;
        Ok(library)
    }

    pub fn install(&mut self, package: &Path) -> Result<InstalledVersion, String> {
        let incoming = self.root.join("packages/.incoming");
        fs::create_dir_all(&incoming).map_err(|error| error.to_string())?;
        let sequence = INSTALL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staged = incoming.join(format!("{}-{sequence}.cartridge", std::process::id()));
        let (bytes, digest) = copy_bounded_and_hash(package, &staged, MAX_PACKAGE_FILE_BYTES)?;
        let archive = match CartridgeArchive::open(&staged) {
            Ok(archive) => archive,
            Err(error) => {
                let _ = fs::remove_file(&staged);
                return Err(error.to_string());
            }
        };
        let id = archive.manifest.cartridge.id.clone();
        let version = archive.manifest.cartridge.version.clone();
        if self.total_versions() >= MAX_INSTALLED_PACKAGES
            && self
                .document
                .installed
                .get(&id)
                .and_then(|values| values.get(&version))
                .is_none()
        {
            let _ = fs::remove_file(&staged);
            return Err(format!(
                "library reached the {MAX_INSTALLED_PACKAGES}-package limit"
            ));
        }
        if let Some(existing) = self
            .document
            .installed
            .get(&id)
            .and_then(|versions| versions.get(&version))
        {
            let _ = fs::remove_file(&staged);
            if existing.package_sha256 != digest {
                return Err("an installed version is immutable; use a new version number".into());
            }
            let existing_path = self.root.join(&existing.relative_path);
            if !existing_path.is_file() || hash_file(&existing_path)? != digest {
                return Err("the installed package failed integrity verification".into());
            }
            return Ok(existing.clone());
        }
        let relative_path = format!("packages/{id}/{version}/{digest}.cartridge");
        let destination = self.root.join(&relative_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        if destination.exists() {
            if hash_file(&destination)? != digest {
                let _ = fs::remove_file(&staged);
                return Err("installed package path has unexpected contents".into());
            }
        } else if let Err(error) = fs::hard_link(&staged, &destination) {
            let _ = fs::remove_file(&staged);
            return Err(error.to_string());
        }
        fs::remove_file(&staged).map_err(|error| error.to_string())?;
        let installed = InstalledVersion {
            name: archive.manifest.cartridge.name,
            description: archive.manifest.cartridge.description,
            package_sha256: digest,
            package_bytes: bytes,
            relative_path,
            requested_permissions: capabilities(&archive.manifest.permissions),
            installed_at_ms: now_ms()?,
        };
        self.document
            .installed
            .entry(id)
            .or_default()
            .insert(version, installed.clone());
        self.save()?;
        Ok(installed)
    }

    #[must_use]
    pub fn list(&self, query: Option<&str>) -> Vec<LibraryEntry> {
        let query = query.unwrap_or_default().to_ascii_lowercase();
        self.document
            .installed
            .iter()
            .filter_map(|(id, versions)| {
                let newest = newest_version(versions)?;
                if !query.is_empty()
                    && !id.to_ascii_lowercase().contains(&query)
                    && !newest.name.to_ascii_lowercase().contains(&query)
                    && !newest.description.to_ascii_lowercase().contains(&query)
                {
                    return None;
                }
                let mut version_names: Vec<_> = versions.keys().cloned().collect();
                version_names.sort_by(|left, right| compare_versions(right, left));
                Some(LibraryEntry {
                    cartridge_id: id.clone(),
                    name: newest.name.clone(),
                    versions: version_names,
                    safe_mode: self
                        .document
                        .health
                        .get(id)
                        .is_some_and(|value| value.safe_mode),
                })
            })
            .collect()
    }

    pub fn preflight(
        &self,
        id: &str,
        version: Option<&str>,
    ) -> Result<PermissionPreflight, String> {
        let (version, installed) = self.installed_version(id, version)?;
        let request_digest = capability_request_digest(&installed.requested_permissions);
        let mut granted = self
            .document
            .grants
            .get(id)
            .map_or_else(BTreeSet::new, |value| {
                if value.approved_request_sha256 == request_digest {
                    value.capabilities.clone()
                } else {
                    BTreeSet::new()
                }
            });
        if let Some(session) = self.session_grants.get(id) {
            granted.extend(session);
        }
        granted = granted
            .intersection(&installed.requested_permissions)
            .copied()
            .collect();
        let missing = installed
            .requested_permissions
            .difference(&granted)
            .copied()
            .collect();
        Ok(PermissionPreflight {
            cartridge_id: id.into(),
            version,
            requested: installed.requested_permissions.clone(),
            granted,
            missing,
        })
    }

    pub fn permission_prompt(
        &self,
        id: &str,
        version: Option<&str>,
    ) -> Result<PermissionPrompt, String> {
        let preflight = self.preflight(id, version)?;
        let rows = preflight
            .missing
            .iter()
            .copied()
            .map(permission_row)
            .collect();
        Ok(PermissionPrompt {
            title: format!("Permissions for {}", preflight.cartridge_id),
            summary: format!(
                "Review {} requested capability or capabilities before launch.",
                preflight.missing.len()
            ),
            rows,
            approve_label: "Approve and launch".into(),
            deny_label: "Cancel".into(),
        })
    }

    pub fn grant(
        &mut self,
        id: &str,
        capabilities: &BTreeSet<Capability>,
        persistent: bool,
    ) -> Result<(), String> {
        let (_, installed) = self.installed_version(id, None)?;
        if !capabilities.is_subset(&installed.requested_permissions) {
            return Err("cannot grant a capability the cartridge did not request".into());
        }
        if persistent {
            let now = now_ms()?;
            let request_digest = capability_request_digest(&installed.requested_permissions);
            self.document
                .grants
                .entry(id.into())
                .or_insert_with(|| PersistentGrant {
                    cartridge_id: id.into(),
                    capabilities: BTreeSet::new(),
                    approved_request_sha256: request_digest.clone(),
                    updated_at_ms: now,
                });
            if let Some(grant) = self.document.grants.get_mut(id) {
                if grant.approved_request_sha256 != request_digest {
                    grant.capabilities.clear();
                    grant.approved_request_sha256 = request_digest;
                }
                grant.capabilities.extend(capabilities);
                grant.updated_at_ms = now;
            }
            self.save()
        } else {
            self.session_grants
                .entry(id.into())
                .or_default()
                .extend(capabilities);
            Ok(())
        }
    }

    pub fn revoke(&mut self, id: &str, capability: Option<Capability>) -> Result<(), String> {
        if let Some(capability) = capability {
            if let Some(grant) = self.document.grants.get_mut(id) {
                grant.capabilities.remove(&capability);
            }
            if let Some(grant) = self.session_grants.get_mut(id) {
                grant.remove(&capability);
            }
        } else {
            self.document.grants.remove(id);
            self.session_grants.remove(id);
        }
        self.save()
    }

    pub fn begin_launch(
        &mut self,
        id: &str,
        version: Option<&str>,
    ) -> Result<LaunchRecord, String> {
        if self
            .document
            .health
            .get(id)
            .is_some_and(|value| value.safe_mode)
        {
            return Err("cartridge is in safe mode; reset it before launching".into());
        }
        let preflight = self.preflight(id, version)?;
        if !preflight.missing.is_empty() {
            return Err(format!(
                "permission approval required: {:?}",
                preflight.missing
            ));
        }
        let record = LaunchRecord {
            id: self
                .document
                .history
                .last()
                .map_or(1, |value| value.id.saturating_add(1)),
            cartridge_id: id.into(),
            version: preflight.version,
            started_at_ms: now_ms()?,
            finished_at_ms: None,
            status: LaunchStatus::Running,
            fuel_consumed: None,
            peak_memory_bytes: None,
            trace_path: None,
            resource_samples: Vec::new(),
        };
        self.document.history.push(record.clone());
        self.trim_history();
        self.save()?;
        Ok(record)
    }

    pub fn finish_launch(
        &mut self,
        launch_id: u64,
        status: LaunchStatus,
        fuel_consumed: Option<u64>,
        peak_memory_bytes: Option<u64>,
        trace_path: Option<String>,
    ) -> Result<(), String> {
        if status == LaunchStatus::Running {
            return Err("a completed launch cannot retain running status".into());
        }
        let record = self
            .document
            .history
            .iter_mut()
            .find(|value| value.id == launch_id)
            .ok_or_else(|| "launch record was not found".to_string())?;
        if record.status != LaunchStatus::Running {
            return Err("launch record is already complete".into());
        }
        record.status = status;
        record.finished_at_ms = Some(now_ms()?);
        record.fuel_consumed = fuel_consumed;
        record.peak_memory_bytes = peak_memory_bytes;
        record.trace_path = trace_path
            .map(|value| sanitize_trace_path(&value))
            .transpose()?;
        let health = self
            .document
            .health
            .entry(record.cartridge_id.clone())
            .or_default();
        if status == LaunchStatus::Succeeded {
            health.consecutive_failures = 0;
        } else {
            health.consecutive_failures = health.consecutive_failures.saturating_add(1);
            health.safe_mode = health.consecutive_failures >= SAFE_MODE_CRASH_THRESHOLD;
        }
        self.save()
    }

    pub fn record_resource_sample(
        &mut self,
        launch_id: u64,
        sample: ResourceSample,
    ) -> Result<(), String> {
        let record = self
            .document
            .history
            .iter_mut()
            .find(|value| value.id == launch_id)
            .ok_or_else(|| "launch record was not found".to_string())?;
        if record.status != LaunchStatus::Running {
            return Err("resource samples require a running launch".into());
        }
        if record.resource_samples.len() >= MAX_RESOURCE_SAMPLES_PER_LAUNCH {
            return Err("resource sample limit exceeded".into());
        }
        if record
            .resource_samples
            .last()
            .is_some_and(|previous| sample.elapsed_ms < previous.elapsed_ms)
        {
            return Err("resource sample time cannot move backwards".into());
        }
        record.resource_samples.push(sample);
        self.save()
    }

    pub fn set_runtime_release(&mut self, channel: &str, version: &str) -> Result<(), String> {
        if !matches!(channel, "stable" | "beta" | "nightly") {
            return Err("runtime channel must be stable, beta, or nightly".into());
        }
        Version::parse(version).map_err(|_| "runtime version must be valid SemVer".to_string())?;
        self.document.runtime_channel = channel.into();
        self.document.runtime_version = version.into();
        self.save()
    }

    pub fn reset_safe_mode(&mut self, id: &str) -> Result<(), String> {
        let health = self.document.health.entry(id.into()).or_default();
        health.consecutive_failures = 0;
        health.safe_mode = false;
        self.save()
    }

    #[must_use]
    pub fn history(&self) -> &[LaunchRecord] {
        &self.document.history
    }

    pub fn set_profile(&mut self, name: &str, cartridges: BTreeSet<String>) -> Result<(), String> {
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err("profile name is invalid".into());
        }
        if cartridges
            .iter()
            .any(|id| !self.document.installed.contains_key(id))
        {
            return Err("profile contains a cartridge that is not installed".into());
        }
        self.document.profiles.insert(
            name.into(),
            Profile {
                name: name.into(),
                cartridges,
            },
        );
        self.save()
    }

    #[must_use]
    pub fn profiles(&self) -> Vec<&Profile> {
        self.document.profiles.values().collect()
    }

    pub fn package_path(&self, id: &str, version: Option<&str>) -> Result<PathBuf, String> {
        let (_, installed) = self.installed_version(id, version)?;
        let path = self.root.join(&installed.relative_path);
        if !path.is_file() || hash_file(&path)? != installed.package_sha256 {
            return Err("installed package is missing or failed integrity verification".into());
        }
        Ok(path)
    }

    #[must_use]
    pub fn accepts_file(path: &Path) -> bool {
        path.extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("cartridge"))
    }

    fn installed_version(
        &self,
        id: &str,
        version: Option<&str>,
    ) -> Result<(String, &InstalledVersion), String> {
        let versions = self
            .document
            .installed
            .get(id)
            .ok_or_else(|| "cartridge is not installed".to_string())?;
        if let Some(version) = version {
            return versions
                .get(version)
                .map(|value| (version.into(), value))
                .ok_or_else(|| "cartridge version is not installed".into());
        }
        newest_version_with_name(versions)
            .ok_or_else(|| "cartridge has no installed versions".into())
    }

    fn total_versions(&self) -> usize {
        self.document.installed.values().map(BTreeMap::len).sum()
    }

    fn recover_interrupted_launches(&mut self) -> Result<(), String> {
        let interrupted: Vec<_> = self
            .document
            .history
            .iter()
            .filter(|value| value.status == LaunchStatus::Running)
            .map(|value| (value.id, value.cartridge_id.clone()))
            .collect();
        if interrupted.is_empty() {
            return Ok(());
        }
        let now = now_ms()?;
        for (id, cartridge_id) in interrupted {
            if let Some(record) = self
                .document
                .history
                .iter_mut()
                .find(|value| value.id == id)
            {
                record.status = LaunchStatus::Terminated;
                record.finished_at_ms = Some(now);
            }
            let health = self.document.health.entry(cartridge_id).or_default();
            health.consecutive_failures = health.consecutive_failures.saturating_add(1);
            health.safe_mode = health.consecutive_failures >= SAFE_MODE_CRASH_THRESHOLD;
        }
        Ok(())
    }

    fn trim_history(&mut self) {
        if self.document.history.len() > MAX_LAUNCH_HISTORY {
            let remove = self.document.history.len() - MAX_LAUNCH_HISTORY;
            self.document.history.drain(..remove);
        }
    }

    fn save(&self) -> Result<(), String> {
        validate_document(&self.document)?;
        let bytes = serde_json::to_vec_pretty(&self.document).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_LIBRARY_DOCUMENT_BYTES {
            return Err("library document exceeds its size limit".into());
        }
        atomic_replace(&self.root.join("library.json"), &bytes)
    }
}

fn capabilities(value: &Permissions) -> BTreeSet<Capability> {
    [
        (Capability::Clock, value.clock),
        (Capability::Random, value.random),
        (Capability::Assets, value.assets),
        (Capability::Storage, value.storage),
        (Capability::Graphics, value.graphics),
        (Capability::Audio, value.audio),
        (Capability::Midi, value.midi),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect()
}

fn permission_row(capability: Capability) -> PermissionRow {
    let (label, description) = match capability {
        Capability::Clock => ("Clock", "Read host wall-clock time."),
        Capability::Random => ("Randomness", "Request host-generated random bytes."),
        Capability::Assets => (
            "Packaged assets",
            "Read files bundled inside this cartridge.",
        ),
        Capability::Storage => (
            "Private storage",
            "Read and change isolated persistent state.",
        ),
        Capability::Graphics => (
            "Graphics",
            "Open cartridge windows and submit drawing work.",
        ),
        Capability::Audio => (
            "Audio",
            "Create audio graphs and send sound to an output device.",
        ),
        Capability::Midi => ("MIDI", "Receive events from approved MIDI devices."),
    };
    PermissionRow {
        capability,
        label,
        description,
    }
}

fn capability_request_digest(value: &BTreeSet<Capability>) -> String {
    let mut digest = Sha256::new();
    for capability in value {
        let label = match capability {
            Capability::Clock => b"clock".as_slice(),
            Capability::Random => b"random".as_slice(),
            Capability::Assets => b"assets".as_slice(),
            Capability::Storage => b"storage".as_slice(),
            Capability::Graphics => b"graphics".as_slice(),
            Capability::Audio => b"audio".as_slice(),
            Capability::Midi => b"midi".as_slice(),
        };
        digest.update((label.len() as u64).to_le_bytes());
        digest.update(label);
    }
    hex::encode(digest.finalize())
}

fn validate_document(value: &LibraryDocument) -> Result<(), String> {
    if value.format_version != LIBRARY_FORMAT_VERSION {
        return Err("unsupported library format".into());
    }
    if value.installed.values().map(BTreeMap::len).sum::<usize>() > MAX_INSTALLED_PACKAGES {
        return Err("library package limit exceeded".into());
    }
    if value.history.len() > MAX_LAUNCH_HISTORY {
        return Err("library history limit exceeded".into());
    }
    if value.history.iter().any(|record| {
        record.resource_samples.len() > MAX_RESOURCE_SAMPLES_PER_LAUNCH
            || record
                .resource_samples
                .windows(2)
                .any(|pair| pair[1].elapsed_ms < pair[0].elapsed_ms)
    }) {
        return Err("invalid launch resource samples".into());
    }
    if value
        .history
        .windows(2)
        .any(|pair| pair[1].id <= pair[0].id)
    {
        return Err("launch record ids must be strictly increasing".into());
    }
    for (id, versions) in &value.installed {
        for (version, installed) in versions {
            Version::parse(version).map_err(|_| "invalid installed version".to_string())?;
            let expected_prefix = format!("packages/{id}/{version}/");
            if !installed.relative_path.starts_with(&expected_prefix)
                || !installed.relative_path.ends_with(".cartridge")
                || installed.relative_path.contains("..")
                || installed.relative_path.contains('\\')
            {
                return Err("unsafe installed package path".into());
            }
            if installed.package_sha256.len() != 64
                || !installed
                    .package_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("invalid installed package digest".into());
            }
        }
    }
    for (id, grant) in &value.grants {
        if grant.cartridge_id != *id
            || grant.approved_request_sha256.len() != 64
            || !grant
                .approved_request_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid persistent grant".into());
        }
    }
    Ok(())
}

fn acquire_library_lock(file: &File) -> Result<(), String> {
    for _ in 0..LIBRARY_LOCK_ATTEMPTS {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(LIBRARY_LOCK_DELAY),
            Err(TryLockError::Error(error)) => return Err(error.to_string()),
        }
    }
    Err("desktop library is busy".into())
}

fn read_document(path: &Path) -> Result<LibraryDocument, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_LIBRARY_DOCUMENT_BYTES {
        return Err("library document exceeds its size limit".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_LIBRARY_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_LIBRARY_DOCUMENT_BYTES {
        return Err("library document exceeded its size limit while reading".into());
    }
    let document = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    validate_document(&document)?;
    Ok(document)
}

fn quarantine_broken_document(root: &Path, source: &Path) -> Result<(), String> {
    let recovery = root.join("recovery");
    for sequence in 0..1024u32 {
        let destination = recovery.join(format!("library-corrupt-{sequence}.json"));
        if !destination.exists() {
            fs::rename(source, destination).map_err(|error| error.to_string())?;
            return Ok(());
        }
    }
    Err("recovery directory is full".into())
}

fn recover_library_document(root: &Path, document: &Path) -> Result<(), String> {
    let backup = root.join("library.json.previous");
    if !document.exists() && backup.exists() {
        if read_document(&backup).is_ok() {
            fs::rename(&backup, document).map_err(|error| error.to_string())?;
        } else {
            quarantine_broken_document(root, &backup)?;
        }
        return Ok(());
    }
    if document.exists() && read_document(document).is_err() && backup.exists() {
        if read_document(&backup).is_ok() {
            quarantine_broken_document(root, document)?;
            fs::rename(&backup, document).map_err(|error| error.to_string())?;
        } else {
            quarantine_broken_document(root, &backup)?;
        }
    }
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let sequence = SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("json.{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    drop(file);
    if path.exists() {
        let backup = path.with_extension("json.previous");
        if backup.exists() {
            fs::remove_file(&backup).map_err(|error| error.to_string())?;
        }
        fs::rename(path, &backup).map_err(|error| error.to_string())?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&backup, path);
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    } else {
        fs::rename(temporary, path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn copy_bounded_and_hash(
    source: &Path,
    destination: &Path,
    limit: u64,
) -> Result<(u64, String), String> {
    if fs::metadata(source)
        .map_err(|error| error.to_string())?
        .len()
        > limit
    {
        return Err(format!("package exceeds the {limit}-byte file limit"));
    }
    let mut input = File::open(source).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let mut digest = Sha256::new();
        let mut total = 0u64;
        let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = input.read(&mut buffer).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| "package size overflow".to_string())?;
            if total > limit {
                return Err(format!(
                    "package exceeded the {limit}-byte limit while reading"
                ));
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| error.to_string())?;
            digest.update(&buffer[..read]);
        }
        output.sync_all().map_err(|error| error.to_string())?;
        Ok((total, hex::encode(digest.finalize())))
    })();
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn newest_version(versions: &BTreeMap<String, InstalledVersion>) -> Option<&InstalledVersion> {
    newest_version_with_name(versions).map(|(_, value)| value)
}

fn newest_version_with_name(
    versions: &BTreeMap<String, InstalledVersion>,
) -> Option<(String, &InstalledVersion)> {
    versions
        .iter()
        .max_by(|(left, _), (right, _)| compare_versions(left, right))
        .map(|(version, value)| (version.clone(), value))
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    Version::parse(left).ok().cmp(&Version::parse(right).ok())
}

fn now_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system timestamp overflow".into())
}

fn sanitize_trace_path(value: &str) -> Result<String, String> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err("trace path is invalid".into());
    }
    Ok(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartridge_core::{PackOptions, pack};

    fn package(root: &Path, permissions: &str) -> PathBuf {
        let manifest = root.join("Cartridge.toml");
        let component = root.join("component.wasm");
        let output = root.join("demo.cartridge");
        fs::write(&manifest, format!("format_version = 1\n[cartridge]\nid = \"dev.test.demo\"\nname = \"Demo\"\nversion = \"1.0.0\"\n[permissions]\n{permissions}\n")).unwrap();
        fs::write(&component, b"\0asm\x01\0\0\0").unwrap();
        pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output: output.clone(),
        })
        .unwrap();
        output
    }

    #[test]
    fn install_preflight_grant_and_revoke() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "graphics = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let preflight = library.preflight("dev.test.demo", None).unwrap();
        assert_eq!(preflight.missing, BTreeSet::from([Capability::Graphics]));
        let prompt = library.permission_prompt("dev.test.demo", None).unwrap();
        assert_eq!(prompt.rows[0].label, "Graphics");
        library
            .grant("dev.test.demo", &preflight.missing, true)
            .unwrap();
        assert!(
            library
                .preflight("dev.test.demo", None)
                .unwrap()
                .missing
                .is_empty()
        );
        library.revoke("dev.test.demo", None).unwrap();
        assert!(
            !library
                .preflight("dev.test.demo", None)
                .unwrap()
                .missing
                .is_empty()
        );
    }

    #[test]
    fn capability_changes_require_fresh_approval() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "graphics = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        library
            .grant(
                "dev.test.demo",
                &BTreeSet::from([Capability::Graphics]),
                true,
            )
            .unwrap();
        library
            .document
            .installed
            .get_mut("dev.test.demo")
            .unwrap()
            .get_mut("1.0.0")
            .unwrap()
            .requested_permissions
            .insert(Capability::Audio);
        let preflight = library.preflight("dev.test.demo", None).unwrap();
        assert!(preflight.granted.is_empty());
        assert_eq!(
            preflight.missing,
            BTreeSet::from([Capability::Graphics, Capability::Audio])
        );
    }

    #[test]
    fn repeated_crashes_enable_safe_mode() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        for _ in 0..SAFE_MODE_CRASH_THRESHOLD {
            let launch = library.begin_launch("dev.test.demo", None).unwrap();
            library
                .finish_launch(launch.id, LaunchStatus::Failed, None, None, None)
                .unwrap();
        }
        assert!(library.begin_launch("dev.test.demo", None).is_err());
        library.reset_safe_mode("dev.test.demo").unwrap();
        assert!(library.begin_launch("dev.test.demo", None).is_ok());
    }

    #[test]
    fn resource_samples_are_bounded_and_monotonic() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let launch = library.begin_launch("dev.test.demo", None).unwrap();
        library
            .record_resource_sample(
                launch.id,
                ResourceSample {
                    elapsed_ms: 5,
                    fuel_consumed: 10,
                    memory_bytes: 1024,
                    audio_underruns: 0,
                },
            )
            .unwrap();
        assert!(
            library
                .record_resource_sample(
                    launch.id,
                    ResourceSample {
                        elapsed_ms: 4,
                        fuel_consumed: 10,
                        memory_bytes: 1024,
                        audio_underruns: 0,
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn corrupt_index_is_quarantined() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        fs::create_dir_all(root.join("packages")).unwrap();
        fs::create_dir_all(root.join("recovery")).unwrap();
        fs::write(root.join("library.json"), b"not json").unwrap();
        let library = Library::open(&root).unwrap();
        assert!(library.list(None).is_empty());
        assert!(root.join("recovery/library-corrupt-0.json").exists());
    }

    #[test]
    fn corrupt_index_and_backup_cannot_block_library_startup() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        fs::create_dir_all(root.join("packages")).unwrap();
        fs::create_dir_all(root.join("recovery")).unwrap();
        fs::write(root.join("library.json"), b"bad current").unwrap();
        fs::write(root.join("library.json.previous"), b"bad backup").unwrap();
        let library = Library::open(&root).unwrap();
        assert!(library.list(None).is_empty());
        assert_eq!(fs::read_dir(root.join("recovery")).unwrap().count(), 2);
    }

    #[test]
    fn interrupted_index_replacement_recovers_the_backup() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        let package = package(directory.path(), "");
        {
            let mut library = Library::open(&root).unwrap();
            library.install(&package).unwrap();
        }
        fs::rename(
            root.join("library.json"),
            root.join("library.json.previous"),
        )
        .unwrap();
        let library = Library::open(&root).unwrap();
        assert_eq!(library.list(None).len(), 1);
    }

    #[test]
    fn concurrent_library_open_waits_for_the_active_writer() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        let first = Library::open(&root).unwrap();
        let second_root = root.clone();
        let second = std::thread::spawn(move || Library::open(second_root));
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(first);
        assert!(second.join().unwrap().is_ok());
    }

    #[test]
    fn gpu_policy_requires_bounded_isolated_adapter() {
        let adapter = GpuAdapterInfo {
            backend: GpuBackend::Software,
            name: "cpu".into(),
            driver: "reference".into(),
            supports_robust_buffer_access: true,
            supports_process_isolation: true,
        };
        assert!(RenderPolicy::canonical().validate_for(&adapter).is_ok());
    }
}

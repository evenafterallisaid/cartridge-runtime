mod daemon;
mod health;
mod probe;
mod rolling;
mod rollout;
mod rollout_progress;
mod supervisor;

pub use daemon::{
    DAEMON_ENDPOINT_FILE, DAEMON_PROTOCOL_VERSION, DaemonCodec, DaemonEndpoint, DaemonFrame,
    DaemonInfo, DaemonLease, DaemonRequest, DaemonResponse, MAX_DAEMON_EVENTS,
    MAX_DAEMON_FRAME_BYTES, MAX_DAEMON_SUPERVISORS, OpenedDaemonRequest, daemon_request,
    daemon_request_with_timeout,
};
pub use health::{
    ENGINE_HEALTH_FORMAT_VERSION, MAX_ENGINE_HEALTH_REPORTS, SUPERVISOR_STALE_AFTER_MS,
    StackHealthReport, StackHealthState, validate_health_reports,
};
pub use probe::{
    ENGINE_PROBE_FORMAT_VERSION, MAX_PROBE_ENVELOPE_BYTES, MAX_PROBE_FAILURE_THRESHOLD,
    MAX_PROBE_TIMEOUT_MS, MIN_PROBE_TIMEOUT_MS, ProbeChannelKey, ProbeEnvelope, ProbeSignal,
    ProbeSignalKind,
};
pub use rolling::{
    MAX_ROLLING_DRAIN_TIMEOUT_MS, MAX_ROLLING_MIN_READY_MS, MAX_ROLLING_PROGRESS_DEADLINE_MS,
    MIN_ROLLING_PROGRESS_DEADLINE_MS, RollingAction, RollingObservation, RollingOrder,
    RollingRollbackReason, RollingUpdatePolicy, RollingWaitReason,
};
pub use rollout::{
    ENGINE_ROLLOUT_FORMAT_VERSION, MAX_ROLLOUT_BYTES, MAX_ROLLOUT_HISTORY,
    MAX_ROLLOUT_HISTORY_BYTES, ROLLOUT_STABILITY_WINDOW_MS, RolloutPhase, RolloutRecord,
    RolloutStatus,
};
pub use rollout_progress::{
    DrainIntent, ENGINE_ROLLOUT_PROGRESS_FORMAT_VERSION, MAX_ROLLOUT_PROGRESS_BYTES,
    RolloutExecutionPhase, RolloutInstanceProgress, RolloutProgress,
};
pub use supervisor::{
    LEGACY_SUPERVISOR_STATUS_FORMAT_VERSION, ProbePhase, ReplicaId, ReplicaPhase,
    ReplicaProbeRuntime, ReplicaRuntime, SUPERVISOR_STATUS_FORMAT_VERSION, StackRuntimeStatus,
};

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use cartridge_core::{
    CartridgeArchive, CompositionLock, LockedPackage, MAX_RESOLUTION_CANDIDATES, PackageManifest,
    RuntimeLimits, resolve_dependencies,
};
use cartridge_desktop::{CatalogPackage, Library};
use fs4::{FileExt, TryLockError};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STACK_FORMAT_VERSION: u32 = 1;
pub const STACK_PLAN_FORMAT_VERSION: u32 = 4;
pub const LEGACY_STACK_PLAN_FORMAT_VERSION: u32 = 2;
pub const HEALTH_STACK_PLAN_FORMAT_VERSION: u32 = 3;
pub const ENGINE_EVENT_FORMAT_VERSION: u32 = 1;
pub const MAX_STACK_BYTES: u64 = 1024 * 1024;
pub const MAX_STACK_INSTANCES: usize = 64;
pub const MAX_STACK_REPLICAS: u16 = 32;
pub const MAX_STACK_TOTAL_REPLICAS: u16 = 256;
pub const MAX_STACK_TOTAL_SURGE_REPLICAS: u16 = 64;
pub const MAX_STACK_TOTAL_ACTIVE_REPLICAS: u16 =
    MAX_STACK_TOTAL_REPLICAS + MAX_STACK_TOTAL_SURGE_REPLICAS;
pub const MAX_STACK_RESTARTS: u16 = 64;
pub const MAX_STACK_RESOURCES: usize = 128;
pub const MAX_STACK_SECRETS: usize = 128;
pub const MAX_STACK_ARGUMENTS: usize = 256;
pub const MAX_STACK_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_STACK_PLAN_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENGINE_EVENTS_PER_STACK: usize = 4096;
pub const MAX_ENGINE_STACKS: usize = 1024;
pub const MAX_ENGINE_EVENT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ENGINE_EVENT_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RUNTIME_STATUS_BYTES: u64 = 1024 * 1024;
pub const MAX_STALE_PROBE_FILES: usize = 4096;

const ENGINE_LOCK_ATTEMPTS: usize = 200;
const ENGINE_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(10);
static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackManifest {
    pub format_version: u32,
    pub name: String,
    #[serde(default)]
    pub security: StackSecurity,
    pub instances: Vec<InstanceSpec>,
    #[serde(default)]
    pub resources: Vec<ResourceSpec>,
    #[serde(default)]
    pub secrets: Vec<SecretSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackSecurity {
    #[serde(default)]
    pub profile: SecurityProfile,
    #[serde(default)]
    pub sandbox: SandboxPolicy,
}

impl Default for StackSecurity {
    fn default() -> Self {
        Self {
            profile: SecurityProfile::Strict,
            sandbox: SandboxPolicy::Required,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityProfile {
    #[default]
    Strict,
    Balanced,
    Permissive,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxPolicy {
    #[default]
    Required,
    Preferred,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceSpec {
    pub name: String,
    pub cartridge: String,
    pub version: String,
    #[serde(default = "one_replica")]
    pub replicas: u16,
    #[serde(default)]
    pub desired: DesiredState,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default = "default_restart_limit")]
    pub max_restarts: u16,
    #[serde(default)]
    pub allow: BTreeSet<StackCapability>,
    #[serde(default)]
    pub deny: BTreeSet<StackCapability>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub secrets: BTreeSet<String>,
    #[serde(default)]
    pub limits: InstanceLimits,
    #[serde(default)]
    pub health: Option<HealthProbeSpec>,
    #[serde(default)]
    pub update: RollingUpdatePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthProbeSpec {
    pub startup_timeout_ms: u64,
    pub readiness_timeout_ms: u64,
    pub liveness_timeout_ms: u64,
    pub failure_threshold: u16,
}

impl Default for HealthProbeSpec {
    fn default() -> Self {
        Self {
            startup_timeout_ms: 10_000,
            readiness_timeout_ms: 30_000,
            liveness_timeout_ms: 15_000,
            failure_threshold: 3,
        }
    }
}

impl HealthProbeSpec {
    pub fn validate(&self) -> Result<(), String> {
        let timeouts = [
            self.startup_timeout_ms,
            self.readiness_timeout_ms,
            self.liveness_timeout_ms,
        ];
        if timeouts
            .into_iter()
            .any(|value| !(MIN_PROBE_TIMEOUT_MS..=MAX_PROBE_TIMEOUT_MS).contains(&value))
            || self.readiness_timeout_ms < self.startup_timeout_ms
            || self.failure_threshold == 0
            || self.failure_threshold > MAX_PROBE_FAILURE_THRESHOLD
        {
            return Err("application health probe policy is invalid".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InstanceLimits {
    pub fuel: Option<u64>,
    pub memory_bytes: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub storage_bytes: Option<usize>,
    pub storage_keys: Option<usize>,
    pub storage_value_bytes: Option<usize>,
    pub graphics_pixels: Option<usize>,
    pub graphics_commands: Option<usize>,
    pub audio_nodes: Option<usize>,
    pub audio_events: Option<usize>,
    pub audio_frames: Option<u64>,
}

impl InstanceLimits {
    fn ceiling(&self) -> Result<RuntimeLimits, String> {
        let mut limits = RuntimeLimits::maximum();
        macro_rules! apply {
            ($field:ident) => {
                if let Some(value) = self.$field {
                    limits.$field = value;
                }
            };
        }
        apply!(fuel);
        apply!(memory_bytes);
        apply!(timeout_ms);
        apply!(storage_bytes);
        apply!(storage_keys);
        apply!(storage_value_bytes);
        apply!(graphics_pixels);
        apply!(graphics_commands);
        apply!(audio_nodes);
        apply!(audio_events);
        apply!(audio_frames);
        limits.storage_value_bytes = limits.storage_value_bytes.min(limits.storage_bytes);
        limits.validate().map_err(|error| error.to_string())?;
        Ok(limits)
    }

    fn apply(&self, requested: &RuntimeLimits) -> Result<RuntimeLimits, String> {
        Ok(requested.constrained_by(&self.ceiling()?))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesiredState {
    #[default]
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Never,
    #[default]
    OnFailure,
    Always,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackCapability {
    Clock,
    Random,
    Assets,
    Storage,
    Graphics,
    Audio,
    Midi,
    Http,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    pub name: String,
    pub kind: ResourceKind,
    pub owner: String,
    #[serde(default)]
    pub retention: RetentionPolicy,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    State,
    Blob,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPolicy {
    #[default]
    Retain,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    pub name: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackPlan {
    pub format_version: u32,
    pub stack: String,
    pub security: PlannedSecurity,
    pub instances: Vec<PlannedInstance>,
    pub resources: Vec<PlannedResource>,
    pub secrets: Vec<PlannedSecret>,
    pub warnings: Vec<String>,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSecurity {
    pub profile: SecurityProfile,
    pub sandbox: SandboxPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedInstance {
    pub name: String,
    pub cartridge_id: String,
    pub version: String,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub replicas: u16,
    pub desired: DesiredState,
    pub restart: RestartPolicy,
    pub max_restarts: u16,
    pub requested: BTreeSet<StackCapability>,
    pub granted: BTreeSet<StackCapability>,
    pub blocked: BTreeSet<StackCapability>,
    pub allowed: BTreeSet<StackCapability>,
    pub denied: BTreeSet<StackCapability>,
    pub args: Vec<String>,
    pub secrets: BTreeSet<String>,
    pub limits: RuntimeLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthProbeSpec>,
    #[serde(default, skip_serializing_if = "RollingUpdatePolicy::is_default")]
    pub update: RollingUpdatePolicy,
    pub composition: CompositionLock,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedResource {
    pub name: String,
    pub kind: ResourceKind,
    pub owner: String,
    pub retention: RetentionPolicy,
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSecret {
    pub name: String,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineEventKind {
    Apply,
    Stop,
    Remove,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineEvent {
    pub format_version: u32,
    pub revision: u64,
    pub stack: String,
    pub kind: EngineEventKind,
    pub previous_event_sha256: String,
    pub created_at_ms: u64,
    pub plan: Option<StackPlan>,
    pub event_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineStackState {
    Applied,
    Stopped,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackStatus {
    pub stack: String,
    pub revision: u64,
    pub state: EngineStackState,
    pub plan_sha256: Option<String>,
    pub instance_count: usize,
    pub desired_replicas: u64,
    pub event_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReport {
    pub changed: bool,
    pub status: StackStatus,
}

pub struct EngineStore {
    root: PathBuf,
    _lock: File,
}

pub struct SupervisorLease {
    _lock: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenerationRole {
    Desired,
    RolloutCandidate,
    RolloutPrevious,
}

#[derive(Clone, Debug, Serialize)]
pub struct GenerationTarget {
    pub stack: String,
    pub revision: u64,
    pub generation: String,
    pub role: GenerationRole,
    pub rollout_id: Option<String>,
    pub plan: StackPlan,
}

impl GenerationTarget {
    pub fn validate(&self) -> Result<(), String> {
        self.plan.validate()?;
        let rollout_identity_valid = match self.role {
            GenerationRole::Desired => self.rollout_id.is_none(),
            GenerationRole::RolloutCandidate | GenerationRole::RolloutPrevious => self
                .rollout_id
                .as_ref()
                .is_some_and(|value| is_digest(value)),
        };
        if !valid_name(&self.stack)
            || self.revision == 0
            || !is_digest(&self.generation)
            || self.plan.stack != self.stack
            || !rollout_identity_valid
        {
            return Err("generation target is invalid".into());
        }
        Ok(())
    }
}

impl StackManifest {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() as u64 > MAX_STACK_BYTES {
            return Err("stack manifest exceeds its byte limit".into());
        }
        let value: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        value.validate()?;
        Ok(value)
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_STACK_BYTES
        {
            return Err("stack manifest must be a bounded regular file".into());
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|error| error.to_string())?
            .take(MAX_STACK_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_STACK_BYTES {
            return Err("stack manifest exceeded its byte limit while reading".into());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "stack manifest must be UTF-8".to_string())?;
        Self::parse(text)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != STACK_FORMAT_VERSION
            || !valid_name(&self.name)
            || self.instances.is_empty()
            || self.instances.len() > MAX_STACK_INSTANCES
            || self.resources.len() > MAX_STACK_RESOURCES
            || self.secrets.len() > MAX_STACK_SECRETS
        {
            return Err("stack format, name, or collection count is invalid".into());
        }
        let mut instances = BTreeSet::new();
        let mut total_replicas = 0_u16;
        let mut total_surge = 0_u16;
        for instance in &self.instances {
            validate_instance(instance)?;
            total_replicas = total_replicas
                .checked_add(instance.replicas)
                .ok_or_else(|| "stack replica count overflow".to_string())?;
            total_surge = total_surge
                .checked_add(instance.update.max_surge)
                .ok_or_else(|| "stack surge count overflow".to_string())?;
            if !instances.insert(instance.name.as_str()) {
                return Err("stack instance names must be unique".into());
            }
        }
        if total_replicas > MAX_STACK_TOTAL_REPLICAS || total_surge > MAX_STACK_TOTAL_SURGE_REPLICAS
        {
            return Err("stack exceeds its aggregate replica or surge limit".into());
        }
        let mut resources = BTreeSet::new();
        for resource in &self.resources {
            if !valid_name(&resource.name)
                || !instances.contains(resource.owner.as_str())
                || resource
                    .quota_bytes
                    .is_some_and(|value| value == 0 || value > 64 << 30)
                || !resources.insert(resource.name.as_str())
            {
                return Err("stack resource is invalid".into());
            }
        }
        let mut secrets = BTreeSet::new();
        for secret in &self.secrets {
            if !valid_name(&secret.name) || !secrets.insert(secret.name.as_str()) {
                return Err("stack secret is invalid".into());
            }
        }
        if self
            .instances
            .iter()
            .flat_map(|instance| &instance.secrets)
            .any(|secret| !secrets.contains(secret.as_str()))
        {
            return Err("instance references an undeclared secret".into());
        }
        Ok(())
    }
}

impl StackPlan {
    pub fn build(manifest: &StackManifest, library: &Library) -> Result<Self, String> {
        manifest.validate()?;
        let mut instances = Vec::with_capacity(manifest.instances.len());
        let mut planned_bytes = 0_usize;
        for instance in &manifest.instances {
            let planned = plan_instance(instance, &manifest.security, library)?;
            planned_bytes = planned_bytes
                .checked_add(
                    serde_json::to_vec(&planned)
                        .map_err(|error| error.to_string())?
                        .len(),
                )
                .ok_or_else(|| "stack plan size overflow".to_string())?;
            if planned_bytes > MAX_STACK_PLAN_BYTES {
                return Err("stack plan exceeds its byte limit".into());
            }
            instances.push(planned);
        }
        instances.sort_by(|left, right| left.name.cmp(&right.name));
        let mut resources = manifest
            .resources
            .iter()
            .map(|value| PlannedResource {
                name: value.name.clone(),
                kind: value.kind,
                owner: value.owner.clone(),
                retention: value.retention,
                quota_bytes: value.quota_bytes,
            })
            .collect::<Vec<_>>();
        resources.sort_by(|left, right| left.name.cmp(&right.name));
        let mut secrets = manifest
            .secrets
            .iter()
            .map(|value| PlannedSecret {
                name: value.name.clone(),
                required: value.required,
            })
            .collect::<Vec<_>>();
        secrets.sort_by(|left, right| left.name.cmp(&right.name));
        let mut warnings = Vec::new();
        if manifest.security.sandbox == SandboxPolicy::Disabled {
            warnings.push("native worker sandboxing is explicitly disabled".into());
        }
        for instance in &instances {
            if !instance.denied.is_empty() {
                warnings.push(format!(
                    "{} has denied requested capabilities: {}",
                    instance.name,
                    capability_labels(&instance.denied)
                ));
            }
        }
        let mut value = Self {
            format_version: STACK_PLAN_FORMAT_VERSION,
            stack: manifest.name.clone(),
            security: PlannedSecurity {
                profile: manifest.security.profile,
                sandbox: manifest.security.sandbox,
            },
            instances,
            resources,
            secrets,
            warnings,
            plan_sha256: String::new(),
        };
        value.plan_sha256 = value.computed_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.format_version,
            LEGACY_STACK_PLAN_FORMAT_VERSION
                | HEALTH_STACK_PLAN_FORMAT_VERSION
                | STACK_PLAN_FORMAT_VERSION
        ) || (self.format_version == LEGACY_STACK_PLAN_FORMAT_VERSION
            && self
                .instances
                .iter()
                .any(|instance| instance.health.is_some() || !instance.update.is_default()))
            || (self.format_version == HEALTH_STACK_PLAN_FORMAT_VERSION
                && self
                    .instances
                    .iter()
                    .any(|instance| !instance.update.is_default()))
            || !valid_name(&self.stack)
            || self.instances.is_empty()
            || self.instances.len() > MAX_STACK_INSTANCES
            || !is_digest(&self.plan_sha256)
            || self.computed_sha256()? != self.plan_sha256
        {
            return Err("stack plan identity is invalid".into());
        }
        let names =
            validate_planned_instances(&self.instances, self.security.profile, &self.secrets)?;
        if self.resources.len() > MAX_STACK_RESOURCES
            || self.secrets.len() > MAX_STACK_SECRETS
            || self.warnings.len() > MAX_STACK_INSTANCES + 1
            || self
                .warnings
                .iter()
                .any(|warning| !valid_text(warning, 512, false))
        {
            return Err("stack plan collection is invalid".into());
        }
        validate_planned_resources(&self.resources, &names)?;
        validate_planned_secrets(&self.secrets)?;
        Ok(())
    }

    pub fn stopped(&self) -> Result<Self, String> {
        let mut value = self.clone();
        for instance in &mut value.instances {
            instance.desired = DesiredState::Stopped;
        }
        value.plan_sha256.clear();
        value.plan_sha256 = value.computed_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn verify_installed(&self, library: &Library) -> Result<(), String> {
        self.validate()?;
        let mut checked = BTreeSet::new();
        for instance in &self.instances {
            for package in std::iter::once(&instance.composition.root)
                .chain(instance.composition.providers.iter())
            {
                let key = (package.cartridge_id.as_str(), package.version.as_str());
                if checked.insert(key) {
                    verify_locked_package_installed(package, library)?;
                }
            }
            let record =
                library.catalog_package(&instance.cartridge_id, Some(&instance.version))?;
            let archive = open_catalog_archive(&record)?;
            if archive.manifest.runtime.constrained_by(&instance.limits) != instance.limits {
                return Err(
                    "planned runtime limits are not a ceiling on the installed package".into(),
                );
            }
        }
        Ok(())
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.plan_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_STACK_PLAN_BYTES {
            return Err("stack plan exceeds its byte limit".into());
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

impl EngineEvent {
    fn new(
        revision: u64,
        stack: String,
        kind: EngineEventKind,
        previous_event_sha256: String,
        plan: Option<StackPlan>,
    ) -> Result<Self, String> {
        let mut value = Self {
            format_version: ENGINE_EVENT_FORMAT_VERSION,
            revision,
            stack,
            kind,
            previous_event_sha256,
            created_at_ms: now_ms()?,
            plan,
            event_sha256: String::new(),
        };
        value.event_sha256 = value.computed_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_EVENT_FORMAT_VERSION
            || self.revision == 0
            || self.created_at_ms == 0
            || !valid_name(&self.stack)
            || (self.revision == 1 && !self.previous_event_sha256.is_empty())
            || (self.revision > 1 && !is_digest(&self.previous_event_sha256))
            || !is_digest(&self.event_sha256)
            || self.computed_sha256()? != self.event_sha256
        {
            return Err("engine event identity is invalid".into());
        }
        match self.kind {
            EngineEventKind::Apply => {
                let plan = self
                    .plan
                    .as_ref()
                    .ok_or_else(|| "engine event is missing its plan".to_string())?;
                plan.validate()?;
                if plan.stack != self.stack {
                    return Err("engine event plan belongs to another stack".into());
                }
            }
            EngineEventKind::Stop => {
                let plan = self
                    .plan
                    .as_ref()
                    .ok_or_else(|| "engine event is missing its plan".to_string())?;
                plan.validate()?;
                if plan.stack != self.stack
                    || plan
                        .instances
                        .iter()
                        .any(|instance| instance.desired != DesiredState::Stopped)
                {
                    return Err("stop event contains a running or foreign plan".into());
                }
            }
            EngineEventKind::Remove if self.plan.is_some() => {
                return Err("remove event cannot retain a plan".into());
            }
            EngineEventKind::Remove => {}
        }
        Ok(())
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.event_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn status(&self) -> StackStatus {
        let state = match self.kind {
            EngineEventKind::Apply => EngineStackState::Applied,
            EngineEventKind::Stop => EngineStackState::Stopped,
            EngineEventKind::Remove => EngineStackState::Removed,
        };
        StackStatus {
            stack: self.stack.clone(),
            revision: self.revision,
            state,
            plan_sha256: self.plan.as_ref().map(|plan| plan.plan_sha256.clone()),
            instance_count: self.plan.as_ref().map_or(0, |plan| plan.instances.len()),
            desired_replicas: self.plan.as_ref().map_or(0, |plan| {
                plan.instances
                    .iter()
                    .filter(|instance| instance.desired == DesiredState::Running)
                    .map(|instance| u64::from(instance.replicas))
                    .sum()
            }),
            event_sha256: self.event_sha256.clone(),
        }
    }
}

impl EngineStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        ensure_directory(&root)?;
        ensure_directory(&root.join("stacks"))?;
        let lock_path = root.join("engine.lock");
        if lock_path.exists() && !is_regular_file(&lock_path) {
            return Err("engine lock path is not a regular file".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options.open(lock_path).map_err(|error| error.to_string())?;
        acquire_lock(&lock)?;
        Ok(Self { root, _lock: lock })
    }

    pub fn apply(&self, plan: &StackPlan, allow_insecure: bool) -> Result<ApplyReport, String> {
        plan.validate()?;
        self.ensure_no_active_rollout(&plan.stack)?;
        if plan.security.sandbox == SandboxPolicy::Disabled && !allow_insecure {
            return Err(
                "sandbox-disabled stacks require an explicit insecure-apply confirmation".into(),
            );
        }
        let previous = self.latest(&plan.stack)?;
        if previous.is_none() && self.list()?.len() >= MAX_ENGINE_STACKS {
            return Err("engine stack limit reached".into());
        }
        if let Some(previous) = &previous
            && previous.kind == EngineEventKind::Apply
            && previous
                .plan
                .as_ref()
                .is_some_and(|current| current.plan_sha256 == plan.plan_sha256)
        {
            return Ok(ApplyReport {
                changed: false,
                status: previous.status(),
            });
        }
        let event = next_event(
            previous.as_ref(),
            EngineEventKind::Apply,
            Some(plan.clone()),
        )?;
        self.append(&event)?;
        Ok(ApplyReport {
            changed: true,
            status: event.status(),
        })
    }

    pub fn stop(&self, stack: &str) -> Result<ApplyReport, String> {
        self.ensure_no_active_rollout(stack)?;
        let previous = self
            .latest(stack)?
            .ok_or_else(|| "stack is not known to the engine".to_string())?;
        if previous.kind == EngineEventKind::Remove {
            return Err("removed stack cannot be stopped".into());
        }
        if previous.kind == EngineEventKind::Stop {
            return Ok(ApplyReport {
                changed: false,
                status: previous.status(),
            });
        }
        let plan = previous
            .plan
            .as_ref()
            .ok_or_else(|| "active stack has no plan".to_string())?
            .stopped()?;
        let event = next_event(Some(&previous), EngineEventKind::Stop, Some(plan))?;
        self.append(&event)?;
        Ok(ApplyReport {
            changed: true,
            status: event.status(),
        })
    }

    pub fn remove(&self, stack: &str) -> Result<ApplyReport, String> {
        self.ensure_no_active_rollout(stack)?;
        let previous = self
            .latest(stack)?
            .ok_or_else(|| "stack is not known to the engine".to_string())?;
        if previous.kind == EngineEventKind::Remove {
            return Ok(ApplyReport {
                changed: false,
                status: previous.status(),
            });
        }
        let event = next_event(Some(&previous), EngineEventKind::Remove, None)?;
        self.append(&event)?;
        Ok(ApplyReport {
            changed: true,
            status: event.status(),
        })
    }

    pub fn status(&self, stack: &str) -> Result<StackStatus, String> {
        self.latest(stack)?
            .map(|event| event.status())
            .ok_or_else(|| "stack is not known to the engine".into())
    }

    pub fn desired_plan(&self, stack: &str) -> Result<Option<(u64, String, StackPlan)>, String> {
        let Some(event) = self.latest(stack)? else {
            return Err("stack is not known to the engine".into());
        };
        Ok(event
            .plan
            .map(|plan| (event.revision, event.event_sha256, plan)))
    }

    pub fn generation_target(
        &self,
        stack: &str,
        generation: &str,
    ) -> Result<Option<GenerationTarget>, String> {
        if !valid_name(stack) || !is_digest(generation) {
            return Err("runtime generation identity is invalid".into());
        }
        let desired = self.desired_plan(stack)?;
        let rollout = self.rollout(stack)?;
        if let Some((revision, current_generation, plan)) = desired
            && current_generation == generation
        {
            let active_rollout = rollout.as_ref().filter(|record| {
                record.phase == RolloutPhase::Activated
                    && record.activated_generation.as_deref() == Some(generation)
            });
            let target = GenerationTarget {
                stack: stack.into(),
                revision,
                generation: current_generation,
                role: if active_rollout.is_some() {
                    GenerationRole::RolloutCandidate
                } else {
                    GenerationRole::Desired
                },
                rollout_id: active_rollout.map(|record| record.rollout_id.clone()),
                plan,
            };
            target.validate()?;
            return Ok(Some(target));
        }
        let Some(record) = rollout.filter(|record| {
            record.phase == RolloutPhase::Activated
                && record.previous_state == Some(EngineStackState::Applied)
                && record.previous_generation.as_deref() == Some(generation)
        }) else {
            return Ok(None);
        };
        let target = GenerationTarget {
            stack: stack.into(),
            revision: record
                .previous_revision
                .ok_or_else(|| "rollout previous revision is missing".to_string())?,
            generation: generation.into(),
            role: GenerationRole::RolloutPrevious,
            rollout_id: Some(record.rollout_id),
            plan: record
                .previous_plan
                .ok_or_else(|| "rollout previous plan is missing".to_string())?,
        };
        target.validate()?;
        Ok(Some(target))
    }

    pub fn generation_targets(&self, stack: &str) -> Result<Vec<GenerationTarget>, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let mut generations = Vec::new();
        if let Some((_revision, generation, _plan)) = self.desired_plan(stack)?
            && let Some(target) = self.generation_target(stack, &generation)?
        {
            generations.push(target);
        }
        if let Some(record) = self.rollout(stack)?
            && record.phase == RolloutPhase::Activated
            && record.previous_state == Some(EngineStackState::Applied)
            && let Some(generation) = record.previous_generation.as_deref()
            && let Some(target) = self.generation_target(stack, generation)?
        {
            generations.push(target);
        }
        generations.sort_by(|left, right| left.generation.cmp(&right.generation));
        generations.dedup_by(|left, right| left.generation == right.generation);
        Ok(generations)
    }

    pub fn runtime_status(&self, stack: &str) -> Result<Option<StackRuntimeStatus>, String> {
        let Some((revision, generation, plan)) = self.desired_plan(stack)? else {
            return Ok(None);
        };
        let generation_path = self.generation_runtime_status_path(stack, &generation)?;
        recover_runtime_status(&generation_path)?;
        if generation_path.exists() {
            let status = read_runtime_status(&generation_path)?;
            status.validate_against(&plan, revision, &generation)?;
            return Ok(Some(status));
        }
        let path = self.runtime_status_path(stack)?;
        recover_runtime_status(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let status = read_runtime_status(&path)?;
        if status.revision != revision || status.generation != generation {
            return Ok(None);
        }
        status.validate_against(&plan, revision, &generation)?;
        Ok(Some(status))
    }

    pub fn health(&self, stack: &str, now_ms: u64) -> Result<StackHealthReport, String> {
        let status = self.status(stack)?;
        let runtime = self.runtime_status(stack)?;
        StackHealthReport::from_status(&status, runtime.as_ref(), now_ms)
    }

    pub fn health_all(&self, now_ms: u64) -> Result<Vec<StackHealthReport>, String> {
        let statuses = self.list()?;
        if statuses.len() > MAX_ENGINE_HEALTH_REPORTS {
            return Err("engine health inventory is too large; select one stack".into());
        }
        let mut reports = statuses
            .into_iter()
            .map(|status| {
                let runtime = self.runtime_status(&status.stack)?;
                StackHealthReport::from_status(&status, runtime.as_ref(), now_ms)
            })
            .collect::<Result<Vec<_>, String>>()?;
        reports.sort_by(|left, right| left.stack.cmp(&right.stack));
        validate_health_reports(&reports)?;
        Ok(reports)
    }

    pub fn save_runtime_status(&self, status: &StackRuntimeStatus) -> Result<(), String> {
        status.validate()?;
        let Some((revision, generation, plan)) = self.desired_plan(&status.stack)? else {
            return Err("removed stack cannot retain observed runtime state".into());
        };
        status.validate_against(&plan, revision, &generation)?;
        let bytes = serde_json::to_vec(status).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_RUNTIME_STATUS_BYTES {
            return Err("runtime status exceeds its byte limit".into());
        }
        let path = self.runtime_status_path(&status.stack)?;
        recover_runtime_status(&path)?;
        write_replace_atomic(&path, &bytes)
    }

    pub fn prepare_runtime_status(
        &self,
        stack: &str,
        now_ms: u64,
    ) -> Result<StackRuntimeStatus, String> {
        let Some((revision, generation, plan)) = self.desired_plan(stack)? else {
            return Err("removed stack has no runtime generation".into());
        };
        let path = self.runtime_status_path(stack)?;
        recover_runtime_status(&path)?;
        let mut status = if path.exists() {
            let previous = read_runtime_status(&path)?;
            if previous
                .validate_against(&plan, revision, &generation)
                .is_ok()
            {
                previous
            } else {
                StackRuntimeStatus::from_plan(&plan, revision, &generation, now_ms)?
            }
        } else {
            StackRuntimeStatus::from_plan(&plan, revision, &generation, now_ms)?
        };
        status.recover_interrupted(now_ms)?;
        self.save_runtime_status(&status)?;
        Ok(status)
    }

    pub fn runtime_status_for_generation(
        &self,
        stack: &str,
        generation: &str,
    ) -> Result<Option<StackRuntimeStatus>, String> {
        let Some(target) = self.generation_target(stack, generation)? else {
            return Ok(None);
        };
        let path = self.generation_runtime_status_path(stack, generation)?;
        recover_runtime_status(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let status = read_runtime_status(&path)?;
        status.validate_against(&target.plan, target.revision, target.generation.as_str())?;
        Ok(Some(status))
    }

    pub fn save_runtime_status_for_generation(
        &self,
        status: &StackRuntimeStatus,
    ) -> Result<(), String> {
        status.validate()?;
        let target = self
            .generation_target(&status.stack, &status.generation)?
            .ok_or_else(|| "runtime status generation is no longer authorized".to_string())?;
        status.validate_against(&target.plan, target.revision, target.generation.as_str())?;
        let bytes = serde_json::to_vec(status).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_RUNTIME_STATUS_BYTES {
            return Err("runtime status exceeds its byte limit".into());
        }
        let path = self.generation_runtime_status_path(&status.stack, &status.generation)?;
        recover_runtime_status(&path)?;
        write_replace_atomic(&path, &bytes)
    }

    pub fn prepare_runtime_status_for_generation(
        &self,
        stack: &str,
        generation: &str,
        now_ms: u64,
    ) -> Result<StackRuntimeStatus, String> {
        let target = self
            .generation_target(stack, generation)?
            .ok_or_else(|| "runtime generation is no longer authorized".to_string())?;
        let path = self.generation_runtime_status_path(stack, generation)?;
        recover_runtime_status(&path)?;
        let mut status = if path.exists() {
            let previous = read_runtime_status(&path)?;
            if previous
                .validate_against(&target.plan, target.revision, &target.generation)
                .is_ok()
            {
                previous
            } else {
                StackRuntimeStatus::from_plan(
                    &target.plan,
                    target.revision,
                    &target.generation,
                    now_ms,
                )?
            }
        } else {
            let legacy_path = self.runtime_status_path(stack)?;
            recover_runtime_status(&legacy_path)?;
            if legacy_path.exists() {
                let legacy = read_runtime_status(&legacy_path)?;
                if legacy
                    .validate_against(&target.plan, target.revision, &target.generation)
                    .is_ok()
                {
                    legacy
                } else {
                    StackRuntimeStatus::from_plan(
                        &target.plan,
                        target.revision,
                        &target.generation,
                        now_ms,
                    )?
                }
            } else {
                StackRuntimeStatus::from_plan(
                    &target.plan,
                    target.revision,
                    &target.generation,
                    now_ms,
                )?
            }
        };
        status.recover_interrupted(now_ms)?;
        self.save_runtime_status_for_generation(&status)?;
        Ok(status)
    }

    pub fn acquire_supervisor_lease(&self, stack: &str) -> Result<SupervisorLease, String> {
        let Some((_revision, _generation, _plan)) = self.desired_plan(stack)? else {
            return Err("removed stack cannot be supervised".into());
        };
        let stack_root = self.root.join("stacks").join(stack);
        ensure_directory(&stack_root)?;
        let path = stack_root.join("supervisor.lock");
        if path.exists() && !is_regular_file(&path) {
            return Err("supervisor lock path is not a regular file".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options.open(path).map_err(|error| error.to_string())?;
        match FileExt::try_lock(&lock) {
            Ok(()) => Ok(SupervisorLease { _lock: lock }),
            Err(TryLockError::WouldBlock) => Err("stack already has an active supervisor".into()),
            Err(TryLockError::Error(error)) => Err(error.to_string()),
        }
    }

    pub fn acquire_generation_supervisor_lease(
        &self,
        stack: &str,
        generation: &str,
    ) -> Result<SupervisorLease, String> {
        if self.generation_target(stack, generation)?.is_none() {
            return Err("runtime generation cannot be supervised".into());
        }
        let directory = self.root.join("stacks").join(stack).join("supervisors");
        ensure_directory(&directory)?;
        let path = directory.join(format!("{generation}.lock"));
        if path.exists() && !is_regular_file(&path) {
            return Err("generation supervisor lock path is not a regular file".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options.open(path).map_err(|error| error.to_string())?;
        match FileExt::try_lock(&lock) {
            Ok(()) => Ok(SupervisorLease { _lock: lock }),
            Err(TryLockError::WouldBlock) => {
                Err("generation already has an active supervisor".into())
            }
            Err(TryLockError::Error(error)) => Err(error.to_string()),
        }
    }

    pub fn replica_state_directory(
        &self,
        stack: &str,
        generation: &str,
        id: &ReplicaId,
    ) -> Result<PathBuf, String> {
        let target = self
            .generation_target(stack, generation)?
            .ok_or_else(|| "runtime generation has no replica state authority".to_string())?;
        let planned_instance = target
            .plan
            .instances
            .iter()
            .find(|instance| instance.name == id.instance && id.ordinal <= instance.replicas);
        if !valid_name(&id.instance) || id.ordinal == 0 || planned_instance.is_none() {
            return Err("replica state request does not match its generation target".into());
        }
        let package_sha256 = &planned_instance
            .ok_or_else(|| "replica is not part of the generation target".to_string())?
            .package_sha256;
        let stack_root = self.root.join("stacks").join(stack);
        ensure_directory(&stack_root)?;
        let replicas = stack_root.join("replicas");
        ensure_directory(&replicas)?;
        let instance = replicas.join(&id.instance);
        ensure_directory(&instance)?;
        let replica = instance.join(format!("{:04}", id.ordinal));
        ensure_directory(&replica)?;
        let generations = replica.join("generations");
        ensure_directory(&generations)?;
        let generation = generations.join(generation);
        ensure_directory(&generation)?;
        let state = generation.join("state");
        ensure_directory(&state)?;
        let package_state = state.join(package_sha256);
        ensure_directory(&package_state)?;
        Ok(package_state)
    }

    pub fn replica_probe_path(
        &self,
        stack: &str,
        generation: &str,
        id: &ReplicaId,
        run_id: &str,
    ) -> Result<PathBuf, String> {
        let target = self
            .generation_target(stack, generation)?
            .ok_or_else(|| "runtime generation has no health-channel authority".to_string())?;
        let probe_is_planned = target.plan.instances.iter().any(|instance| {
            instance.name == id.instance
                && id.ordinal > 0
                && id.ordinal <= instance.replicas
                && instance.desired == DesiredState::Running
                && instance.health.is_some()
        });
        if !valid_name(&id.instance) || !is_digest(run_id) || !probe_is_planned {
            return Err("application health channel does not match the desired generation".into());
        }
        let stack_root = self.root.join("stacks").join(stack);
        ensure_directory(&stack_root)?;
        let probes = stack_root.join("probes");
        ensure_directory(&probes)?;
        let generation = probes.join(generation);
        ensure_directory(&generation)?;
        let instance = generation.join(&id.instance);
        ensure_directory(&instance)?;
        let replica = instance.join(format!("{:04}", id.ordinal));
        ensure_directory(&replica)?;
        let replica = fs::canonicalize(replica).map_err(|error| error.to_string())?;
        Ok(replica.join(format!("{run_id}.probe")))
    }

    pub fn clear_probe_channels(&self, stack: &str) -> Result<usize, String> {
        let Some((_revision, generation, _plan)) = self.desired_plan(stack)? else {
            return Err("stack has no active application health channels".into());
        };
        self.clear_probe_channels_for_generation(stack, &generation)
    }

    pub fn clear_probe_channels_for_generation(
        &self,
        stack: &str,
        generation: &str,
    ) -> Result<usize, String> {
        if self.generation_target(stack, generation)?.is_none() {
            return Err("runtime generation has no health-channel authority".into());
        }
        let probes_root = self.root.join("stacks").join(stack).join("probes");
        if !probes_root.exists() {
            return Ok(0);
        }
        let metadata = fs::symlink_metadata(&probes_root).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("application health channel root is unsafe".into());
        }
        let probes = probes_root.join(generation);
        if !probes.exists() {
            return Ok(0);
        }
        let metadata = fs::symlink_metadata(&probes).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("application health generation root is unsafe".into());
        }
        let mut files = Vec::new();
        let mut directories = Vec::new();
        collect_probe_entries(&probes, 0, &mut files, &mut directories)?;
        for path in &files {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
        for path in &directories {
            fs::remove_dir(path).map_err(|error| error.to_string())?;
        }
        fs::remove_dir(&probes).map_err(|error| error.to_string())?;
        if fs::read_dir(&probes_root)
            .map_err(|error| error.to_string())?
            .next()
            .is_none()
        {
            fs::remove_dir(probes_root).map_err(|error| error.to_string())?;
        }
        Ok(files.len())
    }

    pub fn events(&self, stack: &str) -> Result<Vec<EngineEvent>, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let events = self.root.join("stacks").join(stack).join("events");
        if events.exists() {
            ensure_directory(&events)?;
        }
        read_events(&events, stack)
    }

    pub fn list(&self) -> Result<Vec<StackStatus>, String> {
        let stacks = self.root.join("stacks");
        let mut names = Vec::new();
        for entry in fs::read_dir(stacks).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "engine stack directory name is not UTF-8".to_string())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if !valid_name(&name) || metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("engine contains an unsafe stack directory".into());
            }
            names.push(name);
            if names.len() > MAX_ENGINE_STACKS {
                return Err("engine stack limit exceeded".into());
            }
        }
        names.sort();
        names
            .into_iter()
            .filter_map(|name| match self.latest(&name) {
                Ok(Some(event)) => Some(Ok(event.status())),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn latest(&self, stack: &str) -> Result<Option<EngineEvent>, String> {
        Ok(self.events(stack)?.pop())
    }

    fn create_stack_events(&self, stack: &str) -> Result<PathBuf, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let stack_root = self.root.join("stacks").join(stack);
        ensure_directory(&stack_root)?;
        let events = stack_root.join("events");
        ensure_directory(&events)?;
        Ok(events)
    }

    fn runtime_status_path(&self, stack: &str) -> Result<PathBuf, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let stack_root = self.root.join("stacks").join(stack);
        if stack_root.exists() {
            ensure_directory(&stack_root)?;
        }
        Ok(stack_root.join("runtime.json"))
    }

    fn generation_runtime_status_path(
        &self,
        stack: &str,
        generation: &str,
    ) -> Result<PathBuf, String> {
        if !valid_name(stack) || !is_digest(generation) {
            return Err("runtime generation identity is invalid".into());
        }
        let directory = self.root.join("stacks").join(stack).join("runtime");
        ensure_directory(&directory)?;
        Ok(directory.join(format!("{generation}.json")))
    }

    fn append(&self, event: &EngineEvent) -> Result<(), String> {
        event.validate()?;
        let events = self.create_stack_events(&event.stack)?;
        let (current, current_bytes) = read_events_with_size(&events, &event.stack)?;
        if current.len() >= MAX_ENGINE_EVENTS_PER_STACK {
            return Err("engine event history limit reached".into());
        }
        let expected_revision = current.last().map_or(1, |value| value.revision + 1);
        let expected_previous = current
            .last()
            .map_or("", |value| value.event_sha256.as_str());
        if event.revision != expected_revision || event.previous_event_sha256 != expected_previous {
            return Err("engine event does not continue the current journal".into());
        }
        let bytes = serde_json::to_vec(event).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_ENGINE_EVENT_BYTES {
            return Err("engine event exceeds its byte limit".into());
        }
        if current_bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|total| total > MAX_ENGINE_EVENT_HISTORY_BYTES)
        {
            return Err("engine event history byte limit reached".into());
        }
        let final_path = events.join(format!("{:020}.json", event.revision));
        write_new_atomic(&final_path, &bytes)
    }
}

fn validate_planned_instances(
    instances: &[PlannedInstance],
    profile: SecurityProfile,
    secrets: &[PlannedSecret],
) -> Result<BTreeSet<String>, String> {
    let declared_secrets = secrets
        .iter()
        .map(|secret| secret.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut names = BTreeSet::new();
    let mut previous_name = None;
    let mut total_replicas = 0_u16;
    let mut total_surge = 0_u16;
    for instance in instances {
        validate_planned_instance(instance, profile, &declared_secrets)?;
        total_replicas = total_replicas
            .checked_add(instance.replicas)
            .ok_or_else(|| "stack plan replica count overflow".to_string())?;
        total_surge = total_surge
            .checked_add(instance.update.max_surge)
            .ok_or_else(|| "stack plan surge count overflow".to_string())?;
        if previous_name.is_some_and(|previous| previous >= instance.name.as_str())
            || !names.insert(instance.name.clone())
        {
            return Err("stack plan instances are not strictly sorted".into());
        }
        previous_name = Some(instance.name.as_str());
    }
    if total_replicas > MAX_STACK_TOTAL_REPLICAS || total_surge > MAX_STACK_TOTAL_SURGE_REPLICAS {
        return Err("stack plan exceeds its aggregate replica or surge limit".into());
    }
    Ok(names)
}

fn validate_planned_instance(
    instance: &PlannedInstance,
    profile: SecurityProfile,
    declared_secrets: &BTreeSet<&str>,
) -> Result<(), String> {
    instance
        .limits
        .validate()
        .map_err(|error| error.to_string())?;
    if let Some(health) = &instance.health {
        health.validate()?;
    }
    instance.update.validate(instance.replicas)?;
    let argument_bytes = instance
        .args
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
        .ok_or_else(|| "stack plan argument size overflow".to_string())?;
    if !valid_name(&instance.name)
        || !valid_cartridge_id(&instance.cartridge_id)
        || Version::parse(&instance.version).is_err()
        || !is_digest(&instance.package_sha256)
        || instance.package_bytes == 0
        || instance.package_bytes > 160 * 1024 * 1024
        || instance.replicas == 0
        || instance.replicas > MAX_STACK_REPLICAS
        || instance.max_restarts > MAX_STACK_RESTARTS
        || !instance.allowed.is_subset(&instance.requested)
        || !instance.denied.is_subset(&instance.requested)
        || !instance.granted.is_subset(&instance.requested)
        || !instance.blocked.is_subset(&instance.requested)
        || !instance.granted.is_disjoint(&instance.blocked)
        || !instance.allowed.is_disjoint(&instance.denied)
        || instance
            .allowed
            .union(&instance.denied)
            .copied()
            .collect::<BTreeSet<_>>()
            != instance.requested
        || instance.args.len() > MAX_STACK_ARGUMENTS
        || argument_bytes > MAX_STACK_ARGUMENT_BYTES
        || instance
            .args
            .iter()
            .any(|argument| !valid_text(argument, 4096, true))
        || instance
            .secrets
            .iter()
            .any(|secret| !valid_name(secret) || !declared_secrets.contains(secret.as_str()))
    {
        return Err("stack plan instance is invalid".into());
    }
    instance.composition.validate()?;
    let root = &instance.composition.root;
    if root.cartridge_id != instance.cartridge_id
        || root.version != instance.version
        || root.package_sha256 != instance.package_sha256
        || root.package_bytes != instance.package_bytes
    {
        return Err("stack plan package does not match its composition root".into());
    }
    validate_planned_capabilities(instance, profile)
}

fn validate_planned_capabilities(
    instance: &PlannedInstance,
    profile: SecurityProfile,
) -> Result<(), String> {
    let mut expected_allowed = match profile {
        SecurityProfile::Strict => instance.granted.clone(),
        SecurityProfile::Balanced => instance
            .requested
            .intersection(&balanced_capabilities())
            .copied()
            .chain(instance.granted.iter().copied())
            .collect(),
        SecurityProfile::Permissive => instance.requested.clone(),
    };
    expected_allowed = expected_allowed
        .difference(&instance.blocked)
        .copied()
        .collect();
    let expected_denied = instance
        .requested
        .difference(&instance.allowed)
        .copied()
        .collect::<BTreeSet<_>>();
    if expected_allowed != instance.allowed || expected_denied != instance.denied {
        return Err("stack plan capability policy is inconsistent".into());
    }
    Ok(())
}

fn validate_planned_resources(
    resources: &[PlannedResource],
    instances: &BTreeSet<String>,
) -> Result<(), String> {
    let mut previous = None;
    for resource in resources {
        if !valid_name(&resource.name)
            || !instances.contains(&resource.owner)
            || resource
                .quota_bytes
                .is_some_and(|value| value == 0 || value > 64 << 30)
            || previous.is_some_and(|name| name >= resource.name.as_str())
        {
            return Err("stack plan resource is invalid or not strictly sorted".into());
        }
        previous = Some(resource.name.as_str());
    }
    Ok(())
}

fn validate_planned_secrets(secrets: &[PlannedSecret]) -> Result<(), String> {
    let mut previous = None;
    for secret in secrets {
        if !valid_name(&secret.name) || previous.is_some_and(|name| name >= secret.name.as_str()) {
            return Err("stack plan secret is invalid or not strictly sorted".into());
        }
        previous = Some(secret.name.as_str());
    }
    Ok(())
}

fn validate_instance(value: &InstanceSpec) -> Result<(), String> {
    value.limits.ceiling()?;
    if let Some(health) = &value.health {
        health.validate()?;
    }
    value.update.validate(value.replicas)?;
    let argument_bytes = value
        .args
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
        .ok_or_else(|| "stack argument size overflow".to_string())?;
    if !valid_name(&value.name)
        || !valid_cartridge_id(&value.cartridge)
        || value.version.len() > 128
        || VersionReq::parse(&value.version).is_err()
        || value.replicas == 0
        || value.replicas > MAX_STACK_REPLICAS
        || value.max_restarts > MAX_STACK_RESTARTS
        || value.args.len() > MAX_STACK_ARGUMENTS
        || argument_bytes > MAX_STACK_ARGUMENT_BYTES
        || value
            .args
            .iter()
            .any(|argument| !valid_text(argument, 4096, true))
        || !value.allow.is_disjoint(&value.deny)
        || value.secrets.iter().any(|secret| !valid_name(secret))
    {
        return Err("stack instance is invalid".into());
    }
    Ok(())
}

fn plan_instance(
    spec: &InstanceSpec,
    security: &StackSecurity,
    library: &Library,
) -> Result<PlannedInstance, String> {
    let requirement = VersionReq::parse(&spec.version).map_err(|error| error.to_string())?;
    let record = library
        .catalog_versions(&spec.cartridge, MAX_RESOLUTION_CANDIDATES)?
        .into_iter()
        .find(|record| {
            Version::parse(&record.version).is_ok_and(|version| requirement.matches(&version))
        })
        .ok_or_else(|| {
            format!(
                "no installed version of {} satisfies {}",
                spec.cartridge, spec.version
            )
        })?;
    let archive = open_catalog_archive(&record)?;
    let limits = spec.limits.apply(&archive.manifest.runtime)?;
    let composition = direct_composition_lock(&archive, library)?;
    let requested = capabilities(&archive.manifest);
    if !spec.allow.is_subset(&requested) || !spec.deny.is_subset(&requested) {
        return Err(format!(
            "instance {} grants or denies a capability not requested by its package",
            spec.name
        ));
    }
    let mut allowed = match security.profile {
        SecurityProfile::Strict => spec.allow.clone(),
        SecurityProfile::Balanced => requested
            .intersection(&balanced_capabilities())
            .copied()
            .chain(spec.allow.iter().copied())
            .collect(),
        SecurityProfile::Permissive => requested.clone(),
    };
    allowed = allowed.difference(&spec.deny).copied().collect();
    let denied = requested.difference(&allowed).copied().collect();
    Ok(PlannedInstance {
        name: spec.name.clone(),
        cartridge_id: record.cartridge_id,
        version: record.version,
        package_sha256: record.package_sha256,
        package_bytes: record.package_bytes,
        replicas: spec.replicas,
        desired: spec.desired,
        restart: spec.restart,
        max_restarts: spec.max_restarts,
        requested,
        granted: spec.allow.clone(),
        blocked: spec.deny.clone(),
        allowed,
        denied,
        args: spec.args.clone(),
        secrets: spec.secrets.clone(),
        limits,
        health: spec.health.clone(),
        update: spec.update.clone(),
        composition,
    })
}

fn direct_composition_lock(
    root: &CartridgeArchive,
    library: &Library,
) -> Result<CompositionLock, String> {
    let mut candidates = Vec::new();
    let ids = root
        .manifest
        .dependencies
        .iter()
        .map(|dependency| dependency.cartridge.as_str())
        .collect::<BTreeSet<_>>();
    for id in ids {
        let remaining = MAX_RESOLUTION_CANDIDATES.saturating_sub(candidates.len());
        for record in library.catalog_versions(id, remaining)? {
            candidates.push(open_catalog_archive(&record)?);
        }
    }
    let manifests = candidates
        .iter()
        .map(|candidate| candidate.manifest.clone())
        .collect::<Vec<_>>();
    let packages = candidates.iter().map(locked_package).collect::<Vec<_>>();
    let plan =
        resolve_dependencies(&root.manifest, &manifests).map_err(|error| error.to_string())?;
    let mut selected = Vec::new();
    for dependency in &plan.resolved {
        let package = packages
            .iter()
            .find(|package| {
                package.cartridge_id == dependency.cartridge
                    && package.version == dependency.version
            })
            .ok_or_else(|| "resolver selected a provider without package identity".to_string())?;
        if !selected.iter().any(|value: &LockedPackage| {
            value.cartridge_id == package.cartridge_id && value.version == package.version
        }) {
            selected.push(package.clone());
        }
    }
    CompositionLock::new(locked_package(root), selected, plan)
}

fn open_catalog_archive(record: &CatalogPackage) -> Result<CartridgeArchive, String> {
    let archive = CartridgeArchive::open(&record.path).map_err(|error| error.to_string())?;
    if archive.manifest.cartridge.id != record.cartridge_id
        || archive.manifest.cartridge.version != record.version
        || archive.package_sha256 != record.package_sha256
        || archive.package_bytes != record.package_bytes
    {
        return Err("installed package changed after catalog verification".into());
    }
    Ok(archive)
}

fn verify_locked_package_installed(
    package: &LockedPackage,
    library: &Library,
) -> Result<(), String> {
    let record = library.catalog_package(&package.cartridge_id, Some(&package.version))?;
    let archive = open_catalog_archive(&record)?;
    if locked_package(&archive) != *package {
        return Err("installed package no longer matches the reviewed plan".into());
    }
    Ok(())
}

fn locked_package(archive: &CartridgeArchive) -> LockedPackage {
    LockedPackage {
        cartridge_id: archive.manifest.cartridge.id.clone(),
        version: archive.manifest.cartridge.version.clone(),
        package_sha256: archive.package_sha256.clone(),
        package_bytes: archive.package_bytes,
        component_sha256: archive
            .manifest
            .integrity
            .component_sha256
            .to_ascii_lowercase(),
        assets_root_sha256: archive
            .manifest
            .integrity
            .assets_root_sha256
            .to_ascii_lowercase(),
    }
}

fn capabilities(manifest: &PackageManifest) -> BTreeSet<StackCapability> {
    let value = &manifest.permissions;
    [
        (value.clock, StackCapability::Clock),
        (value.random, StackCapability::Random),
        (value.assets, StackCapability::Assets),
        (value.storage, StackCapability::Storage),
        (value.graphics, StackCapability::Graphics),
        (value.audio, StackCapability::Audio),
        (value.midi, StackCapability::Midi),
        (!manifest.http.scopes.is_empty(), StackCapability::Http),
    ]
    .into_iter()
    .filter_map(|(enabled, capability)| enabled.then_some(capability))
    .collect()
}

fn balanced_capabilities() -> BTreeSet<StackCapability> {
    [
        StackCapability::Clock,
        StackCapability::Assets,
        StackCapability::Graphics,
        StackCapability::Audio,
    ]
    .into_iter()
    .collect()
}

fn capability_labels(value: &BTreeSet<StackCapability>) -> String {
    value
        .iter()
        .map(|capability| format!("{capability:?}").to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

fn next_event(
    previous: Option<&EngineEvent>,
    kind: EngineEventKind,
    plan: Option<StackPlan>,
) -> Result<EngineEvent, String> {
    let stack = plan
        .as_ref()
        .map(|value| value.stack.clone())
        .or_else(|| previous.map(|value| value.stack.clone()))
        .ok_or_else(|| "engine event has no stack identity".to_string())?;
    EngineEvent::new(
        previous.map_or(1, |value| value.revision + 1),
        stack,
        kind,
        previous.map_or_else(String::new, |value| value.event_sha256.clone()),
        plan,
    )
}

fn read_events(path: &Path, stack: &str) -> Result<Vec<EngineEvent>, String> {
    Ok(read_events_with_size(path, stack)?.0)
}

fn read_events_with_size(path: &Path, stack: &str) -> Result<(Vec<EngineEvent>, u64), String> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "engine event file name is not UTF-8".to_string())?;
        if exact_suffix(&name, ".json") {
            paths.push(entry.path());
        } else if !(name.starts_with(".engine-event-") && exact_suffix(&name, ".tmp")) {
            return Err("engine event directory contains an unexpected entry".into());
        }
    }
    paths.sort();
    if paths.len() > MAX_ENGINE_EVENTS_PER_STACK {
        return Err("engine event history limit exceeded".into());
    }
    let mut events = Vec::with_capacity(paths.len());
    let mut total_bytes = 0_u64;
    for path in paths {
        let remaining = MAX_ENGINE_EVENT_HISTORY_BYTES
            .checked_sub(total_bytes)
            .ok_or_else(|| "engine event history byte limit exceeded".to_string())?;
        let (event, event_bytes): (EngineEvent, u64) = read_bounded_json(&path, remaining)?;
        total_bytes = total_bytes
            .checked_add(event_bytes)
            .ok_or_else(|| "engine event history byte count overflow".to_string())?;
        event.validate()?;
        let expected_revision = events
            .last()
            .map_or(1, |value: &EngineEvent| value.revision + 1);
        let expected_previous = events
            .last()
            .map_or("", |value| value.event_sha256.as_str());
        if event.stack != stack
            || event.revision != expected_revision
            || event.previous_event_sha256 != expected_previous
            || path.file_name().and_then(|value| value.to_str())
                != Some(&format!("{:020}.json", event.revision))
        {
            return Err("engine event journal is not a canonical chain".into());
        }
        events.push(event);
    }
    Ok((events, total_bytes))
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    remaining: u64,
) -> Result<(T, u64), String> {
    let limit = MAX_ENGINE_EVENT_BYTES.min(remaining);
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err("engine event must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("engine event exceeded its byte limit while reading".into());
    }
    let length = bytes.len() as u64;
    let value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    Ok((value, length))
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "engine event path has no parent".to_string())?;
    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".engine-event-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    drop(file);
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    fs::remove_file(temporary).map_err(|error| error.to_string())?;
    sync_parent_directory(path)
}

fn read_runtime_status(path: &Path) -> Result<StackRuntimeStatus, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_RUNTIME_STATUS_BYTES
    {
        return Err("runtime status must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_RUNTIME_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_RUNTIME_STATUS_BYTES {
        return Err("runtime status exceeded its byte limit while reading".into());
    }
    let status: StackRuntimeStatus =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    status.validate()?;
    Ok(status)
}

fn collect_probe_entries(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    directories: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "application health channel name is not UTF-8".to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("application health channel contains a symlink".into());
        }
        if metadata.is_dir() {
            let valid_directory = match depth {
                0 => valid_name(&name),
                1 => {
                    name.len() == 4
                        && name.bytes().all(|byte| byte.is_ascii_digit())
                        && name != "0000"
                }
                _ => false,
            };
            if !valid_directory {
                return Err("application health channel directory is not canonical".into());
            }
            collect_probe_entries(&path, depth + 1, files, directories)?;
            directories.push(path);
        } else if metadata.is_file()
            && depth == 2
            && metadata.len() <= MAX_PROBE_ENVELOPE_BYTES as u64
            && valid_probe_file_name(&name)
        {
            files.push(path);
            if files.len() > MAX_STALE_PROBE_FILES {
                return Err("application health channel cleanup limit exceeded".into());
            }
        } else {
            return Err("application health channel contains an unsafe entry".into());
        }
    }
    Ok(())
}

fn valid_probe_file_name(name: &str) -> bool {
    name.strip_suffix(".probe").is_some_and(is_digest)
        || name
            .strip_prefix(".probe-report-")
            .and_then(|value| value.strip_suffix(".tmp"))
            .is_some_and(|value| {
                let mut parts = value.split('-');
                parts.next().is_some_and(|part| {
                    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                }) && parts.next().is_some_and(|part| {
                    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                }) && parts.next().is_none()
            })
}

fn recover_runtime_status(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    if backup.exists() && !is_regular_file(&backup) {
        return Err("runtime status backup is not a regular file".into());
    }
    if path.exists() && !is_regular_file(path) {
        return Err("runtime status path is not a regular file".into());
    }
    if !path.exists() && backup.exists() {
        read_runtime_status(&backup)?;
        fs::rename(&backup, path).map_err(|error| error.to_string())?;
        sync_parent_directory(path)?;
    } else if path.exists() && backup.exists() {
        read_runtime_status(path)?;
        fs::remove_file(backup).map_err(|error| error.to_string())?;
        sync_parent_directory(path)?;
    }
    Ok(())
}

fn write_replace_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "runtime status path has no parent".to_string())?;
    ensure_directory(directory)?;
    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".runtime-status-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    drop(file);
    if path.exists() {
        if !is_regular_file(path) {
            let _ = fs::remove_file(&temporary);
            return Err("runtime status path is not a regular file".into());
        }
        let backup = path.with_extension("json.previous");
        if backup.exists() {
            let _ = fs::remove_file(&temporary);
            return Err("runtime status replacement is already in progress".into());
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
    sync_parent_directory(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "durable file path has no parent".to_string())?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent_directory(_: &Path) -> Result<(), String> {
    Ok(())
}

fn acquire_lock(file: &File) -> Result<(), String> {
    for _ in 0..ENGINE_LOCK_ATTEMPTS {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(ENGINE_LOCK_DELAY),
            Err(TryLockError::Error(error)) => return Err(error.to_string()),
        }
    }
    Err("engine is busy".into())
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        create_private_directory(path)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("engine layout contains an unsafe directory".into());
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir(path).map_err(|error| error.to_string())
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(unix)]
fn private_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn private_options(_: &mut OpenOptions) {}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_cartridge_id(value: &str) -> bool {
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

fn valid_text(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.chars().count() <= maximum
        && !value.chars().any(char::is_control)
}

fn exact_suffix(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|ending| ending == suffix)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system timestamp overflow".into())
}

const fn one_replica() -> u16 {
    1
}

const fn default_restart_limit() -> u16 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartridge_core::{PackOptions, pack};

    fn package(root: &Path, version: &str, permissions: &str) -> PathBuf {
        let manifest = root.join(format!("{version}.Cartridge.toml"));
        let component = root.join("component.wasm");
        let output = root.join(format!("demo-{version}.cartridge"));
        fs::write(
            &manifest,
            format!(
                "format_version = 1\n[cartridge]\nid = \"dev.test.engine\"\nname = \"Engine Test\"\nversion = \"{version}\"\n[permissions]\n{permissions}\n"
            ),
        )
        .unwrap();
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

    fn manifest(sandbox: SandboxPolicy) -> StackManifest {
        StackManifest {
            format_version: STACK_FORMAT_VERSION,
            name: "demo-stack".into(),
            security: StackSecurity {
                profile: SecurityProfile::Strict,
                sandbox,
            },
            instances: vec![InstanceSpec {
                name: "app".into(),
                cartridge: "dev.test.engine".into(),
                version: "^1".into(),
                replicas: 2,
                desired: DesiredState::Running,
                restart: RestartPolicy::OnFailure,
                max_restarts: 3,
                allow: BTreeSet::from([StackCapability::Clock]),
                deny: BTreeSet::new(),
                args: vec!["serve".into()],
                secrets: BTreeSet::from(["api-key".into()]),
                limits: InstanceLimits::default(),
                health: None,
                update: RollingUpdatePolicy::default(),
            }],
            resources: vec![ResourceSpec {
                name: "app-state".into(),
                kind: ResourceKind::State,
                owner: "app".into(),
                retention: RetentionPolicy::Retain,
                quota_bytes: Some(1024 * 1024),
            }],
            secrets: vec![SecretSpec {
                name: "api-key".into(),
                required: true,
            }],
        }
    }

    #[test]
    fn exact_plans_select_the_newest_compatible_installed_package() {
        let directory = tempfile::tempdir().unwrap();
        let old = package(directory.path(), "1.0.0", "clock = true\nstorage = true");
        let new = package(directory.path(), "1.2.0", "clock = true\nstorage = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&old).unwrap();
        library.install(&new).unwrap();

        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();

        assert_eq!(plan.instances[0].version, "1.2.0");
        assert_eq!(
            plan.instances[0].allowed,
            BTreeSet::from([StackCapability::Clock])
        );
        assert_eq!(
            plan.instances[0].denied,
            BTreeSet::from([StackCapability::Storage])
        );
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn legacy_plan_format_remains_readable_without_probe_policy() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let mut plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        plan.format_version = LEGACY_STACK_PLAN_FORMAT_VERSION;
        plan.plan_sha256 = plan.computed_sha256().unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();

        assert!(!String::from_utf8_lossy(&bytes).contains("\"health\""));
        let decoded: StackPlan = serde_json::from_slice(&bytes).unwrap();
        decoded.validate().unwrap();

        plan.instances[0].health = Some(HealthProbeSpec::default());
        plan.plan_sha256 = plan.computed_sha256().unwrap();
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rolling_policy_is_plan_bound_and_format_three_remains_readable() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();

        let mut stack = manifest(SandboxPolicy::Required);
        stack.instances[0].health = Some(HealthProbeSpec::default());
        let mut legacy = StackPlan::build(&stack, &library).unwrap();
        legacy.format_version = HEALTH_STACK_PLAN_FORMAT_VERSION;
        legacy.plan_sha256 = legacy.computed_sha256().unwrap();
        legacy.validate().unwrap();

        legacy.instances[0].update = RollingUpdatePolicy {
            max_surge: 2,
            max_unavailable: 1,
            min_ready_ms: 5_000,
            ..RollingUpdatePolicy::default()
        };
        legacy.plan_sha256 = legacy.computed_sha256().unwrap();
        assert!(legacy.validate().is_err());

        stack.instances[0].update = legacy.instances[0].update.clone();
        let plan = StackPlan::build(&stack, &library).unwrap();
        assert_eq!(plan.format_version, STACK_PLAN_FORMAT_VERSION);
        assert_eq!(plan.instances[0].update.max_surge, 2);
        let mut changed = plan.clone();
        changed.instances[0].update.max_unavailable = 0;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn plans_bind_operator_limits_below_package_requests() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let mut stack = manifest(SandboxPolicy::Required);
        stack.instances[0].limits.fuel = Some(50_000);
        stack.instances[0].limits.memory_bytes = Some(8 * 1024 * 1024);
        stack.instances[0].limits.timeout_ms = Some(250);

        let plan = StackPlan::build(&stack, &library).unwrap();

        assert_eq!(plan.instances[0].limits.fuel, 50_000);
        assert_eq!(plan.instances[0].limits.memory_bytes, 8 * 1024 * 1024);
        assert_eq!(plan.instances[0].limits.timeout_ms, 250);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn recomputed_plans_cannot_widen_policy_or_detach_package_identity() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true\nstorage = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();

        let mut widened = plan.clone();
        widened.instances[0]
            .allowed
            .insert(StackCapability::Storage);
        widened.instances[0]
            .denied
            .remove(&StackCapability::Storage);
        widened.plan_sha256 = widened.computed_sha256().unwrap();
        assert!(widened.validate().is_err());

        let mut raised = plan.clone();
        raised.instances[0].limits.fuel = RuntimeLimits::maximum().fuel;
        raised.plan_sha256 = raised.computed_sha256().unwrap();
        assert!(raised.validate().is_ok());
        assert!(raised.verify_installed(&library).is_err());

        let mut detached = plan;
        detached.instances[0].package_sha256 = "0".repeat(64);
        detached.plan_sha256 = detached.computed_sha256().unwrap();
        assert!(detached.validate().is_err());
    }

    #[test]
    fn reviewed_plans_recheck_every_installed_package_before_apply() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        assert!(plan.verify_installed(&library).is_ok());

        let record = library
            .catalog_package("dev.test.engine", Some("1.0.0"))
            .unwrap();
        fs::write(record.path, b"changed after review").unwrap();
        assert!(plan.verify_installed(&library).is_err());
    }

    #[test]
    fn journal_apply_stop_and_remove_are_chained_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine = EngineStore::open(directory.path().join("engine")).unwrap();

        let first = engine.apply(&plan, false).unwrap();
        assert!(first.changed);
        assert!(!engine.apply(&plan, false).unwrap().changed);
        assert_eq!(engine.stop("demo-stack").unwrap().status.revision, 2);
        assert!(!engine.stop("demo-stack").unwrap().changed);
        assert_eq!(engine.remove("demo-stack").unwrap().status.revision, 3);
        assert!(!engine.remove("demo-stack").unwrap().changed);

        let events = engine.events("demo-stack").unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].previous_event_sha256, events[0].event_sha256);
        assert_eq!(events[2].previous_event_sha256, events[1].event_sha256);
        assert_eq!(
            engine.status("demo-stack").unwrap().state,
            EngineStackState::Removed
        );
    }

    #[test]
    fn disabled_sandbox_requires_a_second_explicit_confirmation() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Disabled), &library).unwrap();
        let engine = EngineStore::open(directory.path().join("engine")).unwrap();

        assert!(engine.apply(&plan, false).is_err());
        assert!(engine.apply(&plan, true).is_ok());
    }

    #[test]
    fn changed_journal_events_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine_root = directory.path().join("engine");
        let engine = EngineStore::open(&engine_root).unwrap();
        engine.apply(&plan, false).unwrap();
        drop(engine);
        let event = engine_root.join("stacks/demo-stack/events/00000000000000000001.json");
        OpenOptions::new()
            .append(true)
            .open(event)
            .unwrap()
            .write_all(b"changed")
            .unwrap();

        let engine = EngineStore::open(&engine_root).unwrap();
        assert!(engine.status("demo-stack").is_err());
    }

    #[test]
    fn unexpected_journal_entries_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine_root = directory.path().join("engine");
        let engine = EngineStore::open(&engine_root).unwrap();
        engine.apply(&plan, false).unwrap();
        fs::write(
            engine_root.join("stacks/demo-stack/events/hidden.data"),
            b"ignored state",
        )
        .unwrap();

        assert!(engine.status("demo-stack").is_err());
    }

    #[test]
    fn observed_runtime_state_is_generation_fenced_and_tamper_evident() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine_root = directory.path().join("engine");
        let engine = EngineStore::open(&engine_root).unwrap();
        engine.apply(&plan, false).unwrap();
        let (revision, generation, desired) = engine.desired_plan("demo-stack").unwrap().unwrap();
        let mut runtime =
            StackRuntimeStatus::from_plan(&desired, revision, &generation, 1).unwrap();
        engine.save_runtime_status(&runtime).unwrap();
        assert_eq!(
            engine.runtime_status("demo-stack").unwrap(),
            Some(runtime.clone())
        );

        engine.stop("demo-stack").unwrap();
        assert!(engine.save_runtime_status(&runtime).is_err());
        assert!(engine.runtime_status("demo-stack").unwrap().is_none());

        let (revision, generation, stopped) = engine.desired_plan("demo-stack").unwrap().unwrap();
        runtime = StackRuntimeStatus::from_plan(&stopped, revision, &generation, 2).unwrap();
        engine.save_runtime_status(&runtime).unwrap();
        drop(engine);
        OpenOptions::new()
            .append(true)
            .open(engine_root.join("stacks/demo-stack/runtime.json"))
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        let engine = EngineStore::open(engine_root).unwrap();
        assert!(engine.runtime_status("demo-stack").is_err());
    }

    #[test]
    fn stale_probe_channels_are_lease_cleanup_bounded_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let mut stack = manifest(SandboxPolicy::Required);
        stack.instances[0].health = Some(HealthProbeSpec::default());
        let plan = StackPlan::build(&stack, &library).unwrap();
        let engine_root = directory.path().join("engine");
        let engine = EngineStore::open(&engine_root).unwrap();
        engine.apply(&plan, false).unwrap();
        let (_, generation, _) = engine.desired_plan("demo-stack").unwrap().unwrap();
        let id = ReplicaId {
            instance: "app".into(),
            ordinal: 1,
        };
        let path = engine
            .replica_probe_path("demo-stack", &generation, &id, &"a".repeat(64))
            .unwrap();
        assert!(path.is_absolute());
        fs::write(&path, b"stale encrypted signal").unwrap();

        assert_eq!(engine.clear_probe_channels("demo-stack").unwrap(), 1);
        assert!(!engine_root.join("stacks/demo-stack/probes").exists());

        let path = engine
            .replica_probe_path("demo-stack", &generation, &id, &"b".repeat(64))
            .unwrap();
        fs::write(&path, b"stale encrypted signal").unwrap();
        let unexpected = path.parent().unwrap().join("notes.txt");
        fs::write(&unexpected, b"do not delete").unwrap();
        assert!(engine.clear_probe_channels("demo-stack").is_err());
        assert!(path.exists());
        assert!(unexpected.exists());
    }

    #[test]
    fn engine_health_tracks_convergence_and_desired_state() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine = EngineStore::open(directory.path().join("engine")).unwrap();
        engine.apply(&plan, false).unwrap();

        let starting = engine.health("demo-stack", 1).unwrap();
        assert_eq!(starting.state, StackHealthState::Starting);
        assert!(!starting.ready());

        let (revision, generation, desired) = engine.desired_plan("demo-stack").unwrap().unwrap();
        let mut runtime =
            StackRuntimeStatus::from_plan(&desired, revision, &generation, 2).unwrap();
        for ordinal in 1..=2 {
            let id = ReplicaId {
                instance: "app".into(),
                ordinal,
            };
            let run_id = format!("{ordinal:064x}");
            runtime.begin_start(&id, &run_id, 2).unwrap();
            runtime.mark_running(&id, &run_id, 2).unwrap();
        }
        engine.save_runtime_status(&runtime).unwrap();
        assert_eq!(
            engine.health("demo-stack", 2).unwrap().state,
            StackHealthState::Healthy
        );

        engine.stop("demo-stack").unwrap();
        assert_eq!(
            engine.health("demo-stack", 3).unwrap().state,
            StackHealthState::Stopped
        );
        engine.remove("demo-stack").unwrap();
        assert_eq!(
            engine.health("demo-stack", 4).unwrap().state,
            StackHealthState::Removed
        );
    }

    #[test]
    fn aggregate_replica_limit_prevents_fork_bomb_plans() {
        let mut value = manifest(SandboxPolicy::Required);
        let template = value.instances[0].clone();
        value.instances.clear();
        for index in 0..9 {
            let mut instance = template.clone();
            instance.name = format!("app-{index}");
            instance.replicas = MAX_STACK_REPLICAS;
            value.instances.push(instance);
        }
        assert!(value.validate().is_err());
    }

    #[test]
    fn aggregate_surge_limit_prevents_replacement_fork_bombs() {
        let mut value = manifest(SandboxPolicy::Required);
        let mut template = value.instances[0].clone();
        template.replicas = 2;
        template.update.max_surge = 2;
        value.instances.clear();
        for index in 0..33 {
            let mut instance = template.clone();
            instance.name = format!("app-{index}");
            value.instances.push(instance);
        }
        assert!(value.validate().is_err());
    }

    #[test]
    fn engine_rejects_more_than_the_bounded_stack_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let engine_root = directory.path().join("engine");
        let engine = EngineStore::open(&engine_root).unwrap();
        for index in 0..=MAX_ENGINE_STACKS {
            fs::create_dir(engine_root.join("stacks").join(format!("stack-{index:04}"))).unwrap();
        }
        assert!(engine.list().is_err());
    }

    #[test]
    fn journal_reads_enforce_the_remaining_aggregate_budget() {
        let directory = tempfile::tempdir().unwrap();
        let event = EngineEvent::new(
            1,
            "demo-stack".into(),
            EngineEventKind::Remove,
            String::new(),
            None,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&event).unwrap();
        let path = directory.path().join("event.json");
        fs::write(&path, &bytes).unwrap();
        assert!(read_bounded_json::<EngineEvent>(&path, bytes.len() as u64 - 1).is_err());
    }

    #[test]
    fn only_one_supervisor_can_own_a_stack() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0", "clock = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&package).unwrap();
        let plan = StackPlan::build(&manifest(SandboxPolicy::Required), &library).unwrap();
        let engine = EngineStore::open(directory.path().join("engine")).unwrap();
        engine.apply(&plan, false).unwrap();

        let lease = engine.acquire_supervisor_lease("demo-stack").unwrap();
        assert!(engine.acquire_supervisor_lease("demo-stack").is_err());
        drop(lease);
        assert!(engine.acquire_supervisor_lease("demo-stack").is_ok());
    }

    #[test]
    fn unsigned_package_upgrades_do_not_inherit_replica_state() {
        let directory = tempfile::tempdir().unwrap();
        let old = package(directory.path(), "1.0.0", "storage = true");
        let mut library = Library::open(directory.path().join("library")).unwrap();
        library.install(&old).unwrap();
        let mut source = manifest(SandboxPolicy::Required);
        source.instances[0].allow = BTreeSet::from([StackCapability::Storage]);
        let old_plan = StackPlan::build(&source, &library).unwrap();
        let engine = EngineStore::open(directory.path().join("engine")).unwrap();
        engine.apply(&old_plan, false).unwrap();
        let (_, old_generation, _) = engine.desired_plan("demo-stack").unwrap().unwrap();
        let id = ReplicaId {
            instance: "app".into(),
            ordinal: 1,
        };
        let old_state = engine
            .replica_state_directory("demo-stack", &old_generation, &id)
            .unwrap();

        let new = package(directory.path(), "1.1.0", "storage = true");
        library.install(&new).unwrap();
        let new_plan = StackPlan::build(&source, &library).unwrap();
        engine.apply(&new_plan, false).unwrap();
        let (_, new_generation, _) = engine.desired_plan("demo-stack").unwrap().unwrap();
        let new_state = engine
            .replica_state_directory("demo-stack", &new_generation, &id)
            .unwrap();

        assert_ne!(old_state, new_state);
        assert_eq!(
            new_state.file_name().and_then(|name| name.to_str()),
            Some(new_plan.instances[0].package_sha256.as_str())
        );
    }
}

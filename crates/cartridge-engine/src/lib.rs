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
    resolve_dependencies,
};
use cartridge_desktop::{CatalogPackage, Library};
use fs4::{FileExt, TryLockError};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STACK_FORMAT_VERSION: u32 = 1;
pub const STACK_PLAN_FORMAT_VERSION: u32 = 1;
pub const ENGINE_EVENT_FORMAT_VERSION: u32 = 1;
pub const MAX_STACK_BYTES: u64 = 1024 * 1024;
pub const MAX_STACK_INSTANCES: usize = 64;
pub const MAX_STACK_REPLICAS: u16 = 32;
pub const MAX_STACK_RESOURCES: usize = 128;
pub const MAX_STACK_SECRETS: usize = 128;
pub const MAX_STACK_ARGUMENTS: usize = 256;
pub const MAX_STACK_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_STACK_PLAN_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENGINE_EVENTS_PER_STACK: usize = 4096;
pub const MAX_ENGINE_EVENT_BYTES: u64 = 16 * 1024 * 1024;

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
        for instance in &self.instances {
            validate_instance(instance)?;
            if !instances.insert(instance.name.as_str()) {
                return Err("stack instance names must be unique".into());
            }
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
        if self.format_version != STACK_PLAN_FORMAT_VERSION
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
        if plan.security.sandbox == SandboxPolicy::Disabled && !allow_insecure {
            return Err(
                "sandbox-disabled stacks require an explicit insecure-apply confirmation".into(),
            );
        }
        let previous = self.latest(&plan.stack)?;
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

    fn append(&self, event: &EngineEvent) -> Result<(), String> {
        event.validate()?;
        let events = self.create_stack_events(&event.stack)?;
        let current = read_events(&events, &event.stack)?;
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
    for instance in instances {
        validate_planned_instance(instance, profile, &declared_secrets)?;
        if previous_name.is_some_and(|previous| previous >= instance.name.as_str())
            || !names.insert(instance.name.clone())
        {
            return Err("stack plan instances are not strictly sorted".into());
        }
        previous_name = Some(instance.name.as_str());
    }
    Ok(names)
}

fn validate_planned_instance(
    instance: &PlannedInstance,
    profile: SecurityProfile,
    declared_secrets: &BTreeSet<&str>,
) -> Result<(), String> {
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
    if !path.exists() {
        return Ok(Vec::new());
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
    for path in paths {
        let event: EngineEvent = read_bounded_json(&path)?;
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
    Ok(events)
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENGINE_EVENT_BYTES
    {
        return Err("engine event must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_ENGINE_EVENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ENGINE_EVENT_BYTES {
        return Err("engine event exceeded its byte limit while reading".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
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

fn private_options(_options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        _options.mode(0o600);
    }
}

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

        let mut detached = plan;
        detached.instances[0].package_sha256 = "0".repeat(64);
        detached.plan_sha256 = detached.computed_sha256().unwrap();
        assert!(detached.validate().is_err());
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
}

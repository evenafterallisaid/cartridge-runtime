use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    DesiredState, EngineStackState, EngineStore, MAX_STACK_INSTANCES, MAX_STACK_REPLICAS,
    MAX_STACK_TOTAL_REPLICAS, MAX_STACK_TOTAL_SURGE_REPLICAS, RollingUpdatePolicy, RolloutPhase,
    RolloutRecord, is_digest, is_regular_file, valid_name, write_replace_atomic,
};

pub const ENGINE_ROLLOUT_PROGRESS_FORMAT_VERSION: u32 = 1;
pub const MAX_ROLLOUT_PROGRESS_BYTES: u64 = 1024 * 1024;

const CURRENT_PROGRESS_FILE: &str = "rollout-progress.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RolloutExecutionPhase {
    Rolling,
    Paused,
    Completing,
    RollingBack,
    Completed,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrainIntent {
    pub requested_at_ms: u64,
    pub deadline_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutInstanceProgress {
    pub name: String,
    pub previous_replicas: u16,
    pub candidate_replicas: u16,
    pub policy: RollingUpdatePolicy,
    pub candidate_enabled: BTreeSet<u16>,
    pub previous_draining: BTreeMap<u16, DrainIntent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutProgress {
    pub format_version: u32,
    pub rollout_id: String,
    pub stack: String,
    pub phase: RolloutExecutionPhase,
    pub previous_generation: Option<String>,
    pub candidate_generation: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub last_progress_at_ms: u64,
    pub action_sequence: u64,
    pub instances: Vec<RolloutInstanceProgress>,
    pub progress_sha256: String,
}

impl RolloutProgress {
    pub fn from_rollout(record: &RolloutRecord, now_ms: u64) -> Result<Self, String> {
        record.validate()?;
        if record.phase != RolloutPhase::Activated || now_ms == 0 || now_ms < record.updated_at_ms {
            return Err("rollout is not activated for live execution".into());
        }
        let candidate_generation = record
            .activated_generation
            .clone()
            .ok_or_else(|| "activated rollout has no candidate generation".to_string())?;
        let previous_plan = (record.previous_state == Some(EngineStackState::Applied))
            .then_some(record.previous_plan.as_ref())
            .flatten();
        let mut names = BTreeSet::new();
        names.extend(
            previous_plan
                .into_iter()
                .flat_map(|plan| plan.instances.iter())
                .map(|instance| instance.name.as_str()),
        );
        names.extend(
            record
                .candidate_plan
                .instances
                .iter()
                .map(|instance| instance.name.as_str()),
        );
        let mut instances = Vec::with_capacity(names.len());
        for name in names {
            let previous = previous_plan
                .and_then(|plan| plan.instances.iter().find(|instance| instance.name == name));
            let candidate = record
                .candidate_plan
                .instances
                .iter()
                .find(|instance| instance.name == name);
            let previous_replicas = previous
                .filter(|instance| instance.desired == DesiredState::Running)
                .map_or(0, |instance| instance.replicas);
            let candidate_replicas = candidate
                .filter(|instance| instance.desired == DesiredState::Running)
                .map_or(0, |instance| instance.replicas);
            if previous_replicas == 0 && candidate_replicas == 0 {
                continue;
            }
            let policy = candidate
                .or(previous)
                .ok_or_else(|| "rollout instance transition is missing its policy".to_string())?
                .update
                .clone();
            instances.push(RolloutInstanceProgress {
                name: name.into(),
                previous_replicas,
                candidate_replicas,
                policy,
                candidate_enabled: BTreeSet::new(),
                previous_draining: BTreeMap::new(),
            });
        }
        let mut value = Self {
            format_version: ENGINE_ROLLOUT_PROGRESS_FORMAT_VERSION,
            rollout_id: record.rollout_id.clone(),
            stack: record.stack.clone(),
            phase: RolloutExecutionPhase::Rolling,
            previous_generation: record.previous_generation.clone(),
            candidate_generation,
            started_at_ms: now_ms,
            updated_at_ms: now_ms,
            last_progress_at_ms: now_ms,
            action_sequence: 0,
            instances,
            progress_sha256: String::new(),
        };
        value.refresh()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_ROLLOUT_PROGRESS_FORMAT_VERSION
            || !is_digest(&self.rollout_id)
            || !valid_name(&self.stack)
            || self
                .previous_generation
                .as_ref()
                .is_some_and(|generation| !is_digest(generation))
            || !is_digest(&self.candidate_generation)
            || self.started_at_ms == 0
            || self.updated_at_ms < self.started_at_ms
            || self.last_progress_at_ms < self.started_at_ms
            || self.last_progress_at_ms > self.updated_at_ms
            || self.instances.len() > MAX_STACK_INSTANCES
            || !is_digest(&self.progress_sha256)
            || self.computed_sha256()? != self.progress_sha256
        {
            return Err("rollout progress identity is invalid".into());
        }
        let mut previous_name = None;
        let mut previous_total = 0_u16;
        let mut candidate_total = 0_u16;
        let mut total_surge = 0_u16;
        for instance in &self.instances {
            instance.validate()?;
            if previous_name.is_some_and(|name| name >= instance.name.as_str()) {
                return Err("rollout progress instances are not strictly sorted".into());
            }
            previous_name = Some(instance.name.as_str());
            previous_total = previous_total
                .checked_add(instance.previous_replicas)
                .ok_or_else(|| "rollout previous replica count overflow".to_string())?;
            candidate_total = candidate_total
                .checked_add(instance.candidate_replicas)
                .ok_or_else(|| "rollout candidate replica count overflow".to_string())?;
            total_surge = total_surge
                .checked_add(instance.policy.max_surge)
                .ok_or_else(|| "rollout surge count overflow".to_string())?;
        }
        if previous_total > MAX_STACK_TOTAL_REPLICAS
            || candidate_total > MAX_STACK_TOTAL_REPLICAS
            || total_surge > MAX_STACK_TOTAL_SURGE_REPLICAS
        {
            return Err("rollout progress exceeds its aggregate replica limits".into());
        }
        Ok(())
    }

    pub fn enable_candidate(
        &mut self,
        instance: &str,
        ordinals: &[u16],
        now_ms: u64,
    ) -> Result<(), String> {
        self.ensure_mutable(now_ms)?;
        if ordinals.is_empty() {
            return Err("candidate start intent is empty".into());
        }
        let progress = self.instance_mut(instance)?;
        if ordinals.iter().any(|ordinal| {
            *ordinal == 0
                || *ordinal > progress.candidate_replicas
                || progress.candidate_enabled.contains(ordinal)
        }) {
            return Err("candidate start intent contains an invalid ordinal".into());
        }
        progress.candidate_enabled.extend(ordinals.iter().copied());
        self.mark_progress(now_ms)
    }

    pub fn request_previous_drain(
        &mut self,
        instance: &str,
        ordinals: &[u16],
        now_ms: u64,
    ) -> Result<(), String> {
        self.ensure_mutable(now_ms)?;
        if ordinals.is_empty() {
            return Err("previous drain intent is empty".into());
        }
        let progress = self.instance_mut(instance)?;
        let deadline_at_ms = now_ms
            .checked_add(progress.policy.drain_timeout_ms)
            .ok_or_else(|| "rollout drain deadline overflow".to_string())?;
        if ordinals.iter().any(|ordinal| {
            *ordinal == 0
                || *ordinal > progress.previous_replicas
                || progress.previous_draining.contains_key(ordinal)
        }) {
            return Err("previous drain intent contains an invalid ordinal".into());
        }
        for ordinal in ordinals {
            progress.previous_draining.insert(
                *ordinal,
                DrainIntent {
                    requested_at_ms: now_ms,
                    deadline_at_ms,
                },
            );
        }
        self.mark_progress(now_ms)
    }

    pub fn set_phase(&mut self, next: RolloutExecutionPhase, now_ms: u64) -> Result<(), String> {
        self.ensure_time(now_ms)?;
        let valid = matches!(
            (self.phase, next),
            (
                RolloutExecutionPhase::Rolling,
                RolloutExecutionPhase::Paused
                    | RolloutExecutionPhase::Completing
                    | RolloutExecutionPhase::RollingBack
            ) | (
                RolloutExecutionPhase::Paused,
                RolloutExecutionPhase::Rolling | RolloutExecutionPhase::RollingBack
            ) | (
                RolloutExecutionPhase::Completing,
                RolloutExecutionPhase::Completed
            ) | (
                RolloutExecutionPhase::RollingBack,
                RolloutExecutionPhase::RolledBack
            )
        );
        if !valid {
            return Err("rollout execution phase transition is invalid".into());
        }
        self.phase = next;
        self.mark_progress(now_ms)
    }

    pub fn heartbeat(&mut self, now_ms: u64) -> Result<(), String> {
        self.ensure_time(now_ms)?;
        self.updated_at_ms = now_ms;
        self.refresh()
    }

    fn ensure_mutable(&self, now_ms: u64) -> Result<(), String> {
        self.ensure_time(now_ms)?;
        if self.phase != RolloutExecutionPhase::Rolling {
            return Err("rollout execution is not accepting scheduler actions".into());
        }
        Ok(())
    }

    fn ensure_time(&self, now_ms: u64) -> Result<(), String> {
        if now_ms == 0 || now_ms < self.updated_at_ms {
            return Err("rollout progress time cannot move backwards".into());
        }
        Ok(())
    }

    fn instance_mut(&mut self, name: &str) -> Result<&mut RolloutInstanceProgress, String> {
        self.instances
            .iter_mut()
            .find(|instance| instance.name == name)
            .ok_or_else(|| "rollout progress has no matching instance".into())
    }

    fn mark_progress(&mut self, now_ms: u64) -> Result<(), String> {
        self.action_sequence = self
            .action_sequence
            .checked_add(1)
            .ok_or_else(|| "rollout action sequence overflow".to_string())?;
        self.updated_at_ms = now_ms;
        self.last_progress_at_ms = now_ms;
        self.refresh()
    }

    fn refresh(&mut self) -> Result<(), String> {
        self.progress_sha256.clear();
        self.progress_sha256 = self.computed_sha256()?;
        self.validate()
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.progress_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_ROLLOUT_PROGRESS_BYTES {
            return Err("rollout progress exceeds its byte limit".into());
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

impl RolloutInstanceProgress {
    fn validate(&self) -> Result<(), String> {
        let policy_replicas = self.previous_replicas.max(self.candidate_replicas);
        if !valid_name(&self.name)
            || policy_replicas == 0
            || self.previous_replicas > MAX_STACK_REPLICAS
            || self.candidate_replicas > MAX_STACK_REPLICAS
        {
            return Err("rollout instance progress is invalid".into());
        }
        self.policy.validate(policy_replicas)?;
        if self
            .candidate_enabled
            .iter()
            .any(|ordinal| *ordinal == 0 || *ordinal > self.candidate_replicas)
            || self.previous_draining.iter().any(|(ordinal, intent)| {
                *ordinal == 0
                    || *ordinal > self.previous_replicas
                    || intent.requested_at_ms == 0
                    || intent.deadline_at_ms < intent.requested_at_ms
            })
        {
            return Err("rollout instance ordinal progress is invalid".into());
        }
        Ok(())
    }
}

impl EngineStore {
    pub fn rollout_progress(&self, stack: &str) -> Result<Option<RolloutProgress>, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let path = self.rollout_progress_path(stack)?;
        recover_progress_file(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let progress = read_progress_file(&path)?;
        if progress.stack != stack {
            return Err("rollout progress belongs to another stack".into());
        }
        let rollout = self
            .rollout(stack)?
            .ok_or_else(|| "rollout progress has no transaction checkpoint".to_string())?;
        validate_progress_against_rollout(&progress, &rollout)?;
        Ok(Some(progress))
    }

    pub fn begin_rollout_progress(
        &self,
        stack: &str,
        rollout_id: &str,
        now_ms: u64,
    ) -> Result<RolloutProgress, String> {
        if let Some(progress) = self.rollout_progress(stack)? {
            if progress.rollout_id == rollout_id {
                return Ok(progress);
            }
            return Err("stack already has progress for another rollout".into());
        }
        let rollout = self
            .rollout(stack)?
            .ok_or_else(|| "stack has no rollout checkpoint".to_string())?;
        if rollout.rollout_id != rollout_id {
            return Err("rollout identity does not match the current checkpoint".into());
        }
        let progress = RolloutProgress::from_rollout(&rollout, now_ms)?;
        write_progress_file(&self.rollout_progress_path(stack)?, &progress)?;
        Ok(progress)
    }

    pub fn save_rollout_progress(&self, progress: &RolloutProgress) -> Result<(), String> {
        progress.validate()?;
        let rollout = self
            .rollout(&progress.stack)?
            .ok_or_else(|| "rollout progress has no transaction checkpoint".to_string())?;
        validate_progress_against_rollout(progress, &rollout)?;
        let path = self.rollout_progress_path(&progress.stack)?;
        recover_progress_file(&path)?;
        write_progress_file(&path, progress)
    }

    fn rollout_progress_path(&self, stack: &str) -> Result<PathBuf, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        Ok(self
            .root
            .join("stacks")
            .join(stack)
            .join(CURRENT_PROGRESS_FILE))
    }
}

fn validate_progress_against_rollout(
    progress: &RolloutProgress,
    rollout: &RolloutRecord,
) -> Result<(), String> {
    rollout.validate()?;
    if progress.rollout_id != rollout.rollout_id
        || progress.stack != rollout.stack
        || progress.previous_generation != rollout.previous_generation
        || Some(progress.candidate_generation.as_str()) != rollout.activated_generation.as_deref()
    {
        return Err("rollout progress does not match its transaction checkpoint".into());
    }
    Ok(())
}

fn write_progress_file(path: &Path, progress: &RolloutProgress) -> Result<(), String> {
    progress.validate()?;
    let bytes = serde_json::to_vec(progress).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ROLLOUT_PROGRESS_BYTES {
        return Err("rollout progress exceeds its byte limit".into());
    }
    write_replace_atomic(path, &bytes)
}

fn read_progress_file(path: &Path) -> Result<RolloutProgress, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ROLLOUT_PROGRESS_BYTES
    {
        return Err("rollout progress must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_ROLLOUT_PROGRESS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ROLLOUT_PROGRESS_BYTES {
        return Err("rollout progress exceeded its byte limit while reading".into());
    }
    let progress: RolloutProgress =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    progress.validate()?;
    Ok(progress)
}

fn recover_progress_file(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    if backup.exists() && !is_regular_file(&backup) {
        return Err("rollout progress backup is not a regular file".into());
    }
    if path.exists() && !is_regular_file(path) {
        return Err("rollout progress path is not a regular file".into());
    }
    if !path.exists() && backup.exists() {
        read_progress_file(&backup)?;
        fs::rename(&backup, path).map_err(|error| error.to_string())?;
    } else if path.exists() && backup.exists() {
        read_progress_file(path)?;
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cartridge_core::{CompositionLock, LockedPackage, ResolutionPlan, RuntimeLimits};

    use super::*;
    use crate::{
        PlannedInstance, PlannedSecurity, RestartPolicy, SandboxPolicy, SecurityProfile, StackPlan,
    };

    fn plan(stack: &str, package: char, replicas: u16) -> StackPlan {
        let digest = package.to_string().repeat(64);
        let mut value = StackPlan {
            format_version: crate::STACK_PLAN_FORMAT_VERSION,
            stack: stack.into(),
            security: PlannedSecurity {
                profile: SecurityProfile::Strict,
                sandbox: SandboxPolicy::Required,
            },
            instances: vec![PlannedInstance {
                name: "app".into(),
                cartridge_id: "dev.test.app".into(),
                version: "1.0.0".into(),
                package_sha256: digest.clone(),
                package_bytes: 8,
                replicas,
                desired: DesiredState::Running,
                restart: RestartPolicy::OnFailure,
                max_restarts: 2,
                requested: BTreeSet::new(),
                granted: BTreeSet::new(),
                blocked: BTreeSet::new(),
                allowed: BTreeSet::new(),
                denied: BTreeSet::new(),
                args: Vec::new(),
                secrets: BTreeSet::new(),
                limits: RuntimeLimits::default(),
                health: None,
                update: RollingUpdatePolicy::default(),
                composition: CompositionLock::new(
                    LockedPackage {
                        cartridge_id: "dev.test.app".into(),
                        version: "1.0.0".into(),
                        package_sha256: digest,
                        package_bytes: 8,
                        component_sha256: "c".repeat(64),
                        assets_root_sha256: "d".repeat(64),
                    },
                    Vec::new(),
                    ResolutionPlan {
                        resolved: Vec::new(),
                        unavailable_optional: Vec::new(),
                    },
                )
                .unwrap(),
            }],
            resources: Vec::new(),
            secrets: Vec::new(),
            warnings: Vec::new(),
            plan_sha256: String::new(),
        };
        value.plan_sha256 = value.computed_sha256().unwrap();
        value.validate().unwrap();
        value
    }

    fn activated_rollout(engine: &EngineStore) -> RolloutRecord {
        engine.apply(&plan("demo", 'a', 2), false).unwrap();
        let prepared = engine
            .prepare_rollout(&plan("demo", 'b', 3), false, 10)
            .unwrap();
        engine
            .activate_rollout("demo", &prepared.rollout_id, 11)
            .unwrap()
    }

    #[test]
    fn progress_persists_topology_and_monotonic_scheduler_intent() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let rollout = activated_rollout(&engine);
        let mut progress = engine
            .begin_rollout_progress("demo", &rollout.rollout_id, 12)
            .unwrap();
        assert_eq!(progress.instances[0].previous_replicas, 2);
        assert_eq!(progress.instances[0].candidate_replicas, 3);

        progress.enable_candidate("app", &[1], 13).unwrap();
        progress.request_previous_drain("app", &[1], 14).unwrap();
        engine.save_rollout_progress(&progress).unwrap();
        let loaded = engine.rollout_progress("demo").unwrap().unwrap();
        assert_eq!(loaded.action_sequence, 2);
        assert_eq!(loaded.instances[0].candidate_enabled, BTreeSet::from([1]));
        assert_eq!(loaded.instances[0].previous_draining.len(), 1);
        assert_eq!(loaded, progress);
    }

    #[test]
    fn progress_rejects_replay_cross_rollout_tampering_and_bad_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let rollout = activated_rollout(&engine);
        let mut progress = engine
            .begin_rollout_progress("demo", &rollout.rollout_id, 12)
            .unwrap();
        assert!(progress.enable_candidate("app", &[0], 13).is_err());
        progress.enable_candidate("app", &[1], 13).unwrap();
        assert!(progress.enable_candidate("app", &[1], 14).is_err());
        assert!(progress.heartbeat(12).is_err());
        progress
            .set_phase(RolloutExecutionPhase::Paused, 14)
            .unwrap();
        assert!(progress.enable_candidate("app", &[2], 15).is_err());

        let path = directory.path().join("stacks/demo/rollout-progress.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["candidate_generation"] = serde_json::Value::String("f".repeat(64));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(engine.rollout_progress("demo").is_err());
    }

    #[test]
    fn interrupted_progress_replacement_recovers_only_a_valid_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let rollout = activated_rollout(&engine);
        let progress = engine
            .begin_rollout_progress("demo", &rollout.rollout_id, 12)
            .unwrap();
        let path = directory.path().join("stacks/demo/rollout-progress.json");
        let backup = path.with_extension("json.previous");
        fs::rename(&path, &backup).unwrap();

        assert_eq!(engine.rollout_progress("demo").unwrap(), Some(progress));
        assert!(path.exists());
        assert!(!backup.exists());
    }
}

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    DesiredState, EngineStore, GenerationRole, MAX_STACK_REPLICAS, MAX_STACK_TOTAL_ACTIVE_REPLICAS,
    ProbePhase, ReplicaId, ReplicaPhase, RolloutExecutionPhase, RolloutPhase, RolloutProgress,
    StackRuntimeStatus, is_digest, is_regular_file, sync_parent_directory, valid_name,
    write_replace_atomic,
};

pub const ENGINE_ROUTING_FORMAT_VERSION: u32 = 1;
pub const MAX_ENGINE_ROUTING_BYTES: u64 = 1024 * 1024;

const ROUTING_FILE: &str = "routes.json";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTarget {
    pub instance: String,
    pub ordinal: u16,
    pub revision: u64,
    pub generation: String,
    pub run_id: String,
    pub ready_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingSnapshot {
    pub format_version: u32,
    pub stack: String,
    pub routing_epoch: String,
    pub sequence: u64,
    pub published_at_ms: u64,
    pub rollout_id: Option<String>,
    pub targets: Vec<RouteTarget>,
    pub routing_sha256: String,
}

impl RoutingSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_ROUTING_FORMAT_VERSION
            || !valid_name(&self.stack)
            || !is_digest(&self.routing_epoch)
            || self.sequence == 0
            || self.published_at_ms == 0
            || self
                .rollout_id
                .as_ref()
                .is_some_and(|rollout_id| !is_digest(rollout_id))
            || self.targets.len() > usize::from(MAX_STACK_TOTAL_ACTIVE_REPLICAS)
            || !is_digest(&self.routing_sha256)
            || self.computed_sha256()? != self.routing_sha256
        {
            return Err("routing snapshot identity is invalid".into());
        }
        let mut previous: Option<&RouteTarget> = None;
        let mut identities = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if previous.is_some_and(|value| value >= target)
                || !identities.insert((
                    target.generation.as_str(),
                    target.instance.as_str(),
                    target.ordinal,
                ))
            {
                return Err("routing targets are not strictly sorted".into());
            }
            previous = Some(target);
        }
        Ok(())
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.routing_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn refresh(&mut self) -> Result<(), String> {
        self.targets.sort();
        self.routing_sha256 = self.computed_sha256()?;
        self.validate()
    }
}

impl RouteTarget {
    fn validate(&self) -> Result<(), String> {
        if !valid_name(&self.instance)
            || self.ordinal == 0
            || self.ordinal > MAX_STACK_REPLICAS
            || self.revision == 0
            || !is_digest(&self.generation)
            || !is_digest(&self.run_id)
            || self.ready_at_ms == 0
        {
            return Err("routing target identity is invalid".into());
        }
        Ok(())
    }
}

impl EngineStore {
    pub fn publish_routing_snapshot(
        &self,
        stack: &str,
        now_ms: u64,
    ) -> Result<RoutingSnapshot, String> {
        let progress = self.active_routing_progress(stack)?;
        self.publish_routing_snapshot_inner(stack, progress.as_ref(), now_ms)
    }

    pub fn publish_routing_snapshot_for_progress(
        &self,
        progress: &RolloutProgress,
        now_ms: u64,
    ) -> Result<RoutingSnapshot, String> {
        progress.validate()?;
        let rollout = self
            .rollout(&progress.stack)?
            .ok_or_else(|| "routing progress has no rollout checkpoint".to_string())?;
        if rollout.phase != RolloutPhase::Activated
            || rollout.rollout_id != progress.rollout_id
            || rollout.previous_revision != progress.previous_revision
            || rollout.previous_generation != progress.previous_generation
            || rollout.activated_revision != Some(progress.candidate_revision)
            || rollout.activated_generation.as_deref()
                != Some(progress.candidate_generation.as_str())
        {
            return Err("routing progress does not match the active rollout".into());
        }
        self.publish_routing_snapshot_inner(&progress.stack, Some(progress), now_ms)
    }

    pub fn routing_snapshot(&self, stack: &str) -> Result<Option<RoutingSnapshot>, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        self.status(stack)?;
        let path = self.routing_path(stack)?;
        recover_routing_file(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let snapshot = read_routing_file(&path)?;
        if snapshot.stack != stack {
            return Err("routing snapshot belongs to another stack".into());
        }
        let progress = self.active_routing_progress(stack)?;
        let (rollout_id, expected) = self.routing_targets(stack, progress.as_ref())?;
        if snapshot.rollout_id != rollout_id || snapshot.targets != expected {
            return Err("published routes no longer match authoritative runtime state".into());
        }
        Ok(Some(snapshot))
    }

    fn publish_routing_snapshot_inner(
        &self,
        stack: &str,
        progress: Option<&RolloutProgress>,
        now_ms: u64,
    ) -> Result<RoutingSnapshot, String> {
        if !valid_name(stack) || now_ms == 0 {
            return Err("routing publication identity is invalid".into());
        }
        self.status(stack)?;
        let path = self.routing_path(stack)?;
        let previous = routing_snapshot_for_publish(&path)?;
        let (rollout_id, targets) = self.routing_targets(stack, progress)?;
        if let Some(previous) = &previous
            && previous.rollout_id == rollout_id
            && previous.targets == targets
        {
            return Ok(previous.clone());
        }
        let sequence = previous.as_ref().map_or(Ok(1), |value| {
            value
                .sequence
                .checked_add(1)
                .ok_or_else(|| "routing sequence overflow".to_string())
        })?;
        if previous
            .as_ref()
            .is_some_and(|value| now_ms < value.published_at_ms)
        {
            return Err("routing publication time moved backwards".into());
        }
        let mut snapshot = RoutingSnapshot {
            format_version: ENGINE_ROUTING_FORMAT_VERSION,
            stack: stack.into(),
            routing_epoch: previous.as_ref().map_or_else(
                || hex::encode(random::<[u8; 32]>()),
                |value| value.routing_epoch.clone(),
            ),
            sequence,
            published_at_ms: now_ms,
            rollout_id,
            targets,
            routing_sha256: String::new(),
        };
        snapshot.refresh()?;
        write_routing_file(&path, &snapshot)?;
        Ok(snapshot)
    }

    fn routing_targets(
        &self,
        stack: &str,
        progress: Option<&RolloutProgress>,
    ) -> Result<(Option<String>, Vec<RouteTarget>), String> {
        let rollout = self.rollout(stack)?;
        let active = rollout
            .as_ref()
            .filter(|record| record.phase == RolloutPhase::Activated);
        if let Some(progress) = progress {
            let active = active
                .ok_or_else(|| "routing progress exists without an active rollout".to_string())?;
            if active.rollout_id != progress.rollout_id || progress.stack != stack {
                return Err("routing progress belongs to another rollout".into());
            }
        }
        let rollout_id = active.map(|record| record.rollout_id.clone());
        let mut targets = Vec::new();
        for generation in self.generation_targets(stack)? {
            let Some(runtime) =
                self.runtime_status_for_generation(stack, &generation.generation)?
            else {
                continue;
            };
            let allowed = routing_controls(generation.role, progress);
            append_ready_targets(&mut targets, &generation, &runtime, &allowed)?;
        }
        targets.sort();
        if targets.len() > usize::from(MAX_STACK_TOTAL_ACTIVE_REPLICAS) {
            return Err("routing targets exceed the aggregate replica limit".into());
        }
        Ok((rollout_id, targets))
    }

    fn routing_path(&self, stack: &str) -> Result<PathBuf, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        Ok(self.root.join("stacks").join(stack).join(ROUTING_FILE))
    }

    fn active_routing_progress(&self, stack: &str) -> Result<Option<RolloutProgress>, String> {
        if self
            .rollout(stack)?
            .is_some_and(|record| record.phase == RolloutPhase::Activated)
        {
            self.rollout_progress(stack)
        } else {
            Ok(None)
        }
    }
}

enum RoutingControls {
    All,
    Only(BTreeSet<ReplicaId>),
    Except(BTreeSet<ReplicaId>),
    None,
}

fn routing_controls(role: GenerationRole, progress: Option<&RolloutProgress>) -> RoutingControls {
    match role {
        GenerationRole::Desired => RoutingControls::All,
        GenerationRole::RolloutCandidate => {
            let Some(progress) = progress else {
                return RoutingControls::None;
            };
            if matches!(
                progress.phase,
                RolloutExecutionPhase::Rolling
                    | RolloutExecutionPhase::Paused
                    | RolloutExecutionPhase::Completing
            ) {
                RoutingControls::Only(progress.candidate_enabled())
            } else {
                RoutingControls::None
            }
        }
        GenerationRole::RolloutPrevious => {
            let Some(progress) = progress else {
                return RoutingControls::All;
            };
            if matches!(
                progress.phase,
                RolloutExecutionPhase::Rolling
                    | RolloutExecutionPhase::Paused
                    | RolloutExecutionPhase::Completing
            ) {
                RoutingControls::Except(progress.previous_draining())
            } else {
                RoutingControls::All
            }
        }
    }
}

fn append_ready_targets(
    targets: &mut Vec<RouteTarget>,
    generation: &super::GenerationTarget,
    runtime: &StackRuntimeStatus,
    controls: &RoutingControls,
) -> Result<(), String> {
    for replica in &runtime.replicas {
        if replica.desired != DesiredState::Running
            || replica.phase != ReplicaPhase::Running
            || !matches_controls(controls, &replica.id)
        {
            continue;
        }
        let Some(run_id) = replica.run_id.as_ref() else {
            return Err("ready routing replica has no run identity".into());
        };
        let ready_at_ms = match &replica.probe {
            Some(probe) if probe.phase == ProbePhase::Ready => probe.ready_at_ms,
            Some(_) => None,
            None => replica.started_at_ms,
        };
        let Some(ready_at_ms) = ready_at_ms else {
            continue;
        };
        targets.push(RouteTarget {
            instance: replica.id.instance.clone(),
            ordinal: replica.id.ordinal,
            revision: generation.revision,
            generation: generation.generation.clone(),
            run_id: run_id.clone(),
            ready_at_ms,
        });
    }
    Ok(())
}

fn matches_controls(controls: &RoutingControls, id: &ReplicaId) -> bool {
    match controls {
        RoutingControls::All => true,
        RoutingControls::Only(values) => values.contains(id),
        RoutingControls::Except(values) => !values.contains(id),
        RoutingControls::None => false,
    }
}

impl RolloutProgress {
    fn candidate_enabled(&self) -> BTreeSet<ReplicaId> {
        self.instances
            .iter()
            .flat_map(|instance| {
                instance.candidate_enabled.iter().map(|ordinal| ReplicaId {
                    instance: instance.name.clone(),
                    ordinal: *ordinal,
                })
            })
            .collect()
    }

    fn previous_draining(&self) -> BTreeSet<ReplicaId> {
        self.instances
            .iter()
            .flat_map(|instance| {
                instance.previous_draining.keys().map(|ordinal| ReplicaId {
                    instance: instance.name.clone(),
                    ordinal: *ordinal,
                })
            })
            .collect()
    }
}

fn write_routing_file(path: &Path, snapshot: &RoutingSnapshot) -> Result<(), String> {
    snapshot.validate()?;
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ENGINE_ROUTING_BYTES {
        return Err("routing snapshot exceeds its byte limit".into());
    }
    write_replace_atomic(path, &bytes)
}

fn read_routing_file(path: &Path) -> Result<RoutingSnapshot, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENGINE_ROUTING_BYTES
    {
        return Err("routing snapshot must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_ENGINE_ROUTING_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ENGINE_ROUTING_BYTES {
        return Err("routing snapshot exceeded its byte limit while reading".into());
    }
    let snapshot: RoutingSnapshot =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    snapshot.validate()?;
    Ok(snapshot)
}

fn recover_routing_file(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    if backup.exists() && !is_regular_file(&backup) {
        return Err("routing snapshot backup is not a regular file".into());
    }
    if path.exists() && !is_regular_file(path) {
        return Err("routing snapshot path is not a regular file".into());
    }
    if !path.exists() && backup.exists() {
        read_routing_file(&backup)?;
        fs::rename(&backup, path).map_err(|error| error.to_string())?;
        sync_parent_directory(path)?;
    } else if path.exists() && backup.exists() {
        read_routing_file(path)?;
        fs::remove_file(backup).map_err(|error| error.to_string())?;
        sync_parent_directory(path)?;
    }
    Ok(())
}

fn routing_snapshot_for_publish(path: &Path) -> Result<Option<RoutingSnapshot>, String> {
    if let Err(error) = recover_routing_file(path) {
        reset_invalid_routing_files(path).map_err(|reset| format!("{error}; {reset}"))?;
        return Ok(None);
    }
    if !path.exists() {
        return Ok(None);
    }
    if let Ok(snapshot) = read_routing_file(path) {
        Ok(Some(snapshot))
    } else {
        reset_invalid_routing_files(path)?;
        Ok(None)
    }
}

fn reset_invalid_routing_files(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    let mut removed = false;
    for artifact in [path, backup.as_path()] {
        match fs::symlink_metadata(artifact) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(artifact).map_err(|error| error.to_string())?;
                removed = true;
            }
            Ok(_) => return Err("invalid routing artifact is not a regular file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    if removed {
        sync_parent_directory(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cartridge_core::{CompositionLock, LockedPackage, ResolutionPlan, RuntimeLimits};

    use super::*;
    use crate::{
        HealthProbeSpec, PlannedInstance, PlannedSecurity, ProbeSignalKind, RestartPolicy,
        RollingUpdatePolicy, SandboxPolicy, SecurityProfile, StackPlan,
    };

    fn plan(package: char, replicas: u16, probes: bool) -> StackPlan {
        let digest = package.to_string().repeat(64);
        let mut value = StackPlan {
            format_version: crate::STACK_PLAN_FORMAT_VERSION,
            stack: "demo".into(),
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
                health: probes.then(HealthProbeSpec::default),
                update: RollingUpdatePolicy::default(),
                composition: CompositionLock::new(
                    LockedPackage {
                        cartridge_id: "dev.test.app".into(),
                        version: "1.0.0".into(),
                        package_sha256: digest,
                        package_bytes: 8,
                        component_sha256: "e".repeat(64),
                        assets_root_sha256: "f".repeat(64),
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
        value
    }

    fn ready_runtime(
        plan: &StackPlan,
        revision: u64,
        generation: &str,
        ordinals: &[u16],
        now_ms: u64,
    ) -> StackRuntimeStatus {
        let mut status = StackRuntimeStatus::from_plan(plan, revision, generation, now_ms).unwrap();
        for ordinal in ordinals {
            let id = ReplicaId {
                instance: "app".into(),
                ordinal: *ordinal,
            };
            let run_id = format!("{ordinal:064x}");
            status.begin_start(&id, &run_id, now_ms).unwrap();
            if plan.instances[0].health.is_some() {
                status
                    .mark_probe_signal(&id, &run_id, 1, ProbeSignalKind::Ready, now_ms)
                    .unwrap();
            } else {
                status.mark_running(&id, &run_id, now_ms).unwrap();
            }
        }
        status
    }

    #[test]
    fn routing_publishes_only_ready_replicas_and_rejects_stale_state() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let plan = plan('1', 1, true);
        engine.apply(&plan, false).unwrap();
        let (revision, generation, _) = engine.desired_plan("demo").unwrap().unwrap();
        let mut status = StackRuntimeStatus::from_plan(&plan, revision, &generation, 10).unwrap();
        let id = status.replicas[0].id.clone();
        let run_id = "a".repeat(64);
        status.begin_start(&id, &run_id, 10).unwrap();
        engine.save_runtime_status_for_generation(&status).unwrap();

        let waiting = engine.publish_routing_snapshot("demo", 11).unwrap();
        assert!(waiting.targets.is_empty());
        status
            .mark_probe_signal(&id, &run_id, 1, ProbeSignalKind::Ready, 12)
            .unwrap();
        engine.save_runtime_status_for_generation(&status).unwrap();
        let ready = engine.publish_routing_snapshot("demo", 13).unwrap();
        assert_eq!(ready.targets.len(), 1);
        assert_eq!(engine.routing_snapshot("demo").unwrap(), Some(ready));

        status.mark_probe_timeout(&id, &run_id, 14).unwrap();
        engine.save_runtime_status_for_generation(&status).unwrap();
        assert!(engine.routing_snapshot("demo").is_err());
        assert!(
            engine
                .publish_routing_snapshot("demo", 15)
                .unwrap()
                .targets
                .is_empty()
        );
    }

    #[test]
    fn drain_intent_is_published_before_it_becomes_visible_to_supervisors() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let old = plan('2', 2, false);
        let candidate = plan('3', 2, false);
        engine.apply(&old, false).unwrap();
        let (old_revision, old_generation, _) = engine.desired_plan("demo").unwrap().unwrap();
        let old_runtime = ready_runtime(&old, old_revision, &old_generation, &[1, 2], 20);
        engine
            .save_runtime_status_for_generation(&old_runtime)
            .unwrap();
        assert_eq!(
            engine
                .publish_routing_snapshot("demo", 21)
                .unwrap()
                .targets
                .len(),
            2
        );

        let prepared = engine.prepare_rollout(&candidate, false, 22).unwrap();
        let activated = engine
            .activate_rollout("demo", &prepared.rollout_id, 23)
            .unwrap();
        let mut progress = engine
            .begin_rollout_progress("demo", &prepared.rollout_id, 24)
            .unwrap();
        progress.enable_candidate("app", &[1], 25).unwrap();
        engine.save_rollout_progress(&progress).unwrap();
        let candidate_generation = activated.activated_generation.unwrap();
        let candidate_runtime = ready_runtime(
            &candidate,
            activated.activated_revision.unwrap(),
            &candidate_generation,
            &[1],
            25,
        );
        engine
            .save_runtime_status_for_generation(&candidate_runtime)
            .unwrap();
        assert_eq!(
            engine
                .publish_routing_snapshot_for_progress(&progress, 26)
                .unwrap()
                .targets
                .len(),
            3
        );

        progress.request_previous_drain("app", &[1], 27).unwrap();
        let published = engine
            .publish_routing_snapshot_for_progress(&progress, 27)
            .unwrap();
        assert_eq!(published.targets.len(), 2);
        assert!(
            !published
                .targets
                .iter()
                .any(|target| { target.generation == old_generation && target.ordinal == 1 })
        );
        let raw = read_routing_file(&engine.routing_path("demo").unwrap()).unwrap();
        assert_eq!(raw, published);
        assert!(engine.routing_snapshot("demo").is_err());

        engine.save_rollout_progress(&progress).unwrap();
        assert_eq!(engine.routing_snapshot("demo").unwrap(), Some(published));
    }

    #[test]
    fn changed_routing_files_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let plan = plan('4', 1, false);
        engine.apply(&plan, false).unwrap();
        engine.publish_routing_snapshot("demo", 30).unwrap();
        let path = engine.routing_path("demo").unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["sequence"] = serde_json::json!(2);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(engine.routing_snapshot("demo").is_err());

        let repaired = engine.publish_routing_snapshot("demo", 31).unwrap();
        assert_eq!(repaired.sequence, 1);
        assert_eq!(engine.routing_snapshot("demo").unwrap(), Some(repaired));
    }

    #[test]
    fn corrupt_routing_state_restarts_in_a_new_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let plan = plan('5', 1, false);
        engine.apply(&plan, false).unwrap();
        let first = engine.publish_routing_snapshot("demo", 40).unwrap();
        let path = engine.routing_path("demo").unwrap();
        fs::write(&path, b"not json").unwrap();

        assert!(engine.routing_snapshot("demo").is_err());
        let repaired = engine.publish_routing_snapshot("demo", 41).unwrap();
        assert_eq!(repaired.sequence, 1);
        assert_ne!(repaired.routing_epoch, first.routing_epoch);
        assert_eq!(engine.routing_snapshot("demo").unwrap(), Some(repaired));
    }

    #[test]
    fn changed_routes_reject_backwards_publication_time() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let plan = plan('6', 1, true);
        engine.apply(&plan, false).unwrap();
        let (revision, generation, _) = engine.desired_plan("demo").unwrap().unwrap();
        let mut status = StackRuntimeStatus::from_plan(&plan, revision, &generation, 50).unwrap();
        let id = status.replicas[0].id.clone();
        let run_id = "b".repeat(64);
        status.begin_start(&id, &run_id, 50).unwrap();
        engine.save_runtime_status_for_generation(&status).unwrap();
        engine.publish_routing_snapshot("demo", 55).unwrap();
        status
            .mark_probe_signal(&id, &run_id, 1, ProbeSignalKind::Ready, 56)
            .unwrap();
        engine.save_runtime_status_for_generation(&status).unwrap();

        assert!(engine.publish_routing_snapshot("demo", 54).is_err());
        assert!(engine.routing_snapshot("demo").is_err());
        assert_eq!(
            engine
                .publish_routing_snapshot("demo", 57)
                .unwrap()
                .sequence,
            2
        );
    }

    #[test]
    fn stopped_stacks_publish_an_empty_route_set() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let plan = plan('7', 1, false);
        engine.apply(&plan, false).unwrap();
        let (revision, generation, _) = engine.desired_plan("demo").unwrap().unwrap();
        let status = ready_runtime(&plan, revision, &generation, &[1], 60);
        engine.save_runtime_status_for_generation(&status).unwrap();
        let ready = engine.publish_routing_snapshot("demo", 61).unwrap();
        assert_eq!(ready.targets.len(), 1);

        engine.stop("demo").unwrap();
        let stopped = engine.publish_routing_snapshot("demo", 62).unwrap();
        assert!(stopped.targets.is_empty());
        assert_eq!(stopped.sequence, ready.sequence + 1);
        assert_eq!(stopped.routing_epoch, ready.routing_epoch);
    }

    #[test]
    fn routing_snapshot_rejects_targets_above_the_engine_ceiling() {
        let targets = (0..=MAX_STACK_TOTAL_ACTIVE_REPLICAS)
            .map(|index| RouteTarget {
                instance: format!("app-{index}"),
                ordinal: 1,
                revision: 1,
                generation: "8".repeat(64),
                run_id: "9".repeat(64),
                ready_at_ms: 1,
            })
            .collect();
        let mut snapshot = RoutingSnapshot {
            format_version: ENGINE_ROUTING_FORMAT_VERSION,
            stack: "demo".into(),
            routing_epoch: "a".repeat(64),
            sequence: 1,
            published_at_ms: 1,
            rollout_id: None,
            targets,
            routing_sha256: String::new(),
        };

        assert!(snapshot.refresh().is_err());
    }
}

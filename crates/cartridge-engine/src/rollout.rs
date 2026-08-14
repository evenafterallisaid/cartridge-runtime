use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    EngineEvent, EngineEventKind, EngineStackState, EngineStore, MAX_ENGINE_STACKS,
    MAX_STACK_PLAN_BYTES, SandboxPolicy, StackHealthState, StackPlan, ensure_directory,
    exact_suffix, is_digest, is_regular_file, next_event, valid_name, write_new_atomic,
    write_replace_atomic,
};

pub const ENGINE_ROLLOUT_FORMAT_VERSION: u32 = 1;
pub const MAX_ROLLOUT_HISTORY: usize = 256;
pub const MAX_ROLLOUT_HISTORY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ROLLOUT_BYTES: u64 = (MAX_STACK_PLAN_BYTES as u64) * 2 + 64 * 1024;
pub const ROLLOUT_STABILITY_WINDOW_MS: u64 = 2_000;

const CURRENT_ROLLOUT_FILE: &str = "rollout.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RolloutPhase {
    Prepared,
    Activated,
    Committed,
    RolledBack,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutRecord {
    pub format_version: u32,
    pub rollout_id: String,
    pub stack: String,
    pub phase: RolloutPhase,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub previous_revision: Option<u64>,
    pub previous_generation: Option<String>,
    pub previous_state: Option<EngineStackState>,
    pub previous_plan: Option<StackPlan>,
    pub candidate_plan: StackPlan,
    pub activated_revision: Option<u64>,
    pub activated_generation: Option<String>,
    pub rollback_revision: Option<u64>,
    pub rollback_generation: Option<String>,
    pub health_report_sha256: Option<String>,
    pub record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutStatus {
    pub format_version: u32,
    pub rollout_id: String,
    pub stack: String,
    pub phase: RolloutPhase,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub previous_revision: Option<u64>,
    pub previous_generation: Option<String>,
    pub previous_state: Option<EngineStackState>,
    pub previous_plan_sha256: Option<String>,
    pub candidate_plan_sha256: String,
    pub activated_revision: Option<u64>,
    pub activated_generation: Option<String>,
    pub rollback_revision: Option<u64>,
    pub rollback_generation: Option<String>,
    pub health_report_sha256: Option<String>,
    pub checkpoint_sha256: String,
    pub status_sha256: String,
}

impl RolloutRecord {
    pub fn validate(&self) -> Result<(), String> {
        self.candidate_plan.validate()?;
        if self.format_version != ENGINE_ROLLOUT_FORMAT_VERSION
            || !is_digest(&self.rollout_id)
            || !valid_name(&self.stack)
            || self.candidate_plan.stack != self.stack
            || self.created_at_ms == 0
            || self.updated_at_ms < self.created_at_ms
            || self.rollout_id != self.computed_rollout_id()?
            || !is_digest(&self.record_sha256)
            || self.record_sha256 != self.computed_sha256()?
        {
            return Err("engine rollout identity is invalid".into());
        }
        self.validate_previous()?;
        self.validate_phase()
    }

    #[must_use]
    pub const fn active(&self) -> bool {
        matches!(self.phase, RolloutPhase::Prepared | RolloutPhase::Activated)
    }

    #[must_use]
    pub const fn terminal(&self) -> bool {
        !self.active()
    }

    fn validate_previous(&self) -> Result<(), String> {
        match (
            self.previous_revision,
            self.previous_generation.as_deref(),
            self.previous_state,
        ) {
            (None, None, None) if self.previous_plan.is_none() => Ok(()),
            (Some(revision), Some(generation), Some(state))
                if revision > 0 && is_digest(generation) =>
            {
                match state {
                    EngineStackState::Applied | EngineStackState::Stopped => {
                        let plan = self.previous_plan.as_ref().ok_or_else(|| {
                            "rollout previous state is missing its plan".to_string()
                        })?;
                        plan.validate()?;
                        if plan.stack != self.stack
                            || (state == EngineStackState::Stopped
                                && plan.instances.iter().any(|instance| {
                                    instance.desired != super::DesiredState::Stopped
                                }))
                        {
                            return Err("rollout previous plan is inconsistent".into());
                        }
                    }
                    EngineStackState::Removed if self.previous_plan.is_none() => {}
                    EngineStackState::Removed => {
                        return Err("removed rollout state cannot retain a plan".into());
                    }
                }
                Ok(())
            }
            _ => Err("rollout previous generation is incomplete".into()),
        }
    }

    fn validate_phase(&self) -> Result<(), String> {
        if !valid_phase_fields(
            self.phase,
            self.previous_revision,
            self.activated_revision,
            self.activated_generation.as_deref(),
            self.rollback_revision,
            self.rollback_generation.as_deref(),
            self.health_report_sha256.as_deref(),
        ) {
            return Err("engine rollout phase fields are inconsistent".into());
        }
        Ok(())
    }

    fn new(
        candidate_plan: StackPlan,
        previous: Option<&EngineEvent>,
        now_ms: u64,
    ) -> Result<Self, String> {
        if now_ms == 0 {
            return Err("rollout timestamp is invalid".into());
        }
        let mut value = Self {
            format_version: ENGINE_ROLLOUT_FORMAT_VERSION,
            rollout_id: String::new(),
            stack: candidate_plan.stack.clone(),
            phase: RolloutPhase::Prepared,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            previous_revision: previous.map(|event| event.revision),
            previous_generation: previous.map(|event| event.event_sha256.clone()),
            previous_state: previous.map(|event| event.status().state),
            previous_plan: previous.and_then(|event| event.plan.clone()),
            candidate_plan,
            activated_revision: None,
            activated_generation: None,
            rollback_revision: None,
            rollback_generation: None,
            health_report_sha256: None,
            record_sha256: String::new(),
        };
        value.rollout_id = value.computed_rollout_id()?;
        value.refresh()?;
        Ok(value)
    }

    fn computed_rollout_id(&self) -> Result<String, String> {
        rollout_id(
            &self.stack,
            self.created_at_ms,
            self.previous_revision,
            self.previous_generation.as_deref(),
            &self.candidate_plan.plan_sha256,
        )
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.record_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_ROLLOUT_BYTES {
            return Err("engine rollout exceeds its byte limit".into());
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn refresh(&mut self) -> Result<(), String> {
        self.record_sha256.clear();
        self.record_sha256 = self.computed_sha256()?;
        self.validate()
    }
}

impl RolloutStatus {
    pub fn from_record(record: &RolloutRecord) -> Result<Self, String> {
        record.validate()?;
        let mut value = Self {
            format_version: record.format_version,
            rollout_id: record.rollout_id.clone(),
            stack: record.stack.clone(),
            phase: record.phase,
            created_at_ms: record.created_at_ms,
            updated_at_ms: record.updated_at_ms,
            previous_revision: record.previous_revision,
            previous_generation: record.previous_generation.clone(),
            previous_state: record.previous_state,
            previous_plan_sha256: record
                .previous_plan
                .as_ref()
                .map(|plan| plan.plan_sha256.clone()),
            candidate_plan_sha256: record.candidate_plan.plan_sha256.clone(),
            activated_revision: record.activated_revision,
            activated_generation: record.activated_generation.clone(),
            rollback_revision: record.rollback_revision,
            rollback_generation: record.rollback_generation.clone(),
            health_report_sha256: record.health_report_sha256.clone(),
            checkpoint_sha256: record.record_sha256.clone(),
            status_sha256: String::new(),
        };
        value.status_sha256 = value.computed_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        let previous_valid = match (
            self.previous_revision,
            self.previous_generation.as_deref(),
            self.previous_state,
            self.previous_plan_sha256.as_deref(),
        ) {
            (None, None, None, None) => true,
            (Some(revision), Some(generation), Some(EngineStackState::Removed), None) => {
                revision > 0 && is_digest(generation)
            }
            (Some(revision), Some(generation), Some(_), Some(plan)) => {
                revision > 0 && is_digest(generation) && is_digest(plan)
            }
            _ => false,
        };
        if self.format_version != ENGINE_ROLLOUT_FORMAT_VERSION
            || !valid_name(&self.stack)
            || !previous_valid
            || !is_digest(&self.candidate_plan_sha256)
            || !is_digest(&self.checkpoint_sha256)
            || !is_digest(&self.status_sha256)
            || self.created_at_ms == 0
            || self.updated_at_ms < self.created_at_ms
            || self.rollout_id
                != rollout_id(
                    &self.stack,
                    self.created_at_ms,
                    self.previous_revision,
                    self.previous_generation.as_deref(),
                    &self.candidate_plan_sha256,
                )?
            || !valid_phase_fields(
                self.phase,
                self.previous_revision,
                self.activated_revision,
                self.activated_generation.as_deref(),
                self.rollback_revision,
                self.rollback_generation.as_deref(),
                self.health_report_sha256.as_deref(),
            )
            || self.computed_sha256()? != self.status_sha256
        {
            return Err("engine rollout status is invalid".into());
        }
        Ok(())
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.status_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

fn rollout_id(
    stack: &str,
    created_at_ms: u64,
    previous_revision: Option<u64>,
    previous_generation: Option<&str>,
    candidate_plan_sha256: &str,
) -> Result<String, String> {
    let identity = serde_json::to_vec(&(
        ENGINE_ROLLOUT_FORMAT_VERSION,
        stack,
        created_at_ms,
        previous_revision,
        previous_generation,
        candidate_plan_sha256,
    ))
    .map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(identity)))
}

fn valid_phase_fields(
    phase: RolloutPhase,
    previous_revision: Option<u64>,
    activated_revision: Option<u64>,
    activated_generation: Option<&str>,
    rollback_revision: Option<u64>,
    rollback_generation: Option<&str>,
    health_report_sha256: Option<&str>,
) -> bool {
    let activation_valid = activated_revision.is_some_and(|value| value > 0)
        && activated_generation.is_some_and(is_digest);
    let rollback_valid = rollback_revision.is_some_and(|value| value > 0)
        && rollback_generation.is_some_and(is_digest);
    let activation_absent = activated_revision.is_none() && activated_generation.is_none();
    let rollback_absent = rollback_revision.is_none() && rollback_generation.is_none();
    let health_valid = health_report_sha256.is_some_and(is_digest);
    let phase_valid = match phase {
        RolloutPhase::Prepared | RolloutPhase::Cancelled => {
            activation_absent && rollback_absent && health_report_sha256.is_none()
        }
        RolloutPhase::Activated => {
            activation_valid && rollback_absent && health_report_sha256.is_none()
        }
        RolloutPhase::Committed => activation_valid && rollback_absent && health_valid,
        RolloutPhase::RolledBack => {
            activation_valid && rollback_valid && health_report_sha256.is_none_or(is_digest)
        }
    };
    let activation_revision_valid = activated_revision.is_none_or(|activated| {
        activated == previous_revision.map_or(1, |revision| revision.saturating_add(1))
    });
    let rollback_revision_valid = match (activated_revision, rollback_revision) {
        (Some(activated), Some(rollback)) => rollback == activated.saturating_add(1),
        (_, None) => true,
        (None, Some(_)) => false,
    };
    phase_valid && activation_revision_valid && rollback_revision_valid
}

impl EngineStore {
    pub fn rollout(&self, stack: &str) -> Result<Option<RolloutRecord>, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        let path = self.rollout_path(stack)?;
        recover_rollout_file(&path)?;
        if !path.exists() {
            return Ok(None);
        }
        let mut record = read_rollout_file(&path)?;
        if record.stack != stack {
            return Err("engine rollout belongs to another stack".into());
        }
        if self.recover_rollout_checkpoint(&mut record)? {
            write_rollout_file(&path, &record)?;
        }
        Ok(Some(record))
    }

    pub fn prepare_rollout(
        &self,
        plan: &StackPlan,
        allow_insecure: bool,
        now_ms: u64,
    ) -> Result<RolloutRecord, String> {
        plan.validate()?;
        if plan.security.sandbox == SandboxPolicy::Disabled && !allow_insecure {
            return Err(
                "sandbox-disabled rollouts require an explicit insecure confirmation".into(),
            );
        }
        if let Some(current) = self.rollout(&plan.stack)? {
            if current.active() {
                if current.phase == RolloutPhase::Prepared
                    && current.candidate_plan.plan_sha256 == plan.plan_sha256
                {
                    return Ok(current);
                }
                return Err("stack already has an active rollout".into());
            }
            if current.phase == RolloutPhase::Committed
                && current.candidate_plan.plan_sha256 == plan.plan_sha256
                && ensure_matches_activation(&current, self.latest(&plan.stack)?.as_ref()).is_ok()
            {
                return Ok(current);
            }
            self.archive_rollout(&current)?;
        }
        let previous = self.latest(&plan.stack)?;
        if previous.is_none() && self.list()?.len() >= MAX_ENGINE_STACKS {
            return Err("engine stack limit reached".into());
        }
        if previous.as_ref().is_some_and(|event| {
            event.kind == EngineEventKind::Apply
                && event
                    .plan
                    .as_ref()
                    .is_some_and(|current| current.plan_sha256 == plan.plan_sha256)
        }) {
            return Err("candidate plan is already the desired generation".into());
        }
        let record = RolloutRecord::new(plan.clone(), previous.as_ref(), now_ms)?;
        write_rollout_file(&self.rollout_path(&plan.stack)?, &record)?;
        Ok(record)
    }

    pub fn activate_rollout(
        &self,
        stack: &str,
        rollout_id: &str,
        now_ms: u64,
    ) -> Result<RolloutRecord, String> {
        let mut record = self.require_rollout(stack, rollout_id)?;
        if record.phase == RolloutPhase::Activated {
            return Ok(record);
        }
        if record.phase != RolloutPhase::Prepared {
            return Err("rollout is not prepared for activation".into());
        }
        ensure_time_advances(&record, now_ms)?;
        let previous = self.latest(stack)?;
        ensure_matches_previous(&record, previous.as_ref())?;
        let event = next_event(
            previous.as_ref(),
            EngineEventKind::Apply,
            Some(record.candidate_plan.clone()),
        )?;
        self.append(&event)?;
        record.phase = RolloutPhase::Activated;
        record.updated_at_ms = now_ms;
        record.activated_revision = Some(event.revision);
        record.activated_generation = Some(event.event_sha256);
        record.refresh()?;
        write_rollout_file(&self.rollout_path(stack)?, &record)?;
        Ok(record)
    }

    pub fn commit_rollout(
        &self,
        stack: &str,
        rollout_id: &str,
        now_ms: u64,
    ) -> Result<RolloutRecord, String> {
        let mut record = self.require_rollout(stack, rollout_id)?;
        if record.phase == RolloutPhase::Committed {
            return Ok(record);
        }
        if record.phase != RolloutPhase::Activated {
            return Err("rollout is not active and cannot be committed".into());
        }
        ensure_time_advances(&record, now_ms)?;
        ensure_matches_activation(&record, self.latest(stack)?.as_ref())?;
        let health = self.health(stack, now_ms)?;
        let stopped_candidate = health.state == StackHealthState::Stopped
            && health.desired_replicas == 0
            && record
                .candidate_plan
                .instances
                .iter()
                .all(|instance| instance.desired == super::DesiredState::Stopped);
        if !health.ready() && !stopped_candidate {
            return Err(format!(
                "rollout cannot commit while stack health is {:?}",
                health.state
            ));
        }
        if health.state == StackHealthState::Healthy {
            let runtime = self
                .runtime_status(stack)?
                .ok_or_else(|| "rollout has no observed runtime state".to_string())?;
            let stable = runtime.replicas.iter().all(|replica| match replica.phase {
                super::ReplicaPhase::Running => replica.started_at_ms.is_some_and(|started| {
                    now_ms.saturating_sub(started) >= ROLLOUT_STABILITY_WINDOW_MS
                }),
                super::ReplicaPhase::Succeeded | super::ReplicaPhase::Stopped => true,
                _ => false,
            });
            if !stable {
                return Err("rollout stability window has not elapsed".into());
            }
        }
        record.phase = RolloutPhase::Committed;
        record.updated_at_ms = now_ms;
        record.health_report_sha256 = Some(health.report_sha256);
        record.refresh()?;
        write_rollout_file(&self.rollout_path(stack)?, &record)?;
        Ok(record)
    }

    pub fn rollback_rollout(
        &self,
        stack: &str,
        rollout_id: &str,
        now_ms: u64,
    ) -> Result<RolloutRecord, String> {
        let mut record = self.require_rollout(stack, rollout_id)?;
        if matches!(
            record.phase,
            RolloutPhase::Cancelled | RolloutPhase::RolledBack
        ) {
            return Ok(record);
        }
        ensure_time_advances(&record, now_ms)?;
        if record.phase == RolloutPhase::Prepared {
            ensure_matches_previous(&record, self.latest(stack)?.as_ref())?;
            record.phase = RolloutPhase::Cancelled;
            record.updated_at_ms = now_ms;
            record.refresh()?;
            write_rollout_file(&self.rollout_path(stack)?, &record)?;
            return Ok(record);
        }
        if !matches!(
            record.phase,
            RolloutPhase::Activated | RolloutPhase::Committed
        ) {
            return Err("rollout cannot be rolled back from its current phase".into());
        }
        let current = self.latest(stack)?;
        ensure_matches_activation(&record, current.as_ref())?;
        let (kind, plan) = rollback_target(&record)?;
        let event = next_event(current.as_ref(), kind, plan)?;
        self.append(&event)?;
        record.phase = RolloutPhase::RolledBack;
        record.updated_at_ms = now_ms;
        record.rollback_revision = Some(event.revision);
        record.rollback_generation = Some(event.event_sha256);
        record.refresh()?;
        write_rollout_file(&self.rollout_path(stack)?, &record)?;
        Ok(record)
    }

    pub(super) fn ensure_no_active_rollout(&self, stack: &str) -> Result<(), String> {
        if self.rollout(stack)?.is_some_and(|record| record.active()) {
            return Err("stack has an active rollout; commit or roll it back first".into());
        }
        Ok(())
    }

    fn require_rollout(&self, stack: &str, rollout_id: &str) -> Result<RolloutRecord, String> {
        if !is_digest(rollout_id) {
            return Err("rollout identity is invalid".into());
        }
        let record = self
            .rollout(stack)?
            .ok_or_else(|| "stack has no rollout checkpoint".to_string())?;
        if record.rollout_id != rollout_id {
            return Err("rollout identity does not match the current checkpoint".into());
        }
        Ok(record)
    }

    fn recover_rollout_checkpoint(&self, record: &mut RolloutRecord) -> Result<bool, String> {
        let current = self.latest(&record.stack)?;
        match record.phase {
            RolloutPhase::Prepared if matches_candidate(record, current.as_ref()) => {
                let event =
                    current.ok_or_else(|| "activated rollout event is missing".to_string())?;
                record.phase = RolloutPhase::Activated;
                record.updated_at_ms = record.updated_at_ms.max(event.created_at_ms);
                record.activated_revision = Some(event.revision);
                record.activated_generation = Some(event.event_sha256);
                record.refresh()?;
                Ok(true)
            }
            RolloutPhase::Prepared => {
                ensure_matches_previous(record, current.as_ref())?;
                Ok(false)
            }
            RolloutPhase::Activated if matches_rollback(record, current.as_ref()) => {
                let event = current.ok_or_else(|| "rollback event is missing".to_string())?;
                record.phase = RolloutPhase::RolledBack;
                record.updated_at_ms = record.updated_at_ms.max(event.created_at_ms);
                record.rollback_revision = Some(event.revision);
                record.rollback_generation = Some(event.event_sha256);
                record.refresh()?;
                Ok(true)
            }
            RolloutPhase::Activated => {
                ensure_matches_activation(record, current.as_ref())?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn rollout_path(&self, stack: &str) -> Result<PathBuf, String> {
        if !valid_name(stack) {
            return Err("stack name is invalid".into());
        }
        Ok(self
            .root
            .join("stacks")
            .join(stack)
            .join(CURRENT_ROLLOUT_FILE))
    }

    fn archive_rollout(&self, record: &RolloutRecord) -> Result<(), String> {
        if !record.terminal() {
            return Err("active rollout cannot be archived".into());
        }
        let directory = self
            .root
            .join("stacks")
            .join(&record.stack)
            .join("rollouts");
        ensure_directory(&directory)?;
        let mut count = 0_usize;
        let mut total_bytes = 0_u64;
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "rollout archive name is not UTF-8".to_string())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if let Some(identity) = name.strip_suffix(".json")
                && is_digest(identity)
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_ROLLOUT_BYTES
            {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| "rollout archive count overflow".to_string())?;
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| "rollout archive byte count overflow".to_string())?;
            } else if !(name.starts_with(".engine-event-") && exact_suffix(&name, ".tmp")) {
                return Err("rollout archive contains an unexpected entry".into());
            }
        }
        let path = directory.join(format!("{}.json", record.rollout_id));
        if path.exists() {
            if read_rollout_file(&path)? != *record {
                return Err("rollout archive identity collision".into());
            }
            return Ok(());
        }
        let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
        if count >= MAX_ROLLOUT_HISTORY
            || total_bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|value| value > MAX_ROLLOUT_HISTORY_BYTES)
        {
            return Err("rollout history limit reached".into());
        }
        write_new_atomic(&path, &bytes)
    }
}

fn rollback_target(record: &RolloutRecord) -> Result<(EngineEventKind, Option<StackPlan>), String> {
    match record.previous_state {
        Some(EngineStackState::Applied) => Ok((
            EngineEventKind::Apply,
            Some(
                record
                    .previous_plan
                    .clone()
                    .ok_or_else(|| "rollback plan is missing".to_string())?,
            ),
        )),
        Some(EngineStackState::Stopped) => Ok((
            EngineEventKind::Stop,
            Some(
                record
                    .previous_plan
                    .clone()
                    .ok_or_else(|| "rollback plan is missing".to_string())?,
            ),
        )),
        Some(EngineStackState::Removed) | None => Ok((EngineEventKind::Remove, None)),
    }
}

fn ensure_time_advances(record: &RolloutRecord, now_ms: u64) -> Result<(), String> {
    if now_ms == 0 || now_ms < record.updated_at_ms {
        return Err("rollout timestamp cannot move backwards".into());
    }
    Ok(())
}

fn ensure_matches_previous(
    record: &RolloutRecord,
    current: Option<&EngineEvent>,
) -> Result<(), String> {
    let valid = match (record.previous_revision, current) {
        (None, None) => true,
        (Some(revision), Some(event)) => {
            event.revision == revision
                && record.previous_generation.as_deref() == Some(event.event_sha256.as_str())
                && record.previous_state == Some(event.status().state)
                && record
                    .previous_plan
                    .as_ref()
                    .map(|plan| plan.plan_sha256.as_str())
                    == event.plan.as_ref().map(|plan| plan.plan_sha256.as_str())
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("desired state changed after rollout preparation".into())
    }
}

fn ensure_matches_activation(
    record: &RolloutRecord,
    current: Option<&EngineEvent>,
) -> Result<(), String> {
    if matches_candidate(record, current)
        && current.is_some_and(|event| {
            Some(event.revision) == record.activated_revision
                && Some(event.event_sha256.as_str()) == record.activated_generation.as_deref()
        })
    {
        Ok(())
    } else {
        Err("desired state no longer matches the activated rollout".into())
    }
}

fn matches_candidate(record: &RolloutRecord, current: Option<&EngineEvent>) -> bool {
    current.is_some_and(|event| {
        event.kind == EngineEventKind::Apply
            && event
                .plan
                .as_ref()
                .is_some_and(|plan| plan.plan_sha256 == record.candidate_plan.plan_sha256)
            && event.previous_event_sha256
                == record.previous_generation.as_deref().unwrap_or_default()
    })
}

fn matches_rollback(record: &RolloutRecord, current: Option<&EngineEvent>) -> bool {
    let Some(event) = current else {
        return false;
    };
    if event.previous_event_sha256 != record.activated_generation.as_deref().unwrap_or_default() {
        return false;
    }
    match record.previous_state {
        Some(EngineStackState::Applied) => {
            event.kind == EngineEventKind::Apply
                && event.plan.as_ref().map(|plan| plan.plan_sha256.as_str())
                    == record
                        .previous_plan
                        .as_ref()
                        .map(|plan| plan.plan_sha256.as_str())
        }
        Some(EngineStackState::Stopped) => {
            event.kind == EngineEventKind::Stop
                && event.plan.as_ref().map(|plan| plan.plan_sha256.as_str())
                    == record
                        .previous_plan
                        .as_ref()
                        .map(|plan| plan.plan_sha256.as_str())
        }
        Some(EngineStackState::Removed) | None => event.kind == EngineEventKind::Remove,
    }
}

fn write_rollout_file(path: &Path, record: &RolloutRecord) -> Result<(), String> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ROLLOUT_BYTES {
        return Err("engine rollout exceeds its byte limit".into());
    }
    write_replace_atomic(path, &bytes)
}

fn read_rollout_file(path: &Path) -> Result<RolloutRecord, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ROLLOUT_BYTES
    {
        return Err("engine rollout must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_ROLLOUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_ROLLOUT_BYTES {
        return Err("engine rollout exceeded its byte limit while reading".into());
    }
    let record: RolloutRecord =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    record.validate()?;
    Ok(record)
}

fn recover_rollout_file(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    if backup.exists() && !is_regular_file(&backup) {
        return Err("engine rollout backup is not a regular file".into());
    }
    if path.exists() && !is_regular_file(path) {
        return Err("engine rollout path is not a regular file".into());
    }
    if !path.exists() && backup.exists() {
        read_rollout_file(&backup)?;
        fs::rename(&backup, path).map_err(|error| error.to_string())?;
    } else if path.exists() && backup.exists() {
        read_rollout_file(path)?;
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cartridge_core::{CompositionLock, LockedPackage, ResolutionPlan, RuntimeLimits};

    use super::*;
    use crate::{DesiredState, PlannedInstance, PlannedSecurity, RestartPolicy, SecurityProfile};

    fn plan(stack: &str, package: char) -> StackPlan {
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
                package_bytes: 1,
                replicas: 1,
                desired: DesiredState::Running,
                restart: RestartPolicy::OnFailure,
                max_restarts: 3,
                requested: BTreeSet::new(),
                granted: BTreeSet::new(),
                blocked: BTreeSet::new(),
                allowed: BTreeSet::new(),
                denied: BTreeSet::new(),
                args: Vec::new(),
                secrets: BTreeSet::new(),
                limits: RuntimeLimits::default(),
                composition: CompositionLock::new(
                    LockedPackage {
                        cartridge_id: "dev.test.app".into(),
                        version: "1.0.0".into(),
                        package_sha256: digest,
                        package_bytes: 1,
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

    #[test]
    fn rollout_requires_health_before_commit_and_can_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let old = plan("demo", '1');
        let new = plan("demo", '2');
        engine.apply(&old, false).unwrap();

        let prepared = engine.prepare_rollout(&new, false, 10).unwrap();
        assert_eq!(prepared.phase, RolloutPhase::Prepared);
        assert!(engine.apply(&new, false).is_err());
        let activated = engine
            .activate_rollout("demo", &prepared.rollout_id, 11)
            .unwrap();
        assert_eq!(activated.phase, RolloutPhase::Activated);
        assert!(
            engine
                .commit_rollout("demo", &prepared.rollout_id, 12)
                .is_err()
        );

        let rolled_back = engine
            .rollback_rollout("demo", &prepared.rollout_id, 13)
            .unwrap();
        assert_eq!(rolled_back.phase, RolloutPhase::RolledBack);
        assert_eq!(
            engine.desired_plan("demo").unwrap().unwrap().2.plan_sha256,
            old.plan_sha256
        );
    }

    #[test]
    fn prepared_rollout_can_be_cancelled_without_changing_desired_state() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let candidate = plan("new-stack", '3');
        let prepared = engine.prepare_rollout(&candidate, false, 20).unwrap();
        let cancelled = engine
            .rollback_rollout("new-stack", &prepared.rollout_id, 21)
            .unwrap();

        assert_eq!(cancelled.phase, RolloutPhase::Cancelled);
        assert!(engine.events("new-stack").unwrap().is_empty());
    }

    #[test]
    fn activated_rollout_commits_only_checksum_bound_ready_health() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let candidate = plan("demo", '4');
        let prepared = engine.prepare_rollout(&candidate, false, 30).unwrap();
        let activated = engine
            .activate_rollout("demo", &prepared.rollout_id, 31)
            .unwrap();
        let mut runtime = crate::StackRuntimeStatus::from_plan(
            &candidate,
            activated.activated_revision.unwrap(),
            activated.activated_generation.as_deref().unwrap(),
            32,
        )
        .unwrap();
        let id = runtime.replicas[0].id.clone();
        runtime.begin_start(&id, &"9".repeat(64), 32).unwrap();
        runtime.mark_running(&id, &"9".repeat(64), 32).unwrap();
        engine.save_runtime_status(&runtime).unwrap();

        assert!(
            engine
                .commit_rollout("demo", &prepared.rollout_id, 33)
                .unwrap_err()
                .contains("stability window")
        );
        let committed = engine
            .commit_rollout(
                "demo",
                &prepared.rollout_id,
                32 + ROLLOUT_STABILITY_WINDOW_MS,
            )
            .unwrap();
        assert_eq!(committed.phase, RolloutPhase::Committed);
        assert!(committed.health_report_sha256.is_some());
        let repeated = engine
            .prepare_rollout(&candidate, false, 32 + ROLLOUT_STABILITY_WINDOW_MS + 1)
            .unwrap();
        assert_eq!(repeated.rollout_id, committed.rollout_id);
        let reverted = engine
            .rollback_rollout(
                "demo",
                &prepared.rollout_id,
                32 + ROLLOUT_STABILITY_WINDOW_MS + 2,
            )
            .unwrap();
        assert_eq!(reverted.phase, RolloutPhase::RolledBack);
        assert_eq!(
            reverted.health_report_sha256,
            committed.health_report_sha256
        );
    }

    #[test]
    fn rollout_recovers_crashes_between_journal_and_checkpoint_writes() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let old = plan("demo", '5');
        let candidate = plan("demo", '6');
        engine.apply(&old, false).unwrap();
        let prepared = engine.prepare_rollout(&candidate, false, 40).unwrap();

        let previous = engine.latest("demo").unwrap();
        let activation =
            next_event(previous.as_ref(), EngineEventKind::Apply, Some(candidate)).unwrap();
        engine.append(&activation).unwrap();
        let recovered = engine.rollout("demo").unwrap().unwrap();
        assert_eq!(recovered.phase, RolloutPhase::Activated);
        assert_eq!(
            recovered.activated_generation.as_deref(),
            Some(activation.event_sha256.as_str())
        );

        let (kind, plan) = rollback_target(&recovered).unwrap();
        let rollback = next_event(Some(&activation), kind, plan).unwrap();
        engine.append(&rollback).unwrap();
        let recovered = engine.rollout("demo").unwrap().unwrap();
        assert_eq!(recovered.phase, RolloutPhase::RolledBack);
        assert_eq!(
            recovered.rollback_generation.as_deref(),
            Some(rollback.event_sha256.as_str())
        );
        assert_eq!(recovered.rollout_id, prepared.rollout_id);
    }

    #[test]
    fn changed_rollout_checkpoint_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let candidate = plan("demo", '7');
        engine.prepare_rollout(&candidate, false, 50).unwrap();
        let path = directory.path().join("stacks/demo/rollout.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["updated_at_ms"] = serde_json::json!(51);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(engine.rollout("demo").is_err());
        assert!(engine.apply(&candidate, false).is_err());
    }

    #[test]
    fn daemon_rollout_status_is_small_strict_and_plan_free() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let candidate = plan("demo", '8');
        let record = engine.prepare_rollout(&candidate, false, 60).unwrap();
        let status = RolloutStatus::from_record(&record).unwrap();
        let encoded = serde_json::to_vec(&status).unwrap();

        assert!(encoded.len() < 4096);
        assert!(!String::from_utf8_lossy(&encoded).contains("candidate_plan\""));
        let mut changed = status;
        changed.phase = RolloutPhase::Committed;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn intentionally_stopped_candidate_can_commit_without_a_worker() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let mut candidate = plan("demo", '9');
        candidate.instances[0].desired = DesiredState::Stopped;
        candidate.plan_sha256.clear();
        candidate.plan_sha256 = candidate.computed_sha256().unwrap();
        let prepared = engine.prepare_rollout(&candidate, false, 70).unwrap();
        engine
            .activate_rollout("demo", &prepared.rollout_id, 71)
            .unwrap();

        let committed = engine
            .commit_rollout("demo", &prepared.rollout_id, 72)
            .unwrap();
        assert_eq!(committed.phase, RolloutPhase::Committed);
    }

    #[test]
    fn terminal_rollout_history_stops_at_its_entry_ceiling() {
        let directory = tempfile::tempdir().unwrap();
        let engine = EngineStore::open(directory.path()).unwrap();
        let first = plan("demo", 'a');
        let prepared = engine.prepare_rollout(&first, false, 80).unwrap();
        engine
            .rollback_rollout("demo", &prepared.rollout_id, 81)
            .unwrap();
        let archive = directory.path().join("stacks/demo/rollouts");
        fs::create_dir(&archive).unwrap();
        for index in 0..MAX_ROLLOUT_HISTORY {
            fs::write(archive.join(format!("{index:064x}.json")), []).unwrap();
        }

        let error = engine
            .prepare_rollout(&plan("demo", 'b'), false, 82)
            .unwrap_err();
        assert!(error.contains("history limit"));
    }
}

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    DesiredState, MAX_STACK_RESTARTS, MAX_STACK_TOTAL_REPLICAS, RestartPolicy, StackPlan,
    is_digest, valid_name, valid_text,
};

pub const SUPERVISOR_STATUS_FORMAT_VERSION: u32 = 1;
pub const MAX_RESTART_BACKOFF_MS: u64 = 30_000;
const MIN_RESTART_BACKOFF_MS: u64 = 250;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaId {
    pub instance: String,
    pub ordinal: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplicaPhase {
    Pending,
    Starting,
    Running,
    Backoff,
    Succeeded,
    Failed,
    Exhausted,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaRuntime {
    pub id: ReplicaId,
    pub desired: DesiredState,
    pub restart: RestartPolicy,
    pub max_restarts: u16,
    pub attempt: u16,
    pub phase: ReplicaPhase,
    pub run_id: Option<String>,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub next_start_at_ms: Option<u64>,
    pub last_exit_code: Option<i32>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackRuntimeStatus {
    pub format_version: u32,
    pub stack: String,
    pub revision: u64,
    pub generation: String,
    pub observed_at_ms: u64,
    pub replicas: Vec<ReplicaRuntime>,
    pub status_sha256: String,
}

impl StackRuntimeStatus {
    pub fn from_plan(
        plan: &StackPlan,
        revision: u64,
        generation: &str,
        now_ms: u64,
    ) -> Result<Self, String> {
        plan.validate()?;
        if revision == 0 || !is_digest(generation) || now_ms == 0 {
            return Err("runtime generation identity is invalid".into());
        }
        let mut replicas = Vec::new();
        for instance in &plan.instances {
            for ordinal in 1..=instance.replicas {
                replicas.push(ReplicaRuntime {
                    id: ReplicaId {
                        instance: instance.name.clone(),
                        ordinal,
                    },
                    desired: instance.desired,
                    restart: instance.restart,
                    max_restarts: instance.max_restarts,
                    attempt: 0,
                    phase: if instance.desired == DesiredState::Running {
                        ReplicaPhase::Pending
                    } else {
                        ReplicaPhase::Stopped
                    },
                    run_id: None,
                    started_at_ms: None,
                    finished_at_ms: None,
                    next_start_at_ms: None,
                    last_exit_code: None,
                    detail: None,
                });
            }
        }
        let mut value = Self {
            format_version: SUPERVISOR_STATUS_FORMAT_VERSION,
            stack: plan.stack.clone(),
            revision,
            generation: generation.into(),
            observed_at_ms: now_ms,
            replicas,
            status_sha256: String::new(),
        };
        value.refresh()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != SUPERVISOR_STATUS_FORMAT_VERSION
            || !valid_name(&self.stack)
            || self.revision == 0
            || !is_digest(&self.generation)
            || self.observed_at_ms == 0
            || self.replicas.len() > usize::from(MAX_STACK_TOTAL_REPLICAS)
            || !is_digest(&self.status_sha256)
            || self.computed_sha256()? != self.status_sha256
        {
            return Err("runtime status identity is invalid".into());
        }
        let mut ids = BTreeSet::new();
        let mut previous = None;
        for replica in &self.replicas {
            validate_replica(replica)?;
            if previous.as_ref().is_some_and(|value| value >= &replica.id)
                || !ids.insert(replica.id.clone())
            {
                return Err("runtime replicas are not strictly sorted".into());
            }
            previous = Some(replica.id.clone());
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        plan: &StackPlan,
        revision: u64,
        generation: &str,
    ) -> Result<(), String> {
        self.validate()?;
        let expected = Self::from_plan(plan, revision, generation, self.observed_at_ms)?;
        if self.stack != expected.stack
            || self.revision != revision
            || self.generation != generation
            || self.replicas.len() != expected.replicas.len()
            || self
                .replicas
                .iter()
                .zip(&expected.replicas)
                .any(|(actual, expected)| {
                    actual.id != expected.id
                        || actual.desired != expected.desired
                        || actual.restart != expected.restart
                        || actual.max_restarts != expected.max_restarts
                })
        {
            return Err("runtime status does not match the desired generation".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn eligible_starts(&self, now_ms: u64) -> Vec<ReplicaId> {
        self.replicas
            .iter()
            .filter(|replica| {
                replica.desired == DesiredState::Running
                    && match replica.phase {
                        ReplicaPhase::Pending => true,
                        ReplicaPhase::Backoff => replica
                            .next_start_at_ms
                            .is_some_and(|deadline| deadline <= now_ms),
                        _ => false,
                    }
            })
            .map(|replica| replica.id.clone())
            .collect()
    }

    pub fn begin_start(
        &mut self,
        id: &ReplicaId,
        run_id: &str,
        now_ms: u64,
    ) -> Result<u16, String> {
        if !is_digest(run_id) || now_ms < self.observed_at_ms {
            return Err("replica run identity is invalid".into());
        }
        let replica = self.replica_mut(id)?;
        let eligible = match replica.phase {
            ReplicaPhase::Pending => true,
            ReplicaPhase::Backoff => replica
                .next_start_at_ms
                .is_some_and(|deadline| deadline <= now_ms),
            _ => false,
        };
        if !eligible || replica.desired != DesiredState::Running {
            return Err("replica is not eligible to start".into());
        }
        let attempt = replica
            .attempt
            .checked_add(1)
            .ok_or_else(|| "replica attempt counter overflow".to_string())?;
        if attempt > replica.max_restarts + 1 {
            return Err("replica restart budget is exhausted".into());
        }
        replica.attempt = attempt;
        replica.phase = ReplicaPhase::Starting;
        replica.run_id = Some(run_id.into());
        replica.started_at_ms = Some(now_ms);
        replica.finished_at_ms = None;
        replica.next_start_at_ms = None;
        replica.last_exit_code = None;
        replica.detail = None;
        self.observed_at_ms = now_ms;
        self.refresh()?;
        Ok(attempt)
    }

    pub fn mark_running(
        &mut self,
        id: &ReplicaId,
        run_id: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        if now_ms < self.observed_at_ms {
            return Err("runtime observation time cannot move backwards".into());
        }
        let replica = self.replica_mut(id)?;
        if replica.phase != ReplicaPhase::Starting || replica.run_id.as_deref() != Some(run_id) {
            return Err("stale or unexpected replica start acknowledgement".into());
        }
        replica.phase = ReplicaPhase::Running;
        self.observed_at_ms = now_ms;
        self.refresh()
    }

    pub fn mark_exit(
        &mut self,
        id: &ReplicaId,
        run_id: &str,
        success: bool,
        exit_code: Option<i32>,
        detail: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        if !valid_text(detail, 512, false) || now_ms < self.observed_at_ms {
            return Err("replica exit detail is invalid".into());
        }
        let replica = self.replica_mut(id)?;
        if !matches!(
            replica.phase,
            ReplicaPhase::Starting | ReplicaPhase::Running
        ) || replica.run_id.as_deref() != Some(run_id)
        {
            return Err("stale or unexpected replica exit".into());
        }
        finish_replica(replica, success, exit_code, detail, now_ms);
        self.observed_at_ms = now_ms;
        self.refresh()
    }

    pub fn recover_interrupted(&mut self, now_ms: u64) -> Result<usize, String> {
        if now_ms < self.observed_at_ms {
            return Err("runtime observation time cannot move backwards".into());
        }
        let mut recovered = 0;
        for replica in &mut self.replicas {
            if matches!(
                replica.phase,
                ReplicaPhase::Starting | ReplicaPhase::Running
            ) {
                finish_replica(
                    replica,
                    false,
                    None,
                    "previous supervisor exited before the worker",
                    now_ms,
                );
                recovered += 1;
            }
        }
        if recovered > 0 {
            self.observed_at_ms = now_ms;
            self.refresh()?;
        }
        Ok(recovered)
    }

    fn replica_mut(&mut self, id: &ReplicaId) -> Result<&mut ReplicaRuntime, String> {
        self.replicas
            .iter_mut()
            .find(|replica| replica.id == *id)
            .ok_or_else(|| "replica is not part of this runtime generation".into())
    }

    fn refresh(&mut self) -> Result<(), String> {
        self.status_sha256.clear();
        self.status_sha256 = self.computed_sha256()?;
        self.validate()
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.status_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

fn validate_replica(replica: &ReplicaRuntime) -> Result<(), String> {
    if !valid_name(&replica.id.instance)
        || replica.id.ordinal == 0
        || replica.max_restarts > MAX_STACK_RESTARTS
        || replica.attempt > replica.max_restarts + 1
        || replica
            .detail
            .as_ref()
            .is_some_and(|value| !valid_text(value, 512, false))
    {
        return Err("runtime replica is invalid".into());
    }
    let active = matches!(
        replica.phase,
        ReplicaPhase::Starting | ReplicaPhase::Running
    );
    let waiting = replica.phase == ReplicaPhase::Backoff;
    let pending = replica.phase == ReplicaPhase::Pending;
    let stopped = replica.phase == ReplicaPhase::Stopped;
    let terminal = matches!(
        replica.phase,
        ReplicaPhase::Succeeded | ReplicaPhase::Failed | ReplicaPhase::Exhausted
    );
    let policy_phase_is_valid = match replica.phase {
        ReplicaPhase::Backoff | ReplicaPhase::Exhausted => replica.restart != RestartPolicy::Never,
        ReplicaPhase::Succeeded => replica.restart != RestartPolicy::Always,
        ReplicaPhase::Failed => replica.restart == RestartPolicy::Never,
        _ => true,
    };
    if (active
        && (replica.attempt == 0
            || replica
                .run_id
                .as_ref()
                .is_none_or(|value| !is_digest(value))
            || replica.started_at_ms.is_none()
            || replica.finished_at_ms.is_some()
            || replica.next_start_at_ms.is_some()
            || replica.last_exit_code.is_some()
            || replica.detail.is_some()))
        || (waiting
            && (replica.attempt == 0
                || replica.run_id.is_some()
                || replica.started_at_ms.is_none()
                || replica.finished_at_ms.is_none()
                || replica.next_start_at_ms.is_none()
                || replica.detail.is_none()))
        || (pending
            && (replica.attempt != 0
                || replica.run_id.is_some()
                || replica.started_at_ms.is_some()
                || replica.finished_at_ms.is_some()
                || replica.next_start_at_ms.is_some()
                || replica.last_exit_code.is_some()
                || replica.detail.is_some()))
        || (stopped
            && (replica.desired != DesiredState::Stopped
                || replica.attempt != 0
                || replica.run_id.is_some()
                || replica.started_at_ms.is_some()
                || replica.finished_at_ms.is_some()
                || replica.next_start_at_ms.is_some()
                || replica.last_exit_code.is_some()
                || replica.detail.is_some()))
        || (replica.desired == DesiredState::Stopped && !stopped)
        || (terminal
            && (replica.attempt == 0
                || replica.started_at_ms.is_none()
                || replica.finished_at_ms.is_none()
                || replica.next_start_at_ms.is_some()
                || replica.detail.is_none()))
        || (!active && !waiting && !pending && replica.run_id.is_some())
        || !policy_phase_is_valid
        || replica
            .finished_at_ms
            .zip(replica.started_at_ms)
            .is_some_and(|(finished, started)| finished < started)
        || replica
            .next_start_at_ms
            .zip(replica.finished_at_ms)
            .is_some_and(|(next, finished)| next <= finished)
    {
        return Err("runtime replica phase fields are inconsistent".into());
    }
    Ok(())
}

fn finish_replica(
    replica: &mut ReplicaRuntime,
    success: bool,
    exit_code: Option<i32>,
    detail: &str,
    now_ms: u64,
) {
    let restart = match replica.restart {
        RestartPolicy::Never => false,
        RestartPolicy::OnFailure => !success,
        RestartPolicy::Always => true,
    };
    let restart_available = replica.attempt < replica.max_restarts + 1;
    replica.run_id = None;
    replica.finished_at_ms = Some(now_ms);
    replica.last_exit_code = exit_code;
    replica.detail = Some(detail.into());
    if restart && restart_available {
        replica.phase = ReplicaPhase::Backoff;
        replica.next_start_at_ms =
            Some(now_ms.saturating_add(restart_backoff_ms(&replica.id, replica.attempt)));
    } else {
        replica.phase = if restart {
            ReplicaPhase::Exhausted
        } else if success {
            ReplicaPhase::Succeeded
        } else {
            ReplicaPhase::Failed
        };
        replica.next_start_at_ms = None;
    }
}

fn restart_backoff_ms(id: &ReplicaId, attempt: u16) -> u64 {
    let shift = u32::from(attempt.saturating_sub(1).min(7));
    let base = MIN_RESTART_BACKOFF_MS
        .saturating_mul(1_u64 << shift)
        .min(MAX_RESTART_BACKOFF_MS);
    let mut digest = Sha256::new();
    digest.update(id.instance.as_bytes());
    digest.update(id.ordinal.to_le_bytes());
    digest.update(attempt.to_le_bytes());
    let bytes = digest.finalize();
    let jitter = u64::from(u16::from_le_bytes([bytes[0], bytes[1]])) % (base / 4 + 1);
    base.saturating_add(jitter).min(MAX_RESTART_BACKOFF_MS)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cartridge_core::{CompositionLock, LockedPackage, ResolutionPlan, RuntimeLimits};

    use super::*;
    use crate::{PlannedInstance, PlannedSecurity, SandboxPolicy, SecurityProfile};

    fn plan(policy: RestartPolicy, max_restarts: u16) -> StackPlan {
        let mut value = StackPlan {
            format_version: crate::STACK_PLAN_FORMAT_VERSION,
            stack: "demo-stack".into(),
            security: PlannedSecurity {
                profile: SecurityProfile::Strict,
                sandbox: SandboxPolicy::Required,
            },
            instances: vec![PlannedInstance {
                name: "app".into(),
                cartridge_id: "dev.test.app".into(),
                version: "1.0.0".into(),
                package_sha256: "1".repeat(64),
                package_bytes: 8,
                replicas: 1,
                desired: DesiredState::Running,
                restart: policy,
                max_restarts,
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
                        package_sha256: "1".repeat(64),
                        package_bytes: 8,
                        component_sha256: "2".repeat(64),
                        assets_root_sha256: "3".repeat(64),
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
    fn failures_back_off_and_stop_at_the_restart_budget() {
        let plan = plan(RestartPolicy::OnFailure, 2);
        let mut status = StackRuntimeStatus::from_plan(&plan, 1, &"a".repeat(64), 1).unwrap();
        let id = status.eligible_starts(1).pop().unwrap();
        for attempt in 1..=3 {
            let run_id = format!("{attempt:064x}");
            let now = u64::from(attempt) * 100_000;
            assert_eq!(status.begin_start(&id, &run_id, now).unwrap(), attempt);
            status.mark_running(&id, &run_id, now + 1).unwrap();
            status
                .mark_exit(&id, &run_id, false, Some(1), "worker failed", now + 2)
                .unwrap();
            if attempt < 3 {
                let deadline = status.replicas[0].next_start_at_ms.unwrap();
                assert!(status.eligible_starts(deadline - 1).is_empty());
                assert_eq!(status.eligible_starts(deadline), vec![id.clone()]);
            }
        }
        assert_eq!(status.replicas[0].phase, ReplicaPhase::Exhausted);
        assert!(status.eligible_starts(u64::MAX).is_empty());
    }

    #[test]
    fn stale_exits_cannot_change_a_new_run() {
        let plan = plan(RestartPolicy::Always, 2);
        let mut status = StackRuntimeStatus::from_plan(&plan, 1, &"b".repeat(64), 1).unwrap();
        let id = status.eligible_starts(1).pop().unwrap();
        let first = "1".repeat(64);
        status.begin_start(&id, &first, 2).unwrap();
        status.mark_running(&id, &first, 3).unwrap();
        status
            .mark_exit(&id, &first, true, Some(0), "done", 4)
            .unwrap();
        let deadline = status.replicas[0].next_start_at_ms.unwrap();
        let second = "2".repeat(64);
        status.begin_start(&id, &second, deadline).unwrap();
        assert!(
            status
                .mark_exit(&id, &first, false, None, "late exit", deadline + 1)
                .is_err()
        );
        assert_eq!(status.replicas[0].run_id.as_deref(), Some(second.as_str()));
    }

    #[test]
    fn recovery_consumes_restart_budget_instead_of_trusting_stale_pids() {
        let plan = plan(RestartPolicy::OnFailure, 1);
        let mut status = StackRuntimeStatus::from_plan(&plan, 1, &"c".repeat(64), 1).unwrap();
        let id = status.eligible_starts(1).pop().unwrap();
        status.begin_start(&id, &"3".repeat(64), 2).unwrap();
        status.mark_running(&id, &"3".repeat(64), 3).unwrap();
        assert_eq!(status.recover_interrupted(4).unwrap(), 1);
        assert_eq!(status.replicas[0].phase, ReplicaPhase::Backoff);
        assert!(status.replicas[0].run_id.is_none());
    }

    #[test]
    fn checksum_valid_status_cannot_contradict_restart_policy() {
        let plan = plan(RestartPolicy::Always, 1);
        let mut status = StackRuntimeStatus::from_plan(&plan, 1, &"d".repeat(64), 1).unwrap();
        let replica = &mut status.replicas[0];
        replica.attempt = 1;
        replica.phase = ReplicaPhase::Succeeded;
        replica.started_at_ms = Some(2);
        replica.finished_at_ms = Some(3);
        replica.detail = Some("forged terminal phase".into());
        status.status_sha256 = status.computed_sha256().unwrap();

        assert!(status.validate().is_err());
    }
}

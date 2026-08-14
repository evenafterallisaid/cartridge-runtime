use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    EngineStackState, MAX_STACK_INSTANCES, MAX_STACK_TOTAL_REPLICAS, ProbePhase, ReplicaPhase,
    StackRuntimeStatus, StackStatus, is_digest, valid_name,
};

pub const ENGINE_HEALTH_FORMAT_VERSION: u32 = 2;
pub const SUPERVISOR_STALE_AFTER_MS: u64 = 20_000;
pub const MAX_ENGINE_HEALTH_REPORTS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackHealthState {
    Healthy,
    Starting,
    Degraded,
    Failed,
    Completed,
    Stopped,
    Removed,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackHealthReport {
    pub format_version: u32,
    pub stack: String,
    pub revision: u64,
    pub desired_state: EngineStackState,
    pub state: StackHealthState,
    pub observed_at_ms: u64,
    pub runtime_observed_at_ms: Option<u64>,
    pub desired_replicas: u16,
    pub replicas_total: u16,
    pub pending: u16,
    pub starting: u16,
    pub running: u16,
    pub backoff: u16,
    pub succeeded: u16,
    pub failed: u16,
    pub exhausted: u16,
    pub stopped: u16,
    pub probe_waiting: u16,
    pub probe_ready: u16,
    pub probe_unhealthy: u16,
    pub report_sha256: String,
}

impl StackHealthReport {
    pub fn from_status(
        status: &StackStatus,
        runtime: Option<&StackRuntimeStatus>,
        now_ms: u64,
    ) -> Result<Self, String> {
        validate_stack_status(status)?;
        if now_ms == 0 {
            return Err("health observation time is invalid".into());
        }
        let desired_replicas = u16::try_from(status.desired_replicas)
            .map_err(|_| "desired replica count overflow".to_string())?;
        let mut report = Self {
            format_version: ENGINE_HEALTH_FORMAT_VERSION,
            stack: status.stack.clone(),
            revision: status.revision,
            desired_state: status.state,
            state: match status.state {
                EngineStackState::Applied if desired_replicas == 0 => StackHealthState::Stopped,
                EngineStackState::Applied => StackHealthState::Starting,
                EngineStackState::Stopped => StackHealthState::Stopped,
                EngineStackState::Removed => StackHealthState::Removed,
            },
            observed_at_ms: now_ms,
            runtime_observed_at_ms: runtime.map(|value| value.observed_at_ms),
            desired_replicas,
            replicas_total: 0,
            pending: 0,
            starting: 0,
            running: 0,
            backoff: 0,
            succeeded: 0,
            failed: 0,
            exhausted: 0,
            stopped: 0,
            probe_waiting: 0,
            probe_ready: 0,
            probe_unhealthy: 0,
            report_sha256: String::new(),
        };
        if let Some(runtime) = runtime {
            runtime.validate()?;
            if runtime.stack != status.stack
                || runtime.revision != status.revision
                || runtime.generation != status.event_sha256
            {
                return Err("runtime health belongs to another desired generation".into());
            }
            report.replicas_total = u16::try_from(runtime.replicas.len())
                .map_err(|_| "runtime replica count overflow".to_string())?;
            for replica in &runtime.replicas {
                let count = match replica.phase {
                    ReplicaPhase::Pending => &mut report.pending,
                    ReplicaPhase::Starting => &mut report.starting,
                    ReplicaPhase::Running => &mut report.running,
                    ReplicaPhase::Backoff => &mut report.backoff,
                    ReplicaPhase::Succeeded => &mut report.succeeded,
                    ReplicaPhase::Failed => &mut report.failed,
                    ReplicaPhase::Exhausted => &mut report.exhausted,
                    ReplicaPhase::Stopped => &mut report.stopped,
                };
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| "health replica count overflow".to_string())?;
                if let Some(probe) = &replica.probe {
                    let count = match probe.phase {
                        ProbePhase::Waiting => &mut report.probe_waiting,
                        ProbePhase::Ready => &mut report.probe_ready,
                        ProbePhase::Unhealthy => &mut report.probe_unhealthy,
                    };
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| "health probe count overflow".to_string())?;
                }
            }
            if status.state == EngineStackState::Applied && desired_replicas > 0 {
                report.state = report.derived_applied_state(now_ms, runtime.observed_at_ms);
            }
        }
        report.refresh()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), String> {
        let total = self
            .pending
            .checked_add(self.starting)
            .and_then(|value| value.checked_add(self.running))
            .and_then(|value| value.checked_add(self.backoff))
            .and_then(|value| value.checked_add(self.succeeded))
            .and_then(|value| value.checked_add(self.failed))
            .and_then(|value| value.checked_add(self.exhausted))
            .and_then(|value| value.checked_add(self.stopped))
            .ok_or_else(|| "health replica count overflow".to_string())?;
        let probed = self
            .probe_waiting
            .checked_add(self.probe_ready)
            .and_then(|value| value.checked_add(self.probe_unhealthy))
            .ok_or_else(|| "health probe count overflow".to_string())?;
        if self.format_version != ENGINE_HEALTH_FORMAT_VERSION
            || !valid_name(&self.stack)
            || self.revision == 0
            || self.observed_at_ms == 0
            || self.desired_replicas > MAX_STACK_TOTAL_REPLICAS
            || self.replicas_total > MAX_STACK_TOTAL_REPLICAS
            || total != self.replicas_total
            || probed > self.replicas_total
            || self
                .runtime_observed_at_ms
                .is_some_and(|value| value == 0 || value > self.observed_at_ms)
            || !is_digest(&self.report_sha256)
            || self.computed_sha256()? != self.report_sha256
            || !self.state_matches_counts()
        {
            return Err("stack health report is invalid".into());
        }
        Ok(())
    }

    #[must_use]
    pub const fn ready(&self) -> bool {
        matches!(
            self.state,
            StackHealthState::Healthy | StackHealthState::Completed
        )
    }

    #[must_use]
    pub const fn terminal_failure(&self) -> bool {
        matches!(
            self.state,
            StackHealthState::Degraded | StackHealthState::Failed
        )
    }

    fn derived_applied_state(&self, now_ms: u64, runtime_observed_at_ms: u64) -> StackHealthState {
        let waiting = self.pending + self.starting + self.backoff;
        let failures = self.failed + self.exhausted;
        let successful = self.running + self.succeeded;
        let live = self.running > 0 || waiting > 0;
        if live && now_ms.saturating_sub(runtime_observed_at_ms) > SUPERVISOR_STALE_AFTER_MS {
            StackHealthState::Stale
        } else if self.probe_unhealthy > 0 {
            StackHealthState::Degraded
        } else if failures > 0 {
            if successful > 0 || waiting > 0 {
                StackHealthState::Degraded
            } else {
                StackHealthState::Failed
            }
        } else if waiting > 0 || successful < self.desired_replicas {
            StackHealthState::Starting
        } else if self.running == 0 && self.succeeded == self.desired_replicas {
            StackHealthState::Completed
        } else {
            StackHealthState::Healthy
        }
    }

    fn state_matches_counts(&self) -> bool {
        let waiting = self.pending + self.starting + self.backoff;
        let failures = self.failed + self.exhausted;
        let successful = self.running + self.succeeded;
        match self.desired_state {
            EngineStackState::Removed => {
                self.state == StackHealthState::Removed
                    && self.replicas_total == 0
                    && self.runtime_observed_at_ms.is_none()
            }
            EngineStackState::Stopped => {
                self.state == StackHealthState::Stopped
                    && self.desired_replicas == 0
                    && waiting == 0
                    && successful == 0
                    && failures == 0
            }
            EngineStackState::Applied if self.desired_replicas == 0 => {
                self.state == StackHealthState::Stopped
            }
            EngineStackState::Applied => match self.state {
                StackHealthState::Healthy => {
                    failures == 0
                        && self.probe_unhealthy == 0
                        && self.probe_waiting == 0
                        && waiting == 0
                        && self.running > 0
                        && self.running + self.succeeded == self.desired_replicas
                }
                StackHealthState::Completed => {
                    failures == 0
                        && self.probe_unhealthy == 0
                        && self.probe_waiting == 0
                        && waiting == 0
                        && self.running == 0
                        && self.succeeded == self.desired_replicas
                }
                StackHealthState::Starting => {
                    failures == 0
                        && self.probe_unhealthy == 0
                        && (waiting > 0 || successful < self.desired_replicas)
                }
                StackHealthState::Degraded => {
                    self.probe_unhealthy > 0 || (failures > 0 && (successful > 0 || waiting > 0))
                }
                StackHealthState::Failed => failures > 0 && successful == 0 && waiting == 0,
                StackHealthState::Stale => self.runtime_observed_at_ms.is_some_and(|observed| {
                    (self.running > 0 || waiting > 0)
                        && self.observed_at_ms.saturating_sub(observed) > SUPERVISOR_STALE_AFTER_MS
                }),
                StackHealthState::Stopped | StackHealthState::Removed => false,
            },
        }
    }

    fn refresh(&mut self) -> Result<(), String> {
        self.report_sha256.clear();
        self.report_sha256 = self.computed_sha256()?;
        self.validate()
    }

    fn computed_sha256(&self) -> Result<String, String> {
        let mut value = self.clone();
        value.report_sha256.clear();
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

pub fn validate_health_reports(reports: &[StackHealthReport]) -> Result<(), String> {
    if reports.len() > MAX_ENGINE_HEALTH_REPORTS {
        return Err("engine health response contains too many stacks".into());
    }
    let mut previous = None;
    for report in reports {
        report.validate()?;
        if previous.is_some_and(|stack: &str| stack >= report.stack.as_str()) {
            return Err("engine health reports are not strictly sorted".into());
        }
        previous = Some(report.stack.as_str());
    }
    Ok(())
}

fn validate_stack_status(status: &StackStatus) -> Result<(), String> {
    if !valid_name(&status.stack)
        || status.revision == 0
        || status.instance_count > MAX_STACK_INSTANCES
        || status.desired_replicas > u64::from(MAX_STACK_TOTAL_REPLICAS)
        || !is_digest(&status.event_sha256)
        || status
            .plan_sha256
            .as_ref()
            .is_some_and(|value| !is_digest(value))
        || match status.state {
            EngineStackState::Applied | EngineStackState::Stopped => status.plan_sha256.is_none(),
            EngineStackState::Removed => {
                status.plan_sha256.is_some()
                    || status.instance_count != 0
                    || status.desired_replicas != 0
            }
        }
    {
        return Err("stack status is invalid".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cartridge_core::{CompositionLock, LockedPackage, ResolutionPlan, RuntimeLimits};

    use super::*;
    use crate::{
        DesiredState, HealthProbeSpec, PlannedInstance, PlannedSecurity, ProbeSignalKind,
        RestartPolicy, SandboxPolicy, SecurityProfile, StackPlan,
    };

    fn plan(replicas: u16) -> StackPlan {
        let mut value = StackPlan {
            format_version: crate::STACK_PLAN_FORMAT_VERSION,
            stack: "demo".into(),
            security: PlannedSecurity {
                profile: SecurityProfile::Strict,
                sandbox: SandboxPolicy::Required,
            },
            instances: vec![PlannedInstance {
                name: "web".into(),
                cartridge_id: "dev.test.web".into(),
                version: "1.0.0".into(),
                package_sha256: "1".repeat(64),
                package_bytes: 1,
                replicas,
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
                health: None,
                composition: CompositionLock::new(
                    LockedPackage {
                        cartridge_id: "dev.test.web".into(),
                        version: "1.0.0".into(),
                        package_sha256: "1".repeat(64),
                        package_bytes: 1,
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

    fn status(plan: &StackPlan) -> StackStatus {
        StackStatus {
            stack: plan.stack.clone(),
            revision: 1,
            state: EngineStackState::Applied,
            plan_sha256: Some(plan.plan_sha256.clone()),
            instance_count: plan.instances.len(),
            desired_replicas: u64::from(plan.instances[0].replicas),
            event_sha256: "2".repeat(64),
        }
    }

    #[test]
    fn readiness_distinguishes_starting_healthy_completed_and_stale() {
        let plan = plan(1);
        let desired = status(&plan);
        let mut runtime = StackRuntimeStatus::from_plan(&plan, 1, &"2".repeat(64), 100).unwrap();
        let id = runtime.replicas[0].id.clone();

        let starting = StackHealthReport::from_status(&desired, Some(&runtime), 100).unwrap();
        assert_eq!(starting.state, StackHealthState::Starting);

        runtime.begin_start(&id, &"3".repeat(64), 101).unwrap();
        runtime.mark_running(&id, &"3".repeat(64), 102).unwrap();
        let healthy = StackHealthReport::from_status(&desired, Some(&runtime), 102).unwrap();
        assert_eq!(healthy.state, StackHealthState::Healthy);
        assert!(healthy.ready());

        let stale = StackHealthReport::from_status(
            &desired,
            Some(&runtime),
            102 + SUPERVISOR_STALE_AFTER_MS + 1,
        )
        .unwrap();
        assert_eq!(stale.state, StackHealthState::Stale);

        runtime
            .mark_exit(&id, &"3".repeat(64), true, Some(0), "worker exited", 103)
            .unwrap();
        let completed = StackHealthReport::from_status(&desired, Some(&runtime), 103).unwrap();
        assert_eq!(completed.state, StackHealthState::Completed);
        assert!(completed.ready());
    }

    #[test]
    fn changed_health_counts_or_identity_are_rejected() {
        let plan = plan(1);
        let desired = status(&plan);
        let runtime = StackRuntimeStatus::from_plan(&plan, 1, &"2".repeat(64), 100).unwrap();
        let mut report = StackHealthReport::from_status(&desired, Some(&runtime), 100).unwrap();

        report.running = 1;
        assert!(report.validate().is_err());
    }

    #[test]
    fn application_readiness_and_unhealthy_signals_drive_stack_health() {
        let mut plan = plan(1);
        plan.instances[0].health = Some(HealthProbeSpec::default());
        plan.plan_sha256 = plan.computed_sha256().unwrap();
        let desired = status(&plan);
        let mut runtime = StackRuntimeStatus::from_plan(&plan, 1, &"2".repeat(64), 100).unwrap();
        let id = runtime.replicas[0].id.clone();
        let run_id = "9".repeat(64);

        runtime.begin_start(&id, &run_id, 101).unwrap();
        runtime
            .mark_probe_signal(&id, &run_id, 1, ProbeSignalKind::Started, 102)
            .unwrap();
        let starting = StackHealthReport::from_status(&desired, Some(&runtime), 102).unwrap();
        assert_eq!(starting.state, StackHealthState::Starting);
        assert_eq!(starting.probe_waiting, 1);

        runtime
            .mark_probe_signal(&id, &run_id, 2, ProbeSignalKind::Ready, 103)
            .unwrap();
        let healthy = StackHealthReport::from_status(&desired, Some(&runtime), 103).unwrap();
        assert_eq!(healthy.state, StackHealthState::Healthy);
        assert_eq!(healthy.probe_ready, 1);

        runtime
            .mark_probe_signal(&id, &run_id, 3, ProbeSignalKind::Unhealthy, 104)
            .unwrap();
        let degraded = StackHealthReport::from_status(&desired, Some(&runtime), 104).unwrap();
        assert_eq!(degraded.state, StackHealthState::Degraded);
        assert_eq!(degraded.probe_unhealthy, 1);
        assert!(!degraded.ready());
    }

    #[test]
    fn aggregate_health_responses_have_a_strict_stack_ceiling() {
        let plan = plan(1);
        let desired = status(&plan);
        let report = StackHealthReport::from_status(&desired, None, 100).unwrap();
        let reports = vec![report; MAX_ENGINE_HEALTH_REPORTS + 1];

        assert!(validate_health_reports(&reports).is_err());
    }
}

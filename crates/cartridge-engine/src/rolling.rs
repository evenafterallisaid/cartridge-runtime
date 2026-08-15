use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::MAX_STACK_REPLICAS;

pub const MIN_ROLLING_PROGRESS_DEADLINE_MS: u64 = 1_000;
pub const MAX_ROLLING_PROGRESS_DEADLINE_MS: u64 = 60 * 60 * 1_000;
pub const MAX_ROLLING_MIN_READY_MS: u64 = 5 * 60 * 1_000;
pub const MAX_ROLLING_DRAIN_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollingOrder {
    #[default]
    StartFirst,
    StopFirst,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RollingUpdatePolicy {
    pub order: RollingOrder,
    pub max_surge: u16,
    pub max_unavailable: u16,
    pub min_ready_ms: u64,
    pub progress_deadline_ms: u64,
    pub drain_timeout_ms: u64,
}

impl Default for RollingUpdatePolicy {
    fn default() -> Self {
        Self {
            order: RollingOrder::StartFirst,
            max_surge: 1,
            max_unavailable: 0,
            min_ready_ms: 2_000,
            progress_deadline_ms: 5 * 60 * 1_000,
            drain_timeout_ms: 30_000,
        }
    }
}

impl RollingUpdatePolicy {
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn validate(&self, replicas: u16) -> Result<(), String> {
        if replicas == 0
            || replicas > MAX_STACK_REPLICAS
            || self.max_surge > replicas
            || self.max_unavailable > replicas
            || self.max_surge == 0 && self.max_unavailable == 0
            || self.min_ready_ms > MAX_ROLLING_MIN_READY_MS
            || !(MIN_ROLLING_PROGRESS_DEADLINE_MS..=MAX_ROLLING_PROGRESS_DEADLINE_MS)
                .contains(&self.progress_deadline_ms)
            || self.progress_deadline_ms <= self.min_ready_ms
            || self.drain_timeout_ms > MAX_ROLLING_DRAIN_TIMEOUT_MS
            || self.progress_deadline_ms <= self.drain_timeout_ms
        {
            return Err("rolling update policy is invalid".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RollingObservation {
    pub replicas: u16,
    pub previous_active: BTreeSet<u16>,
    pub previous_ready: BTreeSet<u16>,
    pub candidate_active: BTreeSet<u16>,
    pub candidate_ready: BTreeSet<u16>,
    pub candidate_available: BTreeSet<u16>,
    pub candidate_terminal: BTreeSet<u16>,
    pub elapsed_since_progress_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollingWaitReason {
    CandidateReadiness,
    MinimumReadyTime,
    AvailabilityBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollingRollbackReason {
    CandidateFailed,
    ProgressDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollingAction {
    StartCandidate { ordinals: Vec<u16> },
    DrainPrevious { ordinals: Vec<u16>, timeout_ms: u64 },
    Wait { reason: RollingWaitReason },
    Complete,
    Rollback { reason: RollingRollbackReason },
}

impl RollingObservation {
    pub fn validate(&self, policy: &RollingUpdatePolicy) -> Result<(), String> {
        policy.validate(self.replicas)?;
        let valid_ordinal = |ordinal: &u16| *ordinal > 0 && *ordinal <= self.replicas;
        let sets = [
            &self.previous_active,
            &self.previous_ready,
            &self.candidate_active,
            &self.candidate_ready,
            &self.candidate_available,
            &self.candidate_terminal,
        ];
        if sets
            .into_iter()
            .any(|values| values.iter().any(|ordinal| !valid_ordinal(ordinal)))
            || !self.previous_ready.is_subset(&self.previous_active)
            || !self.candidate_ready.is_subset(&self.candidate_active)
            || !self.candidate_available.is_subset(&self.candidate_ready)
            || !self.candidate_terminal.is_disjoint(&self.candidate_active)
        {
            return Err("rolling update observation is inconsistent".into());
        }
        let active = self
            .previous_active
            .len()
            .checked_add(self.candidate_active.len())
            .ok_or_else(|| "rolling update active count overflow".to_string())?;
        let limit = usize::from(self.replicas)
            .checked_add(usize::from(policy.max_surge))
            .ok_or_else(|| "rolling update surge count overflow".to_string())?;
        if active > limit {
            return Err("rolling update exceeds its surge limit".into());
        }
        Ok(())
    }

    pub fn next(&self, policy: &RollingUpdatePolicy) -> Result<RollingAction, String> {
        self.validate(policy)?;
        if !self.candidate_terminal.is_empty() {
            return Ok(RollingAction::Rollback {
                reason: RollingRollbackReason::CandidateFailed,
            });
        }
        let desired = usize::from(self.replicas);
        if self.previous_active.is_empty() && self.candidate_available.len() == desired {
            return Ok(RollingAction::Complete);
        }
        if self.elapsed_since_progress_ms >= policy.progress_deadline_ms {
            return Ok(RollingAction::Rollback {
                reason: RollingRollbackReason::ProgressDeadline,
            });
        }

        let start = || self.start_action(policy);
        let drain = || self.drain_action(policy);
        let action = match policy.order {
            RollingOrder::StartFirst => start().or_else(drain),
            RollingOrder::StopFirst => drain().or_else(start),
        };
        if let Some(action) = action {
            return Ok(action);
        }
        let reason = if self.candidate_ready.len() < self.candidate_active.len() {
            RollingWaitReason::CandidateReadiness
        } else if self.candidate_available.len() < self.candidate_ready.len() {
            RollingWaitReason::MinimumReadyTime
        } else {
            RollingWaitReason::AvailabilityBudget
        };
        Ok(RollingAction::Wait { reason })
    }

    fn start_action(&self, policy: &RollingUpdatePolicy) -> Option<RollingAction> {
        let desired = usize::from(self.replicas);
        let active = self.previous_active.len() + self.candidate_active.len();
        let capacity = desired + usize::from(policy.max_surge);
        let count = desired
            .saturating_sub(self.candidate_active.len())
            .min(capacity.saturating_sub(active));
        if count == 0 {
            return None;
        }
        let ordinals = (1..=self.replicas)
            .filter(|ordinal| {
                !self.candidate_active.contains(ordinal)
                    && !self.candidate_terminal.contains(ordinal)
            })
            .take(count)
            .collect::<Vec<_>>();
        (!ordinals.is_empty()).then_some(RollingAction::StartCandidate { ordinals })
    }

    fn drain_action(&self, policy: &RollingUpdatePolicy) -> Option<RollingAction> {
        if self.previous_active.is_empty() {
            return None;
        }
        let desired = usize::from(self.replicas);
        let minimum_available = desired.saturating_sub(usize::from(policy.max_unavailable));
        let available = self.previous_ready.len() + self.candidate_available.len();
        let ready_budget = available.saturating_sub(minimum_available);
        let mut ordinals = self
            .previous_active
            .difference(&self.previous_ready)
            .copied()
            .collect::<Vec<_>>();
        ordinals.extend(self.previous_ready.iter().copied().take(ready_budget));
        if ordinals.is_empty() {
            return None;
        }
        ordinals.sort_unstable();
        Some(RollingAction::DrainPrevious {
            ordinals,
            timeout_ms: policy.drain_timeout_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinals(values: &[u16]) -> BTreeSet<u16> {
        values.iter().copied().collect()
    }

    fn initial(replicas: u16) -> RollingObservation {
        let previous = (1..=replicas).collect::<BTreeSet<_>>();
        RollingObservation {
            replicas,
            previous_active: previous.clone(),
            previous_ready: previous,
            ..RollingObservation::default()
        }
    }

    #[test]
    fn start_first_never_drops_availability_before_surge_is_ready() {
        let policy = RollingUpdatePolicy::default();
        let mut state = initial(3);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::StartCandidate { ordinals: vec![1] }
        );
        state.candidate_active.insert(1);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::Wait {
                reason: RollingWaitReason::CandidateReadiness
            }
        );
        state.candidate_ready.insert(1);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::Wait {
                reason: RollingWaitReason::MinimumReadyTime
            }
        );
        state.candidate_available.insert(1);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::DrainPrevious {
                ordinals: vec![1],
                timeout_ms: 30_000
            }
        );
    }

    #[test]
    fn stop_first_spends_only_the_unavailable_budget() {
        let policy = RollingUpdatePolicy {
            order: RollingOrder::StopFirst,
            max_surge: 0,
            max_unavailable: 1,
            ..RollingUpdatePolicy::default()
        };
        let mut state = initial(3);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::DrainPrevious {
                ordinals: vec![1],
                timeout_ms: 30_000
            }
        );
        state.previous_active.remove(&1);
        state.previous_ready.remove(&1);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::StartCandidate { ordinals: vec![1] }
        );
    }

    #[test]
    fn terminal_candidates_and_stalled_progress_roll_back() {
        let policy = RollingUpdatePolicy::default();
        let mut failed = initial(2);
        failed.candidate_terminal.insert(1);
        assert_eq!(
            failed.next(&policy).unwrap(),
            RollingAction::Rollback {
                reason: RollingRollbackReason::CandidateFailed
            }
        );
        let mut stalled = initial(2);
        stalled.elapsed_since_progress_ms = policy.progress_deadline_ms;
        assert_eq!(
            stalled.next(&policy).unwrap(),
            RollingAction::Rollback {
                reason: RollingRollbackReason::ProgressDeadline
            }
        );
    }

    #[test]
    fn policy_rejects_deadlocks_and_deadlines_shorter_than_drain() {
        let deadlocked = RollingUpdatePolicy {
            max_surge: 0,
            max_unavailable: 0,
            ..RollingUpdatePolicy::default()
        };
        assert!(deadlocked.validate(2).is_err());
        let ambiguous_deadline = RollingUpdatePolicy {
            progress_deadline_ms: 30_000,
            drain_timeout_ms: 30_000,
            ..RollingUpdatePolicy::default()
        };
        assert!(ambiguous_deadline.validate(2).is_err());
    }

    #[test]
    fn inconsistent_or_over_surge_observations_fail_closed() {
        let policy = RollingUpdatePolicy::default();
        let mut invalid = initial(2);
        invalid.candidate_ready.insert(1);
        assert!(invalid.next(&policy).is_err());
        let mut over = initial(2);
        over.candidate_active = ordinals(&[1, 2]);
        assert!(over.next(&policy).is_err());
    }

    #[test]
    fn only_fully_available_candidate_generations_complete() {
        let policy = RollingUpdatePolicy::default();
        let mut state = RollingObservation {
            replicas: 2,
            candidate_active: ordinals(&[1, 2]),
            candidate_ready: ordinals(&[1, 2]),
            candidate_available: ordinals(&[1, 2]),
            ..RollingObservation::default()
        };
        assert_eq!(state.next(&policy).unwrap(), RollingAction::Complete);
        state.candidate_available.remove(&2);
        assert_eq!(
            state.next(&policy).unwrap(),
            RollingAction::Wait {
                reason: RollingWaitReason::MinimumReadyTime
            }
        );
    }

    #[test]
    fn exhaustive_small_schedules_preserve_capacity_and_availability() {
        for replicas in 1..=3_u16 {
            let states = 1_u16 << replicas;
            for order in [RollingOrder::StartFirst, RollingOrder::StopFirst] {
                for max_surge in 0..=replicas {
                    for max_unavailable in 0..=replicas {
                        if max_surge == 0 && max_unavailable == 0 {
                            continue;
                        }
                        let policy = RollingUpdatePolicy {
                            order,
                            max_surge,
                            max_unavailable,
                            ..RollingUpdatePolicy::default()
                        };
                        for previous_mask in 0..states {
                            let previous_active = from_mask(previous_mask, replicas);
                            for previous_ready_mask in 0..states {
                                let previous_ready = from_mask(previous_ready_mask, replicas);
                                if !previous_ready.is_subset(&previous_active) {
                                    continue;
                                }
                                for candidate_mask in 0..states {
                                    let candidate_active = from_mask(candidate_mask, replicas);
                                    if previous_active.len() + candidate_active.len()
                                        > usize::from(replicas + max_surge)
                                    {
                                        continue;
                                    }
                                    for candidate_ready_mask in 0..states {
                                        let candidate_ready =
                                            from_mask(candidate_ready_mask, replicas);
                                        if !candidate_ready.is_subset(&candidate_active) {
                                            continue;
                                        }
                                        for candidate_available_mask in 0..states {
                                            let candidate_available =
                                                from_mask(candidate_available_mask, replicas);
                                            if !candidate_available.is_subset(&candidate_ready) {
                                                continue;
                                            }
                                            let state = RollingObservation {
                                                replicas,
                                                previous_active: previous_active.clone(),
                                                previous_ready: previous_ready.clone(),
                                                candidate_active: candidate_active.clone(),
                                                candidate_ready: candidate_ready.clone(),
                                                candidate_available: candidate_available.clone(),
                                                ..RollingObservation::default()
                                            };
                                            assert_observation_action_safe(&state, &policy);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn assert_observation_action_safe(state: &RollingObservation, policy: &RollingUpdatePolicy) {
        let before_available = state.previous_ready.len() + state.candidate_available.len();
        let action = state.next(policy).unwrap();
        assert_eq!(action, state.next(policy).unwrap());
        match action {
            RollingAction::StartCandidate { ordinals } => {
                assert!(!ordinals.is_empty());
                assert!(
                    ordinals
                        .iter()
                        .all(|ordinal| !state.candidate_active.contains(ordinal))
                );
                assert!(
                    state.previous_active.len() + state.candidate_active.len() + ordinals.len()
                        <= usize::from(state.replicas + policy.max_surge)
                );
            }
            RollingAction::DrainPrevious { ordinals, .. } => {
                assert!(!ordinals.is_empty());
                assert!(
                    ordinals
                        .iter()
                        .all(|ordinal| state.previous_active.contains(ordinal))
                );
                let ready_drained = ordinals
                    .iter()
                    .filter(|ordinal| state.previous_ready.contains(ordinal))
                    .count();
                let after_available = before_available - ready_drained;
                let minimum = usize::from(state.replicas.saturating_sub(policy.max_unavailable));
                assert!(after_available >= minimum || after_available == before_available);
            }
            RollingAction::Complete => {
                assert!(state.previous_active.is_empty());
                assert_eq!(state.candidate_available.len(), usize::from(state.replicas));
            }
            RollingAction::Wait { .. } => {}
            RollingAction::Rollback { .. } => {
                panic!("a live, non-expired candidate rolled back")
            }
        }
    }

    fn from_mask(mask: u16, replicas: u16) -> BTreeSet<u16> {
        (1..=replicas)
            .filter(|ordinal| mask & (1 << (ordinal - 1)) != 0)
            .collect()
    }
}

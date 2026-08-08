use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const CURRENT_TRACE_FORMAT_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug)]
pub struct TraceIdentity<'a> {
    pub cartridge_id: &'a str,
    pub cartridge_version: &'a str,
    pub component_sha256: &'a str,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTrace {
    pub format_version: u32,
    pub runtime_version: String,
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub component_sha256: String,
    pub args: Vec<String>,
    pub events: Vec<TraceEvent>,
    pub result: TraceResult,
}

impl ExecutionTrace {
    #[must_use]
    pub fn new(
        runtime_version: impl Into<String>,
        identity: TraceIdentity<'_>,
        args: &[String],
        events: Vec<TraceEvent>,
        result: TraceResult,
    ) -> Self {
        Self {
            format_version: CURRENT_TRACE_FORMAT_VERSION,
            runtime_version: runtime_version.into(),
            cartridge_id: identity.cartridge_id.to_owned(),
            cartridge_version: identity.cartridge_version.to_owned(),
            component_sha256: identity.component_sha256.to_owned(),
            args: args.to_vec(),
            events,
            result,
        }
    }

    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.format_version != CURRENT_TRACE_FORMAT_VERSION {
            return Err(ReplayError::UnsupportedFormat {
                found: self.format_version,
                expected: CURRENT_TRACE_FORMAT_VERSION,
            });
        }
        if self.runtime_version.trim().is_empty() {
            return Err(invalid("runtime version is empty"));
        }
        if self.cartridge_id.trim().is_empty() {
            return Err(invalid("cartridge id is empty"));
        }
        if self.cartridge_version.trim().is_empty() {
            return Err(invalid("cartridge version is empty"));
        }
        if self.component_sha256.len() != 64
            || !self
                .component_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("component sha256 is not a hexadecimal digest"));
        }
        for (index, event) in self.events.iter().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| invalid("trace contains more events than can be sequenced"))?;
            if event.sequence != expected {
                return Err(invalid(format!(
                    "event at index {index} has sequence {}, expected {expected}",
                    event.sequence
                )));
            }
            if event.capability.trim().is_empty() {
                return Err(invalid(format!("event {index} has an empty capability")));
            }
            if event.operation.trim().is_empty() {
                return Err(invalid(format!("event {index} has an empty operation")));
            }
        }
        Ok(())
    }

    pub fn validate_invocation(
        &self,
        identity: TraceIdentity<'_>,
        args: &[String],
    ) -> Result<(), ReplayError> {
        self.validate()?;
        check_identity("cartridge id", &self.cartridge_id, identity.cartridge_id)?;
        check_identity(
            "cartridge version",
            &self.cartridge_version,
            identity.cartridge_version,
        )?;
        check_identity(
            "component sha256",
            &self.component_sha256,
            identity.component_sha256,
        )?;
        if self.args != args {
            return Err(ReplayError::InvocationMismatch {
                expected: self.args.clone(),
                actual: args.to_vec(),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> TraceSummary {
        let mut capabilities = BTreeMap::new();
        for event in &self.events {
            *capabilities.entry(event.capability.clone()).or_insert(0) += 1;
        }
        TraceSummary {
            format_version: self.format_version,
            runtime_version: self.runtime_version.clone(),
            cartridge_id: self.cartridge_id.clone(),
            cartridge_version: self.cartridge_version.clone(),
            component_sha256: self.component_sha256.clone(),
            args: self.args.clone(),
            event_count: self.events.len(),
            capabilities,
            result: self.result.clone(),
        }
    }

    #[must_use]
    pub fn compare(&self, other: &Self) -> TraceComparison {
        let difference = first_header_difference(self, other)
            .or_else(|| first_event_difference(self, other))
            .or_else(|| first_result_difference(self, other));
        TraceComparison {
            identical: difference.is_none(),
            difference,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    pub sequence: u64,
    pub capability: String,
    pub operation: String,
    pub outcome: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceResult {
    pub output: String,
    pub fuel_consumed: u64,
}

impl TraceResult {
    pub fn compare(&self, actual: &Self) -> Result<(), ReplayError> {
        if self.output != actual.output {
            return Err(ReplayError::ResultMismatch {
                field: "output",
                expected: self.output.clone(),
                actual: actual.output.clone(),
            });
        }
        if self.fuel_consumed != actual.fuel_consumed {
            return Err(ReplayError::ResultMismatch {
                field: "fuel consumed",
                expected: self.fuel_consumed.to_string(),
                actual: actual.fuel_consumed.to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceSummary {
    pub format_version: u32,
    pub runtime_version: String,
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub component_sha256: String,
    pub args: Vec<String>,
    pub event_count: usize,
    pub capabilities: BTreeMap<String, usize>,
    pub result: TraceResult,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TraceComparison {
    pub identical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difference: Option<TraceDifference>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TraceDifference {
    Header {
        field: String,
        left: Value,
        right: Value,
    },
    Event {
        sequence: u64,
        left: Option<TraceEvent>,
        right: Option<TraceEvent>,
    },
    Result {
        field: String,
        left: Value,
        right: Value,
    },
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ReplayError {
    #[error("unsupported trace format {found}; this runtime expects {expected}")]
    UnsupportedFormat { found: u32, expected: u32 },
    #[error("invalid trace: {reason}")]
    InvalidTrace { reason: String },
    #[error("trace {field} mismatch: expected {expected}, got {actual}")]
    IdentityMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("trace arguments do not match: expected {expected:?}, got {actual:?}")]
    InvocationMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    #[error("trace diverged at event {sequence}: {reason}")]
    Divergence { sequence: u64, reason: String },
    #[error("trace contains {remaining} unconsumed event(s) after execution")]
    EventsRemaining { remaining: usize },
    #[error("replay {field} mismatch: expected {expected:?}, got {actual:?}")]
    ResultMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

fn invalid(reason: impl Into<String>) -> ReplayError {
    ReplayError::InvalidTrace {
        reason: reason.into(),
    }
}

fn check_identity(field: &'static str, expected: &str, actual: &str) -> Result<(), ReplayError> {
    if expected != actual {
        return Err(ReplayError::IdentityMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn first_header_difference(
    left: &ExecutionTrace,
    right: &ExecutionTrace,
) -> Option<TraceDifference> {
    let fields = [
        (
            "format_version",
            Value::from(left.format_version),
            Value::from(right.format_version),
        ),
        (
            "runtime_version",
            Value::from(left.runtime_version.clone()),
            Value::from(right.runtime_version.clone()),
        ),
        (
            "cartridge_id",
            Value::from(left.cartridge_id.clone()),
            Value::from(right.cartridge_id.clone()),
        ),
        (
            "cartridge_version",
            Value::from(left.cartridge_version.clone()),
            Value::from(right.cartridge_version.clone()),
        ),
        (
            "component_sha256",
            Value::from(left.component_sha256.clone()),
            Value::from(right.component_sha256.clone()),
        ),
        (
            "args",
            Value::from(left.args.clone()),
            Value::from(right.args.clone()),
        ),
    ];
    fields
        .into_iter()
        .find(|(_, left, right)| left != right)
        .map(|(field, left, right)| TraceDifference::Header {
            field: field.to_owned(),
            left,
            right,
        })
}

fn first_event_difference(
    left: &ExecutionTrace,
    right: &ExecutionTrace,
) -> Option<TraceDifference> {
    let count = left.events.len().max(right.events.len());
    (0..count).find_map(|index| {
        let left = left.events.get(index);
        let right = right.events.get(index);
        (left != right).then(|| TraceDifference::Event {
            sequence: u64::try_from(index).unwrap_or(u64::MAX),
            left: left.cloned(),
            right: right.cloned(),
        })
    })
}

fn first_result_difference(
    left: &ExecutionTrace,
    right: &ExecutionTrace,
) -> Option<TraceDifference> {
    if left.result.output != right.result.output {
        return Some(TraceDifference::Result {
            field: "output".into(),
            left: Value::from(left.result.output.clone()),
            right: Value::from(right.result.output.clone()),
        });
    }
    (left.result.fuel_consumed != right.result.fuel_consumed).then(|| TraceDifference::Result {
        field: "fuel_consumed".into(),
        left: Value::from(left.result.fuel_consumed),
        right: Value::from(right.result.fuel_consumed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> ExecutionTrace {
        ExecutionTrace::new(
            "0.1.0",
            TraceIdentity {
                cartridge_id: "dev.example.trace",
                cartridge_version: "0.1.0",
                component_sha256: &"a".repeat(64),
            },
            &["one".into()],
            vec![TraceEvent {
                sequence: 0,
                capability: "log".into(),
                operation: "write".into(),
                outcome: serde_json::json!({ "message": "hello" }),
            }],
            TraceResult {
                output: "done".into(),
                fuel_consumed: 10,
            },
        )
    }

    #[test]
    fn valid_trace_has_a_capability_summary() {
        let trace = trace();

        trace.validate().unwrap();
        assert_eq!(trace.summary().capabilities.get("log"), Some(&1));
    }

    #[test]
    fn sequence_gaps_are_rejected() {
        let mut trace = trace();
        trace.events[0].sequence = 2;

        assert!(matches!(
            trace.validate(),
            Err(ReplayError::InvalidTrace { .. })
        ));
    }

    #[test]
    fn invocation_arguments_are_part_of_trace_identity() {
        let trace = trace();
        let identity = TraceIdentity {
            cartridge_id: "dev.example.trace",
            cartridge_version: "0.1.0",
            component_sha256: &"a".repeat(64),
        };

        let error = trace
            .validate_invocation(identity, &["two".to_owned()])
            .unwrap_err();

        assert!(matches!(error, ReplayError::InvocationMismatch { .. }));
    }

    #[test]
    fn comparison_finds_the_first_changed_event() {
        let left = trace();
        let mut right = left.clone();
        right.events[0].operation = "flush".into();

        let comparison = left.compare(&right);

        assert!(!comparison.identical);
        assert!(matches!(
            comparison.difference,
            Some(TraceDifference::Event { sequence: 0, .. })
        ));
    }
}

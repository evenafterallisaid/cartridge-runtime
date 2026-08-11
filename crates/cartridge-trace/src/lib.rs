use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CURRENT_TRACE_FORMAT_VERSION: u32 = 2;
pub const MAX_TRACE_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_TRACE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRACE_EVENTS: usize = 100_000;
pub const MAX_TRACE_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_REDACTED_TRACE_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

const MAX_TRACE_ARGUMENTS: usize = 4096;
const MAX_TRACE_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_TRACE_LABEL_BYTES: usize = 128;

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
        if !valid_label(&self.runtime_version) {
            return Err(invalid("runtime version is empty"));
        }
        if !valid_label(&self.cartridge_id) {
            return Err(invalid("cartridge id is empty"));
        }
        if !valid_label(&self.cartridge_version) {
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
        if self.args.len() > MAX_TRACE_ARGUMENTS {
            return Err(invalid("trace contains too many arguments"));
        }
        let argument_bytes = self.args.iter().try_fold(0usize, |total, argument| {
            total
                .checked_add(argument.len())
                .ok_or_else(|| invalid("trace argument size overflowed"))
        })?;
        if argument_bytes > MAX_TRACE_ARGUMENT_BYTES {
            return Err(invalid("trace arguments exceed their byte budget"));
        }
        if self.events.len() > MAX_TRACE_EVENTS {
            return Err(invalid("trace contains too many events"));
        }
        let mut trace_bytes = 0usize;
        for (index, event) in self.events.iter().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| invalid("trace contains more events than can be sequenced"))?;
            if event.sequence != expected {
                return Err(invalid(format!(
                    "event at index {index} has sequence {}, expected {expected}",
                    event.sequence
                )));
            }
            if !valid_label(&event.capability) {
                return Err(invalid(format!("event {index} has an empty capability")));
            }
            if !valid_label(&event.operation) {
                return Err(invalid(format!("event {index} has an empty operation")));
            }
            let outcome_bytes = serde_json::to_vec(&event.outcome)
                .map_err(|error| invalid(format!("event {index} is not serializable: {error}")))?
                .len();
            trace_bytes = trace_bytes
                .checked_add(event.capability.len())
                .and_then(|bytes| bytes.checked_add(event.operation.len()))
                .and_then(|bytes| bytes.checked_add(outcome_bytes))
                .and_then(|bytes| bytes.checked_add(128))
                .ok_or_else(|| invalid("trace event size overflowed"))?;
            if trace_bytes > MAX_TRACE_BYTES {
                return Err(invalid("trace events exceed their byte budget"));
            }
        }
        if self.result.output.len() > MAX_TRACE_OUTPUT_BYTES {
            return Err(invalid("trace output exceeds its byte budget"));
        }
        Ok(())
    }

    pub fn validate_invocation(
        &self,
        runtime_version: &str,
        identity: TraceIdentity<'_>,
        args: &[String],
    ) -> Result<(), ReplayError> {
        self.validate()?;
        check_identity("runtime version", &self.runtime_version, runtime_version)?;
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

    pub fn redact(&self, profile: RedactionProfile) -> Result<RedactedTrace, ReplayError> {
        self.validate()?;
        let mut capabilities = BTreeMap::new();
        for event in &self.events {
            *capabilities.entry(event.capability.clone()).or_insert(0) += 1;
        }
        let events = match profile {
            RedactionProfile::Summary => Vec::new(),
            RedactionProfile::Metadata => self
                .events
                .iter()
                .map(|event| {
                    let outcome = serde_json::to_vec(&event.outcome).map_err(|error| {
                        invalid(format!("trace event outcome could not be encoded: {error}"))
                    })?;
                    Ok(RedactedEvent {
                        sequence: event.sequence,
                        capability: event.capability.clone(),
                        operation: event.operation.clone(),
                        outcome_bytes: outcome.len(),
                        outcome_sha256: hex::encode(Sha256::digest(outcome)),
                    })
                })
                .collect::<Result<_, ReplayError>>()?,
        };
        let arguments = serde_json::to_vec(&self.args)
            .map_err(|error| invalid(format!("trace arguments could not be encoded: {error}")))?;
        let payload = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("trace could not be encoded: {error}")))?;
        Ok(RedactedTrace {
            format_version: 1,
            replayable: false,
            profile,
            trace_payload_sha256: hex::encode(Sha256::digest(payload)),
            runtime_version: self.runtime_version.clone(),
            cartridge_id: self.cartridge_id.clone(),
            cartridge_version: self.cartridge_version.clone(),
            component_sha256: self.component_sha256.clone(),
            argument_count: self.args.len(),
            argument_bytes: self.args.iter().map(String::len).sum(),
            arguments_sha256: hex::encode(Sha256::digest(arguments)),
            event_count: self.events.len(),
            capabilities,
            events,
            output_bytes: self.result.output.len(),
            output_sha256: hex::encode(Sha256::digest(self.result.output.as_bytes())),
            fuel_consumed: self.result.fuel_consumed,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionProfile {
    Summary,
    Metadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedTrace {
    pub format_version: u32,
    pub replayable: bool,
    pub profile: RedactionProfile,
    pub trace_payload_sha256: String,
    pub runtime_version: String,
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub component_sha256: String,
    pub argument_count: usize,
    pub argument_bytes: usize,
    pub arguments_sha256: String,
    pub event_count: usize,
    pub capabilities: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<RedactedEvent>,
    pub output_bytes: usize,
    pub output_sha256: String,
    pub fuel_consumed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedEvent {
    pub sequence: u64,
    pub capability: String,
    pub operation: String,
    pub outcome_bytes: usize,
    pub outcome_sha256: String,
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
    #[error("trace budget exceeded after {events} event(s) and {bytes} byte(s)")]
    TraceLimitExceeded { events: usize, bytes: usize },
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

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_TRACE_LABEL_BYTES
        && !value.chars().any(char::is_control)
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
    fn redacted_exports_do_not_contain_arguments_outcomes_or_output() {
        let trace = trace();
        let redacted = trace.redact(RedactionProfile::Metadata).unwrap();
        let encoded = serde_json::to_string(&redacted).unwrap();

        assert!(!redacted.replayable);
        assert_eq!(redacted.events.len(), 1);
        assert!(!encoded.contains("hello"));
        assert!(!encoded.contains("done"));
        assert!(!encoded.contains("\"one\""));
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
            .validate_invocation("0.1.0", identity, &["two".to_owned()])
            .unwrap_err();

        assert!(matches!(error, ReplayError::InvocationMismatch { .. }));
    }

    #[test]
    fn invocation_requires_the_recorded_runtime_version() {
        let trace = trace();
        let identity = TraceIdentity {
            cartridge_id: "dev.example.trace",
            cartridge_version: "0.1.0",
            component_sha256: &"a".repeat(64),
        };

        assert!(matches!(
            trace.validate_invocation("0.2.0", identity, &["one".to_owned()]),
            Err(ReplayError::IdentityMismatch {
                field: "runtime version",
                ..
            })
        ));
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

    #[test]
    fn control_characters_in_trace_labels_are_rejected() {
        let mut trace = trace();
        trace.events[0].operation = "write\u{1b}[2J".into();

        assert!(matches!(
            trace.validate(),
            Err(ReplayError::InvalidTrace { .. })
        ));
    }

    #[test]
    fn oversized_trace_output_is_rejected() {
        let mut trace = trace();
        trace.result.output = "x".repeat(MAX_TRACE_OUTPUT_BYTES + 1);

        assert!(matches!(
            trace.validate(),
            Err(ReplayError::InvalidTrace { .. })
        ));
    }
}

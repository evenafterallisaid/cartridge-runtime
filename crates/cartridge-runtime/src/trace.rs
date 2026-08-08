use cartridge_core::PackageManifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const CURRENT_TRACE_FORMAT_VERSION: u32 = 2;

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
    pub(crate) fn new(
        manifest: &PackageManifest,
        args: &[String],
        events: Vec<TraceEvent>,
        result: TraceResult,
    ) -> Self {
        Self {
            format_version: CURRENT_TRACE_FORMAT_VERSION,
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            cartridge_id: manifest.cartridge.id.clone(),
            cartridge_version: manifest.cartridge.version.clone(),
            component_sha256: manifest.integrity.component_sha256.clone(),
            args: args.to_vec(),
            events,
            result,
        }
    }

    pub fn validate_invocation(
        &self,
        manifest: &PackageManifest,
        args: &[String],
    ) -> Result<(), ReplayError> {
        if self.format_version != CURRENT_TRACE_FORMAT_VERSION {
            return Err(ReplayError::UnsupportedFormat {
                found: self.format_version,
                expected: CURRENT_TRACE_FORMAT_VERSION,
            });
        }
        check_identity("cartridge id", &self.cartridge_id, &manifest.cartridge.id)?;
        check_identity(
            "cartridge version",
            &self.cartridge_version,
            &manifest.cartridge.version,
        )?;
        check_identity(
            "component sha256",
            &self.component_sha256,
            &manifest.integrity.component_sha256,
        )?;
        if self.args != args {
            return Err(ReplayError::InvocationMismatch {
                expected: self.args.clone(),
                actual: args.to_vec(),
            });
        }
        Ok(())
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceResult {
    pub output: String,
    pub fuel_consumed: u64,
}

impl TraceResult {
    pub(crate) fn compare(&self, actual: &Self) -> Result<(), ReplayError> {
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

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ReplayError {
    #[error("unsupported trace format {found}; this runtime expects {expected}")]
    UnsupportedFormat { found: u32, expected: u32 },
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

#[cfg(test)]
mod tests {
    use super::*;
    use cartridge_core::{CartridgeMetadata, Integrity, Permissions, RuntimeLimits, Services};
    use std::collections::BTreeMap;

    fn manifest() -> PackageManifest {
        PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.trace".into(),
                name: "Trace".into(),
                version: "0.1.0".into(),
                description: String::new(),
            },
            permissions: Permissions::default(),
            runtime: RuntimeLimits::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity {
                component_sha256: "a".repeat(64),
                assets_sha256: BTreeMap::default(),
            },
        }
    }

    #[test]
    fn invocation_arguments_are_part_of_trace_identity() {
        let expected = vec!["one".to_owned()];
        let trace = ExecutionTrace::new(
            &manifest(),
            &expected,
            Vec::new(),
            TraceResult {
                output: String::new(),
                fuel_consumed: 0,
            },
        );

        let error = trace
            .validate_invocation(&manifest(), &["two".to_owned()])
            .unwrap_err();

        assert!(matches!(error, ReplayError::InvocationMismatch { .. }));
    }

    #[test]
    fn final_output_is_checked_after_replay() {
        let expected = TraceResult {
            output: "first".into(),
            fuel_consumed: 10,
        };
        let actual = TraceResult {
            output: "second".into(),
            fuel_consumed: 10,
        };

        assert!(matches!(
            expected.compare(&actual),
            Err(ReplayError::ResultMismatch {
                field: "output",
                ..
            })
        ));
    }
}

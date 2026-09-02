use std::path::PathBuf;

use cartridge_network::{ServiceRequest, ServiceResponse};
use serde::{Deserialize, Serialize};

use super::{
    EngineStore, MAX_STACK_REPLICAS, ReplicaId, RouteTarget, StackCapability, ensure_directory,
    is_digest, valid_name,
};

pub const ENGINE_INVOCATION_FORMAT_VERSION: u32 = 1;
pub const MAX_INVOCATION_ENVELOPE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_INVOCATIONS_PER_REPLICA: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequestEnvelope {
    pub format_version: u32,
    pub stack: String,
    pub routing_epoch: String,
    pub routing_sequence: u64,
    pub target: RouteTarget,
    pub issued_at_ms: u64,
    pub deadline_at_ms: u64,
    pub request: ServiceRequest,
}

impl InvocationRequestEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_INVOCATION_FORMAT_VERSION
            || !valid_name(&self.stack)
            || !is_digest(&self.routing_epoch)
            || self.routing_sequence == 0
            || self.issued_at_ms == 0
            || self.deadline_at_ms <= self.issued_at_ms
            || self.deadline_at_ms.saturating_sub(self.issued_at_ms)
                > cartridge_network::MAX_SERVICE_TIMEOUT_MS
        {
            return Err("invocation request identity is invalid".into());
        }
        self.request.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResponseEnvelope {
    pub format_version: u32,
    pub stack: String,
    pub target: RouteTarget,
    pub request_id: String,
    pub responded_at_ms: u64,
    pub response: ServiceResponse,
}

impl InvocationResponseEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_INVOCATION_FORMAT_VERSION
            || !valid_name(&self.stack)
            || !is_digest(&self.request_id)
            || self.responded_at_ms == 0
        {
            return Err("invocation response identity is invalid".into());
        }
        self.response.validate()
    }
}

impl EngineStore {
    pub fn invocation_directory(
        &self,
        stack: &str,
        target: &RouteTarget,
    ) -> Result<PathBuf, String> {
        if !self.route_target_is_ready(stack, target)? {
            return Err("invocation target is no longer routable".into());
        }
        let generation = self
            .generation_target(stack, &target.generation)?
            .ok_or_else(|| "invocation generation is no longer authorized".to_string())?;
        let instance = generation
            .plan
            .instances
            .iter()
            .find(|instance| instance.name == target.instance)
            .ok_or_else(|| "invocation instance is not in the generation".to_string())?;
        if !instance.allowed.contains(&StackCapability::Serve) {
            return Err("instance was not granted the serve capability".into());
        }
        self.replica_invocation_directory(
            stack,
            &target.generation,
            &ReplicaId {
                instance: target.instance.clone(),
                ordinal: target.ordinal,
            },
            &target.run_id,
        )
    }

    pub fn replica_invocation_directory(
        &self,
        stack: &str,
        generation: &str,
        id: &ReplicaId,
        run_id: &str,
    ) -> Result<PathBuf, String> {
        if !valid_name(stack)
            || !is_digest(generation)
            || !valid_name(&id.instance)
            || id.ordinal == 0
            || id.ordinal > MAX_STACK_REPLICAS
            || !is_digest(run_id)
        {
            return Err("invocation channel identity is invalid".into());
        }
        let target = self
            .generation_target(stack, generation)?
            .ok_or_else(|| "invocation generation is no longer authorized".to_string())?;
        let instance = target
            .plan
            .instances
            .iter()
            .find(|instance| instance.name == id.instance)
            .ok_or_else(|| "invocation instance is not in the generation".to_string())?;
        if id.ordinal > instance.replicas {
            return Err("invocation replica is outside the generation".into());
        }
        if !instance.allowed.contains(&StackCapability::Serve) {
            return Err("instance was not granted the serve capability".into());
        }
        let stack_root = self.root.join("stacks").join(stack);
        let invocations = stack_root.join("invocations");
        ensure_directory(&invocations)?;
        let generation_root = invocations.join(generation);
        ensure_directory(&generation_root)?;
        let replica_root = generation_root.join(format!("{}-{}", id.instance, id.ordinal));
        ensure_directory(&replica_root)?;
        let directory = replica_root.join(run_id);
        ensure_directory(&directory)?;
        Ok(directory)
    }
}

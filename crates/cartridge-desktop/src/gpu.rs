use serde::{Deserialize, Serialize};

pub const GPU_PROTOCOL_VERSION: u32 = 1;
pub const MAX_GPU_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_GPU_TEXTURE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_GPU_COMMANDS: u32 = 65_536;
pub const MAX_GPU_PASSES: u32 = 256;
pub const MAX_SHADER_BYTES: u64 = 1024 * 1024;
pub const MAX_GPU_STREAM_BYTES: usize = 16 * 1024 * 1024;
const GPU_HEADER_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphicsMode {
    CanonicalCpu,
    AcceleratedGpu,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuBackend {
    Metal,
    Vulkan,
    Direct3d12,
    WebGpu,
    Software,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuLimits {
    pub buffer_bytes: u64,
    pub texture_bytes: u64,
    pub commands: u32,
    pub passes: u32,
    pub shader_bytes: u64,
}

impl Default for GpuLimits {
    fn default() -> Self {
        Self {
            buffer_bytes: 64 * 1024 * 1024,
            texture_bytes: 128 * 1024 * 1024,
            commands: 16_384,
            passes: 64,
            shader_bytes: 256 * 1024,
        }
    }
}

impl GpuLimits {
    pub fn validate(&self) -> Result<(), String> {
        if self.buffer_bytes == 0 || self.buffer_bytes > MAX_GPU_BUFFER_BYTES {
            return Err("GPU buffer budget is outside the supported range".into());
        }
        if self.texture_bytes == 0 || self.texture_bytes > MAX_GPU_TEXTURE_BYTES {
            return Err("GPU texture budget is outside the supported range".into());
        }
        if self.commands == 0 || self.commands > MAX_GPU_COMMANDS {
            return Err("GPU command budget is outside the supported range".into());
        }
        if self.passes == 0 || self.passes > MAX_GPU_PASSES {
            return Err("GPU pass budget is outside the supported range".into());
        }
        if self.shader_bytes == 0 || self.shader_bytes > MAX_SHADER_BYTES {
            return Err("GPU shader budget is outside the supported range".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuAdapterInfo {
    pub backend: GpuBackend,
    pub name: String,
    pub driver: String,
    pub supports_robust_buffer_access: bool,
    pub supports_process_isolation: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenderPolicy {
    pub mode: GraphicsMode,
    pub allow_custom_shaders: bool,
    pub require_robust_buffer_access: bool,
    pub require_helper_process: bool,
    pub limits: GpuLimits,
}

impl RenderPolicy {
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            mode: GraphicsMode::CanonicalCpu,
            allow_custom_shaders: false,
            require_robust_buffer_access: true,
            require_helper_process: true,
            limits: GpuLimits::default(),
        }
    }

    pub fn validate_for(&self, adapter: &GpuAdapterInfo) -> Result<(), String> {
        self.limits.validate()?;
        if self.mode == GraphicsMode::AcceleratedGpu
            && self.require_robust_buffer_access
            && !adapter.supports_robust_buffer_access
        {
            return Err("GPU adapter does not provide robust buffer access".into());
        }
        if self.mode == GraphicsMode::AcceleratedGpu
            && self.require_helper_process
            && !adapter.supports_process_isolation
        {
            return Err("accelerated graphics requires an isolated GPU helper".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedGpuStream {
    bytes: Vec<u8>,
    commands: u32,
    passes: u32,
}

impl ValidatedGpuStream {
    pub fn parse(bytes: Vec<u8>, policy: &RenderPolicy) -> Result<Self, String> {
        policy.limits.validate()?;
        if bytes.len() < GPU_HEADER_BYTES || bytes.len() > MAX_GPU_STREAM_BYTES {
            return Err("GPU command stream is outside its byte limit".into());
        }
        if &bytes[..4] != b"CGRP" {
            return Err("GPU command stream has an invalid magic value".into());
        }
        let version = read_u32(&bytes, 4)?;
        if version != GPU_PROTOCOL_VERSION {
            return Err("GPU command stream version is unsupported".into());
        }
        let commands = read_u32(&bytes, 8)?;
        let passes = read_u32(&bytes, 12)?;
        if commands > policy.limits.commands || passes > policy.limits.passes {
            return Err("GPU command stream exceeds its command or pass budget".into());
        }
        Ok(Self {
            bytes,
            commands,
            passes,
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn commands(&self) -> u32 {
        self.commands
    }

    #[must_use]
    pub fn passes(&self) -> u32 {
        self.passes
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "GPU command stream header is truncated".to_string())?;
    let value: [u8; 4] = value
        .try_into()
        .map_err(|_| "GPU command stream header is malformed".to_string())?;
    Ok(u32::from_le_bytes(value))
}

pub trait GraphicsPresenter {
    type Error;

    fn adapter(&self) -> &GpuAdapterInfo;
    fn present(&mut self, stream: &ValidatedGpuStream) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unisolated_acceleration() {
        let policy = RenderPolicy {
            mode: GraphicsMode::AcceleratedGpu,
            ..RenderPolicy::canonical()
        };
        let adapter = GpuAdapterInfo {
            backend: GpuBackend::Vulkan,
            name: "test".into(),
            driver: "test".into(),
            supports_robust_buffer_access: true,
            supports_process_isolation: false,
        };
        assert!(policy.validate_for(&adapter).is_err());
    }

    #[test]
    fn stream_validation_rejects_bad_headers_and_excess_work() {
        let policy = RenderPolicy::canonical();
        assert!(ValidatedGpuStream::parse(vec![0; 16], &policy).is_err());
        let mut bytes = Vec::from(b"CGRP".as_slice());
        bytes.extend_from_slice(&GPU_PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(policy.limits.commands + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(ValidatedGpuStream::parse(bytes, &policy).is_err());
    }
}

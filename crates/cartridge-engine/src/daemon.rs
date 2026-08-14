use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use fs4::{FileExt, TryLockError};
use rand::random;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{
    ApplyReport, EngineEvent, RolloutStatus, StackHealthReport, StackManifest, StackPlan,
    StackRuntimeStatus, StackStatus, ensure_directory, is_digest, is_regular_file, private_options,
    valid_name, valid_text, validate_health_reports,
};

pub const DAEMON_PROTOCOL_VERSION: u32 = 2;
pub const DAEMON_ENDPOINT_FILE: &str = "daemon.json";
pub const MAX_DAEMON_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DAEMON_EVENTS: u16 = 256;
pub const MAX_DAEMON_SUPERVISORS: u16 = 64;
const MAX_DAEMON_ENDPOINT_BYTES: u64 = 4096;
const DAEMON_DIRECTION_REQUEST: &[u8] = b"cartridge-daemon-request-v1";
const DAEMON_DIRECTION_RESPONSE: &[u8] = b"cartridge-daemon-response-v1";
const DAEMON_CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
static ENDPOINT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonEndpoint {
    pub protocol_version: u32,
    pub instance_id: String,
    pub key_hex: String,
    pub port: u16,
    pub pid: u32,
    pub started_at_ms: u64,
}

impl fmt::Debug for DaemonEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonEndpoint")
            .field("protocol_version", &self.protocol_version)
            .field("instance_id", &self.instance_id)
            .field("key_hex", &"[redacted]")
            .field("port", &self.port)
            .field("pid", &self.pid)
            .field("started_at_ms", &self.started_at_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonInfo {
    pub protocol_version: u32,
    pub instance_id: String,
    pub pid: u32,
    pub started_at_ms: u64,
    pub active_supervisors: u16,
    pub max_supervisors: u16,
    pub workers_per_stack: u16,
    pub known_stacks: u32,
    pub applied_stacks: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "kebab-case",
    tag = "kind",
    content = "data"
)]
pub enum DaemonRequest {
    Ping,
    Info,
    List,
    Status {
        stack: String,
    },
    RuntimeStatus {
        stack: String,
    },
    Events {
        stack: String,
        tail: u16,
    },
    Health {
        stack: Option<String>,
    },
    Plan {
        manifest: Box<StackManifest>,
    },
    Apply {
        plan: Box<StackPlan>,
        allow_insecure: bool,
    },
    RolloutStatus {
        stack: String,
    },
    RolloutPrepare {
        plan: Box<StackPlan>,
        allow_insecure: bool,
    },
    RolloutActivate {
        stack: String,
        rollout_id: String,
    },
    RolloutCommit {
        stack: String,
        rollout_id: String,
    },
    RolloutRollback {
        stack: String,
        rollout_id: String,
    },
    Stop {
        stack: String,
    },
    Remove {
        stack: String,
    },
    Shutdown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "kebab-case",
    tag = "kind",
    content = "data"
)]
pub enum DaemonResponse {
    Pong,
    Info(DaemonInfo),
    Stacks(Vec<StackStatus>),
    Status(StackStatus),
    RuntimeStatus(Option<StackRuntimeStatus>),
    Events(Vec<EngineEvent>),
    Health(Vec<StackHealthReport>),
    Planned(Box<StackPlan>),
    Applied(ApplyReport),
    Rollout(Option<RolloutStatus>),
    Stopped(ApplyReport),
    Removed(ApplyReport),
    ShuttingDown,
    Error { code: String, message: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonFrame {
    pub protocol_version: u32,
    pub instance_id: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    request_id: String,
    issued_at_ms: u64,
    request: DaemonRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    request_id: String,
    response: DaemonResponse,
}

pub struct OpenedDaemonRequest {
    pub request_id: String,
    pub issued_at_ms: u64,
    pub request: DaemonRequest,
}

pub struct DaemonCodec {
    instance_id: String,
    key: [u8; 32],
}

pub struct DaemonLease {
    root: PathBuf,
    _lock: File,
}

impl Drop for DaemonCodec {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for DaemonEndpoint {
    fn drop(&mut self) {
        self.key_hex.zeroize();
    }
}

impl DaemonEndpoint {
    pub fn read(root: &Path) -> Result<Self, String> {
        let path = root.join(DAEMON_ENDPOINT_FILE);
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DAEMON_ENDPOINT_BYTES
        {
            return Err("daemon endpoint must be a bounded regular file".into());
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|error| error.to_string())?
            .take(MAX_DAEMON_ENDPOINT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_DAEMON_ENDPOINT_BYTES {
            return Err("daemon endpoint exceeded its byte limit while reading".into());
        }
        let endpoint: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != DAEMON_PROTOCOL_VERSION
            || !is_digest(&self.instance_id)
            || !is_digest(&self.key_hex)
            || self.port == 0
            || self.pid == 0
            || self.started_at_ms == 0
        {
            return Err("daemon endpoint identity is invalid".into());
        }
        Ok(())
    }
}

impl DaemonInfo {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != DAEMON_PROTOCOL_VERSION
            || !is_digest(&self.instance_id)
            || self.pid == 0
            || self.started_at_ms == 0
            || self.active_supervisors > self.max_supervisors
            || self.max_supervisors == 0
            || self.max_supervisors > MAX_DAEMON_SUPERVISORS
            || self.workers_per_stack == 0
            || self.workers_per_stack > super::MAX_STACK_TOTAL_REPLICAS
            || self.applied_stacks > self.known_stacks
        {
            return Err("daemon information is invalid".into());
        }
        Ok(())
    }
}

impl DaemonRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Ping | Self::Info | Self::List | Self::Shutdown => Ok(()),
            Self::Status { stack }
            | Self::RuntimeStatus { stack }
            | Self::RolloutStatus { stack }
            | Self::Stop { stack }
            | Self::Remove { stack }
                if valid_name(stack) =>
            {
                Ok(())
            }
            Self::Events { stack, tail }
                if valid_name(stack) && *tail > 0 && *tail <= MAX_DAEMON_EVENTS =>
            {
                Ok(())
            }
            Self::Health { stack } if stack.as_ref().is_none_or(|value| valid_name(value)) => {
                Ok(())
            }
            Self::Plan { manifest } => manifest.validate(),
            Self::Apply { plan, .. } | Self::RolloutPrepare { plan, .. } => plan.validate(),
            Self::RolloutActivate { stack, rollout_id }
            | Self::RolloutCommit { stack, rollout_id }
            | Self::RolloutRollback { stack, rollout_id }
                if valid_name(stack) && is_digest(rollout_id) =>
            {
                Ok(())
            }
            _ => Err("daemon request is invalid".into()),
        }
    }
}

impl DaemonResponse {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Info(info) => info.validate(),
            Self::Stacks(stacks) => validate_stack_responses(stacks),
            Self::Status(status) => validate_stack_responses(std::slice::from_ref(status)),
            Self::RuntimeStatus(Some(status)) => status.validate(),
            Self::Pong | Self::ShuttingDown | Self::RuntimeStatus(None) | Self::Rollout(None) => {
                Ok(())
            }
            Self::Events(events) => {
                if events.len() > usize::from(MAX_DAEMON_EVENTS) {
                    return Err("daemon response contains too many events".into());
                }
                for event in events {
                    event.validate()?;
                }
                Ok(())
            }
            Self::Health(reports) => validate_health_reports(reports),
            Self::Planned(plan) => plan.validate(),
            Self::Rollout(Some(record)) => record.validate(),
            Self::Applied(report) | Self::Stopped(report) | Self::Removed(report) => {
                validate_stack_responses(std::slice::from_ref(&report.status))
            }
            Self::Error { code, message }
                if valid_name(code) && valid_text(message, 1024, false) =>
            {
                Ok(())
            }
            Self::Error { .. } => Err("daemon error response is invalid".into()),
        }
    }
}

impl DaemonFrame {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != DAEMON_PROTOCOL_VERSION
            || !is_digest(&self.instance_id)
            || self.nonce_hex.len() != 48
            || !lower_hex(&self.nonce_hex)
            || self.ciphertext_hex.is_empty()
            || self.ciphertext_hex.len() > MAX_DAEMON_FRAME_BYTES.saturating_mul(2)
            || self.ciphertext_hex.len() % 2 != 0
            || !lower_hex(&self.ciphertext_hex)
        {
            return Err("daemon frame is invalid".into());
        }
        Ok(())
    }
}

impl DaemonCodec {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            instance_id: hex::encode(random::<[u8; 32]>()),
            key: random(),
        }
    }

    pub fn from_endpoint(endpoint: &DaemonEndpoint) -> Result<Self, String> {
        endpoint.validate()?;
        let key: [u8; 32] = hex::decode(&endpoint.key_hex)
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "daemon endpoint key has the wrong length".to_string())?;
        Ok(Self {
            instance_id: endpoint.instance_id.clone(),
            key,
        })
    }

    #[must_use]
    pub fn endpoint(&self, port: u16, pid: u32, started_at_ms: u64) -> DaemonEndpoint {
        DaemonEndpoint {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            instance_id: self.instance_id.clone(),
            key_hex: hex::encode(self.key),
            port,
            pid,
            started_at_ms,
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn seal_request(
        &self,
        request: DaemonRequest,
        issued_at_ms: u64,
    ) -> Result<(String, Vec<u8>), String> {
        request.validate()?;
        if issued_at_ms == 0 {
            return Err("daemon request timestamp is invalid".into());
        }
        let request_id = hex::encode(random::<[u8; 32]>());
        let envelope = RequestEnvelope {
            request_id: request_id.clone(),
            issued_at_ms,
            request,
        };
        let bytes = self.seal(DAEMON_DIRECTION_REQUEST, &envelope)?;
        Ok((request_id, bytes))
    }

    pub fn open_request(&self, bytes: &[u8]) -> Result<OpenedDaemonRequest, String> {
        let envelope: RequestEnvelope = self.open(DAEMON_DIRECTION_REQUEST, bytes)?;
        if !is_digest(&envelope.request_id) || envelope.issued_at_ms == 0 {
            return Err("daemon request envelope is invalid".into());
        }
        envelope.request.validate()?;
        Ok(OpenedDaemonRequest {
            request_id: envelope.request_id,
            issued_at_ms: envelope.issued_at_ms,
            request: envelope.request,
        })
    }

    pub fn seal_response(
        &self,
        request_id: &str,
        response: DaemonResponse,
    ) -> Result<Vec<u8>, String> {
        if !is_digest(request_id) {
            return Err("daemon response request identity is invalid".into());
        }
        response.validate()?;
        self.seal(
            DAEMON_DIRECTION_RESPONSE,
            &ResponseEnvelope {
                request_id: request_id.into(),
                response,
            },
        )
    }

    pub fn open_response(
        &self,
        expected_request_id: &str,
        bytes: &[u8],
    ) -> Result<DaemonResponse, String> {
        if !is_digest(expected_request_id) {
            return Err("daemon response request identity is invalid".into());
        }
        let envelope: ResponseEnvelope = self.open(DAEMON_DIRECTION_RESPONSE, bytes)?;
        if envelope.request_id != expected_request_id {
            return Err("daemon response belongs to another request".into());
        }
        envelope.response.validate()?;
        Ok(envelope.response)
    }

    fn seal<T: Serialize>(&self, direction: &[u8], value: &T) -> Result<Vec<u8>, String> {
        let plaintext = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        let maximum_plaintext = MAX_DAEMON_FRAME_BYTES.saturating_sub(1024) / 2;
        if plaintext.len() > maximum_plaintext {
            return Err("daemon message exceeds its byte limit".into());
        }
        let nonce = random::<[u8; 24]>();
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "daemon nonce has the wrong length".to_string())?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let associated = associated_data(direction, &self.instance_id);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: &associated,
                },
            )
            .map_err(|_| "daemon message encryption failed".to_string())?;
        let frame = DaemonFrame {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            instance_id: self.instance_id.clone(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };
        frame.validate()?;
        let bytes = serde_json::to_vec(&frame).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_DAEMON_FRAME_BYTES {
            return Err("daemon frame exceeds its byte limit".into());
        }
        Ok(bytes)
    }

    fn open<T: for<'de> Deserialize<'de>>(
        &self,
        direction: &[u8],
        bytes: &[u8],
    ) -> Result<T, String> {
        if bytes.is_empty() || bytes.len() > MAX_DAEMON_FRAME_BYTES {
            return Err("daemon frame exceeds its byte limit".into());
        }
        let frame: DaemonFrame =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        frame.validate()?;
        if frame.instance_id != self.instance_id {
            return Err("daemon frame belongs to another engine instance".into());
        }
        let nonce = hex::decode(frame.nonce_hex).map_err(|error| error.to_string())?;
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "daemon nonce has the wrong length".to_string())?;
        let ciphertext = hex::decode(frame.ciphertext_hex).map_err(|error| error.to_string())?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let associated = associated_data(direction, &self.instance_id);
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: &associated,
                },
            )
            .map_err(|_| "daemon message authentication failed".to_string())?;
        serde_json::from_slice(&plaintext).map_err(|error| error.to_string())
    }
}

impl DaemonLease {
    pub fn acquire(root: &Path) -> Result<Self, String> {
        ensure_directory(root)?;
        ensure_daemon_root_private(root)?;
        let path = root.join("daemon.lock");
        if path.exists() && !is_regular_file(&path) {
            return Err("daemon lock path is not a regular file".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options.open(path).map_err(|error| error.to_string())?;
        match FileExt::try_lock(&lock) {
            Ok(()) => Ok(Self {
                root: root.into(),
                _lock: lock,
            }),
            Err(TryLockError::WouldBlock) => Err("engine daemon is already running".into()),
            Err(TryLockError::Error(error)) => Err(error.to_string()),
        }
    }

    pub fn is_active(root: &Path) -> Result<bool, String> {
        let path = root.join("daemon.lock");
        if !path.exists() {
            return Ok(false);
        }
        if !is_regular_file(&path) {
            return Err("daemon lock path is not a regular file".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        let lock = options.open(path).map_err(|error| error.to_string())?;
        match FileExt::try_lock(&lock) {
            Ok(()) => Ok(false),
            Err(TryLockError::WouldBlock) => Ok(true),
            Err(TryLockError::Error(error)) => Err(error.to_string()),
        }
    }

    pub fn publish(&self, endpoint: &DaemonEndpoint) -> Result<(), String> {
        endpoint.validate()?;
        let bytes = serde_json::to_vec(endpoint).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_DAEMON_ENDPOINT_BYTES {
            return Err("daemon endpoint exceeds its byte limit".into());
        }
        replace_private(&self.root.join(DAEMON_ENDPOINT_FILE), &bytes)
    }

    pub fn remove_endpoint(&self, instance_id: &str) -> Result<(), String> {
        let path = self.root.join(DAEMON_ENDPOINT_FILE);
        if !path.exists() {
            return Ok(());
        }
        let endpoint = DaemonEndpoint::read(&self.root)?;
        if endpoint.instance_id != instance_id {
            return Err("refusing to remove another daemon's endpoint".into());
        }
        fs::remove_file(path).map_err(|error| error.to_string())
    }
}

pub fn daemon_request(root: &Path, request: DaemonRequest) -> Result<DaemonResponse, String> {
    daemon_request_with_timeout(root, request, DAEMON_CLIENT_TIMEOUT)
}

pub fn daemon_request_with_timeout(
    root: &Path,
    request: DaemonRequest,
    timeout: Duration,
) -> Result<DaemonResponse, String> {
    if timeout.is_zero() {
        return Err("engine request timeout is invalid".into());
    }
    let timeout = timeout.min(DAEMON_CLIENT_TIMEOUT);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "engine request deadline overflow".to_string())?;
    let endpoint = DaemonEndpoint::read(root)?;
    if !DaemonLease::is_active(root)? {
        return Err("engine daemon is not running".into());
    }
    let codec = DaemonCodec::from_endpoint(&endpoint)?;
    let (request_id, frame) = codec.seal_request(request, current_time_ms()?)?;
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, endpoint.port));
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)
        .map_err(|error| format!("could not connect to the engine daemon: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("could not configure the engine daemon connection: {error}"))?;
    write_frame_before(&mut stream, &frame, deadline)?;
    let response = read_frame_before(&mut stream, deadline)?;
    let response = codec.open_response(&request_id, &response)?;
    match response {
        DaemonResponse::Error { code, message } => Err(format!("engine {code}: {message}")),
        response => Ok(response),
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err("engine request deadline exceeded".into())
    } else {
        Ok(remaining)
    }
}

fn read_frame_before(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    read_exact_before(stream, &mut length, deadline, "engine frame length")?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "engine frame length overflow".to_string())?;
    if length == 0 || length > MAX_DAEMON_FRAME_BYTES {
        return Err("engine frame length is invalid".into());
    }
    let mut frame = vec![0_u8; length];
    read_exact_before(stream, &mut frame, deadline, "engine frame")?;
    Ok(frame)
}

fn read_exact_before(
    stream: &mut TcpStream,
    mut buffer: &mut [u8],
    deadline: Instant,
    label: &str,
) -> Result<(), String> {
    while !buffer.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|error| {
                format!("could not configure the engine daemon connection: {error}")
            })?;
        match stream.read(buffer) {
            Ok(0) => return Err(format!("could not read {label}: connection closed")),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err("engine request deadline exceeded".into());
            }
            Err(error) => return Err(format!("could not read {label}: {error}")),
        }
    }
    Ok(())
}

fn write_frame_before(
    stream: &mut TcpStream,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    if frame.is_empty() || frame.len() > MAX_DAEMON_FRAME_BYTES {
        return Err("engine frame length is invalid".into());
    }
    let length =
        u32::try_from(frame.len()).map_err(|_| "engine frame length overflow".to_string())?;
    write_all_before(stream, &length.to_be_bytes(), deadline)?;
    write_all_before(stream, frame, deadline)?;
    stream
        .flush()
        .map_err(|error| format!("could not write engine frame: {error}"))
}

fn write_all_before(
    stream: &mut TcpStream,
    mut remaining_bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    while !remaining_bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|error| {
                format!("could not configure the engine daemon connection: {error}")
            })?;
        match stream.write(remaining_bytes) {
            Ok(0) => return Err("could not write engine frame: connection closed".into()),
            Ok(written) => remaining_bytes = &remaining_bytes[written..],
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err("engine request deadline exceeded".into());
            }
            Err(error) => return Err(format!("could not write engine frame: {error}")),
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("could not read engine frame length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "engine frame length overflow".to_string())?;
    if length == 0 || length > MAX_DAEMON_FRAME_BYTES {
        return Err("engine frame length is invalid".into());
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .map_err(|error| format!("could not read engine frame: {error}"))?;
    Ok(frame)
}

#[cfg(test)]
fn write_frame(stream: &mut impl Write, frame: &[u8]) -> Result<(), String> {
    if frame.is_empty() || frame.len() > MAX_DAEMON_FRAME_BYTES {
        return Err("engine frame length is invalid".into());
    }
    let length =
        u32::try_from(frame.len()).map_err(|_| "engine frame length overflow".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(frame))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not write engine frame: {error}"))
}

fn current_time_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_string())?
        .as_millis();
    u64::try_from(value).map_err(|_| "system clock is outside the supported range".to_string())
}

#[cfg(unix)]
fn ensure_daemon_root_private(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::symlink_metadata(root)
        .map_err(|error| error.to_string())?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("daemon root must not be accessible to group or other users".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_daemon_root_private(root: &Path) -> Result<(), String> {
    fs::metadata(root).map_err(|error| error.to_string())?;
    Ok(())
}

fn associated_data(direction: &[u8], instance_id: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(direction.len() + instance_id.len() + 8);
    value.extend_from_slice(&(direction.len() as u64).to_le_bytes());
    value.extend_from_slice(direction);
    value.extend_from_slice(instance_id.as_bytes());
    value
}

fn validate_stack_responses(stacks: &[StackStatus]) -> Result<(), String> {
    if stacks.len() > 1024 {
        return Err("daemon response contains too many stacks".into());
    }
    if stacks.iter().any(|status| {
        !valid_name(&status.stack)
            || status.revision == 0
            || !is_digest(&status.event_sha256)
            || status
                .plan_sha256
                .as_ref()
                .is_some_and(|digest| !is_digest(digest))
    }) {
        return Err("daemon stack response is invalid".into());
    }
    Ok(())
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| "daemon endpoint has no parent".to_string())?;
    ensure_directory(directory)?;
    let sequence = ENDPOINT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".daemon-endpoint-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    drop(file);
    if path.exists() {
        if !is_regular_file(path) {
            let _ = fs::remove_file(&temporary);
            return Err("daemon endpoint path is not a regular file".into());
        }
        let backup = path.with_extension("json.previous");
        if backup.exists() {
            if !is_regular_file(&backup) {
                let _ = fs::remove_file(&temporary);
                return Err("daemon endpoint backup is not a regular file".into());
            }
            fs::remove_file(&backup).map_err(|error| error.to_string())?;
        }
        fs::rename(path, &backup).map_err(|error| error.to_string())?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&backup, path);
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    } else {
        fs::rename(temporary, path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, sync::Arc, thread};

    #[test]
    fn request_and_response_frames_are_confidential_and_bound_to_the_instance() {
        let codec = DaemonCodec::generate();
        let (request_id, encoded) = codec.seal_request(DaemonRequest::Ping, 10).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("ping"));
        let opened = codec.open_request(&encoded).unwrap();
        assert_eq!(opened.request_id, request_id);
        assert!(matches!(opened.request, DaemonRequest::Ping));

        let response = codec
            .seal_response(&request_id, DaemonResponse::Pong)
            .unwrap();
        assert_eq!(
            codec.open_response(&request_id, &response).unwrap(),
            DaemonResponse::Pong
        );
        assert!(DaemonCodec::generate().open_request(&encoded).is_err());
    }

    #[test]
    fn changed_frames_and_cross_direction_replay_fail_closed() {
        let codec = DaemonCodec::generate();
        let (request_id, mut encoded) = codec.seal_request(DaemonRequest::Ping, 10).unwrap();
        let last = encoded.len() - 2;
        encoded[last] = if encoded[last] == b'a' { b'b' } else { b'a' };
        assert!(codec.open_request(&encoded).is_err());

        let (_, request) = codec.seal_request(DaemonRequest::Ping, 11).unwrap();
        assert!(codec.open_response(&request_id, &request).is_err());
    }

    #[test]
    fn protocol_documents_reject_unknown_fields() {
        assert!(
            serde_json::from_str::<DaemonRequest>(
                r#"{"kind":"status","data":{"stack":"demo","extra":true}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<DaemonFrame>(
                r#"{"protocol_version":1,"instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ciphertext_hex":"aa","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_round_trip_is_private_and_never_debugs_the_key() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lease = DaemonLease::acquire(directory.path()).unwrap();
        let codec = DaemonCodec::generate();
        let endpoint = codec.endpoint(1234, 42, 10);
        lease.publish(&endpoint).unwrap();
        assert_eq!(DaemonEndpoint::read(directory.path()).unwrap(), endpoint);
        assert!(!format!("{endpoint:?}").contains(&endpoint.key_hex));
        lease.remove_endpoint(codec.instance_id()).unwrap();
        assert!(!directory.path().join(DAEMON_ENDPOINT_FILE).exists());
    }

    #[test]
    fn shared_client_authenticates_and_bounds_a_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lease = DaemonLease::acquire(directory.path()).unwrap();
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let codec = Arc::new(DaemonCodec::generate());
        let endpoint = codec.endpoint(listener.local_addr().unwrap().port(), 42, 10);
        lease.publish(&endpoint).unwrap();
        let server_codec = codec.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let frame = read_frame(&mut stream).unwrap();
            let opened = server_codec.open_request(&frame).unwrap();
            assert!(matches!(opened.request, DaemonRequest::Ping));
            let response = server_codec
                .seal_response(&opened.request_id, DaemonResponse::Pong)
                .unwrap();
            write_frame(&mut stream, &response).unwrap();
        });

        assert_eq!(
            daemon_request(directory.path(), DaemonRequest::Ping).unwrap(),
            DaemonResponse::Pong
        );
        server.join().unwrap();
    }

    #[test]
    fn shared_client_rejects_a_zero_deadline_before_endpoint_access() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            daemon_request_with_timeout(directory.path(), DaemonRequest::Ping, Duration::ZERO)
                .unwrap_err(),
            "engine request timeout is invalid"
        );
    }

    #[test]
    fn shared_client_enforces_the_response_deadline() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lease = DaemonLease::acquire(directory.path()).unwrap();
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let codec = DaemonCodec::generate();
        lease
            .publish(&codec.endpoint(listener.local_addr().unwrap().port(), 42, 10))
            .unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_frame(&mut stream).unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let error = daemon_request_with_timeout(
            directory.path(),
            DaemonRequest::Ping,
            Duration::from_millis(20),
        )
        .unwrap_err();

        assert_eq!(error, "engine request deadline exceeded");
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn daemon_rejects_a_shared_control_root() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(DaemonLease::acquire(directory.path()).is_err());
    }
}

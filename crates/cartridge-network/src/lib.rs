use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroize;

pub const NETWORK_FORMAT_VERSION: u32 = 1;
pub const MAX_HTTP_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_HTTP_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_HTTP_HEADERS: usize = 128;
pub const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_HTTP_SCOPES: usize = 128;
pub const MAX_FIXTURES: usize = 4096;
pub const MAX_CHANNEL_MESSAGES: usize = 4096;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_DOCUMENT_OPERATIONS: usize = 100_000;
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ASSET_BYTES: usize = 128 * 1024 * 1024;
pub const ASSET_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_SIMULATED_PACKETS: usize = 100_000;
pub const MAX_ROLLBACK_DATAGRAMS: usize = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpScope {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path_prefix: String,
    pub methods: BTreeSet<HttpMethod>,
}

impl HttpScope {
    pub fn validate(&self) -> Result<(), String> {
        if self.scheme != "https" && self.scheme != "http" {
            return Err("HTTP scope scheme must be http or https".into());
        }
        if self.scheme == "http" && !is_loopback_host(&self.host) {
            return Err("unencrypted HTTP is limited to loopback hosts".into());
        }
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.contains('/')
            || self.host.contains('@')
            || self.host.chars().any(char::is_control)
        {
            return Err("HTTP scope host is invalid".into());
        }
        if !self.path_prefix.starts_with('/')
            || self.path_prefix.contains("..")
            || self.path_prefix.len() > 2048
        {
            return Err("HTTP path prefix must be an absolute normalized path".into());
        }
        if self.methods.is_empty() {
            return Err("HTTP scope must allow at least one method".into());
        }
        Ok(())
    }

    fn permits(&self, method: HttpMethod, url: &Url) -> bool {
        self.methods.contains(&method)
            && url.scheme() == self.scheme
            && url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && effective_port(url) == self.port.or_else(|| default_port(&self.scheme))
            && path_prefix_matches(&self.path_prefix, url.path())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    pub scopes: Vec<HttpScope>,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_redirects: u8,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            max_request_bytes: MAX_HTTP_REQUEST_BYTES,
            max_response_bytes: MAX_HTTP_RESPONSE_BYTES,
            max_redirects: 0,
        }
    }
}

impl HttpPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.scopes.len() > MAX_HTTP_SCOPES
            || self.max_request_bytes == 0
            || self.max_request_bytes > MAX_HTTP_REQUEST_BYTES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_HTTP_RESPONSE_BYTES
            || self.max_redirects > 10
        {
            return Err("HTTP policy limits are invalid".into());
        }
        for scope in &self.scopes {
            scope.validate()?;
        }
        Ok(())
    }

    pub fn authorize(&self, request: &HttpRequest) -> Result<Url, String> {
        self.validate()?;
        request.validate(self.max_request_bytes)?;
        let url = Url::parse(&request.url).map_err(|_| "request URL is invalid".to_string())?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err("request URLs cannot contain credentials or fragments".into());
        }
        if !self
            .scopes
            .iter()
            .any(|scope| scope.permits(request.method, &url))
        {
            return Err("request URL is outside the declared HTTP scopes".into());
        }
        Ok(url)
    }

    pub fn validate_response(&self, response: &HttpResponse) -> Result<(), String> {
        if response.body.len() > self.max_response_bytes {
            return Err("HTTP response exceeds its byte limit".into());
        }
        if !(100..=599).contains(&response.status) {
            return Err("HTTP response status is invalid".into());
        }
        validate_headers(&response.headers)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn validate(&self, max_body: usize) -> Result<(), String> {
        if self.url.len() > 8192 || self.body.len() > max_body {
            return Err("HTTP request exceeds its size limit".into());
        }
        validate_headers(&self.headers)
    }

    pub fn fingerprint(&self) -> Result<String, String> {
        self.validate(MAX_HTTP_REQUEST_BYTES)?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Vec<u8>,
}

pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String>;
}

impl HttpTransport for HttpFixtures {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        if self.format_version != NETWORK_FORMAT_VERSION || self.responses.len() > MAX_FIXTURES {
            return Err("HTTP fixture document is invalid".into());
        }
        self.responses
            .get(&request.fingerprint()?)
            .cloned()
            .ok_or_else(|| "no HTTP fixture matches this request".into())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFixtures {
    pub format_version: u32,
    pub responses: BTreeMap<String, HttpResponse>,
}

impl HttpFixtures {
    #[must_use]
    pub fn new() -> Self {
        Self {
            format_version: NETWORK_FORMAT_VERSION,
            responses: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        policy: &HttpPolicy,
        request: &HttpRequest,
        response: HttpResponse,
    ) -> Result<(), String> {
        policy.authorize(request)?;
        policy.validate_response(&response)?;
        if self.responses.len() >= MAX_FIXTURES
            && !self.responses.contains_key(&request.fingerprint()?)
        {
            return Err("HTTP fixture limit exceeded".into());
        }
        self.responses.insert(request.fingerprint()?, response);
        Ok(())
    }

    pub fn replay(
        &self,
        policy: &HttpPolicy,
        request: &HttpRequest,
    ) -> Result<HttpResponse, String> {
        if self.format_version != NETWORK_FORMAT_VERSION || self.responses.len() > MAX_FIXTURES {
            return Err("HTTP fixture document is invalid".into());
        }
        policy.authorize(request)?;
        let response = self
            .responses
            .get(&request.fingerprint()?)
            .ok_or_else(|| "no HTTP fixture matches this request".to_string())?
            .clone();
        policy.validate_response(&response)?;
        Ok(response)
    }

    pub fn read(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read;
        let limit = MAX_HTTP_RESPONSE_BYTES.saturating_mul(2);
        if std::fs::metadata(path)
            .map_err(|error| error.to_string())?
            .len()
            > limit as u64
        {
            return Err("HTTP fixture document exceeds its size limit".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|error| error.to_string())?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > limit {
            return Err("HTTP fixture document exceeds its size limit".into());
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if value.format_version != NETWORK_FORMAT_VERSION || value.responses.len() > MAX_FIXTURES {
            return Err("HTTP fixture document is invalid".into());
        }
        Ok(value)
    }
}

pub struct PeerIdentity {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Drop for PeerIdentity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl PeerIdentity {
    #[must_use]
    pub fn generate() -> Self {
        let secret: [u8; 32] = rand::random();
        let public = x25519(secret, X25519_BASEPOINT_BYTES);
        Self { secret, public }
    }

    #[must_use]
    pub fn public(&self) -> PeerPublic {
        PeerPublic {
            peer_id: peer_id(&self.public),
            public_key: hex::encode(self.public),
        }
    }

    pub fn session(&self, remote: &PeerPublic) -> Result<PeerSession, String> {
        remote.validate()?;
        let remote_public = decode_array::<32>(&remote.public_key, "peer public key")?;
        let shared = x25519(self.secret, remote_public);
        if shared == [0; 32] {
            return Err("peer key agreement produced an invalid shared secret".into());
        }
        let mut digest = Sha256::new();
        digest.update(b"cartridge-peer-session-v1");
        digest.update(shared);
        let mut peers = [self.public, remote_public];
        peers.sort_unstable();
        digest.update(peers[0]);
        digest.update(peers[1]);
        let key: [u8; 32] = digest.finalize().into();
        Ok(PeerSession {
            local_peer_id: peer_id(&self.public),
            remote_peer_id: remote.peer_id.clone(),
            key,
            send_sequence: 0,
            receive_sequence: 0,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPublic {
    pub peer_id: String,
    pub public_key: String,
}

impl PeerPublic {
    pub fn validate(&self) -> Result<(), String> {
        let public = decode_array::<32>(&self.public_key, "peer public key")?;
        if peer_id(&public) != self.peer_id {
            return Err("peer id does not match its public key".into());
        }
        Ok(())
    }
}

pub struct PeerSession {
    local_peer_id: String,
    remote_peer_id: String,
    key: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
}

impl Drop for PeerSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedMessage {
    pub sender: String,
    pub recipient: String,
    pub sequence: u64,
    pub nonce: String,
    pub ciphertext: String,
}

impl PeerSession {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage, String> {
        if plaintext.len() > MAX_MESSAGE_BYTES {
            return Err("peer message exceeds its byte limit".into());
        }
        let nonce: [u8; 24] = rand::random();
        let aad = message_aad(
            &self.local_peer_id,
            &self.remote_peer_id,
            self.send_sequence,
        );
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let nonce =
            XNonce::try_from(&nonce[..]).map_err(|_| "peer nonce is invalid".to_string())?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "peer message encryption failed".to_string())?;
        let message = EncryptedMessage {
            sender: self.local_peer_id.clone(),
            recipient: self.remote_peer_id.clone(),
            sequence: self.send_sequence,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| "peer send sequence overflow".to_string())?;
        Ok(message)
    }

    pub fn open(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>, String> {
        if message.sender != self.remote_peer_id
            || message.recipient != self.local_peer_id
            || message.sequence != self.receive_sequence
        {
            return Err("peer message identity or sequence is invalid".into());
        }
        let nonce = decode_array::<24>(&message.nonce, "peer nonce")?;
        let ciphertext = hex::decode(&message.ciphertext)
            .map_err(|_| "peer ciphertext is not hexadecimal".to_string())?;
        if ciphertext.len() > MAX_MESSAGE_BYTES + 32 {
            return Err("peer ciphertext exceeds its byte limit".into());
        }
        let aad = message_aad(&message.sender, &message.recipient, message.sequence);
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let nonce =
            XNonce::try_from(&nonce[..]).map_err(|_| "peer nonce is invalid".to_string())?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "peer message authentication failed".to_string())?;
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or_else(|| "peer receive sequence overflow".to_string())?;
        Ok(plaintext)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecord {
    pub peer: PeerPublic,
    pub route_token: String,
    pub expires_at_ms: u64,
}

impl DiscoveryRecord {
    pub fn validate(&self, now_ms: u64) -> Result<(), String> {
        self.peer.validate()?;
        if self.route_token.len() < 32
            || self.route_token.len() > 512
            || self.route_token.chars().any(char::is_control)
            || self.expires_at_ms <= now_ms
        {
            return Err("discovery record is invalid or expired".into());
        }
        Ok(())
    }
}

pub struct MessageChannel {
    queue: VecDeque<Vec<u8>>,
    max_messages: usize,
    max_bytes: usize,
    bytes: usize,
}

impl MessageChannel {
    pub fn new(max_messages: usize, max_bytes: usize) -> Result<Self, String> {
        if max_messages == 0
            || max_messages > MAX_CHANNEL_MESSAGES
            || max_bytes == 0
            || max_bytes > MAX_ASSET_BYTES
        {
            return Err("message channel limits are invalid".into());
        }
        Ok(Self {
            queue: VecDeque::new(),
            max_messages,
            max_bytes,
            bytes: 0,
        })
    }
    pub fn send(&mut self, value: Vec<u8>) -> Result<(), String> {
        if value.len() > MAX_MESSAGE_BYTES
            || self.queue.len() >= self.max_messages
            || self.bytes.saturating_add(value.len()) > self.max_bytes
        {
            return Err("message channel quota exceeded".into());
        }
        self.bytes += value.len();
        self.queue.push_back(value);
        Ok(())
    }
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        let value = self.queue.pop_front()?;
        self.bytes -= value.len();
        Some(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentOperation {
    pub document_id: String,
    pub key: String,
    pub value: Option<Vec<u8>>,
    pub clock: u64,
    pub peer_id: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SharedDocument {
    document_id: String,
    entries: BTreeMap<String, DocumentOperation>,
    seen: BTreeSet<String>,
    bytes: usize,
}

impl SharedDocument {
    pub fn new(id: &str) -> Result<Self, String> {
        validate_token(id, "document id", 128)?;
        Ok(Self {
            document_id: id.into(),
            ..Self::default()
        })
    }
    pub fn apply(&mut self, operation: DocumentOperation) -> Result<bool, String> {
        validate_operation(&operation, &self.document_id)?;
        let identity = operation_id(&operation)?;
        if self.seen.contains(&identity) {
            return Ok(false);
        }
        if self.seen.len() >= MAX_DOCUMENT_OPERATIONS {
            return Err("document operation limit exceeded".into());
        }
        let replace = self.entries.get(&operation.key).is_none_or(|current| {
            (operation.clock, &operation.peer_id) > (current.clock, &current.peer_id)
        });
        if replace {
            let old = self
                .entries
                .get(&operation.key)
                .and_then(|value| value.value.as_ref())
                .map_or(0, Vec::len);
            let new = operation.value.as_ref().map_or(0, Vec::len);
            let next = self
                .bytes
                .saturating_sub(old)
                .checked_add(new)
                .ok_or_else(|| "document byte count overflow".to_string())?;
            if next > MAX_DOCUMENT_BYTES {
                return Err("document byte quota exceeded".into());
            }
            self.bytes = next;
            self.entries.insert(operation.key.clone(), operation);
        }
        self.seen.insert(identity);
        Ok(replace)
    }
    pub fn merge(&mut self, other: &Self) -> Result<(), String> {
        if self.document_id != other.document_id {
            return Err("cannot merge different documents".into());
        }
        for operation in other.entries.values() {
            self.apply(operation.clone())?;
        }
        Ok(())
    }
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key)?.value.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetChunk {
    pub asset_sha256: String,
    pub offset: u64,
    pub total_bytes: u64,
    pub bytes: Vec<u8>,
    pub chunk_sha256: String,
}

pub fn split_asset(bytes: &[u8]) -> Result<Vec<AssetChunk>, String> {
    if bytes.len() > MAX_ASSET_BYTES {
        return Err("asset exceeds transfer limit".into());
    }
    let asset_sha256 = hex::encode(Sha256::digest(bytes));
    Ok(bytes
        .chunks(ASSET_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| AssetChunk {
            asset_sha256: asset_sha256.clone(),
            offset: (index * ASSET_CHUNK_BYTES) as u64,
            total_bytes: bytes.len() as u64,
            bytes: chunk.to_vec(),
            chunk_sha256: hex::encode(Sha256::digest(chunk)),
        })
        .collect())
}

pub fn assemble_asset(chunks: &[AssetChunk]) -> Result<Vec<u8>, String> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }
    let expected = &chunks[0].asset_sha256;
    let total = usize::try_from(chunks[0].total_bytes)
        .map_err(|_| "asset byte length exceeds this platform".to_string())?;
    if total > MAX_ASSET_BYTES {
        return Err("asset exceeds transfer limit".into());
    }
    let mut output = Vec::with_capacity(total);
    let mut offset = 0usize;
    for chunk in chunks {
        if &chunk.asset_sha256 != expected
            || usize::try_from(chunk.total_bytes).ok() != Some(total)
            || usize::try_from(chunk.offset).ok() != Some(offset)
            || chunk.bytes.len() > ASSET_CHUNK_BYTES
            || hex::encode(Sha256::digest(&chunk.bytes)) != chunk.chunk_sha256
        {
            return Err("asset chunk sequence or integrity is invalid".into());
        }
        output.extend_from_slice(&chunk.bytes);
        offset += chunk.bytes.len();
    }
    if output.len() != total || hex::encode(Sha256::digest(&output)) != *expected {
        return Err("assembled asset identity is invalid".into());
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct SimulationConfig {
    pub base_latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_per_million: u32,
    pub reorder_per_million: u32,
    pub seed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulatedPacket {
    pub sequence: u64,
    pub deliver_at_ms: u64,
    pub payload: Vec<u8>,
}

impl SimulationConfig {
    pub fn simulate(
        &self,
        packets: impl IntoIterator<Item = (u64, Vec<u8>)>,
    ) -> Result<Vec<SimulatedPacket>, String> {
        if self.base_latency_ms > 60_000
            || self.jitter_ms > 60_000
            || self.loss_per_million > 1_000_000
            || self.reorder_per_million > 1_000_000
        {
            return Err("network simulation limits are invalid".into());
        }
        let mut state = self.seed;
        let mut output = Vec::new();
        for (sequence, payload) in packets {
            if output.len() >= MAX_SIMULATED_PACKETS {
                return Err("simulated packet count exceeded".into());
            }
            if payload.len() > MAX_MESSAGE_BYTES {
                return Err("simulated packet exceeds its byte limit".into());
            }
            if random_u32(&mut state) % 1_000_000 < self.loss_per_million {
                continue;
            }
            let spread = self.jitter_ms.saturating_mul(2).saturating_add(1);
            let jitter = if spread == 0 {
                0
            } else {
                random_u32(&mut state) % spread
            };
            let latency = self
                .base_latency_ms
                .saturating_add(jitter)
                .saturating_sub(self.jitter_ms);
            let reorder = random_u32(&mut state) % 1_000_000 < self.reorder_per_million;
            let adjustment = if reorder {
                u64::from(self.base_latency_ms.min(10))
            } else {
                0
            };
            output.push(SimulatedPacket {
                sequence,
                deliver_at_ms: u64::from(latency).saturating_sub(adjustment),
                payload,
            });
        }
        output.sort_by_key(|packet| (packet.deliver_at_ms, packet.sequence));
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackDatagram {
    pub tick: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

pub struct RollbackWindow {
    newest_tick: u64,
    max_rollback_ticks: u64,
    seen: BTreeSet<(u64, u64)>,
}

impl RollbackWindow {
    pub fn new(max_rollback_ticks: u64) -> Result<Self, String> {
        if max_rollback_ticks == 0 || max_rollback_ticks > 10_000 {
            return Err("rollback window is invalid".into());
        }
        Ok(Self {
            newest_tick: 0,
            max_rollback_ticks,
            seen: BTreeSet::new(),
        })
    }
    pub fn accept(&mut self, packet: &RollbackDatagram) -> Result<bool, String> {
        if packet.payload.len() > MAX_MESSAGE_BYTES {
            return Err("datagram exceeds its byte limit".into());
        }
        if packet.tick.saturating_add(self.max_rollback_ticks) < self.newest_tick {
            return Ok(false);
        }
        self.newest_tick = self.newest_tick.max(packet.tick);
        let oldest = self.newest_tick.saturating_sub(self.max_rollback_ticks);
        self.seen.retain(|(tick, _)| *tick >= oldest);
        if self.seen.len() >= MAX_ROLLBACK_DATAGRAMS {
            return Err("rollback datagram window is full".into());
        }
        Ok(self.seen.insert((packet.tick, packet.sequence)))
    }
}

fn validate_headers(headers: &BTreeMap<String, String>) -> Result<(), String> {
    if headers.len() > MAX_HTTP_HEADERS {
        return Err("HTTP header count exceeded".into());
    }
    let mut bytes = 0usize;
    let mut normalized = BTreeSet::new();
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > 256
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value
                .chars()
                .any(|ch| ch == '\r' || ch == '\n' || ch == '\0')
        {
            return Err("HTTP header is invalid".into());
        }
        let lower = name.to_ascii_lowercase();
        if !normalized.insert(lower.clone()) {
            return Err("duplicate HTTP header names are not allowed".into());
        }
        if matches!(
            lower.as_str(),
            "connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "transfer-encoding"
                | "upgrade"
                | "host"
                | "content-length"
        ) {
            return Err("hop-by-hop or host-controlled HTTP header is forbidden".into());
        }
        bytes = bytes
            .checked_add(name.len() + value.len())
            .ok_or_else(|| "HTTP header size overflow".to_string())?;
    }
    if bytes > MAX_HTTP_HEADER_BYTES {
        return Err("HTTP headers exceed their byte limit".into());
    }
    Ok(())
}
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
}
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}
fn effective_port(url: &Url) -> Option<u16> {
    url.port_or_known_default()
}
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "::1"
}
fn peer_id(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}
fn message_aad(sender: &str, recipient: &str, sequence: u64) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(sender.as_bytes());
    value.push(0);
    value.extend_from_slice(recipient.as_bytes());
    value.extend_from_slice(&sequence.to_le_bytes());
    value
}
fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| format!("{label} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
}
fn validate_token(value: &str, label: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}
fn validate_operation(value: &DocumentOperation, id: &str) -> Result<(), String> {
    if value.document_id != id {
        return Err("document operation targets another document".into());
    }
    validate_token(&value.key, "document key", 1024)?;
    validate_token(&value.peer_id, "peer id", 128)?;
    if value
        .value
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_MESSAGE_BYTES)
    {
        return Err("document value exceeds its byte limit".into());
    }
    Ok(())
}
fn operation_id(value: &DocumentOperation) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|error| error.to_string())?,
    )))
}
fn random_u32(state: &mut u64) -> u32 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (*state >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> HttpPolicy {
        HttpPolicy {
            scopes: vec![HttpScope {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: None,
                path_prefix: "/v1".into(),
                methods: BTreeSet::from([HttpMethod::Get]),
            }],
            max_request_bytes: 1024,
            max_response_bytes: 2048,
            max_redirects: 2,
        }
    }
    #[test]
    fn http_is_origin_path_and_method_scoped() {
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://api.example.com/v1/items".into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        assert!(policy().authorize(&request).is_ok());
        let mut denied = request;
        denied.url = "https://evil.example/v1/items".into();
        assert!(policy().authorize(&denied).is_err());
    }
    #[test]
    fn fixtures_replay_without_transport() {
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: "https://api.example.com/v1/items".into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let mut fixtures = HttpFixtures::new();
        fixtures
            .insert(
                &policy(),
                &request,
                HttpResponse {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: b"ok".to_vec(),
                },
            )
            .unwrap();
        assert_eq!(fixtures.replay(&policy(), &request).unwrap().body, b"ok");
    }
    #[test]
    fn peer_sessions_encrypt_authenticate_and_reject_replay() {
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let mut outbound = alice.session(&bob.public()).unwrap();
        let mut inbound = bob.session(&alice.public()).unwrap();
        let message = outbound.seal(b"hello").unwrap();
        assert_eq!(inbound.open(&message).unwrap(), b"hello");
        assert!(inbound.open(&message).is_err());
    }
    #[test]
    fn documents_converge_after_offline_edits() {
        let mut left = SharedDocument::new("notes").unwrap();
        let mut right = SharedDocument::new("notes").unwrap();
        left.apply(DocumentOperation {
            document_id: "notes".into(),
            key: "title".into(),
            value: Some(b"left".to_vec()),
            clock: 2,
            peer_id: "a".into(),
        })
        .unwrap();
        right
            .apply(DocumentOperation {
                document_id: "notes".into(),
                key: "title".into(),
                value: Some(b"right".to_vec()),
                clock: 2,
                peer_id: "b".into(),
            })
            .unwrap();
        let l = left.clone();
        let r = right.clone();
        left.merge(&r).unwrap();
        right.merge(&l).unwrap();
        assert_eq!(left.get("title"), right.get("title"));
    }
    #[test]
    fn asset_transfer_checks_every_chunk() {
        let bytes = vec![7; ASSET_CHUNK_BYTES + 3];
        let chunks = split_asset(&bytes).unwrap();
        assert_eq!(assemble_asset(&chunks).unwrap(), bytes);
        let mut changed = chunks;
        changed[0].bytes[0] = 9;
        assert!(assemble_asset(&changed).is_err());
    }
    #[test]
    fn simulation_is_reproducible() {
        let config = SimulationConfig {
            base_latency_ms: 50,
            jitter_ms: 10,
            loss_per_million: 100_000,
            reorder_per_million: 100_000,
            seed: 7,
        };
        let packets = (0_u8..100)
            .map(|i| (u64::from(i), vec![i]))
            .collect::<Vec<_>>();
        assert_eq!(
            config.simulate(packets.clone()).unwrap(),
            config.simulate(packets).unwrap()
        );
    }
}

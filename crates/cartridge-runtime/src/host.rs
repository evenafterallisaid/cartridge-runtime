mod storage;

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cartridge_core::{PackageManifest, Permissions};
use cartridge_storage::{StorageBackend, StorageLimits};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasmtime::component::ResourceTable;
use wasmtime::{StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{
    WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView,
    clocks::{HostMonotonicClock, HostWallClock},
};

use crate::{ReplayError, TraceEvent, cartridge};

const MAX_RANDOM_BYTES: u32 = 1024 * 1024;
const MAX_LOG_CHARACTERS: usize = 16 * 1024;

pub(crate) struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    pub(crate) limits: StoreLimits,
    permissions: Permissions,
    assets: BTreeMap<String, Vec<u8>>,
    storage: Arc<dyn StorageBackend>,
    storage_namespace: String,
    storage_limits: StorageLimits,
    pub(crate) events: Vec<TraceEvent>,
    next_sequence: u64,
    replay: Option<ReplayCursor>,
    divergence: Option<ReplayError>,
}

impl HostState {
    pub(crate) fn new(
        manifest: &PackageManifest,
        assets: BTreeMap<String, Vec<u8>>,
        storage: Arc<dyn StorageBackend>,
        replay_events: Option<Vec<TraceEvent>>,
    ) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false);
        if !manifest.permissions.clock {
            wasi.wall_clock(FrozenWallClock)
                .monotonic_clock(FrozenMonotonicClock);
        }
        if !manifest.permissions.random {
            wasi.secure_random(StdRng::seed_from_u64(0))
                .insecure_random(StdRng::seed_from_u64(1))
                .insecure_random_seed(0);
        }
        let wasi = wasi.build();
        let limits = StoreLimitsBuilder::new()
            .memory_size(manifest.runtime.memory_bytes)
            .build();
        Self {
            table: ResourceTable::new(),
            wasi,
            limits,
            permissions: manifest.permissions.clone(),
            assets,
            storage,
            storage_namespace: manifest.cartridge.id.clone(),
            storage_limits: StorageLimits {
                max_bytes: manifest.runtime.storage_bytes,
                max_keys: manifest.runtime.storage_keys,
                max_value_bytes: manifest.runtime.storage_value_bytes,
            },
            events: Vec::new(),
            next_sequence: 0,
            replay: replay_events.map(ReplayCursor::new),
            divergence: None,
        }
    }

    pub(crate) fn finish_replay(&mut self) -> Result<(), ReplayError> {
        if let Some(error) = self.divergence.take() {
            return Err(error);
        }
        if let Some(replay) = &self.replay {
            let remaining = replay.events.len().saturating_sub(replay.cursor);
            if remaining != 0 {
                return Err(ReplayError::EventsRemaining { remaining });
            }
        }
        Ok(())
    }

    fn record(&mut self, capability: &str, operation: &str, outcome: Value) {
        let actual = TraceEvent {
            sequence: self.next_sequence,
            capability: capability.to_owned(),
            operation: operation.to_owned(),
            outcome,
        };
        let replay_divergence = self.replay.as_mut().and_then(|replay| {
            let reason = match replay.events.get(replay.cursor) {
                Some(expected) if expected == &actual => None,
                Some(expected) => Some(format!(
                    "expected {}, got {}",
                    event_label(expected),
                    event_label(&actual)
                )),
                None => Some(format!(
                    "execution produced an extra {}",
                    event_label(&actual)
                )),
            };
            replay.cursor += 1;
            reason
        });
        if let Some(reason) = replay_divergence {
            self.set_divergence(reason);
        }
        self.events.push(actual);
        self.next_sequence += 1;
    }

    fn replay_outcome(
        &mut self,
        capability: &str,
        operation: &str,
    ) -> Option<Result<Value, String>> {
        let replay = self.replay.as_ref()?;
        let Some(expected) = replay.events.get(replay.cursor).cloned() else {
            let message = format!("trace ended before {capability}.{operation}");
            self.set_divergence(message.clone());
            return Some(Err(message));
        };
        if expected.sequence != self.next_sequence
            || expected.capability != capability
            || expected.operation != operation
        {
            let message = format!(
                "expected {}, guest called {capability}.{operation}",
                event_label(&expected)
            );
            self.set_divergence(message.clone());
            return Some(Err(message));
        }
        Some(Ok(expected.outcome))
    }

    fn set_divergence(&mut self, reason: String) {
        if self.divergence.is_none() {
            self.divergence = Some(ReplayError::Divergence {
                sequence: self.next_sequence,
                reason,
            });
        }
    }
}

struct ReplayCursor {
    events: Vec<TraceEvent>,
    cursor: usize,
}

impl ReplayCursor {
    fn new(events: Vec<TraceEvent>) -> Self {
        Self { events, cursor: 0 }
    }
}

struct FrozenWallClock;

impl HostWallClock for FrozenWallClock {
    fn resolution(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn now(&self) -> Duration {
        Duration::ZERO
    }
}

struct FrozenMonotonicClock;

impl HostMonotonicClock for FrozenMonotonicClock {
    fn resolution(&self) -> u64 {
        1
    }

    fn now(&self) -> u64 {
        0
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl cartridge::api::host::Host for HostState {
    fn log(&mut self, level: cartridge::api::host::LogLevel, message: String) {
        let message: String = message.chars().take(MAX_LOG_CHARACTERS).collect();
        let label = match level {
            cartridge::api::host::LogLevel::Debug => "debug",
            cartridge::api::host::LogLevel::Info => "info",
            cartridge::api::host::LogLevel::Warn => "warn",
            cartridge::api::host::LogLevel::Error => "error",
        };
        eprintln!("[{label}] {message}");
        self.record(
            "log",
            "write",
            json!({ "level": label, "message": message }),
        );
    }

    fn wall_clock_ms(&mut self) -> Result<u64, String> {
        if !self.permissions.clock {
            let error = "clock capability was not granted".to_owned();
            self.record("clock", "wall-clock-ms", json!({ "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("clock", "wall-clock-ms") {
            let outcome = outcome?;
            let Some(millis) = outcome.get("value").and_then(Value::as_u64) else {
                let error = "recorded clock outcome does not contain an unsigned value".to_owned();
                self.set_divergence(error.clone());
                return Err(error);
            };
            self.record("clock", "wall-clock-ms", outcome);
            return Ok(millis);
        }
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis();
        let millis = u64::try_from(millis).map_err(|_| "system time is out of range".to_owned())?;
        self.record("clock", "wall-clock-ms", json!({ "value": millis }));
        Ok(millis)
    }

    fn random_bytes(&mut self, length: u32) -> Result<Vec<u8>, String> {
        if !self.permissions.random {
            let error = "random capability was not granted".to_owned();
            self.record("random", "random-bytes", json!({ "denied": error }));
            return Err(error);
        }
        if length > MAX_RANDOM_BYTES {
            let error = format!("random request exceeds the {MAX_RANDOM_BYTES}-byte limit");
            self.record("random", "random-bytes", json!({ "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("random", "random-bytes") {
            let outcome = outcome?;
            let recorded_length = outcome.get("length").and_then(Value::as_u64);
            if recorded_length != Some(u64::from(length)) {
                let error = format!(
                    "recorded random length was {}, guest requested {length}",
                    recorded_length.map_or_else(|| "missing".to_owned(), |value| value.to_string())
                );
                self.set_divergence(error.clone());
                return Err(error);
            }
            let Some(encoded) = outcome.get("bytes").and_then(Value::as_str) else {
                let error = "recorded random outcome does not contain bytes".to_owned();
                self.set_divergence(error.clone());
                return Err(error);
            };
            let bytes = hex::decode(encoded).map_err(|error| {
                let message = format!("recorded random bytes are invalid: {error}");
                self.set_divergence(message.clone());
                message
            })?;
            if bytes.len() != length as usize {
                let error = format!(
                    "recorded random data has {} bytes, expected {length}",
                    bytes.len()
                );
                self.set_divergence(error.clone());
                return Err(error);
            }
            self.record("random", "random-bytes", outcome);
            return Ok(bytes);
        }
        let mut bytes = vec![0; length as usize];
        rand::rng().fill_bytes(&mut bytes);
        self.record(
            "random",
            "random-bytes",
            json!({ "length": length, "bytes": hex::encode(&bytes) }),
        );
        Ok(bytes)
    }

    fn read_asset(&mut self, path: String) -> Result<Vec<u8>, String> {
        if !self.permissions.assets {
            let error = "asset capability was not granted".to_owned();
            self.record("assets", "read", json!({ "path": path, "denied": error }));
            return Err(error);
        }
        if !is_safe_asset_path(&path) {
            let error = "asset path must be a normalized relative path".to_owned();
            self.record("assets", "read", json!({ "path": path, "denied": error }));
            return Err(error);
        }
        let Some(bytes) = self.assets.get(&path).cloned() else {
            let error = format!("asset does not exist: {path}");
            self.record("assets", "read", json!({ "path": path, "missing": true }));
            return Err(error);
        };
        self.record(
            "assets",
            "read",
            json!({
                "path": path,
                "length": bytes.len(),
                "sha256": hex::encode(Sha256::digest(&bytes)),
            }),
        );
        Ok(bytes)
    }

    fn storage_get(&mut self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.get_storage(&key)
    }

    fn storage_put(&mut self, key: String, value: Vec<u8>) -> Result<(), String> {
        self.put_storage(&key, &value)
    }

    fn storage_delete(&mut self, key: String) -> Result<bool, String> {
        self.delete_storage(&key)
    }

    fn storage_list(&mut self, prefix: String) -> Result<Vec<String>, String> {
        self.list_storage(&prefix)
    }
}

fn event_label(event: &TraceEvent) -> String {
    format!(
        "event {} {}.{} with {}",
        event.sequence, event.capability, event.operation, event.outcome
    )
}

fn is_safe_asset_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartridge_core::{CartridgeMetadata, Integrity, RuntimeLimits, Services, StateConfig};
    use cartridge_storage::MemoryStorage;

    #[test]
    fn asset_paths_cannot_escape_the_package() {
        assert!(is_safe_asset_path("images/icon.png"));
        assert!(!is_safe_asset_path("../secret"));
        assert!(!is_safe_asset_path("C:/secret"));
        assert!(!is_safe_asset_path("images\\icon.png"));
    }

    #[test]
    fn undeclared_capabilities_are_denied_and_traced() {
        let mut state = HostState::new(
            &manifest(Permissions::default()),
            BTreeMap::new(),
            Arc::new(MemoryStorage::new()),
            None,
        );

        let result = cartridge::api::host::Host::random_bytes(&mut state, 8);

        assert_eq!(result.unwrap_err(), "random capability was not granted");
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.events[0].capability, "random");
    }

    #[test]
    fn replay_uses_the_recorded_clock_value() {
        let permissions = Permissions {
            clock: true,
            ..Permissions::default()
        };
        let event = TraceEvent {
            sequence: 0,
            capability: "clock".into(),
            operation: "wall-clock-ms".into(),
            outcome: json!({ "value": 1234 }),
        };
        let mut state = HostState::new(
            &manifest(permissions),
            BTreeMap::new(),
            Arc::new(MemoryStorage::new()),
            Some(vec![event.clone()]),
        );

        let value = cartridge::api::host::Host::wall_clock_ms(&mut state).unwrap();

        assert_eq!(value, 1234);
        assert_eq!(state.events, vec![event]);
        state.finish_replay().unwrap();
    }

    #[test]
    fn replay_reports_the_first_different_event() {
        let expected = TraceEvent {
            sequence: 0,
            capability: "log".into(),
            operation: "write".into(),
            outcome: json!({ "level": "info", "message": "expected" }),
        };
        let mut state = HostState::new(
            &manifest(Permissions::default()),
            BTreeMap::new(),
            Arc::new(MemoryStorage::new()),
            Some(vec![expected]),
        );

        cartridge::api::host::Host::log(
            &mut state,
            cartridge::api::host::LogLevel::Info,
            "actual".into(),
        );

        assert!(matches!(
            state.finish_replay(),
            Err(ReplayError::Divergence { sequence: 0, .. })
        ));
    }

    #[test]
    fn replay_uses_recorded_random_bytes() {
        let permissions = Permissions {
            random: true,
            ..Permissions::default()
        };
        let event = TraceEvent {
            sequence: 0,
            capability: "random".into(),
            operation: "random-bytes".into(),
            outcome: json!({ "length": 4, "bytes": "01020304" }),
        };
        let mut state = HostState::new(
            &manifest(permissions),
            BTreeMap::new(),
            Arc::new(MemoryStorage::new()),
            Some(vec![event]),
        );

        let bytes = cartridge::api::host::Host::random_bytes(&mut state, 4).unwrap();

        assert_eq!(bytes, vec![1, 2, 3, 4]);
        state.finish_replay().unwrap();
    }

    #[test]
    fn replay_rejects_unconsumed_events() {
        let event = TraceEvent {
            sequence: 0,
            capability: "log".into(),
            operation: "write".into(),
            outcome: json!({ "level": "info", "message": "unused" }),
        };
        let mut state = HostState::new(
            &manifest(Permissions::default()),
            BTreeMap::new(),
            Arc::new(MemoryStorage::new()),
            Some(vec![event]),
        );

        assert_eq!(
            state.finish_replay(),
            Err(ReplayError::EventsRemaining { remaining: 1 })
        );
    }

    #[test]
    fn storage_calls_share_the_cartridge_namespace() {
        let permissions = Permissions {
            storage: true,
            ..Permissions::default()
        };
        let storage = Arc::new(MemoryStorage::new());
        let mut state = HostState::new(&manifest(permissions), BTreeMap::new(), storage, None);

        cartridge::api::host::Host::storage_put(
            &mut state,
            "settings/theme".into(),
            b"dark".to_vec(),
        )
        .unwrap();
        let value =
            cartridge::api::host::Host::storage_get(&mut state, "settings/theme".into()).unwrap();

        assert_eq!(value, Some(b"dark".to_vec()));
        assert_eq!(state.events.len(), 2);
        assert!(
            state
                .events
                .iter()
                .all(|event| event.capability == "storage")
        );
    }

    #[test]
    fn storage_replay_does_not_mutate_live_state() {
        let permissions = Permissions {
            storage: true,
            ..Permissions::default()
        };
        let value = b"dark";
        let event = TraceEvent {
            sequence: 0,
            capability: "storage".into(),
            operation: "put".into(),
            outcome: json!({
                "key": "settings/theme",
                "length": value.len(),
                "sha256": hex::encode(Sha256::digest(value)),
                "stored": true,
            }),
        };
        let storage = Arc::new(MemoryStorage::new());
        let mut state = HostState::new(
            &manifest(permissions),
            BTreeMap::new(),
            storage.clone(),
            Some(vec![event]),
        );

        cartridge::api::host::Host::storage_put(
            &mut state,
            "settings/theme".into(),
            value.to_vec(),
        )
        .unwrap();

        state.finish_replay().unwrap();
        assert_eq!(
            storage.get("dev.example.host", "settings/theme").unwrap(),
            None
        );
    }

    fn manifest(permissions: Permissions) -> PackageManifest {
        PackageManifest {
            format_version: 1,
            cartridge: CartridgeMetadata {
                id: "dev.example.host".into(),
                name: "Host".into(),
                version: "0.1.0".into(),
                description: String::new(),
            },
            permissions,
            runtime: RuntimeLimits::default(),
            state: StateConfig::default(),
            dependencies: Vec::new(),
            services: Services::default(),
            integrity: Integrity::default(),
        }
    }
}

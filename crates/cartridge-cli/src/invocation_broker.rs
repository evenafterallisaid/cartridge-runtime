use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cartridge_engine::{
    ENGINE_INVOCATION_FORMAT_VERSION, EngineStore, InvocationRequestEnvelope,
    InvocationResponseEnvelope, MAX_INVOCATION_ENVELOPE_BYTES, MAX_INVOCATIONS_PER_REPLICA,
    RouteTarget,
};
use cartridge_network::{InvocationBroker, ServiceRequest, ServiceResponse};

static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct FileInvocationBroker {
    root: PathBuf,
    stack: String,
    directory: PathBuf,
    target: RouteTarget,
    active: Mutex<BTreeMap<String, (RouteTarget, u64)>>,
}

impl FileInvocationBroker {
    pub fn new(
        root: PathBuf,
        stack: String,
        directory: PathBuf,
        target: RouteTarget,
    ) -> Result<Self, String> {
        if !root.is_absolute() || !directory.is_absolute() {
            return Err("invocation channel paths must be absolute".into());
        }
        let expected = EngineStore::open(&root)?.replica_invocation_directory(
            &stack,
            &target.generation,
            &cartridge_engine::ReplicaId {
                instance: target.instance.clone(),
                ordinal: target.ordinal,
            },
            &target.run_id,
        )?;
        if expected != directory {
            return Err("invocation channel path does not match its worker identity".into());
        }
        Ok(Self {
            root,
            stack,
            directory,
            target,
            active: Mutex::new(BTreeMap::new()),
        })
    }

    fn take_request(&self) -> Result<Option<ServiceRequest>, String> {
        let metadata = fs::symlink_metadata(&self.directory).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("invocation channel directory is unsafe".into());
        }
        let mut entries = fs::read_dir(&self.directory)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if entries.len() > MAX_INVOCATIONS_PER_REPLICA.saturating_mul(3) {
            return Err("invocation channel entry limit exceeded".into());
        }
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(request_id) = name.strip_suffix(".request") else {
                continue;
            };
            if !digest(request_id) {
                continue;
            }
            let request_path = entry.path();
            let active_path = self.directory.join(format!("{request_id}.active"));
            match fs::rename(&request_path, &active_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            }
            match self.open_claimed(&active_path, request_id) {
                Ok(request) => return Ok(Some(request)),
                Err(error) => {
                    let _ = fs::remove_file(&active_path);
                    return Err(error);
                }
            }
        }
        Ok(None)
    }

    fn open_claimed(&self, path: &Path, request_id: &str) -> Result<ServiceRequest, String> {
        let bytes = read_bounded(path)?;
        let envelope: InvocationRequestEnvelope =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        envelope.validate()?;
        if envelope.request.id != request_id
            || envelope.stack != self.stack
            || envelope.target.instance != self.target.instance
            || envelope.target.ordinal != self.target.ordinal
            || envelope.target.revision != self.target.revision
            || envelope.target.generation != self.target.generation
            || envelope.target.run_id != self.target.run_id
        {
            return Err("invocation request belongs to another worker".into());
        }
        let now_ms = current_time_ms()?;
        if now_ms > envelope.deadline_at_ms {
            return Err("invocation request expired before delivery".into());
        }
        if !EngineStore::open(&self.root)?.route_target_is_ready(&self.stack, &envelope.target)? {
            return Err("invocation route changed before delivery".into());
        }
        self.active
            .lock()
            .map_err(|_| "invocation broker state is unavailable".to_string())?
            .insert(
                envelope.request.id.clone(),
                (envelope.target, envelope.deadline_at_ms),
            );
        Ok(envelope.request)
    }
}

impl InvocationBroker for FileInvocationBroker {
    fn receive(&self, timeout: Duration) -> Result<Option<ServiceRequest>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(request) = self.take_request()? {
                return Ok(Some(request));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10).min(remaining));
        }
    }

    fn respond(&self, request_id: &str, response: &ServiceResponse) -> Result<(), String> {
        response.validate()?;
        let (target, deadline_at_ms) = self
            .active
            .lock()
            .map_err(|_| "invocation broker state is unavailable".to_string())?
            .get(request_id)
            .cloned()
            .ok_or_else(|| "invocation response does not match a claimed request".to_string())?;
        if current_time_ms()? > deadline_at_ms {
            self.active
                .lock()
                .map_err(|_| "invocation broker state is unavailable".to_string())?
                .remove(request_id);
            return Err("invocation deadline expired before the response".into());
        }
        let envelope = InvocationResponseEnvelope {
            format_version: ENGINE_INVOCATION_FORMAT_VERSION,
            stack: self.stack.clone(),
            target,
            request_id: request_id.into(),
            responded_at_ms: current_time_ms()?,
            response: response.clone(),
        };
        envelope.validate()?;
        write_new_atomic(
            &self.directory.join(format!("{request_id}.response")),
            &serde_json::to_vec(&envelope).map_err(|error| error.to_string())?,
        )?;
        self.active
            .lock()
            .map_err(|_| "invocation broker state is unavailable".to_string())?
            .remove(request_id);
        let active = self.directory.join(format!("{request_id}.active"));
        let metadata = match fs::symlink_metadata(&active) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        if let Some(metadata) = metadata {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("claimed invocation path is unsafe".into());
            }
            if let Err(error) = fs::remove_file(active)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error.to_string());
            }
        }
        Ok(())
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INVOCATION_ENVELOPE_BYTES
    {
        return Err("invocation envelope is not a bounded regular file".into());
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| "invocation envelope size overflow".to_string())?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_INVOCATION_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_INVOCATION_ENVELOPE_BYTES {
        return Err("invocation envelope exceeded its limit while reading".into());
    }
    Ok(bytes)
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_INVOCATION_ENVELOPE_BYTES {
        return Err("invocation envelope exceeds its byte limit".into());
    }
    if path.exists() {
        return Err("invocation response already exists".into());
    }
    let sequence = WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}

fn current_time_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "timestamp overflow".into())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

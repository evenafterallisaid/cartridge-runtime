use std::{
    collections::BTreeMap,
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use cartridge_desktop::Library;
use cartridge_engine::{
    DAEMON_PROTOCOL_VERSION, DaemonCodec, DaemonInfo, DaemonLease, DaemonRequest, DaemonResponse,
    EngineStackState, EngineStore, MAX_DAEMON_EVENTS, MAX_DAEMON_FRAME_BYTES,
    MAX_DAEMON_SUPERVISORS, MAX_STACK_TOTAL_ACTIVE_REPLICAS, ReplicaPhase, StackPlan,
    daemon_request,
};

use crate::process_control::{
    ContainedChild, ContainedCommand, OutputMode, TERMINATION_GRACE, spawn_contained,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RECONCILE_INTERVAL: Duration = Duration::from_millis(250);
const AUTH_TIMEOUT: Duration = Duration::from_millis(500);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_MAX_SKEW_MS: u64 = 30_000;
const REPLAY_RETENTION_MS: u64 = 60_000;
const MAX_REPLAY_IDS: usize = 4096;
const MAX_CLIENTS: usize = 8;
const MIN_SUPERVISOR_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_SUPERVISOR_RETRY_DELAY: Duration = Duration::from_secs(30);
const SUPERVISOR_STABLE_WINDOW: Duration = Duration::from_secs(60);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

pub struct ServeOptions<'a> {
    pub root: &'a Path,
    pub library: &'a Path,
    pub max_supervisors: u16,
    pub workers_per_stack: u16,
    pub json: bool,
}

struct DaemonState {
    root: PathBuf,
    library: PathBuf,
    codec: Arc<DaemonCodec>,
    started_at_ms: u64,
    max_supervisors: u16,
    workers_per_stack: u16,
    stopping: Arc<AtomicBool>,
    replay: Mutex<ReplayCache>,
    mutations: Mutex<()>,
    active_supervisors: Arc<AtomicUsize>,
}

#[derive(Default)]
struct ReplayCache(BTreeMap<String, u64>);

struct ManagedSupervisor {
    child: ContainedChild,
    generation: String,
    started_at: Instant,
}

struct SupervisorRetry {
    attempts: u8,
    deadline: Instant,
}

struct ClientSlot {
    active: Arc<AtomicUsize>,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ReplayCache {
    fn accept(&mut self, request_id: &str, issued_at_ms: u64, now_ms: u64) -> Result<()> {
        if now_ms.abs_diff(issued_at_ms) > REQUEST_MAX_SKEW_MS {
            bail!("daemon request is outside the freshness window");
        }
        let cutoff = now_ms.saturating_sub(REPLAY_RETENTION_MS);
        self.0.retain(|_, seen_at| *seen_at >= cutoff);
        if self.0.contains_key(request_id) {
            bail!("daemon request was already used");
        }
        if self.0.len() >= MAX_REPLAY_IDS {
            bail!("daemon replay cache is full");
        }
        self.0.insert(request_id.into(), now_ms);
        Ok(())
    }
}

pub fn serve(options: &ServeOptions<'_>) -> Result<()> {
    if options.max_supervisors == 0 || options.max_supervisors > MAX_DAEMON_SUPERVISORS {
        bail!("daemon supervisor limit is invalid");
    }
    if options.workers_per_stack == 0 || options.workers_per_stack > MAX_STACK_TOTAL_ACTIVE_REPLICAS
    {
        bail!("daemon worker limit is invalid");
    }

    let lease = DaemonLease::acquire(options.root).map_err(anyhow::Error::msg)?;
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .context("could not bind the engine daemon")?;
    listener
        .set_nonblocking(true)
        .context("could not configure the engine daemon listener")?;
    let port = listener.local_addr()?.port();
    let codec = Arc::new(DaemonCodec::generate());
    let started_at_ms = current_time_ms()?;
    let stopping = Arc::new(AtomicBool::new(false));
    let signal = stopping.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .context("could not install the engine daemon shutdown handler")?;

    let state = Arc::new(DaemonState {
        root: options.root.into(),
        library: options.library.into(),
        codec: codec.clone(),
        started_at_ms,
        max_supervisors: options.max_supervisors,
        workers_per_stack: options.workers_per_stack,
        stopping: stopping.clone(),
        replay: Mutex::new(ReplayCache::default()),
        mutations: Mutex::new(()),
        active_supervisors: Arc::new(AtomicUsize::new(0)),
    });
    let endpoint = codec.endpoint(port, std::process::id(), started_at_ms);
    lease.publish(&endpoint).map_err(anyhow::Error::msg)?;

    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "protocol_version": DAEMON_PROTOCOL_VERSION,
                "instance_id": codec.instance_id(),
                "pid": std::process::id(),
                "started_at_ms": started_at_ms,
                "address": format!("127.0.0.1:{port}"),
            }))?
        );
    } else {
        println!("cartridge engine listening on 127.0.0.1:{port}");
    }

    let active_clients = Arc::new(AtomicUsize::new(0));
    let executable = std::env::current_exe().context("could not locate the cartridge engine")?;
    let mut supervisors = BTreeMap::new();
    let mut retries = BTreeMap::new();
    let mut next_reconcile = Instant::now();

    let run_result = (|| -> Result<()> {
        while !stopping.load(Ordering::Acquire) {
            accept_clients(&listener, &state, &active_clients)?;
            if Instant::now() >= next_reconcile {
                reconcile_supervisors(&state, &executable, &mut supervisors, &mut retries)?;
                next_reconcile = Instant::now() + RECONCILE_INTERVAL;
            }
            thread::sleep(ACCEPT_POLL_INTERVAL);
        }
        Ok(())
    })();

    stopping.store(true, Ordering::Release);
    let endpoint_result = lease
        .remove_endpoint(codec.instance_id())
        .map_err(anyhow::Error::msg);
    let clients_result = drain_clients(&active_clients);
    stop_supervisors(&mut supervisors);
    state.active_supervisors.store(0, Ordering::Release);
    run_result.and(endpoint_result).and(clients_result)
}

pub fn request(root: &Path, request: DaemonRequest) -> Result<DaemonResponse> {
    daemon_request(root, request).map_err(anyhow::Error::msg)
}

fn accept_clients(
    listener: &TcpListener,
    state: &Arc<DaemonState>,
    active: &Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error).context("engine daemon accept failed"),
        };
        if !peer.ip().is_loopback() || !reserve_client(active) {
            drop(stream);
            continue;
        }
        let slot = ClientSlot {
            active: active.clone(),
        };
        let state = state.clone();
        thread::spawn(move || {
            let _slot = slot;
            let _ = handle_client(stream, &state);
        });
    }
}

fn reserve_client(active: &AtomicUsize) -> bool {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < MAX_CLIENTS).then_some(current + 1)
        })
        .is_ok()
}

fn handle_client(mut stream: TcpStream, state: &DaemonState) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(AUTH_TIMEOUT))?;
    stream.set_write_timeout(Some(AUTH_TIMEOUT))?;
    let frame = read_frame(&mut stream)?;
    let opened = state
        .codec
        .open_request(&frame)
        .map_err(anyhow::Error::msg)?;
    let now = current_time_ms()?;
    state
        .replay
        .lock()
        .map_err(|_| anyhow::anyhow!("daemon replay state is unavailable"))?
        .accept(&opened.request_id, opened.issued_at_ms, now)?;
    configure_stream(&stream)?;
    let request_id = opened.request_id;
    let shutdown = matches!(opened.request, DaemonRequest::Shutdown);
    let response = if shutdown {
        let _mutation = state
            .mutations
            .lock()
            .map_err(|_| anyhow::anyhow!("daemon mutation state is unavailable"))?;
        state.stopping.store(true, Ordering::Release);
        DaemonResponse::ShuttingDown
    } else {
        execute_request(state, opened.request).unwrap_or_else(|error| DaemonResponse::Error {
            code: "request-failed".into(),
            message: safe_error(&format!("{error:#}")),
        })
    };
    let frame = state
        .codec
        .seal_response(&request_id, response)
        .map_err(anyhow::Error::msg)?;
    write_frame(&mut stream, &frame)?;
    Ok(())
}

fn execute_request(state: &DaemonState, request: DaemonRequest) -> Result<DaemonResponse> {
    match request {
        DaemonRequest::Ping => Ok(DaemonResponse::Pong),
        DaemonRequest::Info => {
            let statuses = EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .list()
                .map_err(anyhow::Error::msg)?;
            let known_stacks = u32::try_from(statuses.len()).context("stack count overflow")?;
            let applied_stacks = u32::try_from(
                statuses
                    .iter()
                    .filter(|status| status.state == EngineStackState::Applied)
                    .count(),
            )
            .context("applied stack count overflow")?;
            Ok(DaemonResponse::Info(DaemonInfo {
                protocol_version: DAEMON_PROTOCOL_VERSION,
                instance_id: state.codec.instance_id().into(),
                pid: std::process::id(),
                started_at_ms: state.started_at_ms,
                active_supervisors: u16::try_from(state.active_supervisors.load(Ordering::Acquire))
                    .context("active supervisor count overflow")?,
                max_supervisors: state.max_supervisors,
                workers_per_stack: state.workers_per_stack,
                known_stacks,
                applied_stacks,
            }))
        }
        DaemonRequest::List => Ok(DaemonResponse::Stacks(
            EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .list()
                .map_err(anyhow::Error::msg)?,
        )),
        DaemonRequest::Status { stack } => Ok(DaemonResponse::Status(
            EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .status(&stack)
                .map_err(anyhow::Error::msg)?,
        )),
        DaemonRequest::RuntimeStatus { stack } => Ok(DaemonResponse::RuntimeStatus(
            EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .runtime_status(&stack)
                .map_err(anyhow::Error::msg)?,
        )),
        DaemonRequest::Events { stack, tail } => {
            let mut events = EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .events(&stack)
                .map_err(anyhow::Error::msg)?;
            let keep = usize::from(tail.min(MAX_DAEMON_EVENTS));
            if events.len() > keep {
                events.drain(..events.len() - keep);
            }
            Ok(DaemonResponse::Events(events))
        }
        DaemonRequest::Health { stack } => engine_health(state, stack),
        request @ (DaemonRequest::RolloutStatus { .. }
        | DaemonRequest::RolloutPrepare { .. }
        | DaemonRequest::RolloutActivate { .. }
        | DaemonRequest::RolloutCommit { .. }
        | DaemonRequest::RolloutRollback { .. }) => execute_rollout_request(state, request),
        DaemonRequest::Plan { manifest } => {
            let library = Library::open(&state.library).map_err(anyhow::Error::msg)?;
            let plan = StackPlan::build(&manifest, &library).map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Planned(Box::new(plan)))
        }
        request @ (DaemonRequest::Apply { .. }
        | DaemonRequest::Stop { .. }
        | DaemonRequest::Remove { .. }) => execute_stack_mutation(state, request),
        DaemonRequest::Shutdown => Ok(DaemonResponse::ShuttingDown),
    }
}

fn execute_stack_mutation(state: &DaemonState, request: DaemonRequest) -> Result<DaemonResponse> {
    let _mutation = lock_mutation(state)?;
    let engine = EngineStore::open(&state.root).map_err(anyhow::Error::msg)?;
    match request {
        DaemonRequest::Apply {
            plan,
            allow_insecure,
        } => {
            let library = Library::open(&state.library).map_err(anyhow::Error::msg)?;
            plan.verify_installed(&library)
                .map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Applied(
                engine
                    .apply(&plan, allow_insecure)
                    .map_err(anyhow::Error::msg)?,
            ))
        }
        DaemonRequest::Stop { stack } => Ok(DaemonResponse::Stopped(
            engine.stop(&stack).map_err(anyhow::Error::msg)?,
        )),
        DaemonRequest::Remove { stack } => Ok(DaemonResponse::Removed(
            engine.remove(&stack).map_err(anyhow::Error::msg)?,
        )),
        _ => bail!("request is not a stack mutation"),
    }
}

fn execute_rollout_request(state: &DaemonState, request: DaemonRequest) -> Result<DaemonResponse> {
    match request {
        DaemonRequest::RolloutStatus { stack } => Ok(DaemonResponse::Rollout(
            EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .rollout(&stack)
                .map_err(anyhow::Error::msg)?
                .as_ref()
                .map(cartridge_engine::RolloutStatus::from_record)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        )),
        DaemonRequest::RolloutPrepare {
            plan,
            allow_insecure,
        } => {
            let _mutation = lock_mutation(state)?;
            let library = Library::open(&state.library).map_err(anyhow::Error::msg)?;
            plan.verify_installed(&library)
                .map_err(anyhow::Error::msg)?;
            let record = EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .prepare_rollout(&plan, allow_insecure, current_time_ms()?)
                .map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Rollout(Some(
                cartridge_engine::RolloutStatus::from_record(&record)
                    .map_err(anyhow::Error::msg)?,
            )))
        }
        DaemonRequest::RolloutActivate { stack, rollout_id } => {
            let _mutation = lock_mutation(state)?;
            let engine = EngineStore::open(&state.root).map_err(anyhow::Error::msg)?;
            let checkpoint = current_rollout(&engine, &stack, &rollout_id)?;
            let library = Library::open(&state.library).map_err(anyhow::Error::msg)?;
            checkpoint
                .candidate_plan
                .verify_installed(&library)
                .map_err(anyhow::Error::msg)?;
            let record = engine
                .activate_rollout(&stack, &rollout_id, current_time_ms()?)
                .map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Rollout(Some(
                cartridge_engine::RolloutStatus::from_record(&record)
                    .map_err(anyhow::Error::msg)?,
            )))
        }
        DaemonRequest::RolloutCommit { stack, rollout_id } => {
            let _mutation = lock_mutation(state)?;
            let record = EngineStore::open(&state.root)
                .map_err(anyhow::Error::msg)?
                .commit_rollout(&stack, &rollout_id, current_time_ms()?)
                .map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Rollout(Some(
                cartridge_engine::RolloutStatus::from_record(&record)
                    .map_err(anyhow::Error::msg)?,
            )))
        }
        DaemonRequest::RolloutRollback { stack, rollout_id } => {
            let _mutation = lock_mutation(state)?;
            let engine = EngineStore::open(&state.root).map_err(anyhow::Error::msg)?;
            let checkpoint = current_rollout(&engine, &stack, &rollout_id)?;
            if let Some(previous) = &checkpoint.previous_plan {
                let library = Library::open(&state.library).map_err(anyhow::Error::msg)?;
                previous
                    .verify_installed(&library)
                    .map_err(anyhow::Error::msg)?;
            }
            let record = engine
                .rollback_rollout(&stack, &rollout_id, current_time_ms()?)
                .map_err(anyhow::Error::msg)?;
            Ok(DaemonResponse::Rollout(Some(
                cartridge_engine::RolloutStatus::from_record(&record)
                    .map_err(anyhow::Error::msg)?,
            )))
        }
        _ => bail!("request is not a rollout operation"),
    }
}

fn current_rollout(
    engine: &EngineStore,
    stack: &str,
    rollout_id: &str,
) -> Result<cartridge_engine::RolloutRecord> {
    let checkpoint = engine
        .rollout(stack)
        .map_err(anyhow::Error::msg)?
        .context("stack has no rollout checkpoint")?;
    if checkpoint.rollout_id != rollout_id {
        bail!("rollout identity does not match the current checkpoint");
    }
    Ok(checkpoint)
}

fn engine_health(state: &DaemonState, stack: Option<String>) -> Result<DaemonResponse> {
    let engine = EngineStore::open(&state.root).map_err(anyhow::Error::msg)?;
    let observed_at_ms = current_time_ms()?;
    let reports = if let Some(stack) = stack {
        vec![
            engine
                .health(&stack, observed_at_ms)
                .map_err(anyhow::Error::msg)?,
        ]
    } else {
        engine
            .health_all(observed_at_ms)
            .map_err(anyhow::Error::msg)?
    };
    Ok(DaemonResponse::Health(reports))
}

fn lock_mutation(state: &DaemonState) -> Result<std::sync::MutexGuard<'_, ()>> {
    let guard = state
        .mutations
        .lock()
        .map_err(|_| anyhow::anyhow!("daemon mutation state is unavailable"))?;
    if state.stopping.load(Ordering::Acquire) {
        bail!("engine daemon is shutting down");
    }
    Ok(guard)
}

fn drain_clients(active: &AtomicUsize) -> Result<()> {
    let deadline = Instant::now() + CLIENT_DRAIN_TIMEOUT;
    while active.load(Ordering::Acquire) != 0 {
        if Instant::now() >= deadline {
            bail!("engine clients did not drain before shutdown");
        }
        thread::sleep(ACCEPT_POLL_INTERVAL);
    }
    Ok(())
}

fn reconcile_supervisors(
    state: &DaemonState,
    executable: &Path,
    supervisors: &mut BTreeMap<String, ManagedSupervisor>,
    retries: &mut BTreeMap<String, SupervisorRetry>,
) -> Result<()> {
    let finished = supervisors
        .iter_mut()
        .filter_map(|(stack, supervisor)| match supervisor.child.try_wait() {
            Ok(Some(_)) | Err(_) => Some((
                stack.clone(),
                supervisor.started_at.elapsed() >= SUPERVISOR_STABLE_WINDOW,
            )),
            Ok(None) => None,
        })
        .collect::<Vec<_>>();
    for (stack, stable) in finished {
        supervisors.remove(&stack);
        schedule_supervisor_retry(retries, &stack, stable);
    }
    state
        .active_supervisors
        .store(supervisors.len(), Ordering::Release);

    let engine = EngineStore::open(&state.root).map_err(anyhow::Error::msg)?;
    let statuses = engine.list().map_err(anyhow::Error::msg)?;
    for status in statuses {
        if status.state != EngineStackState::Applied {
            retries.remove(&status.stack);
            continue;
        }
        let Some((_revision, generation, _plan)) = engine
            .desired_plan(&status.stack)
            .map_err(anyhow::Error::msg)?
        else {
            continue;
        };
        if let Some(supervisor) = supervisors.get(&status.stack) {
            if supervisor.generation == generation {
                continue;
            }
            continue;
        }
        if supervisors.len() >= usize::from(state.max_supervisors)
            || retries
                .get(&status.stack)
                .is_some_and(|retry| Instant::now() < retry.deadline)
        {
            continue;
        }
        let should_run = engine
            .runtime_status(&status.stack)
            .map_err(anyhow::Error::msg)?
            .is_none_or(|runtime| {
                runtime.replicas.iter().any(|replica| {
                    matches!(
                        replica.phase,
                        ReplicaPhase::Pending
                            | ReplicaPhase::Starting
                            | ReplicaPhase::Running
                            | ReplicaPhase::Backoff
                    )
                })
            });
        if !should_run {
            retries.remove(&status.stack);
            continue;
        }
        let Ok(child) = spawn_supervisor(state, executable, &status.stack) else {
            schedule_supervisor_retry(retries, &status.stack, false);
            continue;
        };
        supervisors.insert(
            status.stack.clone(),
            ManagedSupervisor {
                child,
                generation,
                started_at: Instant::now(),
            },
        );
    }
    state
        .active_supervisors
        .store(supervisors.len(), Ordering::Release);
    Ok(())
}

fn schedule_supervisor_retry(
    retries: &mut BTreeMap<String, SupervisorRetry>,
    stack: &str,
    stable: bool,
) {
    let attempts = if stable {
        1
    } else {
        retries
            .get(stack)
            .map_or(1, |retry| retry.attempts.saturating_add(1))
    };
    let multiplier = 1_u32 << u32::from(attempts.saturating_sub(1).min(7));
    let delay = MIN_SUPERVISOR_RETRY_DELAY
        .saturating_mul(multiplier)
        .min(MAX_SUPERVISOR_RETRY_DELAY);
    retries.insert(
        stack.into(),
        SupervisorRetry {
            attempts,
            deadline: Instant::now() + delay,
        },
    );
}

fn spawn_supervisor(state: &DaemonState, executable: &Path, stack: &str) -> Result<ContainedChild> {
    let mut command = ContainedCommand::new(executable);
    command
        .arg("stack")
        .arg("supervise")
        .arg(stack)
        .arg("--library")
        .arg(&state.library)
        .arg("--root")
        .arg(&state.root)
        .arg("--max-workers")
        .arg(state.workers_per_stack.to_string())
        .arg("--daemon-instance")
        .arg(state.codec.instance_id())
        .arg("--json")
        .stdout(OutputMode::Null)
        .stderr(OutputMode::Null);
    spawn_contained(&mut command, true).context("could not start a stack supervisor")
}

fn stop_supervisors(supervisors: &mut BTreeMap<String, ManagedSupervisor>) {
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while !supervisors.is_empty() && Instant::now() < deadline {
        supervisors.retain(|_, supervisor| supervisor.child.try_wait().ok().flatten().is_none());
        if !supervisors.is_empty() {
            thread::sleep(RECONCILE_INTERVAL);
        }
    }
    for supervisor in supervisors.values_mut() {
        let _ = supervisor.child.terminate(TERMINATION_GRACE);
    }
    supervisors.clear();
}

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
    Ok(())
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).context("frame length overflow")?;
    if length == 0 || length > MAX_DAEMON_FRAME_BYTES {
        bail!("daemon frame length is invalid");
    }
    let mut frame = vec![0_u8; length];
    stream.read_exact(&mut frame)?;
    Ok(frame)
}

fn write_frame(stream: &mut impl Write, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_DAEMON_FRAME_BYTES {
        bail!("daemon frame length is invalid");
    }
    let length = u32::try_from(frame.len()).context("frame length overflow")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

fn current_time_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_millis();
    u64::try_from(millis).context("system timestamp overflow")
}

fn safe_error(value: &str) -> String {
    let mut safe = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(1024)
        .collect::<String>();
    if safe.trim().is_empty() {
        safe = "engine request failed".into();
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicates_and_stale_requests() {
        let mut cache = ReplayCache::default();
        let id = "a".repeat(64);
        cache.accept(&id, 100_000, 100_000).unwrap();
        assert!(cache.accept(&id, 100_000, 100_000).is_err());
        assert!(cache.accept(&"b".repeat(64), 1, 100_000).is_err());
    }

    #[test]
    fn framing_rejects_zero_and_oversized_messages() {
        let mut zero = std::io::Cursor::new(0_u32.to_be_bytes());
        assert!(read_frame(&mut zero).is_err());

        let oversized = u32::try_from(MAX_DAEMON_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes();
        let mut oversized = std::io::Cursor::new(oversized);
        assert!(read_frame(&mut oversized).is_err());
    }

    #[test]
    fn unsafe_error_text_is_bounded_and_terminal_safe() {
        let safe = safe_error(&format!("{}\nsecret", "x".repeat(2048)));
        assert_eq!(safe.chars().count(), 1024);
        assert!(!safe.chars().any(char::is_control));
    }

    #[test]
    fn supervisor_process_retries_back_off_and_reset_after_stability() {
        let mut retries = BTreeMap::new();
        for expected in 1..=20 {
            schedule_supervisor_retry(&mut retries, "demo", false);
            assert_eq!(retries["demo"].attempts, expected);
            assert!(
                retries["demo"]
                    .deadline
                    .saturating_duration_since(Instant::now())
                    <= MAX_SUPERVISOR_RETRY_DELAY
            );
        }
        schedule_supervisor_retry(&mut retries, "demo", true);
        assert_eq!(retries["demo"].attempts, 1);
    }
}

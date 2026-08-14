mod host;

use std::{path::Path, sync::Arc, thread, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use cartridge_core::{
    CartridgeArchive, MigrationPlan, PackageManifest, Permissions, RuntimeLimits, StateMigration,
    negotiate_platform,
};
pub use cartridge_media::{
    AudioDevice, AudioDeviceCatalog, AudioDocument, AudioLimits, AudioNode, AudioParameter,
    AudioReceipt, AudioRender, AudioTelemetry, Color, DrawCommand, FrameDocument, FrameReceipt,
    GraphicsLimits, InputEvent, MidiEvent, ParameterEvent, RealtimeBuffer, RenderedFrame,
    SAMPLE_RATE, Waveform, WindowConfig,
};
use cartridge_network::HttpTransport;
pub use cartridge_storage::{
    BLOB_REACHABILITY_FORMAT_VERSION, BlobAuditIssue, BlobAuditReport, BlobGcReport, BlobInfo,
    BlobInventory, BlobReachabilityManifest, BlobReachabilitySource, BlobReachabilitySourceKind,
    BlobReachabilitySummary, BlobReference, BlobReferenceVerification, BlobStore, CapturedState,
    DirectoryStorage, GenerationEvidence, MAX_BLOB_BYTES, MAX_BLOB_GC_ROOTS, MAX_BLOB_OBJECTS,
    MAX_BLOB_REACHABILITY_DOCUMENT_BYTES, MAX_BLOB_REACHABILITY_SOURCES,
    MAX_TRANSACTION_INPUT_BYTES, MAX_TRANSACTION_OPERATIONS, MemoryStorage, RecoveryReport,
    RestorePlan, SnapshotComparison, SnapshotDifference, SnapshotEntry, SnapshotStorage,
    StorageBackend, StorageLimits, StorageMutation, StorageSnapshot, StorageSnapshotSummary,
    StorageTransactionResult, StorageUsage,
};
pub use cartridge_trace::{
    CURRENT_TRACE_FORMAT_VERSION, ExecutionTrace, MAX_TRACE_BYTES, MAX_TRACE_DOCUMENT_BYTES,
    MAX_TRACE_EVENTS, MAX_TRACE_OUTPUT_BYTES, ReplayError, TraceComparison, TraceDifference,
    TraceEvent, TraceIdentity, TraceResult, TraceSummary,
};
use host::{HostState, RuntimeMonotonic, RuntimeMonotonicView, RuntimePoll, RuntimePollView};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, WasmBacktraceDetails};
use wasmtime_wasi::p2::bindings::clocks::monotonic_clock;
use wasmtime_wasi::p2::bindings::sync::io::poll;

const EPOCH_TICK_MS: u64 = 10;
const MAX_GUEST_ERROR_BYTES: usize = 16 * 1024;

pub const MAX_MIGRATION_STEPS_PER_RUN: usize = 64;
pub const MAX_MIGRATION_TOTAL_TIMEOUT_MS: u64 = 10 * 60 * 1000;

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "cartridge",
});

#[derive(Debug)]
pub struct Runtime {
    engine: Engine,
    storage: Arc<dyn StorageBackend>,
    input_events: Vec<InputEvent>,
    midi_events: Vec<MidiEvent>,
    http_transport: Option<Arc<dyn HttpTransport>>,
    permission_ceiling: Option<Permissions>,
    limit_ceiling: Option<RuntimeLimits>,
}

impl Runtime {
    pub fn new() -> Result<Self> {
        Self::with_storage(Arc::new(MemoryStorage::new()))
    }

    pub fn with_storage(storage: Arc<dyn StorageBackend>) -> Result<Self> {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .wasm_component_model_gc(false)
            .wasm_shared_everything_threads(false)
            .wasm_memory64(false)
            .wasm_multi_memory(false)
            .wasm_gc(false)
            .wasm_tail_call(false)
            .wasm_relaxed_simd(false)
            .wasm_stack_switching(false)
            .wasm_custom_page_sizes(false)
            .wasm_wide_arithmetic(false)
            .debug_info(false)
            .debug_symbols(false)
            .generate_address_map(false)
            .wasm_backtrace_details(WasmBacktraceDetails::Disable)
            .consume_fuel(true)
            .epoch_interruption(true);
        let engine = Engine::new(&config)?;
        start_epoch_ticker(&engine)?;
        Ok(Self {
            engine,
            storage,
            input_events: Vec::new(),
            midi_events: Vec::new(),
            http_transport: None,
            permission_ceiling: None,
            limit_ceiling: None,
        })
    }

    pub fn with_media_input(
        mut self,
        input_events: Vec<InputEvent>,
        midi_events: Vec<MidiEvent>,
    ) -> Result<Self> {
        if input_events.len() > cartridge_media::MAX_INPUT_EVENTS {
            bail!("input event limit exceeded");
        }
        if midi_events.len() > cartridge_media::MAX_MIDI_EVENTS {
            bail!("MIDI event limit exceeded");
        }
        for event in &midi_events {
            event.validate().map_err(|error| anyhow!(error))?;
        }
        self.input_events = input_events;
        self.midi_events = midi_events;
        Ok(self)
    }

    #[must_use]
    pub fn with_http_transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.http_transport = Some(transport);
        self
    }

    #[must_use]
    pub fn with_permission_ceiling(mut self, permissions: Permissions) -> Self {
        self.permission_ceiling = Some(permissions);
        self
    }

    pub fn with_limit_ceiling(mut self, limits: RuntimeLimits) -> Result<Self> {
        limits.validate().map_err(|error| anyhow!(error))?;
        self.limit_ceiling = Some(limits);
        Ok(self)
    }

    pub fn run_file(&self, path: impl AsRef<Path>, args: &[String]) -> Result<RunReport> {
        let archive = open_archive(path)?;
        self.run(archive, args)
    }

    pub fn validate_file(&self, path: impl AsRef<Path>) -> Result<PackageManifest> {
        let archive = open_archive(path)?;
        negotiate_platform(&archive.manifest).map_err(|error| anyhow!(error))?;
        let component = Component::new(&self.engine, &archive.component)
            .map_err(|error| anyhow!("the package component could not be compiled: {error}"))?;
        self.linker()?
            .instantiate_pre(&component)
            .map_err(|error| anyhow!("the package API does not match this runtime: {error}"))?;
        Ok(archive.manifest)
    }

    pub fn run(&self, archive: CartridgeArchive, args: &[String]) -> Result<RunReport> {
        self.execute(archive, args, None, false)
    }

    pub fn replay_file(
        &self,
        path: impl AsRef<Path>,
        args: &[String],
        trace: ExecutionTrace,
    ) -> Result<RunReport> {
        let archive = open_archive(path)?;
        self.replay(archive, args, trace)
    }

    pub fn replay(
        &self,
        archive: CartridgeArchive,
        args: &[String],
        trace: ExecutionTrace,
    ) -> Result<RunReport> {
        trace.validate_invocation(
            env!("CARGO_PKG_VERSION"),
            trace_identity(&archive.manifest),
            args,
        )?;
        self.execute(archive, args, Some(trace), false)
    }

    pub fn replay_from_snapshot(
        &self,
        archive: CartridgeArchive,
        args: &[String],
        trace: ExecutionTrace,
        source: &StorageSnapshot,
    ) -> Result<StateReplayReport> {
        trace.validate_invocation(
            env!("CARGO_PKG_VERSION"),
            trace_identity(&archive.manifest),
            args,
        )?;
        let cartridge_id = archive.manifest.cartridge.id.clone();
        let state_schema = archive.manifest.state.schema;
        let runtime_limits = self.effective_limits(&archive.manifest.runtime);
        let limits = storage_limits(&runtime_limits);
        let branch = Arc::new(SnapshotStorage::from_snapshot(
            source,
            &cartridge_id,
            limits,
        )?);
        branch.prepare(&cartridge_id, state_schema, limits)?;
        let runtime = Self {
            engine: self.engine.clone(),
            storage: branch.clone(),
            input_events: self.input_events.clone(),
            midi_events: self.midi_events.clone(),
            http_transport: self.http_transport.clone(),
            permission_ceiling: self.permission_ceiling.clone(),
            limit_ceiling: self.limit_ceiling.clone(),
        };
        let run = runtime.execute(archive, args, Some(trace), true)?;
        let snapshot = branch.export_snapshot()?;
        Ok(StateReplayReport { run, snapshot })
    }

    fn execute(
        &self,
        archive: CartridgeArchive,
        args: &[String],
        replay: Option<ExecutionTrace>,
        apply_replay_storage: bool,
    ) -> Result<RunReport> {
        negotiate_platform(&archive.manifest).map_err(|error| anyhow!(error))?;
        let permissions = self.effective_permissions(&archive.manifest.permissions);
        let mut manifest = archive.manifest;
        manifest.runtime = self.effective_limits(&manifest.runtime);
        if replay.is_none() && permissions.storage {
            self.storage.prepare(
                &manifest.cartridge.id,
                manifest.state.schema,
                storage_limits(&manifest.runtime),
            )?;
        }
        let component = Component::new(&self.engine, &archive.component)
            .map_err(|error| anyhow!("the package component could not be compiled: {error}"))?;
        let linker = self.linker()?;

        let expected_result = replay.as_ref().map(|trace| trace.result.clone());
        let expected_events = replay.map(|trace| trace.events);
        let mut host = HostState::new_with_permissions(
            &manifest,
            permissions,
            Arc::new(archive.assets),
            self.storage.clone(),
            expected_events,
        )
        .with_http_transport(self.http_transport.clone())
        .with_media_input(&self.input_events, &self.midi_events)
        .map_err(|error| anyhow!(error))?;
        if apply_replay_storage {
            host = host.apply_replay_storage();
        }
        let mut store = Store::new(&self.engine, host);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(manifest.runtime.fuel)?;
        store.set_epoch_deadline(timeout_ticks(manifest.runtime.timeout_ms));

        let instance = Cartridge::instantiate(&mut store, &component, &linker)
            .map_err(|error| anyhow!("the component could not be instantiated: {error}"))?;
        let call_result = instance.call_run(&mut store, args);
        let fuel_remaining = store.get_fuel()?;
        let mut state = store.into_data();
        state.finish_replay()?;
        let (frames, audio, media_metrics) = state.take_media();

        let result =
            call_result.map_err(|error| anyhow!("the component trapped while running: {error}"))?;
        let output = match result {
            Ok(output) => output,
            Err(message) if message.len() <= MAX_GUEST_ERROR_BYTES => {
                return Err(anyhow!("cartridge returned an error: {message}"));
            }
            Err(_) => {
                return Err(anyhow!(
                    "cartridge returned an error larger than the {MAX_GUEST_ERROR_BYTES} byte limit"
                ));
            }
        };
        if output.len() > MAX_TRACE_OUTPUT_BYTES {
            return Err(anyhow!(
                "cartridge output exceeds the {MAX_TRACE_OUTPUT_BYTES} byte limit"
            ));
        }
        let fuel_consumed = manifest.runtime.fuel.saturating_sub(fuel_remaining);
        let trace_result = TraceResult {
            output: output.clone(),
            fuel_consumed,
        };
        if let Some(expected) = expected_result {
            expected.compare(&trace_result)?;
        }

        let trace = ExecutionTrace::new(
            env!("CARGO_PKG_VERSION"),
            trace_identity(&manifest),
            args,
            state.events,
            trace_result,
        );
        Ok(RunReport {
            cartridge: manifest.cartridge,
            output,
            fuel_consumed,
            trace,
            media: MediaArtifacts { frames, audio },
            media_metrics,
            declared_memory_limit_bytes: manifest.runtime.memory_bytes,
        })
    }

    pub fn migrate(
        &self,
        archive: CartridgeArchive,
        source: StorageSnapshot,
    ) -> Result<MigrationReport> {
        let mut manifest = archive.manifest;
        manifest.runtime = self.effective_limits(&manifest.runtime);
        let plan = manifest.migration_plan(source.state_schema())?;
        validate_migration_budget(&manifest, &plan)?;
        let limits = storage_limits(&manifest.runtime);
        let cartridge_id = manifest.cartridge.id.clone();
        let initial = SnapshotStorage::from_snapshot(&source, &cartridge_id, limits)?;
        initial.prepare(&cartridge_id, source.state_schema(), limits)?;
        drop(initial);

        if plan.steps.is_empty() {
            return Ok(MigrationReport {
                plan,
                steps: Vec::new(),
                snapshot: source,
            });
        }
        if !self.effective_permissions(&manifest.permissions).storage {
            bail!("state migrations require the storage permission");
        }

        let component = Component::new(&self.engine, &archive.component)
            .map_err(|error| anyhow!("the migration component could not be compiled: {error}"))?;
        let assets = Arc::new(archive.assets);
        let mut current = source;
        let mut reports = Vec::with_capacity(plan.steps.len());

        for step in &plan.steps {
            let branch = Arc::new(SnapshotStorage::from_snapshot(
                &current,
                &cartridge_id,
                limits,
            )?);
            branch.prepare(&cartridge_id, step.from, limits)?;
            let report = self.execute_migration_step(
                &component,
                &manifest,
                assets.clone(),
                branch.clone(),
                step,
            )?;
            let next = branch.export_migrated_snapshot(step.from, step.to, limits)?;
            next.summary()?;
            current = next;
            reports.push(report);
        }

        if current.state_schema() != plan.target_schema {
            bail!(
                "migration ended at schema {}; expected {}",
                current.state_schema(),
                plan.target_schema
            );
        }
        Ok(MigrationReport {
            plan,
            steps: reports,
            snapshot: current,
        })
    }

    fn execute_migration_step(
        &self,
        component: &Component,
        manifest: &PackageManifest,
        assets: Arc<std::collections::BTreeMap<String, Vec<u8>>>,
        storage: Arc<SnapshotStorage>,
        step: &StateMigration,
    ) -> Result<MigrationStepReport> {
        let linker = self.linker()?;
        let permissions = self.effective_permissions(&manifest.permissions);
        let mut store = Store::new(
            &self.engine,
            HostState::new_with_permissions(manifest, permissions, assets, storage, None),
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(manifest.runtime.fuel)?;
        store.set_epoch_deadline(timeout_ticks(manifest.runtime.timeout_ms));

        let instance = linker.instantiate(&mut store, component).map_err(|error| {
            anyhow!("migration {} could not be instantiated: {error}", step.name)
        })?;
        let migrate = instance
            .get_typed_func::<(&str, u32, u32), (std::result::Result<(), String>,)>(
                &mut store, "migrate",
            )
            .map_err(|error| {
                anyhow!("component does not export the required migration function: {error}")
            })?;
        let call = migrate.call(&mut store, (&step.name, step.from, step.to));
        let fuel_remaining = store.get_fuel()?;
        let mut state = store.into_data();
        state.finish_replay()?;
        let (result,) = call
            .map_err(|error| anyhow!("migration {} trapped while running: {error}", step.name))?;
        if let Err(message) = result {
            if message.len() > MAX_GUEST_ERROR_BYTES {
                bail!(
                    "migration {} returned an error larger than the {MAX_GUEST_ERROR_BYTES} byte limit",
                    step.name
                );
            }
            bail!("migration {} returned an error: {message}", step.name);
        }
        Ok(MigrationStepReport {
            name: step.name.clone(),
            from: step.from,
            to: step.to,
            fuel_consumed: manifest.runtime.fuel.saturating_sub(fuel_remaining),
            event_count: state.events.len(),
        })
    }

    fn effective_permissions(&self, requested: &Permissions) -> Permissions {
        let Some(ceiling) = &self.permission_ceiling else {
            return requested.clone();
        };
        Permissions {
            clock: requested.clock && ceiling.clock,
            random: requested.random && ceiling.random,
            assets: requested.assets && ceiling.assets,
            storage: requested.storage && ceiling.storage,
            graphics: requested.graphics && ceiling.graphics,
            audio: requested.audio && ceiling.audio,
            midi: requested.midi && ceiling.midi,
            http: requested.http && ceiling.http,
        }
    }

    fn effective_limits(&self, requested: &RuntimeLimits) -> RuntimeLimits {
        self.limit_ceiling.as_ref().map_or_else(
            || requested.clone(),
            |ceiling| requested.constrained_by(ceiling),
        )
    }

    fn linker(&self) -> Result<Linker<HostState>> {
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        linker.allow_shadowing(true);
        monotonic_clock::add_to_linker::<_, RuntimeMonotonic>(&mut linker, |state| {
            RuntimeMonotonicView { state }
        })?;
        poll::add_to_linker::<_, RuntimePoll>(&mut linker, |state| RuntimePollView { state })?;
        linker.allow_shadowing(false);
        Cartridge::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
        Ok(linker)
    }
}

fn validate_migration_budget(manifest: &PackageManifest, plan: &MigrationPlan) -> Result<()> {
    if plan.steps.len() > MAX_MIGRATION_STEPS_PER_RUN {
        bail!(
            "migration plan contains {} steps; maximum is {MAX_MIGRATION_STEPS_PER_RUN}",
            plan.steps.len()
        );
    }
    let step_count = u64::try_from(plan.steps.len()).unwrap_or(u64::MAX);
    let total_timeout = manifest
        .runtime
        .timeout_ms
        .checked_mul(step_count)
        .ok_or_else(|| anyhow!("migration timeout budget overflowed"))?;
    if total_timeout > MAX_MIGRATION_TOTAL_TIMEOUT_MS {
        bail!(
            "migration timeout budget is {total_timeout} ms; maximum is {MAX_MIGRATION_TOTAL_TIMEOUT_MS} ms"
        );
    }
    Ok(())
}

fn start_epoch_ticker(engine: &Engine) -> Result<()> {
    let engine = engine.weak();
    thread::Builder::new()
        .name("cartridge-epoch".into())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                let Some(engine) = engine.upgrade() else {
                    break;
                };
                engine.increment_epoch();
            }
        })
        .context("could not start the runtime deadline thread")?;
    Ok(())
}

fn timeout_ticks(timeout_ms: u64) -> u64 {
    timeout_ms.div_ceil(EPOCH_TICK_MS)
}

fn trace_identity(manifest: &cartridge_core::PackageManifest) -> TraceIdentity<'_> {
    TraceIdentity {
        cartridge_id: &manifest.cartridge.id,
        cartridge_version: &manifest.cartridge.version,
        component_sha256: &manifest.integrity.component_sha256,
    }
}

fn storage_limits(limits: &RuntimeLimits) -> StorageLimits {
    StorageLimits {
        max_bytes: limits.storage_bytes,
        max_keys: limits.storage_keys,
        max_value_bytes: limits.storage_value_bytes,
    }
}

fn open_archive(path: impl AsRef<Path>) -> Result<CartridgeArchive> {
    CartridgeArchive::open(path.as_ref())
        .with_context(|| format!("could not open {}", path.as_ref().display()))
}

#[derive(Debug)]
pub struct RunReport {
    pub cartridge: cartridge_core::CartridgeMetadata,
    pub output: String,
    pub fuel_consumed: u64,
    pub trace: ExecutionTrace,
    pub media: MediaArtifacts,
    pub media_metrics: MediaMetrics,
    pub declared_memory_limit_bytes: usize,
}

#[derive(Debug, Default)]
pub struct MediaArtifacts {
    pub frames: Vec<RenderedFrame>,
    pub audio: Vec<AudioRender>,
}

#[derive(Debug, Default)]
pub struct MediaMetrics {
    pub graphics_present_calls: u64,
    pub graphics_present_micros: u128,
    pub audio_render_calls: u64,
    pub audio_render_micros: u128,
}

#[derive(Debug)]
pub struct StateReplayReport {
    pub run: RunReport,
    pub snapshot: StorageSnapshot,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MigrationStepReport {
    pub name: String,
    pub from: u32,
    pub to: u32,
    pub fuel_consumed: u64,
    pub event_count: usize,
}

#[derive(Debug)]
pub struct MigrationReport {
    pub plan: MigrationPlan,
    pub steps: Vec<MigrationStepReport>,
    pub snapshot: StorageSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration_manifest(timeout_ms: u64) -> PackageManifest {
        PackageManifest {
            format_version: 1,
            cartridge: cartridge_core::CartridgeMetadata {
                id: "dev.example.migration".into(),
                name: "Migration".into(),
                version: "1.0.0".into(),
                description: String::new(),
            },
            permissions: cartridge_core::Permissions {
                storage: true,
                ..Default::default()
            },
            http: cartridge_network::HttpPolicy::default(),
            compatibility: cartridge_core::Compatibility::default(),
            runtime: cartridge_core::RuntimeLimits {
                timeout_ms,
                ..Default::default()
            },
            state: cartridge_core::StateConfig::default(),
            dependencies: Vec::new(),
            services: cartridge_core::Services::default(),
            integrity: cartridge_core::Integrity::default(),
        }
    }

    fn migration_plan(steps: usize) -> MigrationPlan {
        MigrationPlan {
            format_version: 1,
            cartridge_id: "dev.example.migration".into(),
            cartridge_version: "1.0.0".into(),
            component_sha256: "a".repeat(64),
            source_schema: 0,
            target_schema: u32::try_from(steps).unwrap(),
            steps: (0..steps)
                .map(|index| StateMigration {
                    name: format!("step-{index}"),
                    from: u32::try_from(index).unwrap(),
                    to: u32::try_from(index + 1).unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn timeout_is_rounded_up_to_the_next_epoch() {
        assert_eq!(timeout_ticks(1), 1);
        assert_eq!(timeout_ticks(10), 1);
        assert_eq!(timeout_ticks(11), 2);
    }

    #[test]
    fn epoch_deadline_interrupts_compute() {
        let runtime = Runtime::new().unwrap();
        let wasm = wat::parse_str("(module (func (export \"spin\") (loop br 0)))").unwrap();
        let module = wasmtime::Module::new(&runtime.engine, wasm).unwrap();
        let mut store = Store::new(&runtime.engine, ());
        store.set_fuel(u64::MAX).unwrap();
        store.set_epoch_deadline(1);
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
        let spin = instance
            .get_typed_func::<(), ()>(&mut store, "spin")
            .unwrap();

        let error = spin.call(&mut store, ()).unwrap_err();
        let message = format!("{error:#}");

        assert!(message.contains("interrupt"), "{message}");
    }

    #[test]
    fn migration_budget_bounds_steps_and_aggregate_wall_time() {
        assert!(
            validate_migration_budget(
                &migration_manifest(1),
                &migration_plan(MAX_MIGRATION_STEPS_PER_RUN + 1)
            )
            .is_err()
        );
        assert!(
            validate_migration_budget(&migration_manifest(300_000), &migration_plan(3)).is_err()
        );
        validate_migration_budget(&migration_manifest(300_000), &migration_plan(2)).unwrap();
    }

    #[test]
    fn permission_ceiling_can_only_remove_requested_authority() {
        let requested = Permissions {
            clock: true,
            random: true,
            storage: true,
            http: true,
            ..Permissions::default()
        };
        let ceiling = Permissions {
            clock: true,
            graphics: true,
            ..Permissions::default()
        };
        let runtime = Runtime::new().unwrap().with_permission_ceiling(ceiling);
        let effective = runtime.effective_permissions(&requested);

        assert!(effective.clock);
        assert!(!effective.random);
        assert!(!effective.storage);
        assert!(!effective.http);
        assert!(!effective.graphics);
    }

    #[test]
    fn runtime_limit_ceiling_can_only_reduce_requested_budgets() {
        let requested = RuntimeLimits::maximum();
        let ceiling = RuntimeLimits {
            fuel: 42,
            memory_bytes: 4 * 1024 * 1024,
            timeout_ms: 75,
            ..RuntimeLimits::maximum()
        };
        let runtime = Runtime::new().unwrap().with_limit_ceiling(ceiling).unwrap();

        let effective = runtime.effective_limits(&requested);

        assert_eq!(effective.fuel, 42);
        assert_eq!(effective.memory_bytes, 4 * 1024 * 1024);
        assert_eq!(effective.timeout_ms, 75);
    }
}

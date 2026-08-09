mod host;

use std::{path::Path, sync::Arc, thread, time::Duration};

use anyhow::{Context, Result, anyhow};
use cartridge_core::CartridgeArchive;
pub use cartridge_storage::{
    DirectoryStorage, MemoryStorage, RecoveryReport, RestorePlan, SnapshotComparison,
    SnapshotDifference, SnapshotEntry, SnapshotStorage, StorageBackend, StorageLimits,
    StorageSnapshot, StorageSnapshotSummary, StorageUsage,
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

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "cartridge",
});

#[derive(Debug)]
pub struct Runtime {
    engine: Engine,
    storage: Arc<dyn StorageBackend>,
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
        Ok(Self { engine, storage })
    }

    pub fn run_file(&self, path: impl AsRef<Path>, args: &[String]) -> Result<RunReport> {
        let archive = open_archive(path)?;
        self.run(archive, args)
    }

    pub fn run(&self, archive: CartridgeArchive, args: &[String]) -> Result<RunReport> {
        self.execute(archive, args, None)
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
        self.execute(archive, args, Some(trace))
    }

    fn execute(
        &self,
        archive: CartridgeArchive,
        args: &[String],
        replay: Option<ExecutionTrace>,
    ) -> Result<RunReport> {
        if replay.is_none() && archive.manifest.permissions.storage {
            self.storage.prepare(
                &archive.manifest.cartridge.id,
                archive.manifest.state.schema,
                storage_limits(&archive.manifest),
            )?;
        }
        let component = Component::new(&self.engine, &archive.component)
            .map_err(|error| anyhow!("the package component could not be compiled: {error}"))?;
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        linker.allow_shadowing(true);
        monotonic_clock::add_to_linker::<_, RuntimeMonotonic>(&mut linker, |state| {
            RuntimeMonotonicView { state }
        })?;
        poll::add_to_linker::<_, RuntimePoll>(&mut linker, |state| RuntimePollView { state })?;
        linker.allow_shadowing(false);
        Cartridge::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

        let manifest = archive.manifest;
        let expected_result = replay.as_ref().map(|trace| trace.result.clone());
        let expected_events = replay.map(|trace| trace.events);
        let mut store = Store::new(
            &self.engine,
            HostState::new(
                &manifest,
                archive.assets,
                self.storage.clone(),
                expected_events,
            ),
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(manifest.runtime.fuel)?;
        store.set_epoch_deadline(timeout_ticks(manifest.runtime.timeout_ms));

        let instance = Cartridge::instantiate(&mut store, &component, &linker)
            .map_err(|error| anyhow!("the component could not be instantiated: {error}"))?;
        let call_result = instance.call_run(&mut store, args);
        let fuel_remaining = store.get_fuel()?;
        let mut state = store.into_data();
        state.finish_replay()?;

        let result =
            call_result.map_err(|error| anyhow!("the component trapped while running: {error}"))?;
        let output = result.map_err(|message| anyhow!("cartridge returned an error: {message}"))?;
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
        })
    }
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

fn storage_limits(manifest: &cartridge_core::PackageManifest) -> StorageLimits {
    StorageLimits {
        max_bytes: manifest.runtime.storage_bytes,
        max_keys: manifest.runtime.storage_keys,
        max_value_bytes: manifest.runtime.storage_value_bytes,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

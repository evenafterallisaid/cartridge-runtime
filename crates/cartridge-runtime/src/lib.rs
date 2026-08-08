mod host;
mod trace;

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use cartridge_core::CartridgeArchive;
use host::HostState;
pub use trace::{
    CURRENT_TRACE_FORMAT_VERSION, ExecutionTrace, ReplayError, TraceEvent, TraceResult,
};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "cartridge",
});

#[derive(Debug)]
pub struct Runtime {
    engine: Engine,
}

impl Runtime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true).consume_fuel(true);
        let engine = Engine::new(&config)?;
        Ok(Self { engine })
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
        trace.validate_invocation(&archive.manifest, args)?;
        self.execute(archive, args, Some(trace))
    }

    fn execute(
        &self,
        archive: CartridgeArchive,
        args: &[String],
        replay: Option<ExecutionTrace>,
    ) -> Result<RunReport> {
        let component = Component::new(&self.engine, &archive.component)
            .map_err(|error| anyhow!("the package component could not be compiled: {error}"))?;
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        Cartridge::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

        let manifest = archive.manifest;
        let expected_result = replay.as_ref().map(|trace| trace.result.clone());
        let expected_events = replay.map(|trace| trace.events);
        let mut store = Store::new(
            &self.engine,
            HostState::new(&manifest, archive.assets, expected_events),
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(manifest.runtime.fuel)?;

        let instance = Cartridge::instantiate(&mut store, &component, &linker)
            .map_err(|error| anyhow!("the component could not be instantiated: {error}"))?;
        let call_result = instance.call_run(&mut store, args);
        let fuel_remaining = store.get_fuel()?;
        let mut state = store.into_data();
        state.finish_replay()?;

        let result =
            call_result.map_err(|error| anyhow!("the component trapped while running: {error}"))?;
        let output = result.map_err(|message| anyhow!("cartridge returned an error: {message}"))?;
        let fuel_consumed = manifest.runtime.fuel.saturating_sub(fuel_remaining);
        let trace_result = TraceResult {
            output: output.clone(),
            fuel_consumed,
        };
        if let Some(expected) = expected_result {
            expected.compare(&trace_result)?;
        }

        let trace = ExecutionTrace::new(&manifest, args, state.events, trace_result);
        Ok(RunReport {
            cartridge: manifest.cartridge,
            output,
            fuel_consumed,
            trace,
        })
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

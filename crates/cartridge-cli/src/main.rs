use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode, Stdio},
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use cartridge_core::{CartridgeArchive, PackOptions, ResolutionPlan, pack, resolve_dependencies};
use cartridge_runtime::{
    DirectoryStorage, Runtime, SnapshotDifference, SnapshotStorage, StorageLimits, StorageSnapshot,
};
use cartridge_trace::{ExecutionTrace, MAX_TRACE_DOCUMENT_BYTES, TraceDifference};
use clap::{Parser, Subcommand};

static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const WORKER_STARTUP_BUDGET: Duration = Duration::from_secs(10);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Parser)]
#[command(
    name = "cartridge",
    version,
    about = "pack and run portable wasm cartridges"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// build a cartridge archive from a manifest and component
    Pack {
        manifest: PathBuf,
        #[arg(long)]
        component: PathBuf,
        #[arg(long)]
        assets: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// show a cartridge's metadata without running it
    Inspect {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// validate a cartridge without executing it
    Verify { package: PathBuf },
    /// show requested and provided cartridge services
    Deps {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// resolve a cartridge against candidate dependency packages
    Resolve {
        root: PathBuf,
        candidates: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// execute a cartridge
    Run {
        package: PathBuf,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long, conflicts_with = "from_snapshot")]
        state_dir: Option<PathBuf>,
        #[arg(long, conflicts_with = "state_dir")]
        from_snapshot: Option<PathBuf>,
        #[arg(long, requires = "from_snapshot")]
        snapshot_output: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// replay a cartridge from a recorded trace
    Replay {
        package: PathBuf,
        trace: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    #[command(name = "__worker-run", hide = true)]
    WorkerRun {
        package: PathBuf,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long, conflicts_with = "from_snapshot")]
        state_dir: Option<PathBuf>,
        #[arg(long, conflicts_with = "state_dir")]
        from_snapshot: Option<PathBuf>,
        #[arg(long, requires = "from_snapshot")]
        snapshot_output: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    #[command(name = "__worker-replay", hide = true)]
    WorkerReplay {
        package: PathBuf,
        trace: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// inspect and compare execution traces
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    /// inspect and recover durable cartridge state
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    /// validate a trace and show its execution summary
    Inspect {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// find the first difference between two traces
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// show durable state usage for a cartridge
    Status {
        package: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// quarantine corrupt state and return to the newest valid generation
    Recover {
        package: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// export a portable snapshot without journal metadata
    Export {
        package: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// validate and summarize a portable snapshot
    Inspect {
        snapshot: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// find the first difference between two snapshots
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// plan or commit a transactional snapshot restore
    Restore {
        package: PathBuf,
        snapshot: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// build the ordered migration path to the package's current schema
    MigrationPlan {
        package: PathBuf,
        #[arg(long)]
        from_schema: u32,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", terminal_safe(&format!("{error:#}")));
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> Result<()> {
    match Cli::parse().command {
        Command::Pack {
            manifest,
            component,
            assets,
            output,
        } => pack_command(&manifest, &component, assets.as_deref(), &output),
        Command::Inspect { package, json } => inspect_command(&package, json),
        Command::Verify { package } => verify_command(&package),
        Command::Deps { package, json } => deps_command(&package, json),
        Command::Resolve {
            root,
            candidates,
            json,
        } => resolve_command(&root, &candidates, json),
        Command::Run {
            package,
            trace,
            state_dir,
            from_snapshot,
            snapshot_output,
            args,
        } => supervised_run_command(
            &package,
            trace.as_deref(),
            state_dir.as_deref(),
            from_snapshot.as_deref(),
            snapshot_output.as_deref(),
            &args,
        ),
        Command::Replay {
            package,
            trace,
            args,
        } => supervised_replay_command(&package, &trace, &args),
        Command::WorkerRun {
            package,
            trace,
            state_dir,
            from_snapshot,
            snapshot_output,
            args,
        } => run_command(
            &package,
            trace.as_deref(),
            state_dir.as_deref(),
            from_snapshot.as_deref(),
            snapshot_output.as_deref(),
            &args,
        ),
        Command::WorkerReplay {
            package,
            trace,
            args,
        } => replay_command(&package, &trace, &args),
        Command::Trace { command } => match command {
            TraceCommand::Inspect { trace, json } => trace_inspect_command(&trace, json),
            TraceCommand::Diff { left, right, json } => trace_diff_command(&left, &right, json),
        },
        Command::Storage { command } => match command {
            StorageCommand::Status {
                package,
                state_dir,
                json,
            } => storage_status_command(&package, &state_dir, json),
            StorageCommand::Recover {
                package,
                state_dir,
                json,
            } => storage_recover_command(&package, &state_dir, json),
            StorageCommand::Export {
                package,
                state_dir,
                output,
            } => storage_export_command(&package, &state_dir, &output),
            StorageCommand::Inspect { snapshot, json } => storage_inspect_command(&snapshot, json),
            StorageCommand::Diff { left, right, json } => storage_diff_command(&left, &right, json),
            StorageCommand::Restore {
                package,
                snapshot,
                state_dir,
                dry_run,
                json,
            } => storage_restore_command(&package, &snapshot, &state_dir, dry_run, json),
            StorageCommand::MigrationPlan {
                package,
                from_schema,
                json,
            } => storage_migration_plan_command(&package, from_schema, json),
        },
    }
}

fn supervised_run_command(
    package: &Path,
    trace: Option<&Path>,
    state_dir: Option<&Path>,
    from_snapshot: Option<&Path>,
    snapshot_output: Option<&Path>,
    args: &[String],
) -> Result<()> {
    let mut worker_args = vec![
        OsString::from("__worker-run"),
        package.as_os_str().to_owned(),
    ];
    push_path_option(&mut worker_args, "--trace", trace);
    push_path_option(&mut worker_args, "--state-dir", state_dir);
    push_path_option(&mut worker_args, "--from-snapshot", from_snapshot);
    push_path_option(&mut worker_args, "--snapshot-output", snapshot_output);
    push_worker_arguments(&mut worker_args, args);
    supervise_worker(package, &worker_args)
}

fn supervised_replay_command(package: &Path, trace: &Path, args: &[String]) -> Result<()> {
    let mut worker_args = vec![
        OsString::from("__worker-replay"),
        package.as_os_str().to_owned(),
        trace.as_os_str().to_owned(),
    ];
    push_worker_arguments(&mut worker_args, args);
    supervise_worker(package, &worker_args)
}

fn push_path_option(arguments: &mut Vec<OsString>, name: &str, value: Option<&Path>) {
    if let Some(value) = value {
        arguments.push(OsString::from(name));
        arguments.push(value.as_os_str().to_owned());
    }
}

fn push_worker_arguments(arguments: &mut Vec<OsString>, values: &[String]) {
    if values.is_empty() {
        return;
    }
    arguments.push(OsString::from("--"));
    arguments.extend(values.iter().map(OsString::from));
}

fn supervise_worker(package: &Path, arguments: &[OsString]) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not validate {} before execution", package.display()))?;
    let execution_budget = Duration::from_millis(archive.manifest.runtime.timeout_ms);
    drop(archive);
    let deadline = Instant::now() + WORKER_STARTUP_BUDGET + execution_budget;
    let executable = std::env::current_exe().context("could not locate the cartridge worker")?;
    let mut worker = ProcessCommand::new(executable)
        .args(arguments)
        .env_clear()
        .env("CARTRIDGE_WORKER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("could not start the cartridge worker")?;

    loop {
        if let Some(status) = worker.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(anyhow::anyhow!("cartridge worker exited with {status}"));
        }
        if Instant::now() >= deadline {
            worker
                .kill()
                .context("could not terminate the cartridge worker")?;
            let _ = worker.wait();
            return Err(anyhow::anyhow!(
                "cartridge worker exceeded its {} ms supervised deadline",
                (WORKER_STARTUP_BUDGET + execution_budget).as_millis()
            ));
        }
        thread::sleep(WORKER_POLL_INTERVAL);
    }
}

fn pack_command(
    manifest: &Path,
    component: &Path,
    assets: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let packed = pack(&PackOptions {
        manifest: manifest.to_owned(),
        component: component.to_owned(),
        assets: assets.map(Path::to_owned),
        output: output.to_owned(),
    })?;
    println!(
        "packed {} {} -> {}",
        packed.cartridge.name,
        packed.cartridge.version,
        output.display()
    );
    Ok(())
}

fn inspect_command(package: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&archive.manifest)?);
    } else {
        print_manifest(&archive);
    }
    Ok(())
}

fn verify_command(package: &Path) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not verify {}", package.display()))?;
    println!(
        "verified {} {}: component and {} asset(s)",
        archive.manifest.cartridge.id,
        archive.manifest.cartridge.version,
        archive.assets.len()
    );
    Ok(())
}

fn deps_command(package: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dependencies": archive.manifest.dependencies,
                "services": archive.manifest.services,
            }))?
        );
    } else {
        print_relationships(&archive);
    }
    Ok(())
}

fn resolve_command(root: &Path, candidates: &[PathBuf], json: bool) -> Result<()> {
    let root = CartridgeArchive::open(root)
        .with_context(|| format!("could not inspect {}", root.display()))?;
    let mut manifests = Vec::with_capacity(candidates.len());
    for path in candidates {
        let candidate = CartridgeArchive::open(path)
            .with_context(|| format!("could not inspect {}", path.display()))?;
        manifests.push(candidate.manifest);
    }
    let plan = resolve_dependencies(&root.manifest, &manifests)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_resolution(&plan);
    }
    Ok(())
}

fn run_command(
    package: &Path,
    trace: Option<&Path>,
    state_dir: Option<&Path>,
    from_snapshot: Option<&Path>,
    snapshot_output: Option<&Path>,
    args: &[String],
) -> Result<()> {
    let mut branch = None;
    let report = if let Some(path) = from_snapshot {
        let archive = CartridgeArchive::open(package)
            .with_context(|| format!("could not inspect {}", package.display()))?;
        let snapshot = StorageSnapshot::read(path)
            .with_context(|| format!("could not read snapshot {}", path.display()))?;
        let storage = Arc::new(SnapshotStorage::from_snapshot(
            &snapshot,
            &archive.manifest.cartridge.id,
            storage_limits(&archive.manifest),
        )?);
        let runtime = Runtime::with_storage(storage.clone())?;
        branch = Some(storage);
        runtime.run(archive, args)?
    } else {
        let runtime = match state_dir {
            Some(path) => Runtime::with_storage(Arc::new(DirectoryStorage::open(path)?))?,
            None => Runtime::new()?,
        };
        runtime.run_file(package, args)?
    };
    println!("{}", terminal_safe(&report.output));
    eprintln!("fuel consumed: {}", report.fuel_consumed);
    if let Some(path) = trace {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private(path, &serde_json::to_vec_pretty(&report.trace)?)?;
        eprintln!("trace: {}", path.display());
    }
    if let Some(path) = snapshot_output {
        let snapshot = branch
            .context("snapshot output requires a snapshot branch")?
            .export_snapshot()?;
        let summary = snapshot.summary()?;
        snapshot.write_new(path)?;
        eprintln!(
            "snapshot: {} key(s), {} bytes -> {}",
            summary.entries,
            summary.bytes,
            path.display()
        );
    }
    Ok(())
}

fn storage_status_command(package: &Path, state_dir: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let storage = DirectoryStorage::open(state_dir)?;
    let summary = storage
        .export_snapshot(&archive.manifest.cartridge.id)?
        .summary()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "cartridge_id": archive.manifest.cartridge.id,
                "state_dir": storage.root(),
                "state_schema": summary.state_schema,
                "usage": {
                    "bytes": summary.bytes,
                    "keys": summary.entries,
                },
            }))?
        );
    } else {
        println!("{}", archive.manifest.cartridge.id);
        println!("state directory: {}", storage.root().display());
        println!("state schema: {}", summary.state_schema);
        println!("keys: {}", summary.entries);
        println!("bytes: {}", summary.bytes);
    }
    Ok(())
}

fn storage_recover_command(package: &Path, state_dir: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let storage = DirectoryStorage::open(state_dir)?;
    let report = storage.recover(&archive.manifest.cartridge.id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("recovered {}", archive.manifest.cartridge.id);
        match report.valid_generation {
            Some(generation) => println!("active generation: {generation}"),
            None => println!("active generation: empty"),
        }
        println!("quarantined: {}", report.quarantined.len());
        println!("discarded pending: {}", report.discarded_pending);
    }
    Ok(())
}

fn storage_export_command(package: &Path, state_dir: &Path, output: &Path) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let storage = DirectoryStorage::open(state_dir)?;
    let snapshot = storage.export_snapshot(&archive.manifest.cartridge.id)?;
    let summary = snapshot.summary()?;
    snapshot.write_new(output)?;
    println!(
        "exported {} key(s), {} bytes -> {}",
        summary.entries,
        summary.bytes,
        output.display()
    );
    Ok(())
}

fn storage_inspect_command(path: &Path, json: bool) -> Result<()> {
    let snapshot = StorageSnapshot::read(path)
        .with_context(|| format!("could not inspect snapshot {}", path.display()))?;
    let summary = snapshot.summary()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("{}", summary.cartridge_id);
        println!("snapshot format: {}", summary.format_version);
        println!("state schema: {}", summary.state_schema);
        println!("entries: {}", summary.entries);
        println!("bytes: {}", summary.bytes);
        println!("payload sha256: {}", summary.payload_sha256);
    }
    Ok(())
}

fn storage_diff_command(left: &Path, right: &Path, json: bool) -> Result<()> {
    let left = StorageSnapshot::read(left)
        .with_context(|| format!("could not inspect snapshot {}", left.display()))?;
    let right = StorageSnapshot::read(right)
        .with_context(|| format!("could not inspect snapshot {}", right.display()))?;
    let comparison = left.compare(&right)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&comparison)?);
    } else if comparison.identical {
        println!("snapshots are identical");
    } else if let Some(difference) = comparison.difference {
        match difference {
            SnapshotDifference::Identity { left, right } => {
                println!("cartridge identity differs");
                println!("  left:  {left}");
                println!("  right: {right}");
            }
            SnapshotDifference::Schema { left, right } => {
                println!("state schema differs");
                println!("  left:  {left}");
                println!("  right: {right}");
            }
            SnapshotDifference::Entry { key, left, right } => {
                println!("first entry difference at {key}");
                println!("  left:  {}", serde_json::to_string(&left)?);
                println!("  right: {}", serde_json::to_string(&right)?);
            }
        }
    }
    Ok(())
}

fn storage_restore_command(
    package: &Path,
    snapshot: &Path,
    state_dir: &Path,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let snapshot = StorageSnapshot::read(snapshot)?;
    if snapshot.state_schema() != archive.manifest.state.schema {
        bail!(
            "snapshot uses state schema {}; package expects schema {}; build and execute a migration plan first",
            snapshot.state_schema(),
            archive.manifest.state.schema
        );
    }
    let storage = DirectoryStorage::open(state_dir)?;
    let limits = storage_limits(&archive.manifest);
    let plan = if dry_run {
        storage.plan_restore(&archive.manifest.cartridge.id, &snapshot, limits)?
    } else {
        storage.restore(&archive.manifest.cartridge.id, &snapshot, limits)?
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dry_run": dry_run,
                "changed": plan.changed(),
                "plan": plan,
            }))?
        );
    } else {
        println!(
            "{} restore for {}",
            if dry_run { "planned" } else { "completed" },
            archive.manifest.cartridge.id
        );
        println!("added: {}", plan.added);
        println!("replaced: {}", plan.replaced);
        println!("removed: {}", plan.removed);
        println!("unchanged: {}", plan.unchanged);
        println!(
            "state schema: {} -> {}",
            plan.current_schema, plan.snapshot_schema
        );
        println!(
            "usage: {} key(s), {} bytes -> {} key(s), {} bytes",
            plan.current.keys, plan.current.bytes, plan.snapshot.keys, plan.snapshot.bytes
        );
    }
    Ok(())
}

fn storage_migration_plan_command(package: &Path, from_schema: u32, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let plan = archive.manifest.migration_plan(from_schema)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("{}", plan.cartridge_id);
        println!("package version: {}", plan.cartridge_version);
        println!(
            "state schema: {} -> {}",
            plan.source_schema, plan.target_schema
        );
        if plan.steps.is_empty() {
            println!("migrations: none");
        } else {
            println!("migrations:");
            for migration in plan.steps {
                println!(
                    "  {}: {} -> {}",
                    migration.name, migration.from, migration.to
                );
            }
        }
    }
    Ok(())
}

fn storage_limits(manifest: &cartridge_core::PackageManifest) -> StorageLimits {
    StorageLimits {
        max_bytes: manifest.runtime.storage_bytes,
        max_keys: manifest.runtime.storage_keys,
        max_value_bytes: manifest.runtime.storage_value_bytes,
    }
}

fn replay_command(package: &Path, trace: &Path, args: &[String]) -> Result<()> {
    let trace = read_trace(trace)?;
    let event_count = trace.events.len();
    let report = Runtime::new()?.replay_file(package, args, trace)?;
    println!("{}", terminal_safe(&report.output));
    eprintln!(
        "replay matched {event_count} event(s), {} fuel",
        report.fuel_consumed
    );
    Ok(())
}

fn trace_inspect_command(trace: &Path, json: bool) -> Result<()> {
    let trace = read_trace(trace)?;
    let summary = trace.summary();
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    println!("{} {}", summary.cartridge_id, summary.cartridge_version);
    println!("trace format: {}", summary.format_version);
    println!("runtime: {}", summary.runtime_version);
    println!("component sha256: {}", summary.component_sha256);
    println!("args: {}", serde_json::to_string(&summary.args)?);
    println!("events: {}", summary.event_count);
    if summary.capabilities.is_empty() {
        println!("capabilities: none");
    } else {
        println!("capabilities:");
        for (capability, count) in summary.capabilities {
            println!("  {capability}: {count}");
        }
    }
    println!("output: {:?}", summary.result.output);
    println!("fuel consumed: {}", summary.result.fuel_consumed);
    Ok(())
}

fn trace_diff_command(left: &Path, right: &Path, json: bool) -> Result<()> {
    let left = read_trace(left)?;
    let right = read_trace(right)?;
    let comparison = left.compare(&right);
    if json {
        println!("{}", serde_json::to_string_pretty(&comparison)?);
        return Ok(());
    }

    if comparison.identical {
        println!("traces are identical");
    } else if let Some(difference) = comparison.difference {
        print_trace_difference(&difference)?;
    }
    Ok(())
}

fn read_trace(path: &Path) -> Result<ExecutionTrace> {
    if fs::metadata(path)?.len() > MAX_TRACE_DOCUMENT_BYTES {
        bail!(
            "trace {} exceeds the {} byte input limit",
            path.display(),
            MAX_TRACE_DOCUMENT_BYTES
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("could not read trace {}", path.display()))?;
    let trace: ExecutionTrace = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid trace {}", path.display()))?;
    trace
        .validate()
        .with_context(|| format!("invalid trace {}", path.display()))?;
    Ok(trace)
}

fn terminal_safe(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".cartridge-output-{}-{sequence}.tmp",
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    fs::remove_file(temporary)?;
    Ok(())
}

fn print_trace_difference(difference: &TraceDifference) -> Result<()> {
    match difference {
        TraceDifference::Header { field, left, right } => {
            println!("header differs at {field}");
            println!("  left:  {}", serde_json::to_string(left)?);
            println!("  right: {}", serde_json::to_string(right)?);
        }
        TraceDifference::Event {
            sequence,
            left,
            right,
        } => {
            println!("first event difference at sequence {sequence}");
            println!("  left:  {}", serde_json::to_string(left)?);
            println!("  right: {}", serde_json::to_string(right)?);
        }
        TraceDifference::Result { field, left, right } => {
            println!("result differs at {field}");
            println!("  left:  {}", serde_json::to_string(left)?);
            println!("  right: {}", serde_json::to_string(right)?);
        }
    }
    Ok(())
}

fn print_manifest(archive: &CartridgeArchive) {
    let manifest = &archive.manifest;
    println!("{} {}", manifest.cartridge.name, manifest.cartridge.version);
    println!("id: {}", manifest.cartridge.id);
    if !manifest.cartridge.description.is_empty() {
        println!("description: {}", manifest.cartridge.description);
    }
    println!("assets: {}", archive.assets.len());
    println!(
        "permissions: clock={}, random={}, assets={}, storage={}",
        manifest.permissions.clock,
        manifest.permissions.random,
        manifest.permissions.assets,
        manifest.permissions.storage
    );
    println!("fuel: {}", manifest.runtime.fuel);
    println!("memory: {} bytes", manifest.runtime.memory_bytes);
    println!("timeout: {} ms", manifest.runtime.timeout_ms);
    println!("storage quota: {} bytes", manifest.runtime.storage_bytes);
    println!("storage keys: {}", manifest.runtime.storage_keys);
    println!(
        "storage value limit: {} bytes",
        manifest.runtime.storage_value_bytes
    );
    println!("state schema: {}", manifest.state.schema);
    println!("state migrations: {}", manifest.state.migrations.len());
    println!("component sha256: {}", manifest.integrity.component_sha256);
    println!("dependencies: {}", manifest.dependencies.len());
    println!("provided services: {}", manifest.services.provides.len());
}

fn print_relationships(archive: &CartridgeArchive) {
    let manifest = &archive.manifest;
    if manifest.dependencies.is_empty() {
        println!("requires: none");
    } else {
        println!("requires:");
        for dependency in &manifest.dependencies {
            let requirement = if dependency.optional {
                "optional"
            } else {
                "required"
            };
            println!(
                "  {} -> {} {} ({requirement})",
                dependency.alias, dependency.cartridge, dependency.version
            );
            for interface in &dependency.interfaces {
                println!("    {interface}");
            }
            if !dependency.reason.is_empty() {
                println!("    reason: {}", dependency.reason);
            }
        }
    }

    if manifest.services.provides.is_empty() {
        println!("provides: none");
    } else {
        println!("provides:");
        for service in &manifest.services.provides {
            println!(
                "  {} -> {} ({})",
                service.name, service.interface, service.visibility
            );
            if !service.description.is_empty() {
                println!("    {}", service.description);
            }
        }
    }
}

fn print_resolution(plan: &ResolutionPlan) {
    if plan.resolved.is_empty() {
        println!("resolved: none");
    } else {
        println!("resolved:");
        for dependency in &plan.resolved {
            println!(
                "  {} -> {} {}",
                dependency.alias, dependency.cartridge, dependency.version
            );
            for interface in &dependency.interfaces {
                println!("    {interface}");
            }
        }
    }
    if !plan.unavailable_optional.is_empty() {
        println!("unavailable optional:");
        for dependency in &plan.unavailable_optional {
            println!(
                "  {} -> {}: {}",
                dependency.alias, dependency.cartridge, dependency.reason
            );
        }
    }
}

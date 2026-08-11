mod capsule;
mod migration_receipt;

use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
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
    BlobStore, DirectoryStorage, MAX_MIGRATION_STEPS_PER_RUN, MAX_MIGRATION_TOTAL_TIMEOUT_MS,
    Runtime, SnapshotDifference, SnapshotStorage, StorageLimits, StorageSnapshot,
};
use cartridge_trace::{
    ExecutionTrace, MAX_REDACTED_TRACE_DOCUMENT_BYTES, MAX_TRACE_DOCUMENT_BYTES, RedactionProfile,
    TraceDifference,
};
use clap::{Parser, Subcommand, ValueEnum};
use migration_receipt::{MigrationReceipt, MigrationReceiptPayload};

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
    /// selectively verify package assets
    Asset {
        #[command(subcommand)]
        command: AssetCommand,
    },
    /// manage content-addressed blobs
    Blob {
        #[command(subcommand)]
        command: BlobCommand,
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
    #[command(name = "__worker-capsule-replay", hide = true)]
    WorkerCapsuleReplay {
        capsule: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "__worker-migrate", hide = true)]
    WorkerMigrate {
        package: PathBuf,
        snapshot: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(name = "__worker-migrate-commit", hide = true)]
    WorkerMigrateCommit {
        package: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        rollback_output: PathBuf,
        #[arg(long)]
        receipt_output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// inspect and compare execution traces
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    /// create and verify reproducible execution capsules
    Capsule {
        #[command(subcommand)]
        command: CapsuleCommand,
    },
    /// inspect and recover durable cartridge state
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AssetCommand {
    /// verify one asset without inflating unrelated asset payloads
    Verify {
        package: PathBuf,
        path: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BlobCommand {
    /// stream a file into the blob store
    Put {
        input: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// verify a stored object against its address
    Verify {
        sha256: String,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// stream a verified object to a new file
    Get {
        sha256: String,
        #[arg(long)]
        store: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// find or remove objects not listed by digest
    Gc {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        keep: Vec<String>,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
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
    /// export a non-replayable trace with sensitive values removed
    Redact {
        trace: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = TraceRedactionProfile::Summary)]
        profile: TraceRedactionProfile,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TraceRedactionProfile {
    Summary,
    Metadata,
}

#[derive(Debug, Subcommand)]
enum CapsuleCommand {
    /// bind a package, source state, trace, and result state
    Create {
        package: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// validate and summarize a capsule manifest
    Inspect {
        capsule: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// verify every referenced artifact and semantic binding
    Verify {
        capsule: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// find the first semantic difference between two capsules
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// replay a capsule's recorded invocation in a supervised worker
    Replay {
        capsule: PathBuf,
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
    /// execute a migration plan against an isolated snapshot branch
    Migrate {
        package: PathBuf,
        snapshot: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// migrate durable state with an automatic rollback snapshot
    MigrateCommit {
        package: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        rollback_output: PathBuf,
        #[arg(long)]
        receipt_output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// validate and summarize a durable migration receipt
    #[command(name = "migration-receipt")]
    MigrationReceipt {
        receipt: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// determine whether a receipt's migration commit landed
    #[command(name = "migration-recover")]
    MigrationRecover {
        package: PathBuf,
        receipt: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
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
        Command::Asset { command } => run_asset_command(command),
        Command::Blob { command } => run_blob_command(command),
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
        } => {
            require_worker_context()?;
            run_command(
                &package,
                trace.as_deref(),
                state_dir.as_deref(),
                from_snapshot.as_deref(),
                snapshot_output.as_deref(),
                &args,
            )
        }
        Command::WorkerReplay {
            package,
            trace,
            args,
        } => {
            require_worker_context()?;
            replay_command(&package, &trace, &args)
        }
        Command::WorkerCapsuleReplay { capsule, json } => {
            require_worker_context()?;
            capsule_replay_command(&capsule, json)
        }
        Command::WorkerMigrate {
            package,
            snapshot,
            output,
            json,
        } => {
            require_worker_context()?;
            storage_migrate_command(&package, &snapshot, &output, json)
        }
        Command::WorkerMigrateCommit {
            package,
            state_dir,
            rollback_output,
            receipt_output,
            json,
        } => {
            require_worker_context()?;
            storage_migrate_commit_command(
                &package,
                &state_dir,
                &rollback_output,
                &receipt_output,
                json,
            )
        }
        Command::Trace { command } => run_trace_command(command),
        Command::Capsule { command } => run_capsule_command(command),
        Command::Storage { command } => run_storage_command(command),
    }
}

fn run_blob_command(command: BlobCommand) -> Result<()> {
    match command {
        BlobCommand::Put { input, store, json } => {
            let report = BlobStore::open(store)?.put(input)?;
            print_blob_info(&report, json)
        }
        BlobCommand::Verify {
            sha256,
            store,
            json,
        } => {
            let report = BlobStore::open(store)?.verify(&sha256)?;
            print_blob_info(&report, json)
        }
        BlobCommand::Get {
            sha256,
            store,
            output,
        } => {
            let report = BlobStore::open(store)?.materialize(&sha256, &output)?;
            println!(
                "materialized {} byte(s) -> {}",
                report.bytes,
                output.display()
            );
            Ok(())
        }
        BlobCommand::Gc {
            store,
            keep,
            apply,
            json,
        } => {
            let retained = keep.into_iter().collect();
            let report = BlobStore::open(store)?.gc(&retained, !apply)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("retained: {}", report.retained);
                println!(
                    "removable: {} object(s), {} bytes",
                    report.removable, report.removable_bytes
                );
                println!(
                    "removed: {} object(s), {} bytes",
                    report.removed, report.removed_bytes
                );
                println!("dry run: {}", report.dry_run);
            }
            Ok(())
        }
    }
}

fn print_blob_info(report: &cartridge_runtime::BlobInfo, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("sha256: {}", report.sha256);
        println!("bytes: {}", report.bytes);
        println!("already existed: {}", report.existed);
    }
    Ok(())
}

fn run_trace_command(command: TraceCommand) -> Result<()> {
    match command {
        TraceCommand::Inspect { trace, json } => trace_inspect_command(&trace, json),
        TraceCommand::Diff { left, right, json } => trace_diff_command(&left, &right, json),
        TraceCommand::Redact {
            trace,
            output,
            profile,
        } => trace_redact_command(&trace, &output, profile),
    }
}

fn run_asset_command(command: AssetCommand) -> Result<()> {
    match command {
        AssetCommand::Verify {
            package,
            path,
            json,
        } => asset_verify_command(&package, &path, json),
    }
}

fn asset_verify_command(package: &Path, path: &str, json: bool) -> Result<()> {
    let report = CartridgeArchive::verify_asset(package, path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("verified asset {}", report.path);
        println!("{} {}", report.cartridge_id, report.cartridge_version);
        println!("bytes: {}", report.bytes);
        println!("sha256: {}", report.sha256);
        println!("asset root: {}", report.assets_root_sha256);
    }
    Ok(())
}

fn trace_redact_command(trace: &Path, output: &Path, profile: TraceRedactionProfile) -> Result<()> {
    let trace = read_trace(trace)?;
    let profile = match profile {
        TraceRedactionProfile::Summary => RedactionProfile::Summary,
        TraceRedactionProfile::Metadata => RedactionProfile::Metadata,
    };
    let redacted = trace.redact(profile)?;
    let bytes = serde_json::to_vec_pretty(&redacted)?;
    if bytes.len() > MAX_REDACTED_TRACE_DOCUMENT_BYTES {
        bail!("redacted trace exceeds the {MAX_REDACTED_TRACE_DOCUMENT_BYTES} byte output limit");
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    write_private(output, &bytes)?;
    println!("redacted trace -> {}", output.display());
    println!("profile: {profile:?}");
    println!("replayable: false");
    Ok(())
}

fn run_capsule_command(command: CapsuleCommand) -> Result<()> {
    match command {
        CapsuleCommand::Create {
            package,
            source,
            trace,
            result,
            output,
            json,
        } => {
            let summary = capsule::create(&package, &source, &trace, &result, &output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("created capsule -> {}", output.display());
                print_capsule_summary(&summary);
            }
            Ok(())
        }
        CapsuleCommand::Inspect { capsule, json } => {
            let summary = capsule::inspect(&capsule)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print_capsule_summary(&summary);
            }
            Ok(())
        }
        CapsuleCommand::Verify { capsule, json } => {
            let report = capsule::verify(&capsule)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("verified capsule and all referenced artifacts");
                print_capsule_summary(&report.capsule);
            }
            Ok(())
        }
        CapsuleCommand::Diff { left, right, json } => {
            let comparison = capsule::compare(&left, &right)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            } else if comparison.identical {
                println!("capsules are semantically identical");
            } else if let Some(capsule::CapsuleDifference::Field { field, left, right }) =
                comparison.difference
            {
                println!("first capsule difference at {field}");
                println!("  left:  {}", serde_json::to_string(&left)?);
                println!("  right: {}", serde_json::to_string(&right)?);
            }
            Ok(())
        }
        CapsuleCommand::Replay { capsule, json } => {
            supervised_capsule_replay_command(&capsule, json)
        }
    }
}

fn supervised_capsule_replay_command(capsule_path: &Path, json: bool) -> Result<()> {
    let inputs = capsule::replay_inputs(capsule_path)?;
    let execution_budget = Duration::from_millis(inputs.package.manifest.runtime.timeout_ms);
    let mut worker_args = vec![
        OsString::from("__worker-capsule-replay"),
        capsule_path.as_os_str().to_owned(),
    ];
    if json {
        worker_args.push(OsString::from("--json"));
    }
    supervise_worker(&inputs.package_path, &worker_args, Some(execution_budget))
}

#[derive(Debug, serde::Serialize)]
struct CapsuleReplayReport {
    replayed: bool,
    cartridge_id: String,
    cartridge_version: String,
    runtime_version: String,
    argument_count: usize,
    event_count: usize,
    output_sha256: String,
    fuel_consumed: u64,
    result_snapshot_sha256: String,
    result_state_evidence: &'static str,
}

fn capsule_replay_command(capsule_path: &Path, json: bool) -> Result<()> {
    let inputs = capsule::replay_inputs(capsule_path)?;
    let expected_capsule_sha256 = inputs.summary.capsule_sha256.clone();
    let event_count = inputs.trace.events.len();
    let report = Runtime::new()?.replay_from_snapshot(
        inputs.package,
        &inputs.arguments,
        inputs.trace,
        &inputs.source,
    )?;
    let reproduced = report.snapshot.summary()?;
    if reproduced.payload_sha256 != inputs.summary.result_snapshot_sha256 {
        bail!(
            "replayed result state digest differs: expected {}, got {}",
            inputs.summary.result_snapshot_sha256,
            reproduced.payload_sha256
        );
    }
    let final_verification = capsule::verify(capsule_path)?;
    if final_verification.capsule.capsule_sha256 != expected_capsule_sha256 {
        bail!("capsule changed during replay");
    }
    let replay = CapsuleReplayReport {
        replayed: true,
        cartridge_id: inputs.summary.cartridge_id,
        cartridge_version: inputs.summary.cartridge_version,
        runtime_version: inputs.summary.runtime_version,
        argument_count: inputs.arguments.len(),
        event_count,
        output_sha256: inputs.summary.trace_output_sha256,
        fuel_consumed: report.run.fuel_consumed,
        result_snapshot_sha256: inputs.summary.result_snapshot_sha256,
        result_state_evidence: "recomputed-from-source",
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&replay)?);
    } else {
        println!("replayed capsule {}", capsule_path.display());
        println!("{} {}", replay.cartridge_id, replay.cartridge_version);
        println!("runtime: {}", replay.runtime_version);
        println!("arguments: {}", replay.argument_count);
        println!("events: {}", replay.event_count);
        println!("output sha256: {}", replay.output_sha256);
        println!("fuel consumed: {}", replay.fuel_consumed);
        println!("result snapshot sha256: {}", replay.result_snapshot_sha256);
        println!("result state: reproduced on a disposable source branch");
    }
    Ok(())
}

fn print_capsule_summary(summary: &capsule::CapsuleSummary) {
    println!("{} {}", summary.cartridge_id, summary.cartridge_version);
    println!("capsule format: {}", summary.format_version);
    println!("runtime: {}", summary.runtime_version);
    println!("component sha256: {}", summary.component_sha256);
    println!(
        "arguments: {} value(s), {} bytes ({})",
        summary.argument_count, summary.argument_bytes, summary.arguments_sha256
    );
    println!(
        "source state: schema {}, {} key(s), {} bytes ({})",
        summary.source_schema,
        summary.source_entries,
        summary.source_bytes,
        summary.source_snapshot_sha256
    );
    println!(
        "trace: {} event(s), {} output bytes, {} fuel ({})",
        summary.trace_events,
        summary.trace_output_bytes,
        summary.fuel_consumed,
        summary.trace_output_sha256
    );
    println!(
        "result state: schema {}, {} key(s), {} bytes ({})",
        summary.result_schema,
        summary.result_entries,
        summary.result_bytes,
        summary.result_snapshot_sha256
    );
    println!("capsule sha256: {}", summary.capsule_sha256);
}

fn run_storage_command(command: StorageCommand) -> Result<()> {
    match command {
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
        StorageCommand::Migrate {
            package,
            snapshot,
            output,
            json,
        } => supervised_migrate_command(&package, &snapshot, &output, json),
        StorageCommand::MigrateCommit {
            package,
            state_dir,
            rollback_output,
            receipt_output,
            json,
        } => supervised_migrate_commit_command(
            &package,
            &state_dir,
            &rollback_output,
            &receipt_output,
            json,
        ),
        StorageCommand::MigrationReceipt { receipt, json } => {
            storage_migration_receipt_command(&receipt, json)
        }
        StorageCommand::MigrationRecover {
            package,
            receipt,
            state_dir,
            json,
        } => storage_migration_recover_command(&package, &receipt, &state_dir, json),
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
    supervise_worker(package, &worker_args, None)
}

fn supervised_replay_command(package: &Path, trace: &Path, args: &[String]) -> Result<()> {
    let mut worker_args = vec![
        OsString::from("__worker-replay"),
        package.as_os_str().to_owned(),
        trace.as_os_str().to_owned(),
    ];
    push_worker_arguments(&mut worker_args, args);
    supervise_worker(package, &worker_args, None)
}

fn supervised_migrate_command(
    package: &Path,
    snapshot: &Path,
    output: &Path,
    json: bool,
) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not validate {} before migration", package.display()))?;
    let source = StorageSnapshot::read(snapshot)
        .with_context(|| format!("could not validate {} before migration", snapshot.display()))?;
    let budget_ms = migration_budget_ms(&archive, &source)?;
    drop(source);
    drop(archive);
    let mut worker_args = vec![
        OsString::from("__worker-migrate"),
        package.as_os_str().to_owned(),
        snapshot.as_os_str().to_owned(),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ];
    if json {
        worker_args.push(OsString::from("--json"));
    }
    supervise_worker(
        package,
        &worker_args,
        Some(Duration::from_millis(budget_ms)),
    )
}

fn supervised_migrate_commit_command(
    package: &Path,
    state_dir: &Path,
    rollback_output: &Path,
    receipt_output: &Path,
    json: bool,
) -> Result<()> {
    if rollback_output == receipt_output {
        bail!("rollback and receipt outputs must use different paths");
    }
    for (name, path) in [("rollback", rollback_output), ("receipt", receipt_output)] {
        if path
            .try_exists()
            .with_context(|| format!("could not inspect {name} output {}", path.display()))?
        {
            bail!("{name} output {} already exists", path.display());
        }
    }
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not validate {} before migration", package.display()))?;
    let storage = DirectoryStorage::open(state_dir)?;
    let source = storage.export_snapshot(&archive.manifest.cartridge.id)?;
    if source.state_schema() == archive.manifest.state.schema {
        bail!(
            "durable state already uses schema {}; no migration commit is needed",
            source.state_schema()
        );
    }
    let budget_ms = migration_budget_ms(&archive, &source)?;
    drop(source);
    drop(storage);
    drop(archive);

    let mut worker_args = vec![
        OsString::from("__worker-migrate-commit"),
        package.as_os_str().to_owned(),
        OsString::from("--state-dir"),
        state_dir.as_os_str().to_owned(),
        OsString::from("--rollback-output"),
        rollback_output.as_os_str().to_owned(),
        OsString::from("--receipt-output"),
        receipt_output.as_os_str().to_owned(),
    ];
    if json {
        worker_args.push(OsString::from("--json"));
    }
    supervise_worker(
        package,
        &worker_args,
        Some(Duration::from_millis(budget_ms)),
    )
}

fn migration_budget_ms(archive: &CartridgeArchive, source: &StorageSnapshot) -> Result<u64> {
    if source.cartridge_id() != archive.manifest.cartridge.id {
        bail!(
            "snapshot belongs to {}; package belongs to {}",
            source.cartridge_id(),
            archive.manifest.cartridge.id
        );
    }
    let plan = archive.manifest.migration_plan(source.state_schema())?;
    if plan.steps.len() > MAX_MIGRATION_STEPS_PER_RUN {
        bail!(
            "migration plan contains {} steps; maximum is {MAX_MIGRATION_STEPS_PER_RUN}",
            plan.steps.len()
        );
    }
    let budget_steps = u64::try_from(plan.steps.len().max(1)).unwrap_or(u64::MAX);
    let budget_ms = archive
        .manifest
        .runtime
        .timeout_ms
        .checked_mul(budget_steps)
        .context("migration timeout budget overflowed")?;
    if budget_ms > MAX_MIGRATION_TOTAL_TIMEOUT_MS {
        bail!(
            "migration timeout budget is {budget_ms} ms; maximum is {MAX_MIGRATION_TOTAL_TIMEOUT_MS} ms"
        );
    }
    Ok(budget_ms)
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

fn supervise_worker(
    package: &Path,
    arguments: &[OsString],
    execution_budget: Option<Duration>,
) -> Result<()> {
    let execution_budget = if let Some(budget) = execution_budget {
        budget
    } else {
        let archive = CartridgeArchive::open(package).with_context(|| {
            format!("could not validate {} before execution", package.display())
        })?;
        Duration::from_millis(archive.manifest.runtime.timeout_ms)
    };
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

fn require_worker_context() -> Result<()> {
    if std::env::var_os("CARTRIDGE_WORKER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        bail!("internal worker commands cannot be invoked directly");
    }
    Ok(())
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

fn storage_migrate_command(package: &Path, source: &Path, output: &Path, json: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let source = StorageSnapshot::read(source)
        .with_context(|| format!("could not read snapshot {}", source.display()))?;
    let report = Runtime::new()?.migrate(archive, source)?;
    let summary = report.snapshot.summary()?;
    report.snapshot.write_new(output)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "plan": report.plan,
                "steps": report.steps,
                "result": summary,
                "output": output.display().to_string(),
            }))?
        );
    } else {
        println!("migrated {}", summary.cartridge_id);
        println!(
            "state schema: {} -> {}",
            report.plan.source_schema, report.plan.target_schema
        );
        if report.steps.is_empty() {
            println!("migrations: none");
        } else {
            println!("migrations:");
            for step in report.steps {
                println!(
                    "  {}: {} -> {} ({} fuel, {} event(s))",
                    step.name, step.from, step.to, step.fuel_consumed, step.event_count
                );
            }
        }
        println!(
            "result: {} key(s), {} bytes",
            summary.entries, summary.bytes
        );
        println!("snapshot: {}", output.display());
    }
    Ok(())
}

fn storage_migrate_commit_command(
    package: &Path,
    state_dir: &Path,
    rollback_output: &Path,
    receipt_output: &Path,
    json: bool,
) -> Result<()> {
    if rollback_output == receipt_output {
        bail!("rollback and receipt outputs must use different paths");
    }
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let cartridge_id = archive.manifest.cartridge.id.clone();
    let limits = storage_limits(&archive.manifest);
    let storage = DirectoryStorage::open(state_dir)?;
    let source = storage.capture(&cartridge_id)?;
    source
        .snapshot()
        .write_new(rollback_output)
        .with_context(|| {
            format!(
                "could not create rollback snapshot {}",
                rollback_output.display()
            )
        })?;

    let report = Runtime::new()?.migrate(archive, source.snapshot().clone())?;
    if report.plan.steps.is_empty() {
        bail!(
            "durable state already uses schema {}; no migration commit is needed",
            report.plan.target_schema
        );
    }
    let summary = report.snapshot.summary()?;
    let source_summary = source.snapshot().summary()?;
    let target_generation = source
        .generation()
        .checked_add(1)
        .context("durable generation overflowed")?;
    let receipt = MigrationReceipt::new(MigrationReceiptPayload {
        format_version: 0,
        cartridge_id: cartridge_id.clone(),
        package_version: report.plan.cartridge_version.clone(),
        component_sha256: report.plan.component_sha256.to_ascii_lowercase(),
        source_generation: source.generation(),
        target_generation,
        source_schema: report.plan.source_schema,
        target_schema: report.plan.target_schema,
        source_snapshot_sha256: source_summary.payload_sha256,
        target_snapshot_sha256: summary.payload_sha256.clone(),
    })?;
    receipt.write_new(receipt_output).with_context(|| {
        format!(
            "could not create migration receipt {}",
            receipt_output.display()
        )
    })?;
    let commit = storage.restore_if_unchanged(&cartridge_id, &source, &report.snapshot, limits)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "plan": report.plan,
                "steps": report.steps,
                "result": summary,
                "commit": commit,
                "rollback": rollback_output.display().to_string(),
                "receipt": receipt_output.display().to_string(),
            }))?
        );
    } else {
        println!("migrated and committed {cartridge_id}");
        println!(
            "state schema: {} -> {}",
            report.plan.source_schema, report.plan.target_schema
        );
        if report.steps.is_empty() {
            println!("migrations: none");
        } else {
            println!("migrations:");
            for step in report.steps {
                println!(
                    "  {}: {} -> {} ({} fuel, {} event(s))",
                    step.name, step.from, step.to, step.fuel_consumed, step.event_count
                );
            }
        }
        println!(
            "committed: {} key(s), {} bytes",
            summary.entries, summary.bytes
        );
        println!("rollback: {}", rollback_output.display());
        println!("receipt: {}", receipt_output.display());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum MigrationRecoveryStatus {
    NotCommitted,
    Committed,
    CommittedThenChanged,
    Indeterminate,
}

#[derive(Debug, serde::Serialize)]
struct MigrationRecoveryReport {
    cartridge_id: String,
    receipt_sha256: String,
    status: MigrationRecoveryStatus,
    source_generation: u64,
    target_generation: u64,
    observed_generation: u64,
    observed_schema: u32,
    observed_snapshot_sha256: String,
    target_generation_retained: bool,
}

fn storage_migration_receipt_command(path: &Path, json: bool) -> Result<()> {
    let receipt = MigrationReceipt::read(path)?;
    let payload = receipt.payload();
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        println!("{} {}", payload.cartridge_id, payload.package_version);
        println!("receipt format: {}", payload.format_version);
        println!(
            "state schema: {} -> {}",
            payload.source_schema, payload.target_schema
        );
        println!(
            "durable generation: {} -> {}",
            payload.source_generation, payload.target_generation
        );
        println!("component sha256: {}", payload.component_sha256);
        println!("source snapshot sha256: {}", payload.source_snapshot_sha256);
        println!("target snapshot sha256: {}", payload.target_snapshot_sha256);
        println!("receipt sha256: {}", receipt.payload_sha256());
    }
    Ok(())
}

fn storage_migration_recover_command(
    package: &Path,
    receipt_path: &Path,
    state_dir: &Path,
    json: bool,
) -> Result<()> {
    let archive = CartridgeArchive::open(package)
        .with_context(|| format!("could not inspect {}", package.display()))?;
    let receipt = MigrationReceipt::read(receipt_path)?;
    let payload = receipt.payload();
    if payload.cartridge_id != archive.manifest.cartridge.id
        || payload.package_version != archive.manifest.cartridge.version
        || !payload
            .component_sha256
            .eq_ignore_ascii_case(&archive.manifest.integrity.component_sha256)
        || payload.target_schema != archive.manifest.state.schema
    {
        bail!("migration receipt does not belong to this exact package");
    }

    let storage = DirectoryStorage::open(state_dir)?;
    let evidence = storage.evidence(&payload.cartridge_id, payload.target_generation)?;
    let current = evidence.current();
    let current_summary = current.snapshot().summary()?;
    let target_matches = evidence.requested().is_some_and(|captured| {
        captured.generation() == payload.target_generation
            && captured.snapshot().state_schema() == payload.target_schema
            && captured
                .snapshot()
                .summary()
                .is_ok_and(|summary| summary.payload_sha256 == payload.target_snapshot_sha256)
    });
    let source_matches = current.generation() == payload.source_generation
        && current_summary.state_schema == payload.source_schema
        && current_summary.payload_sha256 == payload.source_snapshot_sha256;
    let status = if target_matches && current.generation() == payload.target_generation {
        MigrationRecoveryStatus::Committed
    } else if target_matches {
        MigrationRecoveryStatus::CommittedThenChanged
    } else if evidence.requested().is_some() || source_matches {
        MigrationRecoveryStatus::NotCommitted
    } else {
        MigrationRecoveryStatus::Indeterminate
    };
    let report = MigrationRecoveryReport {
        cartridge_id: payload.cartridge_id.clone(),
        receipt_sha256: receipt.payload_sha256().to_owned(),
        status,
        source_generation: payload.source_generation,
        target_generation: payload.target_generation,
        observed_generation: current.generation(),
        observed_schema: current_summary.state_schema,
        observed_snapshot_sha256: current_summary.payload_sha256,
        target_generation_retained: evidence.requested().is_some(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.cartridge_id);
        println!("recovery status: {}", recovery_status_name(report.status));
        println!(
            "receipt generation: {} -> {}",
            report.source_generation, report.target_generation
        );
        println!("observed generation: {}", report.observed_generation);
        println!("observed schema: {}", report.observed_schema);
        println!(
            "target generation retained: {}",
            report.target_generation_retained
        );
        println!("receipt sha256: {}", report.receipt_sha256);
    }
    Ok(())
}

const fn recovery_status_name(status: MigrationRecoveryStatus) -> &'static str {
    match status {
        MigrationRecoveryStatus::NotCommitted => "not committed",
        MigrationRecoveryStatus::Committed => "committed",
        MigrationRecoveryStatus::CommittedThenChanged => "committed, then changed",
        MigrationRecoveryStatus::Indeterminate => "indeterminate",
    }
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
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("could not open trace {}", path.display()))?
        .take(MAX_TRACE_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read trace {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRACE_DOCUMENT_BYTES {
        bail!(
            "trace {} exceeds the {} byte input limit",
            path.display(),
            MAX_TRACE_DOCUMENT_BYTES
        );
    }
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

mod capsule;
mod engine_daemon;
mod migration_receipt;
mod process_control;

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode, Stdio},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use cartridge_core::{
    CartridgeArchive, CompositionLock, LockedPackage, MAX_RESOLUTION_CANDIDATES, PackOptions,
    Permissions, ResolutionPlan, negotiate_platform, pack, resolve_dependencies,
};
use cartridge_desktop::{Capability, CatalogPackage, LaunchStatus, Library};
use cartridge_dev::{
    Language, create_project, inspect_project, manifest_schema, profile_project, reload_decision,
    source_fingerprint,
};
use cartridge_engine::{
    DaemonEndpoint, DaemonLease, DaemonRequest, DaemonResponse, EngineStore, PlannedInstance,
    ReplicaId, ReplicaPhase, StackCapability, StackManifest, StackPlan, StackRuntimeStatus,
};
use cartridge_identity::{
    DeveloperKey, KeyRotation, Registry, RevocationRecord, TrustStore, read_revocation,
    read_rotation, read_signature, write_revocation, write_rotation, write_signature,
};
use cartridge_network::HttpFixtures;
use cartridge_release::{ReleaseArtifact, ReleasePayload, SignedRelease, Updater};
use cartridge_runtime::{
    BlobReachabilityManifest, BlobReachabilitySource, BlobReachabilitySourceKind, BlobStore,
    DirectoryStorage, InputEvent, MAX_MIGRATION_STEPS_PER_RUN, MAX_MIGRATION_TOTAL_TIMEOUT_MS,
    MediaArtifacts, MidiEvent, Runtime, SnapshotDifference, SnapshotStorage, StorageLimits,
    StorageSnapshot,
};
use cartridge_trace::{
    ExecutionTrace, MAX_REDACTED_TRACE_DOCUMENT_BYTES, MAX_TRACE_DOCUMENT_BYTES, RedactionProfile,
    TraceDifference,
};
use clap::{Parser, Subcommand, ValueEnum};
use migration_receipt::{MigrationReceipt, MigrationReceiptPayload};
use process_control::{
    ContainedChild, ContainedCommand, OutputMode, TERMINATION_GRACE,
    install_parent_liveness_watchdog, spawn_contained,
};
use sha2::{Digest, Sha256};

static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const WORKER_STARTUP_BUDGET: Duration = Duration::from_secs(10);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_BLOB_GC_ROOT_ARTIFACTS: usize = 256;
const MAX_BLOB_GC_REFERENCES: usize = 100_000;
const MAX_EVENT_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_STABILITY_WALL_TIME: Duration = Duration::from_secs(60 * 60);
const DEFAULT_SUPERVISOR_WORKERS: u16 = 32;
const DESIRED_STATE_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct RunCommandOptions<'a> {
    package: &'a Path,
    trace: Option<&'a Path>,
    state_dir: Option<&'a Path>,
    from_snapshot: Option<&'a Path>,
    snapshot_output: Option<&'a Path>,
    input: Option<&'a Path>,
    midi: Option<&'a Path>,
    media_dir: Option<&'a Path>,
    http_fixtures: Option<&'a Path>,
    storage_signature: Option<&'a Path>,
    storage_trust: Option<&'a Path>,
    local_storage_authority: bool,
    permission_ceiling: Option<&'a Permissions>,
    args: &'a [String],
}

#[derive(Debug, Parser)]
#[command(
    name = "cartridge",
    version,
    about = "pack and run portable wasm cartridges"
)]
struct Cli {
    /// trusted signature required for durable cartridge state
    #[arg(long = "storage-signature", global = true, requires = "storage_trust")]
    storage_signature: Option<PathBuf>,
    /// trust store used to authenticate durable cartridge identity
    #[arg(long = "storage-trust", global = true, requires = "storage_signature")]
    storage_trust: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

struct DurableAuth {
    signature: Option<PathBuf>,
    trust: Option<PathBuf>,
}

impl DurableAuth {
    fn verify(&self, package: &Path) -> Result<()> {
        let signature_path = self
            .signature
            .as_deref()
            .context("durable state requires --storage-signature and --storage-trust")?;
        let trust_path = self
            .trust
            .as_deref()
            .context("durable state requires --storage-signature and --storage-trust")?;
        let signature = read_signature(signature_path).map_err(anyhow::Error::msg)?;
        let trust = TrustStore::read(trust_path).map_err(anyhow::Error::msg)?;
        trust
            .verify(package, &signature)
            .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// create a cartridge project from a tested language template
    New {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = DevLanguage::Rust)]
        language: DevLanguage,
    },
    /// validate a developer project before building it
    Check {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// build and run a project, optionally watching for changes
    Dev {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        preserve_state: bool,
    },
    /// profile project size and declared runtime budgets
    Profile {
        #[arg(default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// emit editor metadata for Cartridge.toml
    Schema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// run API preflight, execution, and deterministic replay checks
    Conformance {
        package: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// manage the installed desktop cartridge library
    Library {
        #[command(subcommand)]
        command: LibraryCommand,
    },
    /// plan and manage declarative cartridge stacks
    Stack {
        #[command(subcommand)]
        command: StackCommand,
    },
    /// run and control the persistent local cartridge engine
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
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
        #[arg(long, conflicts_with = "locked")]
        lock: Option<PathBuf>,
        #[arg(long, conflicts_with = "lock")]
        locked: Option<PathBuf>,
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
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        midi: Option<PathBuf>,
        #[arg(long)]
        media_dir: Option<PathBuf>,
        #[arg(long)]
        http_fixtures: Option<PathBuf>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// replay a cartridge from a recorded trace
    Replay {
        package: PathBuf,
        trace: PathBuf,
        #[arg(long)]
        media_dir: Option<PathBuf>,
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
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        midi: Option<PathBuf>,
        #[arg(long)]
        media_dir: Option<PathBuf>,
        #[arg(long)]
        http_fixtures: Option<PathBuf>,
        #[arg(long, hide = true)]
        local_storage_authority: bool,
        #[arg(long, hide = true)]
        capability_ceiling: Option<u16>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    #[command(name = "__worker-replay", hide = true)]
    WorkerReplay {
        package: PathBuf,
        trace: PathBuf,
        #[arg(long)]
        media_dir: Option<PathBuf>,
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
    /// create keys, sign packages, and manage trust
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// publish and resolve immutable signed packages
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// inspect host API and capability compatibility
    Platform {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// create, verify, install, and roll back signed runtime releases
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// run deterministic soak and performance measurements
    Stability {
        #[command(subcommand)]
        command: StabilityCommand,
    },
    #[command(name = "__worker-stability", hide = true)]
    WorkerStability {
        #[command(subcommand)]
        command: StabilityCommand,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Keygen {
        #[arg(short, long)]
        output: PathBuf,
    },
    Sign {
        package: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Verify {
        package: PathBuf,
        signature: PathBuf,
        #[arg(long)]
        trust: Option<PathBuf>,
    },
    Trust {
        signature: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        label: String,
    },
    RotateCreate {
        #[arg(long)]
        old_key: PathBuf,
        #[arg(long)]
        new_key: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    RotateApply {
        rotation: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
    RevokeCreate {
        key_id: String,
        #[arg(long)]
        signer: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    RevokeApply {
        revocation: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryCommand {
    Init {
        root: PathBuf,
    },
    Publish {
        package: PathBuf,
        signature: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        root: PathBuf,
    },
    Resolve {
        cartridge: String,
        requirement: String,
        #[arg(long)]
        root: PathBuf,
    },
    Audit {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    Create {
        artifact: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Verify {
        release: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    Install {
        release: PathBuf,
        artifact: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long)]
        allow_downgrade: bool,
    },
    Status {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long)]
        json: bool,
    },
    Rollback {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "stable")]
        channel: String,
    },
}

#[derive(Debug, Subcommand)]
enum StabilityCommand {
    Benchmark {
        package: PathBuf,
        #[arg(long, default_value_t = 10)]
        iterations: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
    Soak {
        package: PathBuf,
        #[arg(long, default_value_t = 100)]
        iterations: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DevLanguage {
    Rust,
    TinyGo,
    JavaScript,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PermissionName {
    Clock,
    Random,
    Assets,
    Storage,
    Graphics,
    Audio,
    Midi,
    Http,
}

#[derive(Debug, Subcommand)]
enum LibraryCommand {
    /// verify and install a package
    Install {
        package: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// search installed cartridges
    List {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// resolve an installed cartridge against the verified library catalog
    Resolve {
        cartridge: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        version: Option<String>,
        #[arg(long, conflicts_with = "locked")]
        lock: Option<PathBuf>,
        #[arg(long, conflicts_with = "lock")]
        locked: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// show requested, granted, and missing permissions
    Preflight {
        cartridge: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// approve requested capabilities
    Grant {
        cartridge: String,
        capabilities: Vec<PermissionName>,
        #[arg(long)]
        root: PathBuf,
    },
    /// revoke one capability or every grant
    Revoke {
        cartridge: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        capability: Option<PermissionName>,
    },
    /// launch an installed cartridge after permission preflight
    Run {
        cartridge: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long, value_enum)]
        allow: Vec<PermissionName>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// show bounded launch and resource history
    History {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// clear crash-loop safe mode for one cartridge
    ResetSafeMode {
        cartridge: String,
        #[arg(long)]
        root: PathBuf,
    },
    /// manage named cartridge profiles
    Profile {
        #[command(subcommand)]
        command: LibraryProfileCommand,
    },
    /// select an independently versioned runtime release
    RuntimeRelease {
        #[arg(long)]
        root: PathBuf,
        channel: String,
        version: String,
    },
}

#[derive(Debug, Subcommand)]
enum StackCommand {
    /// validate a stack manifest without consulting installed packages
    Validate {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// resolve a stack into an exact, side-effect-free plan
    Plan {
        file: PathBuf,
        #[arg(long)]
        library: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// append an exact plan to the crash-consistent desired-state journal
    Apply {
        file: PathBuf,
        #[arg(long)]
        library: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        allow_insecure: bool,
        #[arg(long)]
        json: bool,
    },
    /// run one stack generation under the bounded local supervisor
    Supervise {
        stack: String,
        #[arg(long)]
        library: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(
            long,
            default_value_t = DEFAULT_SUPERVISOR_WORKERS,
            value_parser = clap::value_parser!(u16).range(1..=256)
        )]
        max_workers: u16,
        #[arg(long, hide = true)]
        daemon_instance: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// list known stacks and their desired state
    List {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// inspect one stack's latest desired state
    Status {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// inspect observed replica lifecycle state
    Ps {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// set every instance in a stack to stopped
    Stop {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// tombstone a stack while retaining its audit journal
    Remove {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// show the checksum-chained control-plane event history
    Events {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EngineCommand {
    /// run the authenticated per-user engine service
    Serve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        library: PathBuf,
        #[arg(
            long,
            default_value_t = 8,
            value_parser = clap::value_parser!(u16).range(1..=64)
        )]
        max_supervisors: u16,
        #[arg(
            long,
            default_value_t = DEFAULT_SUPERVISOR_WORKERS,
            value_parser = clap::value_parser!(u16).range(1..=256)
        )]
        workers_per_stack: u16,
        #[arg(long)]
        json: bool,
    },
    /// verify that the engine is reachable and authenticated
    Ping {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// show engine identity, capacity, and stack counts
    Info {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// list stacks through the persistent engine
    List {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// resolve a manifest using the daemon's installed library
    Plan {
        file: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// apply a manifest and let the daemon reconcile it
    Apply {
        file: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        allow_insecure: bool,
        #[arg(long)]
        json: bool,
    },
    /// inspect one stack's desired state
    Status {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// inspect one stack's observed replica state
    Ps {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// show the latest checksum-chained stack events
    Events {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=256))]
        tail: u16,
        #[arg(long)]
        json: bool,
    },
    /// set a stack's desired state to stopped
    Stop {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// tombstone a stack while retaining its audit journal
    Remove {
        stack: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// gracefully stop the engine service
    Shutdown {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum LibraryProfileCommand {
    /// create or replace a profile
    Set {
        name: String,
        cartridges: Vec<String>,
        #[arg(long)]
        root: PathBuf,
    },
    /// list profiles
    List {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
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
    /// list every verified object in address order
    List {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// verify every object and report all content failures
    Audit {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// create and verify reusable reachability root sets
    Roots {
        #[command(subcommand)]
        command: BlobRootsCommand,
    },
    /// find or remove objects not listed by digest
    Gc {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        keep: Vec<String>,
        #[arg(long, value_name = "SNAPSHOT")]
        snapshot: Vec<PathBuf>,
        #[arg(long, value_name = "CAPSULE")]
        capsule: Vec<PathBuf>,
        #[arg(long, value_name = "MANIFEST")]
        manifest: Vec<PathBuf>,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BlobRootsCommand {
    /// resolve snapshots and capsules into one checksummed root set
    Create {
        #[arg(long, value_name = "SNAPSHOT")]
        snapshot: Vec<PathBuf>,
        #[arg(long, value_name = "CAPSULE")]
        capsule: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// validate and summarize a reachability manifest
    Inspect {
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// verify every object retained by a reachability manifest
    Verify {
        manifest: PathBuf,
        #[arg(long)]
        store: PathBuf,
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
    /// export a bounded timeline document for trace viewers
    Export {
        trace: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
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

#[allow(clippy::too_many_lines)]
fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let durable_auth = DurableAuth {
        signature: cli.storage_signature,
        trust: cli.storage_trust,
    };
    match cli.command {
        Command::New { path, language } => new_command(&path, language),
        Command::Check { project, json } => check_command(&project, json),
        Command::Dev {
            project,
            once,
            preserve_state,
        } => dev_command(&project, once, preserve_state),
        Command::Profile { project, json } => profile_command(&project, json),
        Command::Schema { output } => schema_command(output.as_deref()),
        Command::Conformance {
            package,
            json,
            args,
        } => conformance_command(&package, json, &args),
        Command::Library { command } => run_library_command(command),
        Command::Stack { command } => run_stack_command(command),
        Command::Engine { command } => run_engine_command(command),
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
            lock,
            locked,
        } => resolve_command(&root, &candidates, json, lock.as_deref(), locked.as_deref()),
        Command::Asset { command } => run_asset_command(command),
        Command::Blob { command } => run_blob_command(command),
        Command::Run {
            package,
            trace,
            state_dir,
            from_snapshot,
            snapshot_output,
            input,
            midi,
            media_dir,
            http_fixtures,
            args,
        } => {
            if state_dir.is_some() {
                durable_auth.verify(&package)?;
            }
            supervised_run_command(RunCommandOptions {
                package: &package,
                trace: trace.as_deref(),
                state_dir: state_dir.as_deref(),
                from_snapshot: from_snapshot.as_deref(),
                snapshot_output: snapshot_output.as_deref(),
                input: input.as_deref(),
                midi: midi.as_deref(),
                media_dir: media_dir.as_deref(),
                http_fixtures: http_fixtures.as_deref(),
                storage_signature: durable_auth.signature.as_deref(),
                storage_trust: durable_auth.trust.as_deref(),
                local_storage_authority: false,
                permission_ceiling: None,
                args: &args,
            })
        }
        Command::Replay {
            package,
            trace,
            media_dir,
            args,
        } => supervised_replay_command(&package, &trace, media_dir.as_deref(), &args),
        Command::WorkerRun {
            package,
            trace,
            state_dir,
            from_snapshot,
            snapshot_output,
            input,
            midi,
            media_dir,
            http_fixtures,
            local_storage_authority,
            capability_ceiling,
            args,
        } => {
            require_worker_context()?;
            let permission_ceiling = capability_ceiling.map(permissions_from_mask).transpose()?;
            if state_dir.is_some() && !local_storage_authority {
                durable_auth.verify(&package)?;
            }
            run_command(RunCommandOptions {
                package: &package,
                trace: trace.as_deref(),
                state_dir: state_dir.as_deref(),
                from_snapshot: from_snapshot.as_deref(),
                snapshot_output: snapshot_output.as_deref(),
                input: input.as_deref(),
                midi: midi.as_deref(),
                media_dir: media_dir.as_deref(),
                http_fixtures: http_fixtures.as_deref(),
                storage_signature: None,
                storage_trust: None,
                local_storage_authority,
                permission_ceiling: permission_ceiling.as_ref(),
                args: &args,
            })
        }
        Command::WorkerReplay {
            package,
            trace,
            media_dir,
            args,
        } => {
            require_worker_context()?;
            replay_command(&package, &trace, media_dir.as_deref(), &args)
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
            durable_auth.verify(&package)?;
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
        Command::Storage { command } => run_storage_command(command, &durable_auth),
        Command::Identity { command } => run_identity_command(command),
        Command::Registry { command } => run_registry_command(command),
        Command::Platform { package, json } => platform_command(&package, json),
        Command::Release { command } => run_release_command(command),
        Command::Stability { command } => supervised_stability_command(&command),
        Command::WorkerStability { command } => {
            require_worker_context()?;
            run_stability_command(command)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_engine_command(command: EngineCommand) -> Result<()> {
    match command {
        EngineCommand::Serve {
            root,
            library,
            max_supervisors,
            workers_per_stack,
            json,
        } => engine_daemon::serve(&engine_daemon::ServeOptions {
            root: &root,
            library: &library,
            max_supervisors,
            workers_per_stack,
            json,
        }),
        EngineCommand::Ping { root, json } => {
            match engine_daemon::request(&root, DaemonRequest::Ping)? {
                DaemonResponse::Pong if json => println!("{{\"reachable\":true}}"),
                DaemonResponse::Pong => println!("engine is reachable and authenticated"),
                _ => bail!("engine returned an unexpected response"),
            }
            Ok(())
        }
        EngineCommand::Info { root, json } => {
            let DaemonResponse::Info(info) = engine_daemon::request(&root, DaemonRequest::Info)?
            else {
                bail!("engine returned an unexpected response");
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("engine {} pid={}", info.instance_id, info.pid);
                println!("started: {}", info.started_at_ms);
                println!(
                    "supervisors: {}/{} ({} workers per stack)",
                    info.active_supervisors, info.max_supervisors, info.workers_per_stack
                );
                println!(
                    "stacks: {} known, {} applied",
                    info.known_stacks, info.applied_stacks
                );
            }
            Ok(())
        }
        EngineCommand::List { root, json } => {
            let DaemonResponse::Stacks(statuses) =
                engine_daemon::request(&root, DaemonRequest::List)?
            else {
                bail!("engine returned an unexpected response");
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&statuses)?);
            } else {
                for status in statuses {
                    println!(
                        "{} {:?} revision={} instances={} replicas={}",
                        status.stack,
                        status.state,
                        status.revision,
                        status.instance_count,
                        status.desired_replicas
                    );
                }
            }
            Ok(())
        }
        EngineCommand::Plan {
            file,
            root,
            output,
            json,
        } => {
            let manifest = StackManifest::read(&file).map_err(anyhow::Error::msg)?;
            let DaemonResponse::Planned(plan) = engine_daemon::request(
                &root,
                DaemonRequest::Plan {
                    manifest: Box::new(manifest),
                },
            )?
            else {
                bail!("engine returned an unexpected response");
            };
            if let Some(path) = output {
                write_private(&path, &serde_json::to_vec_pretty(&plan)?)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_stack_plan(&plan);
            }
            Ok(())
        }
        EngineCommand::Apply {
            file,
            root,
            allow_insecure,
            json,
        } => {
            let manifest = StackManifest::read(&file).map_err(anyhow::Error::msg)?;
            let DaemonResponse::Planned(plan) = engine_daemon::request(
                &root,
                DaemonRequest::Plan {
                    manifest: Box::new(manifest),
                },
            )?
            else {
                bail!("engine returned an unexpected response");
            };
            let DaemonResponse::Applied(report) = engine_daemon::request(
                &root,
                DaemonRequest::Apply {
                    plan,
                    allow_insecure,
                },
            )?
            else {
                bail!("engine returned an unexpected response");
            };
            print_stack_report(&report, json)
        }
        EngineCommand::Status { stack, root, json } => {
            let DaemonResponse::Status(status) =
                engine_daemon::request(&root, DaemonRequest::Status { stack })?
            else {
                bail!("engine returned an unexpected response");
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{} {:?} revision={} instances={} replicas={}",
                    status.stack,
                    status.state,
                    status.revision,
                    status.instance_count,
                    status.desired_replicas
                );
            }
            Ok(())
        }
        EngineCommand::Ps { stack, root, json } => {
            let DaemonResponse::RuntimeStatus(runtime) = engine_daemon::request(
                &root,
                DaemonRequest::RuntimeStatus {
                    stack: stack.clone(),
                },
            )?
            else {
                bail!("engine returned an unexpected response");
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&runtime)?);
            } else if let Some(runtime) = runtime {
                print_runtime_status(&runtime);
            } else {
                println!("{stack} has no observed runtime state");
            }
            Ok(())
        }
        EngineCommand::Events {
            stack,
            root,
            tail,
            json,
        } => {
            let DaemonResponse::Events(events) =
                engine_daemon::request(&root, DaemonRequest::Events { stack, tail })?
            else {
                bail!("engine returned an unexpected response");
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "{} {:?} {} {}",
                        event.revision, event.kind, event.created_at_ms, event.event_sha256
                    );
                }
            }
            Ok(())
        }
        EngineCommand::Stop { stack, root, json } => {
            let DaemonResponse::Stopped(report) =
                engine_daemon::request(&root, DaemonRequest::Stop { stack })?
            else {
                bail!("engine returned an unexpected response");
            };
            print_stack_report(&report, json)
        }
        EngineCommand::Remove { stack, root, json } => {
            let DaemonResponse::Removed(report) =
                engine_daemon::request(&root, DaemonRequest::Remove { stack })?
            else {
                bail!("engine returned an unexpected response");
            };
            print_stack_report(&report, json)
        }
        EngineCommand::Shutdown { root, json } => {
            match engine_daemon::request(&root, DaemonRequest::Shutdown)? {
                DaemonResponse::ShuttingDown if json => println!("{{\"stopping\":true}}"),
                DaemonResponse::ShuttingDown => println!("engine is shutting down"),
                _ => bail!("engine returned an unexpected response"),
            }
            Ok(())
        }
    }
}

fn new_command(path: &Path, language: DevLanguage) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("project path must end in a UTF-8 project name")?;
    let language = match language {
        DevLanguage::Rust => Language::Rust,
        DevLanguage::TinyGo => Language::TinyGo,
        DevLanguage::JavaScript => Language::JavaScript,
    };
    create_project(path, name, language).map_err(anyhow::Error::msg)?;
    println!(
        "created {} project at {}",
        language_name(language),
        path.display()
    );
    Ok(())
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::Rust => "rust",
        Language::TinyGo => "tinygo",
        Language::JavaScript => "javascript",
    }
}

fn check_command(project: &Path, json: bool) -> Result<()> {
    let report = profile_project(project).map_err(anyhow::Error::msg)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{} {}", report.cartridge_id, report.cartridge_version);
        println!("language: {}", report.language);
        println!("files: {}", report.files);
        println!("source bytes: {}", report.source_bytes);
        println!("asset bytes: {}", report.asset_bytes);
        println!("component: {}", report.component.display());
        println!("component built: {}", report.component_exists);
        println!("component bytes: {}", report.component_bytes);
        println!("fuel budget: {}", report.fuel_budget);
        println!("memory budget: {}", report.memory_budget_bytes);
        println!("timeout budget: {} ms", report.timeout_budget_ms);
        println!("permissions: {}", report.requested_permissions.join(", "));
    }
    Ok(())
}

fn profile_command(project: &Path, json: bool) -> Result<()> {
    check_command(project, json)
}

fn schema_command(output: Option<&Path>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&manifest_schema())?;
    if let Some(output) = output {
        write_private(output, &bytes)?;
        println!("wrote manifest schema -> {}", output.display());
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

fn conformance_command(package: &Path, json: bool, args: &[String]) -> Result<()> {
    let manifest = Runtime::new()?.validate_file(package)?;
    let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "cartridge-conformance-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)
        .with_context(|| format!("could not reserve {}", directory.display()))?;
    let trace = directory.join("run.trace.json");
    let run = supervised_run_command(RunCommandOptions {
        package,
        trace: Some(&trace),
        state_dir: None,
        from_snapshot: None,
        snapshot_output: None,
        input: None,
        midi: None,
        media_dir: None,
        http_fixtures: None,
        storage_signature: None,
        storage_trust: None,
        local_storage_authority: false,
        permission_ceiling: None,
        args,
    });
    let replay = run.and_then(|()| supervised_replay_command(package, &trace, None, args));
    let cleanup = fs::remove_file(&trace).and_then(|()| fs::remove_dir(&directory));
    replay?;
    cleanup.with_context(|| format!("could not clean {}", directory.display()))?;
    let report = serde_json::json!({
        "conformance_format": 1,
        "cartridge_id": manifest.cartridge.id,
        "cartridge_version": manifest.cartridge.version,
        "api_preflight": true,
        "execution": true,
        "deterministic_replay": true
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("API preflight: passed");
        println!("execution: passed");
        println!("deterministic replay: passed");
    }
    Ok(())
}

fn dev_command(project: &Path, once: bool, preserve_state: bool) -> Result<()> {
    let project = fs::canonicalize(project)
        .with_context(|| format!("could not open project {}", project.display()))?;
    let mut fingerprint = String::new();
    let mut previous_manifest = None;
    loop {
        let next_fingerprint = source_fingerprint(&project).map_err(anyhow::Error::msg)?;
        if next_fingerprint != fingerprint {
            let (config, manifest) = inspect_project(&project).map_err(anyhow::Error::msg)?;
            if preserve_state {
                if let Some(previous) = &previous_manifest {
                    match reload_decision(previous, &manifest) {
                        cartridge_dev::ReloadDecision::Reject { reason } => {
                            bail!("hot reload refused state handoff: {reason}")
                        }
                        cartridge_dev::ReloadDecision::Migrate { from, to } => bail!(
                            "state schema changed from {from} to {to}; run the declared migration before reloading"
                        ),
                        cartridge_dev::ReloadDecision::Fresh
                        | cartridge_dev::ReloadDecision::PreserveState => {}
                    }
                }
            }
            run_dev_build(&project, &config, &manifest, preserve_state)?;
            previous_manifest = Some(manifest);
            fingerprint = next_fingerprint;
        }
        if once {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn run_dev_build(
    project: &Path,
    config: &cartridge_dev::ProjectConfig,
    manifest: &cartridge_core::PackageManifest,
    preserve_state: bool,
) -> Result<()> {
    let (program, arguments) = config
        .build
        .split_first()
        .context("build command is empty")?;
    println!("building {}", manifest.cartridge.id);
    let status = ProcessCommand::new(program)
        .args(arguments)
        .current_dir(project)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("could not start build command {program:?}"))?;
    if !status.success() {
        bail!("build command exited with {status}");
    }

    let component = project.join(&config.component);
    if !component.is_file() {
        bail!("build did not create {}", component.display());
    }
    let work = project.join(".cartridge");
    fs::create_dir_all(&work)?;
    let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let package = work.join(format!("dev-{}-{sequence}.cartridge", std::process::id()));
    let assets = project.join("assets");
    pack(&PackOptions {
        manifest: project.join("Cartridge.toml"),
        component,
        assets: assets.is_dir().then_some(assets),
        output: package.clone(),
    })?;
    let state = preserve_state
        .then(|| work.join("state"))
        .filter(|_| manifest.permissions.storage);
    let result = supervised_run_command(RunCommandOptions {
        package: &package,
        trace: None,
        state_dir: state.as_deref(),
        from_snapshot: None,
        snapshot_output: None,
        input: None,
        midi: None,
        media_dir: None,
        http_fixtures: None,
        storage_signature: None,
        storage_trust: None,
        local_storage_authority: true,
        permission_ceiling: None,
        args: &[],
    });
    fs::remove_file(&package)
        .with_context(|| format!("could not remove temporary package {}", package.display()))?;
    result
}

#[allow(clippy::too_many_lines)]
fn run_library_command(command: LibraryCommand) -> Result<()> {
    match command {
        LibraryCommand::Install {
            package,
            root,
            json,
        } => {
            let installed = Library::open(root)
                .map_err(anyhow::Error::msg)?
                .install(&package)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&installed)?);
            } else {
                println!(
                    "installed {} ({} bytes)",
                    installed.name, installed.package_bytes
                );
                println!("sha256: {}", installed.package_sha256);
            }
            Ok(())
        }
        LibraryCommand::List { root, query, json } => {
            let library = Library::open(root).map_err(anyhow::Error::msg)?;
            let entries = library.list(query.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in entries {
                    let safe = if entry.safe_mode { " [safe mode]" } else { "" };
                    println!(
                        "{} {} {}{safe}",
                        entry.cartridge_id,
                        entry.versions.join(","),
                        entry.name
                    );
                }
            }
            Ok(())
        }
        LibraryCommand::Resolve {
            cartridge,
            root,
            version,
            lock,
            locked,
            json,
        } => library_resolve_command(
            &root,
            &cartridge,
            version.as_deref(),
            lock.as_deref(),
            locked.as_deref(),
            json,
        ),
        LibraryCommand::Preflight {
            cartridge,
            root,
            version,
            json,
        } => {
            let report = Library::open(root)
                .map_err(anyhow::Error::msg)?
                .preflight(&cartridge, version.as_deref())
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{} {}", report.cartridge_id, report.version);
                println!("requested: {}", capability_list(&report.requested));
                println!("granted: {}", capability_list(&report.granted));
                println!("missing: {}", capability_list(&report.missing));
            }
            Ok(())
        }
        LibraryCommand::Grant {
            cartridge,
            capabilities,
            root,
        } => {
            let mut library = Library::open(root).map_err(anyhow::Error::msg)?;
            let capabilities = capabilities.into_iter().map(capability).collect();
            library
                .grant(&cartridge, &capabilities, true)
                .map_err(anyhow::Error::msg)?;
            println!("updated persistent grants for {cartridge}");
            Ok(())
        }
        LibraryCommand::Revoke {
            cartridge,
            root,
            capability: value,
        } => {
            Library::open(root)
                .map_err(anyhow::Error::msg)?
                .revoke(&cartridge, value.map(capability))
                .map_err(anyhow::Error::msg)?;
            println!("revoked grant for {cartridge}");
            Ok(())
        }
        LibraryCommand::Run {
            cartridge,
            root,
            version,
            trace,
            allow,
            args,
        } => library_run_command(
            &root,
            &cartridge,
            version.as_deref(),
            trace.as_deref(),
            allow,
            &args,
        ),
        LibraryCommand::History { root, json } => {
            let library = Library::open(root).map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(library.history())?);
            } else {
                for record in library.history() {
                    println!(
                        "{} {} {} {:?} fuel={}",
                        record.id,
                        record.cartridge_id,
                        record.version,
                        record.status,
                        record
                            .fuel_consumed
                            .map_or_else(|| "-".into(), |value| value.to_string())
                    );
                }
            }
            Ok(())
        }
        LibraryCommand::ResetSafeMode { cartridge, root } => {
            Library::open(root)
                .map_err(anyhow::Error::msg)?
                .reset_safe_mode(&cartridge)
                .map_err(anyhow::Error::msg)?;
            println!("safe mode cleared for {cartridge}");
            Ok(())
        }
        LibraryCommand::Profile { command } => match command {
            LibraryProfileCommand::Set {
                name,
                cartridges,
                root,
            } => {
                Library::open(root)
                    .map_err(anyhow::Error::msg)?
                    .set_profile(&name, cartridges.into_iter().collect())
                    .map_err(anyhow::Error::msg)?;
                println!("updated profile {name}");
                Ok(())
            }
            LibraryProfileCommand::List { root, json } => {
                let library = Library::open(root).map_err(anyhow::Error::msg)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&library.profiles())?);
                } else {
                    for profile in library.profiles() {
                        println!(
                            "{}: {}",
                            profile.name,
                            profile
                                .cartridges
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
                Ok(())
            }
        },
        LibraryCommand::RuntimeRelease {
            root,
            channel,
            version,
        } => {
            Library::open(root)
                .map_err(anyhow::Error::msg)?
                .set_runtime_release(&channel, &version)
                .map_err(anyhow::Error::msg)?;
            println!("runtime release set to {channel} {version}");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_stack_command(command: StackCommand) -> Result<()> {
    match command {
        StackCommand::Validate { file, json } => {
            let manifest = StackManifest::read(&file).map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                println!(
                    "validated stack {} with {} instance(s)",
                    manifest.name,
                    manifest.instances.len()
                );
            }
            Ok(())
        }
        StackCommand::Plan {
            file,
            library,
            output,
            json,
        } => {
            let plan = build_stack_plan(&file, &library)?;
            if let Some(path) = output {
                write_private(&path, &serde_json::to_vec_pretty(&plan)?)?;
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_stack_plan(&plan);
            }
            Ok(())
        }
        StackCommand::Apply {
            file,
            library,
            root,
            allow_insecure,
            json,
        } => {
            let plan = build_stack_plan(&file, &library)?;
            let report = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .apply(&plan, allow_insecure)
                .map_err(anyhow::Error::msg)?;
            print_stack_report(&report, json)
        }
        StackCommand::Supervise {
            stack,
            library,
            root,
            max_workers,
            daemon_instance,
            json,
        } => supervise_stack(
            &stack,
            &root,
            &library,
            usize::from(max_workers),
            daemon_instance.as_deref(),
            json,
        ),
        StackCommand::List { root, json } => {
            let statuses = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .list()
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&statuses)?);
            } else {
                for status in statuses {
                    println!(
                        "{} {:?} revision={} instances={} replicas={}",
                        status.stack,
                        status.state,
                        status.revision,
                        status.instance_count,
                        status.desired_replicas
                    );
                }
            }
            Ok(())
        }
        StackCommand::Status { stack, root, json } => {
            let status = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .status(&stack)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!(
                    "{} {:?} revision={}",
                    status.stack, status.state, status.revision
                );
                println!("instances: {}", status.instance_count);
                println!("desired replicas: {}", status.desired_replicas);
                println!(
                    "plan: {}",
                    status.plan_sha256.as_deref().unwrap_or("removed")
                );
            }
            Ok(())
        }
        StackCommand::Ps { stack, root, json } => {
            let runtime = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .runtime_status(&stack)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&runtime)?);
            } else if let Some(runtime) = runtime {
                print_runtime_status(&runtime);
            } else {
                println!("{stack} has no observed runtime state");
            }
            Ok(())
        }
        StackCommand::Stop { stack, root, json } => {
            let report = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .stop(&stack)
                .map_err(anyhow::Error::msg)?;
            print_stack_report(&report, json)
        }
        StackCommand::Remove { stack, root, json } => {
            let report = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .remove(&stack)
                .map_err(anyhow::Error::msg)?;
            print_stack_report(&report, json)
        }
        StackCommand::Events { stack, root, json } => {
            let events = EngineStore::open(root)
                .map_err(anyhow::Error::msg)?
                .events(&stack)
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "{} {:?} {} {}",
                        event.revision, event.kind, event.created_at_ms, event.event_sha256
                    );
                }
            }
            Ok(())
        }
    }
}

struct StackWorkerTemplate {
    package: PathBuf,
    state: PathBuf,
    args: Vec<String>,
    permissions: Permissions,
    timeout: Duration,
}

struct ActiveStackWorker {
    child: ContainedChild,
    run_id: String,
    deadline: Instant,
}

#[derive(Default)]
struct ActiveStackWorkers(BTreeMap<ReplicaId, ActiveStackWorker>);

impl ActiveStackWorkers {
    fn terminate_all(&mut self) {
        for worker in self.0.values_mut() {
            let _ = worker.child.terminate(TERMINATION_GRACE);
        }
        self.0.clear();
    }
}

impl Drop for ActiveStackWorkers {
    fn drop(&mut self) {
        self.terminate_all();
    }
}

#[allow(clippy::too_many_lines)]
fn supervise_stack(
    stack: &str,
    root: &Path,
    library_root: &Path,
    max_workers: usize,
    daemon_instance: Option<&str>,
    json: bool,
) -> Result<()> {
    if max_workers == 0 || max_workers > 256 {
        bail!("supervisor worker limit is invalid");
    }
    if let Some(instance) = daemon_instance
        && (!valid_daemon_instance(instance) || !daemon_owner_is_active(root, instance)?)
    {
        bail!("engine daemon ownership could not be verified");
    }
    if daemon_instance.is_some() {
        install_parent_liveness_watchdog()?;
    }
    let now = current_time_ms()?;
    let engine = EngineStore::open(root).map_err(anyhow::Error::msg)?;
    let (revision, generation, plan) = engine
        .desired_plan(stack)
        .map_err(anyhow::Error::msg)?
        .context("stack was removed and has no runnable generation")?;
    let _lease = engine
        .acquire_supervisor_lease(stack)
        .map_err(anyhow::Error::msg)?;
    let library = Library::open(library_root).map_err(anyhow::Error::msg)?;
    plan.verify_installed(&library)
        .map_err(anyhow::Error::msg)?;
    let mut status = engine
        .prepare_runtime_status(stack, now)
        .map_err(anyhow::Error::msg)?;
    let templates = stack_worker_templates(&engine, &library, &plan, &generation)?;
    drop(library);
    drop(engine);

    let executable = std::env::current_exe().context("could not locate the cartridge worker")?;
    let mut active = ActiveStackWorkers::default();
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = interrupted.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .context("could not install the supervisor shutdown handler")?;
    let mut next_desired_check = Instant::now();
    loop {
        if interrupted.load(Ordering::Acquire) {
            stop_active_workers(&mut active, &mut status, root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("{stack} supervisor interrupted");
                print_runtime_status(&status);
            }
            return Ok(());
        }
        if Instant::now() >= next_desired_check {
            let generation_is_current =
                runtime_generation_is_current(root, stack, revision, &generation)?;
            let daemon_is_current = daemon_instance
                .map(|instance| daemon_owner_is_active(root, instance))
                .transpose()?
                .unwrap_or(true);
            if !generation_is_current || !daemon_is_current {
                if generation_is_current {
                    stop_active_workers(&mut active, &mut status, root)?;
                } else {
                    active.terminate_all();
                }
                if !json {
                    println!("{stack} ownership changed; stopped generation {revision}");
                }
                return Ok(());
            }
            next_desired_check = Instant::now() + DESIRED_STATE_POLL_INTERVAL;
        }

        let mut changed = false;
        let now_ms = current_time_ms()?;
        let ids = active.0.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let timed_out = active
                .0
                .get(&id)
                .is_some_and(|worker| Instant::now() >= worker.deadline);
            let outcome = if timed_out {
                let worker = active.0.get_mut(&id).context("active worker disappeared")?;
                let exit = worker
                    .child
                    .terminate(TERMINATION_GRACE)
                    .context("could not terminate timed-out worker")?;
                Some((
                    false,
                    exit.and_then(|status| status.code()),
                    "worker exceeded its supervised deadline",
                ))
            } else {
                active
                    .0
                    .get_mut(&id)
                    .context("active worker disappeared")?
                    .child
                    .try_wait()?
                    .map(|exit| (exit.success(), exit.code(), "worker exited"))
            };
            if let Some((success, code, detail)) = outcome {
                let worker = active.0.remove(&id).context("active worker disappeared")?;
                status
                    .mark_exit(&id, &worker.run_id, success, code, detail, now_ms)
                    .map_err(anyhow::Error::msg)?;
                changed = true;
            }
        }
        if changed {
            persist_runtime_status(root, &status)?;
        }

        while active.0.len() < max_workers {
            let Some(id) = status
                .eligible_starts(now_ms)
                .into_iter()
                .find(|id| !active.0.contains_key(id))
            else {
                break;
            };
            let replica = status
                .replicas
                .iter()
                .find(|replica| replica.id == id)
                .context("runtime replica disappeared")?;
            let attempt = replica
                .attempt
                .checked_add(1)
                .context("replica attempt counter overflow")?;
            let run_id = replica_run_id(&generation, &id, attempt);
            status
                .begin_start(&id, &run_id, now_ms)
                .map_err(anyhow::Error::msg)?;
            persist_runtime_status(root, &status)?;
            let template = templates
                .get(&id)
                .context("replica has no verified worker template")?;
            match spawn_stack_worker(&executable, template) {
                Ok(child) => {
                    active.0.insert(
                        id.clone(),
                        ActiveStackWorker {
                            child,
                            run_id: run_id.clone(),
                            deadline: Instant::now() + WORKER_STARTUP_BUDGET + template.timeout,
                        },
                    );
                    status
                        .mark_running(&id, &run_id, now_ms)
                        .map_err(anyhow::Error::msg)?;
                }
                Err(_) => {
                    status
                        .mark_exit(
                            &id,
                            &run_id,
                            false,
                            None,
                            "worker process could not be started",
                            now_ms,
                        )
                        .map_err(anyhow::Error::msg)?;
                }
            }
            persist_runtime_status(root, &status)?;
        }

        let waiting = status.replicas.iter().any(|replica| {
            matches!(
                replica.phase,
                ReplicaPhase::Pending
                    | ReplicaPhase::Starting
                    | ReplicaPhase::Running
                    | ReplicaPhase::Backoff
            )
        });
        if active.0.is_empty() && !waiting {
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_runtime_status(&status);
            }
            return Ok(());
        }
        thread::sleep(WORKER_POLL_INTERVAL);
    }
}

fn stop_active_workers(
    active: &mut ActiveStackWorkers,
    status: &mut StackRuntimeStatus,
    root: &Path,
) -> Result<()> {
    let ids = active.0.keys().cloned().collect::<Vec<_>>();
    for id in ids {
        let mut worker = active.0.remove(&id).context("active worker disappeared")?;
        let exit = if let Some(exit) = worker.child.try_wait()? {
            Some(exit)
        } else {
            worker
                .child
                .terminate(TERMINATION_GRACE)
                .context("could not terminate interrupted worker")?
        };
        status
            .mark_exit(
                &id,
                &worker.run_id,
                false,
                exit.and_then(|status| status.code()),
                "supervisor was interrupted",
                current_time_ms()?,
            )
            .map_err(anyhow::Error::msg)?;
    }
    persist_runtime_status(root, status)
}

fn stack_worker_templates(
    engine: &EngineStore,
    library: &Library,
    plan: &StackPlan,
    generation: &str,
) -> Result<BTreeMap<ReplicaId, StackWorkerTemplate>> {
    let mut templates = BTreeMap::new();
    for instance in &plan.instances {
        let record = library
            .catalog_package(&instance.cartridge_id, Some(&instance.version))
            .map_err(anyhow::Error::msg)?;
        if record.package_sha256 != instance.package_sha256
            || record.package_bytes != instance.package_bytes
        {
            bail!("installed package no longer matches the desired stack generation");
        }
        let archive = CartridgeArchive::open(&record.path)?;
        for ordinal in 1..=instance.replicas {
            let id = ReplicaId {
                instance: instance.name.clone(),
                ordinal,
            };
            let state = engine
                .replica_state_directory(&plan.stack, generation, &id)
                .map_err(anyhow::Error::msg)?;
            templates.insert(
                id,
                StackWorkerTemplate {
                    package: record.path.clone(),
                    state,
                    args: instance.args.clone(),
                    permissions: stack_permissions(instance),
                    timeout: Duration::from_millis(archive.manifest.runtime.timeout_ms),
                },
            );
        }
    }
    Ok(templates)
}

fn stack_permissions(instance: &PlannedInstance) -> Permissions {
    Permissions {
        clock: instance.allowed.contains(&StackCapability::Clock),
        random: instance.allowed.contains(&StackCapability::Random),
        assets: instance.allowed.contains(&StackCapability::Assets),
        storage: instance.allowed.contains(&StackCapability::Storage),
        graphics: instance.allowed.contains(&StackCapability::Graphics),
        audio: instance.allowed.contains(&StackCapability::Audio),
        midi: instance.allowed.contains(&StackCapability::Midi),
        http: instance.allowed.contains(&StackCapability::Http),
    }
}

fn spawn_stack_worker(executable: &Path, template: &StackWorkerTemplate) -> Result<ContainedChild> {
    let mut arguments = vec![
        OsString::from("__worker-run"),
        template.package.as_os_str().to_owned(),
        OsString::from("--state-dir"),
        template.state.as_os_str().to_owned(),
        OsString::from("--local-storage-authority"),
        OsString::from("--capability-ceiling"),
        OsString::from(permissions_mask(&template.permissions).to_string()),
    ];
    push_worker_arguments(&mut arguments, &template.args);
    let mut command = ContainedCommand::new(executable);
    command
        .args(arguments)
        .env("CARTRIDGE_WORKER", "1")
        .stdout(OutputMode::Inherit)
        .stderr(OutputMode::Inherit);
    spawn_contained(&mut command, true).context("could not start the cartridge worker")
}

fn runtime_generation_is_current(
    root: &Path,
    stack: &str,
    revision: u64,
    generation: &str,
) -> Result<bool> {
    Ok(EngineStore::open(root)
        .map_err(anyhow::Error::msg)?
        .desired_plan(stack)
        .map_err(anyhow::Error::msg)?
        .is_some_and(|(current_revision, current_generation, _)| {
            current_revision == revision && current_generation == generation
        }))
}

fn daemon_owner_is_active(root: &Path, instance: &str) -> Result<bool> {
    let Ok(endpoint) = DaemonEndpoint::read(root) else {
        return Ok(false);
    };
    Ok(endpoint.instance_id == instance
        && DaemonLease::is_active(root).map_err(anyhow::Error::msg)?)
}

fn valid_daemon_instance(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn persist_runtime_status(root: &Path, status: &StackRuntimeStatus) -> Result<()> {
    EngineStore::open(root)
        .map_err(anyhow::Error::msg)?
        .save_runtime_status(status)
        .map_err(anyhow::Error::msg)
}

fn replica_run_id(generation: &str, id: &ReplicaId, attempt: u16) -> String {
    let mut digest = Sha256::new();
    digest.update(generation.as_bytes());
    digest.update((id.instance.len() as u64).to_le_bytes());
    digest.update(id.instance.as_bytes());
    digest.update(id.ordinal.to_le_bytes());
    digest.update(attempt.to_le_bytes());
    hex::encode(digest.finalize())
}

fn print_runtime_status(status: &StackRuntimeStatus) {
    println!(
        "{} generation={} revision={}",
        status.stack, status.generation, status.revision
    );
    for replica in &status.replicas {
        println!(
            "{}-{} {:?} attempt={}/{}{}",
            replica.id.instance,
            replica.id.ordinal,
            replica.phase,
            replica.attempt,
            replica.max_restarts + 1,
            replica
                .detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(" {detail}"))
        );
    }
}

fn build_stack_plan(file: &Path, library: &Path) -> Result<StackPlan> {
    let manifest = StackManifest::read(file).map_err(anyhow::Error::msg)?;
    let library = Library::open(library).map_err(anyhow::Error::msg)?;
    StackPlan::build(&manifest, &library).map_err(anyhow::Error::msg)
}

fn print_stack_plan(plan: &StackPlan) {
    println!("stack: {}", plan.stack);
    println!("plan sha256: {}", plan.plan_sha256);
    println!(
        "security: {:?}, sandbox {:?}",
        plan.security.profile, plan.security.sandbox
    );
    println!("instances:");
    for instance in &plan.instances {
        println!(
            "  {}: {} {} x{} {:?}",
            instance.name,
            instance.cartridge_id,
            instance.version,
            instance.replicas,
            instance.desired
        );
        println!("    package: {}", instance.package_sha256);
        println!("    allowed: {}", stack_capability_list(&instance.allowed));
        println!("    denied: {}", stack_capability_list(&instance.denied));
    }
    for warning in &plan.warnings {
        println!("warning: {warning}");
    }
}

fn print_stack_report(report: &cartridge_engine::ApplyReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        let action = if report.changed {
            "updated"
        } else {
            "unchanged"
        };
        println!(
            "{} {} {:?} revision={}",
            action, report.status.stack, report.status.state, report.status.revision
        );
        println!("event sha256: {}", report.status.event_sha256);
    }
    Ok(())
}

fn stack_capability_list(value: &BTreeSet<cartridge_engine::StackCapability>) -> String {
    if value.is_empty() {
        return "none".into();
    }
    value
        .iter()
        .map(|capability| format!("{capability:?}").to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

fn library_run_command(
    root: &Path,
    cartridge: &str,
    version: Option<&str>,
    trace: Option<&Path>,
    allow: Vec<PermissionName>,
    args: &[String],
) -> Result<()> {
    let mut library = Library::open(root).map_err(anyhow::Error::msg)?;
    let session = allow.into_iter().map(capability).collect();
    library
        .grant(cartridge, &session, false)
        .map_err(anyhow::Error::msg)?;
    let package = library
        .package_path(cartridge, version)
        .map_err(anyhow::Error::msg)?;
    let launch = library
        .begin_launch(cartridge, version)
        .map_err(anyhow::Error::msg)?;
    let state = root.join("state");
    let result = supervised_run_command(RunCommandOptions {
        package: &package,
        trace,
        state_dir: Some(&state),
        from_snapshot: None,
        snapshot_output: None,
        input: None,
        midi: None,
        media_dir: None,
        http_fixtures: None,
        storage_signature: None,
        storage_trust: None,
        local_storage_authority: true,
        permission_ceiling: None,
        args,
    });
    let status = if result.is_ok() {
        LaunchStatus::Succeeded
    } else {
        LaunchStatus::Failed
    };
    library
        .finish_launch(
            launch.id,
            status,
            None,
            None,
            trace.map(|path| path.display().to_string()),
        )
        .map_err(anyhow::Error::msg)?;
    result
}

fn capability(value: PermissionName) -> Capability {
    match value {
        PermissionName::Clock => Capability::Clock,
        PermissionName::Random => Capability::Random,
        PermissionName::Assets => Capability::Assets,
        PermissionName::Storage => Capability::Storage,
        PermissionName::Graphics => Capability::Graphics,
        PermissionName::Audio => Capability::Audio,
        PermissionName::Midi => Capability::Midi,
        PermissionName::Http => Capability::Http,
    }
}

fn capability_list(values: &BTreeSet<Capability>) -> String {
    values
        .iter()
        .map(|value| format!("{value:?}").to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
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
        BlobCommand::List { store, json } => blob_list_command(&store, json),
        BlobCommand::Audit { store, json } => blob_audit_command(&store, json),
        BlobCommand::Roots { command } => run_blob_roots_command(command),
        BlobCommand::Gc {
            store,
            keep,
            snapshot,
            capsule,
            manifest,
            apply,
            json,
        } => blob_gc_command(&store, keep, snapshot, capsule, manifest, apply, json),
    }
}

fn blob_list_command(store: &Path, json: bool) -> Result<()> {
    let inventory = BlobStore::open(store)?.inventory()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inventory)?);
    } else {
        for object in &inventory.objects {
            println!("{} {}", object.sha256, object.bytes);
        }
        println!("objects: {}", inventory.objects.len());
        println!("bytes: {}", inventory.total_bytes);
    }
    Ok(())
}

fn blob_audit_command(store: &Path, json: bool) -> Result<()> {
    let report = BlobStore::open(store)?.audit()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("valid objects: {}", report.valid_objects);
        println!("valid bytes: {}", report.valid_bytes);
        println!("issues: {}", report.issues.len());
        for issue in &report.issues {
            println!("  {}: {}", issue.sha256, issue.error);
        }
    }
    if !report.healthy() {
        bail!("blob store audit found {} issue(s)", report.issues.len());
    }
    Ok(())
}

fn blob_gc_command(
    store: &Path,
    keep: Vec<String>,
    snapshots: Vec<PathBuf>,
    capsules: Vec<PathBuf>,
    manifests: Vec<PathBuf>,
    apply: bool,
    json: bool,
) -> Result<()> {
    let root_count = snapshots
        .len()
        .checked_add(capsules.len())
        .and_then(|count| count.checked_add(manifests.len()))
        .context("blob reachability root count overflowed")?;
    if root_count > MAX_BLOB_GC_ROOT_ARTIFACTS {
        bail!(
            "blob garbage collection accepts at most {MAX_BLOB_GC_ROOT_ARTIFACTS} artifact roots"
        );
    }
    let retained: BTreeSet<_> = keep.into_iter().collect();
    let mut references = BTreeMap::new();
    for path in snapshots {
        let snapshot = StorageSnapshot::read(&path)
            .with_context(|| format!("could not read snapshot {}", path.display()))?;
        merge_blob_references(&mut references, snapshot.blob_references()?)?;
    }
    for path in capsules {
        let reachability = capsule::blob_references(&path)?;
        merge_blob_references(&mut references, reachability.references)?;
    }
    for path in manifests {
        let manifest = BlobReachabilityManifest::read(&path)
            .with_context(|| format!("could not read reachability manifest {}", path.display()))?;
        merge_blob_references(&mut references, manifest.objects().clone())?;
    }
    let report = BlobStore::open(store)?.gc_with_references(&retained, &references, !apply)?;
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

fn run_blob_roots_command(command: BlobRootsCommand) -> Result<()> {
    match command {
        BlobRootsCommand::Create {
            snapshot,
            capsule,
            output,
        } => {
            let (sources, references) = collect_blob_reachability(snapshot, capsule)?;
            let manifest = BlobReachabilityManifest::new(sources, references)?;
            let summary = manifest.summary()?;
            manifest.write_new(&output)?;
            println!(
                "wrote {} source(s) and {} object(s) -> {}",
                summary.sources,
                summary.objects,
                output.display()
            );
            Ok(())
        }
        BlobRootsCommand::Inspect { manifest, json } => {
            let summary = BlobReachabilityManifest::read(manifest)?.summary()?;
            print_blob_reachability_summary(&summary, json)
        }
        BlobRootsCommand::Verify {
            manifest,
            store,
            json,
        } => {
            let manifest = BlobReachabilityManifest::read(manifest)?;
            let verification = BlobStore::open(store)?.verify_references(manifest.objects())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&verification)?);
            } else {
                println!("verified objects: {}", verification.objects);
                println!("verified bytes: {}", verification.bytes);
            }
            Ok(())
        }
    }
}

fn collect_blob_reachability(
    snapshots: Vec<PathBuf>,
    capsules: Vec<PathBuf>,
) -> Result<(BTreeSet<BlobReachabilitySource>, BTreeMap<String, u64>)> {
    let root_count = snapshots
        .len()
        .checked_add(capsules.len())
        .context("blob reachability root count overflowed")?;
    if root_count == 0 || root_count > MAX_BLOB_GC_ROOT_ARTIFACTS {
        bail!(
            "blob reachability requires between 1 and {MAX_BLOB_GC_ROOT_ARTIFACTS} snapshot or capsule roots"
        );
    }
    let mut sources = BTreeSet::new();
    let mut references = BTreeMap::new();
    for path in snapshots {
        let snapshot = StorageSnapshot::read(&path)
            .with_context(|| format!("could not read snapshot {}", path.display()))?;
        let summary = snapshot.summary()?;
        sources.insert(BlobReachabilitySource::new(
            BlobReachabilitySourceKind::Snapshot,
            summary.payload_sha256,
        )?);
        merge_blob_references(&mut references, snapshot.blob_references()?)?;
    }
    for path in capsules {
        let reachability = capsule::blob_references(&path)?;
        sources.insert(BlobReachabilitySource::new(
            BlobReachabilitySourceKind::Capsule,
            reachability.capsule_sha256,
        )?);
        merge_blob_references(&mut references, reachability.references)?;
    }
    Ok((sources, references))
}

fn print_blob_reachability_summary(
    summary: &cartridge_runtime::BlobReachabilitySummary,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
    } else {
        println!("reachability format: {}", summary.format_version);
        println!("sources: {}", summary.sources);
        println!("objects: {}", summary.objects);
        println!("bytes: {}", summary.bytes);
        println!("payload sha256: {}", summary.payload_sha256);
    }
    Ok(())
}

fn merge_blob_references(
    target: &mut BTreeMap<String, u64>,
    source: BTreeMap<String, u64>,
) -> Result<()> {
    for (sha256, bytes) in source {
        match target.insert(sha256.clone(), bytes) {
            Some(existing) if existing != bytes => {
                bail!("artifacts have conflicting sizes for blob {sha256}");
            }
            _ => {}
        }
        if target.len() > MAX_BLOB_GC_REFERENCES {
            bail!("blob reachability exceeds the {MAX_BLOB_GC_REFERENCES}-reference limit");
        }
    }
    Ok(())
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
        TraceCommand::Export { trace, output } => trace_export_command(&trace, &output),
    }
}

fn trace_export_command(trace: &Path, output: &Path) -> Result<()> {
    let trace = read_trace(trace)?;
    let document = serde_json::json!({
        "viewer_format": 1,
        "summary": trace.summary(),
        "events": trace.events
    });
    let bytes = serde_json::to_vec_pretty(&document)?;
    if bytes.len() as u64 > MAX_TRACE_DOCUMENT_BYTES {
        bail!("trace viewer export exceeds the {MAX_TRACE_DOCUMENT_BYTES}-byte limit");
    }
    write_private(output, &bytes)?;
    println!("wrote trace viewer data -> {}", output.display());
    Ok(())
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

fn run_storage_command(command: StorageCommand, durable_auth: &DurableAuth) -> Result<()> {
    let durable_package = match &command {
        StorageCommand::Status { package, .. }
        | StorageCommand::Recover { package, .. }
        | StorageCommand::Export { package, .. }
        | StorageCommand::Restore { package, .. }
        | StorageCommand::MigrateCommit { package, .. }
        | StorageCommand::MigrationRecover { package, .. } => Some(package.as_path()),
        StorageCommand::Inspect { .. }
        | StorageCommand::Diff { .. }
        | StorageCommand::MigrationPlan { .. }
        | StorageCommand::Migrate { .. }
        | StorageCommand::MigrationReceipt { .. } => None,
    };
    if let Some(package) = durable_package {
        durable_auth.verify(package)?;
    }
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
            durable_auth,
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

fn load_or_create_trust(path: &Path) -> Result<TrustStore> {
    if path.exists() {
        TrustStore::read(path).map_err(anyhow::Error::msg)
    } else {
        Ok(TrustStore::new())
    }
}

fn save_trust(path: &Path, trust: &TrustStore) -> Result<()> {
    if path.exists() {
        trust.write_replace(path)
    } else {
        trust.write_new(path)
    }
    .map_err(anyhow::Error::msg)
}

#[allow(clippy::too_many_lines)]
fn run_identity_command(command: IdentityCommand) -> Result<()> {
    match command {
        IdentityCommand::Keygen { output } => {
            let key = DeveloperKey::generate();
            key.write_new(&output).map_err(anyhow::Error::msg)?;
            println!(
                "created developer key {} -> {}",
                key.key_id(),
                output.display()
            );
        }
        IdentityCommand::Sign {
            package,
            key,
            output,
        } => {
            let signature = DeveloperKey::read(&key)
                .map_err(anyhow::Error::msg)?
                .sign_package(&package)
                .map_err(anyhow::Error::msg)?;
            write_signature(&output, &signature).map_err(anyhow::Error::msg)?;
            println!(
                "signed {} as {}",
                package.display(),
                signature.identity.package_sha256
            );
        }
        IdentityCommand::Verify {
            package,
            signature,
            trust,
        } => {
            let signature = read_signature(&signature).map_err(anyhow::Error::msg)?;
            let identity = match trust {
                Some(path) => {
                    TrustStore::read(&path).and_then(|store| store.verify(&package, &signature))
                }
                None => cartridge_identity::verify_package(&package, &signature),
            }
            .map_err(anyhow::Error::msg)?;
            println!(
                "verified {} {} ({})",
                identity.cartridge_id, identity.version, identity.package_sha256
            );
        }
        IdentityCommand::Trust {
            signature,
            store,
            label,
        } => {
            let signature = read_signature(&signature).map_err(anyhow::Error::msg)?;
            let mut trust = load_or_create_trust(&store)?;
            trust
                .trust(hex_array(&signature.public_key)?, &label, BTreeSet::new())
                .map_err(anyhow::Error::msg)?;
            save_trust(&store, &trust)?;
            println!("trusted {}", signature.key_id);
        }
        IdentityCommand::RotateCreate {
            old_key,
            new_key,
            reason,
            output,
        } => {
            let value = KeyRotation::create(
                &DeveloperKey::read(&old_key).map_err(anyhow::Error::msg)?,
                &DeveloperKey::read(&new_key).map_err(anyhow::Error::msg)?,
                &reason,
            )
            .map_err(anyhow::Error::msg)?;
            write_rotation(&output, &value).map_err(anyhow::Error::msg)?;
            println!("created key rotation -> {}", output.display());
        }
        IdentityCommand::RotateApply { rotation, store } => {
            let mut trust = TrustStore::read(&store).map_err(anyhow::Error::msg)?;
            trust
                .apply_rotation(read_rotation(&rotation).map_err(anyhow::Error::msg)?)
                .map_err(anyhow::Error::msg)?;
            save_trust(&store, &trust)?;
            println!("applied key rotation");
        }
        IdentityCommand::RevokeCreate {
            key_id,
            signer,
            reason,
            output,
        } => {
            let value = RevocationRecord::create(
                key_id,
                &DeveloperKey::read(&signer).map_err(anyhow::Error::msg)?,
                &reason,
            )
            .map_err(anyhow::Error::msg)?;
            write_revocation(&output, &value).map_err(anyhow::Error::msg)?;
            println!("created revocation -> {}", output.display());
        }
        IdentityCommand::RevokeApply { revocation, store } => {
            let mut trust = TrustStore::read(&store).map_err(anyhow::Error::msg)?;
            trust
                .apply_revocation(read_revocation(&revocation).map_err(anyhow::Error::msg)?)
                .map_err(anyhow::Error::msg)?;
            save_trust(&store, &trust)?;
            println!("applied key revocation");
        }
    }
    Ok(())
}

fn run_registry_command(command: RegistryCommand) -> Result<()> {
    match command {
        RegistryCommand::Init { root } => {
            Registry::open(&root).map_err(anyhow::Error::msg)?;
            println!("initialized registry -> {}", root.display());
        }
        RegistryCommand::Publish {
            package,
            signature,
            trust,
            root,
        } => {
            let trust = TrustStore::read(&trust).map_err(anyhow::Error::msg)?;
            let signature = read_signature(&signature).map_err(anyhow::Error::msg)?;
            let mut registry = Registry::open(root).map_err(anyhow::Error::msg)?;
            let version = registry
                .publish(&package, &signature, &trust)
                .map_err(anyhow::Error::msg)?;
            println!(
                "published {} {} ({})",
                version.identity.cartridge_id,
                version.identity.version,
                version.identity.package_sha256
            );
        }
        RegistryCommand::Resolve {
            cartridge,
            requirement,
            root,
        } => {
            let registry = Registry::open(root).map_err(anyhow::Error::msg)?;
            let version = registry
                .resolve(&cartridge, &requirement)
                .map_err(anyhow::Error::msg)?
                .context("no matching signed package")?;
            println!(
                "{} {} {}",
                version.identity.cartridge_id,
                version.identity.version,
                version.identity.package_sha256
            );
        }
        RegistryCommand::Audit { root, trust } => {
            let registry = Registry::open(root).map_err(anyhow::Error::msg)?;
            let trust = TrustStore::read(&trust).map_err(anyhow::Error::msg)?;
            println!(
                "verified {} signed registry version(s)",
                registry.audit(&trust).map_err(anyhow::Error::msg)?
            );
        }
    }
    Ok(())
}

fn platform_command(package: &Path, json_output: bool) -> Result<()> {
    let archive = CartridgeArchive::open(package)?;
    let negotiated = negotiate_platform(&archive.manifest)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&negotiated)?);
    } else {
        println!("host API: {}", negotiated.host_api);
        for (name, version) in negotiated.capabilities {
            println!("{name}: {version}");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_release_command(command: ReleaseCommand) -> Result<()> {
    match command {
        ReleaseCommand::Create {
            artifact,
            target,
            version,
            channel,
            key,
            output,
        } => {
            let (bytes, sha256) =
                hash_bounded_file(&artifact, cartridge_release::MAX_RUNTIME_ARTIFACT_BYTES)?;
            let filename = artifact
                .file_name()
                .and_then(|value| value.to_str())
                .context("runtime artifact filename must be UTF-8")?
                .to_owned();
            let payload = ReleasePayload::new(
                channel,
                version,
                current_time_ms()?,
                env!("CARGO_PKG_VERSION").into(),
                vec![ReleaseArtifact {
                    target,
                    filename,
                    bytes,
                    sha256,
                }],
            )
            .map_err(anyhow::Error::msg)?;
            let release = SignedRelease::create(
                &DeveloperKey::read(&key).map_err(anyhow::Error::msg)?,
                payload,
            )
            .map_err(anyhow::Error::msg)?;
            release.write_new(&output).map_err(anyhow::Error::msg)?;
            println!(
                "signed runtime release {} -> {}",
                release.payload.version,
                output.display()
            );
        }
        ReleaseCommand::Verify { release, trust } => {
            let release = SignedRelease::read(&release).map_err(anyhow::Error::msg)?;
            let trust = TrustStore::read(&trust).map_err(anyhow::Error::msg)?;
            release
                .verify(&trust, env!("CARGO_PKG_VERSION"))
                .map_err(anyhow::Error::msg)?;
            println!(
                "verified runtime release {} ({})",
                release.payload.version, release.payload.channel
            );
        }
        ReleaseCommand::Install {
            release,
            artifact,
            target,
            trust,
            root,
            channel,
            allow_downgrade,
        } => {
            let release = SignedRelease::read(&release).map_err(anyhow::Error::msg)?;
            let trust = TrustStore::read(&trust).map_err(anyhow::Error::msg)?;
            let installed = Updater::open(root, &channel)
                .and_then(|mut updater| {
                    updater.install(
                        &release,
                        &trust,
                        &artifact,
                        &target,
                        env!("CARGO_PKG_VERSION"),
                        allow_downgrade,
                    )
                })
                .map_err(anyhow::Error::msg)?;
            println!(
                "activated runtime {} -> {}",
                installed.version, installed.relative_path
            );
        }
        ReleaseCommand::Status {
            root,
            channel,
            json,
        } => {
            let active = Updater::open(root, &channel)
                .and_then(|updater| updater.active())
                .map_err(anyhow::Error::msg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&active)?);
            } else if let Some(active) = active {
                println!(
                    "active runtime: {} ({})",
                    active.version, active.relative_path
                );
            } else {
                println!("no active runtime release");
            }
        }
        ReleaseCommand::Rollback { root, channel } => {
            let release = Updater::open(root, &channel)
                .and_then(|mut updater| updater.rollback())
                .map_err(anyhow::Error::msg)?;
            println!("rolled back to runtime {}", release.version);
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct StabilityReport {
    format_version: u32,
    kind: &'static str,
    local_only: bool,
    operating_system: &'static str,
    architecture: &'static str,
    cartridge_id: String,
    cartridge_version: String,
    iterations: u32,
    total_ms: u128,
    minimum_us: u128,
    median_us: u128,
    p95_us: u128,
    maximum_us: u128,
    declared_memory_limit_bytes: usize,
    fuel_consumed: u64,
    trace_events: usize,
    output_sha256: String,
    frames: usize,
    audio_renders: usize,
    graphics_present_calls: u64,
    graphics_present_micros: u128,
    audio_render_calls: u64,
    audio_render_micros: u128,
}

fn supervised_stability_command(command: &StabilityCommand) -> Result<()> {
    let (kind, package, iterations, output, args) = match &command {
        StabilityCommand::Benchmark {
            package,
            iterations,
            output,
            args,
        } => ("benchmark", package, *iterations, output, args),
        StabilityCommand::Soak {
            package,
            iterations,
            output,
            args,
        } => ("soak", package, *iterations, output, args),
    };
    validate_iterations(iterations)?;
    if output
        .try_exists()
        .with_context(|| format!("could not inspect stability output {}", output.display()))?
    {
        bail!("stability output already exists: {}", output.display());
    }
    let archive = CartridgeArchive::open(package).with_context(|| {
        format!(
            "could not validate {} before stability run",
            package.display()
        )
    })?;
    let runs = iterations.saturating_add(1);
    let requested = Duration::from_millis(archive.manifest.runtime.timeout_ms)
        .checked_mul(runs)
        .unwrap_or(MAX_STABILITY_WALL_TIME);
    let budget = requested.min(MAX_STABILITY_WALL_TIME);
    drop(archive);

    let mut worker_args = vec![
        OsString::from("__worker-stability"),
        OsString::from(kind),
        package.as_os_str().to_owned(),
        OsString::from("--iterations"),
        OsString::from(iterations.to_string()),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ];
    push_worker_arguments(&mut worker_args, args);
    supervise_worker(package, &worker_args, Some(budget))
}

fn run_stability_command(command: StabilityCommand) -> Result<()> {
    match command {
        StabilityCommand::Benchmark {
            package,
            iterations,
            output,
            args,
        } => stability_benchmark(&package, iterations, &output, &args),
        StabilityCommand::Soak {
            package,
            iterations,
            output,
            args,
        } => stability_soak(&package, iterations, &output, &args),
    }
}

fn stability_benchmark(
    package: &Path,
    iterations: u32,
    output: &Path,
    args: &[String],
) -> Result<()> {
    validate_iterations(iterations)?;
    let started = Instant::now();
    let mut timings = Vec::with_capacity(iterations as usize);
    let mut last = None;
    for _ in 0..iterations {
        let iteration = Instant::now();
        let report = Runtime::new()?.run_file(package, args)?;
        timings.push(iteration.elapsed().as_micros());
        last = Some(report);
    }
    write_stability_report(
        output,
        "cold-start-benchmark",
        iterations,
        started.elapsed(),
        timings,
        last.context("benchmark produced no run")?,
    )
}

fn stability_soak(package: &Path, iterations: u32, output: &Path, args: &[String]) -> Result<()> {
    validate_iterations(iterations)?;
    let runtime = Runtime::new()?;
    let baseline = runtime.run_file(package, args)?;
    let trace = baseline.trace.clone();
    let started = Instant::now();
    let mut timings = Vec::with_capacity(iterations as usize);
    let mut last = None;
    for _ in 0..iterations {
        let iteration = Instant::now();
        let report = runtime.replay_file(package, args, trace.clone())?;
        timings.push(iteration.elapsed().as_micros());
        last = Some(report);
    }
    write_stability_report(
        output,
        "deterministic-soak",
        iterations,
        started.elapsed(),
        timings,
        last.context("soak produced no replay")?,
    )
}

fn validate_iterations(iterations: u32) -> Result<()> {
    if !(1..=10_000).contains(&iterations) {
        bail!("iterations must be between 1 and 10000");
    }
    Ok(())
}

fn write_stability_report(
    output: &Path,
    kind: &'static str,
    iterations: u32,
    elapsed: Duration,
    mut timings: Vec<u128>,
    run: cartridge_runtime::RunReport,
) -> Result<()> {
    timings.sort_unstable();
    let percentile =
        |numerator: usize| timings[(timings.len().saturating_sub(1) * numerator) / 100];
    let report = StabilityReport {
        format_version: 1,
        kind,
        local_only: true,
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        cartridge_id: run.cartridge.id,
        cartridge_version: run.cartridge.version,
        iterations,
        total_ms: elapsed.as_millis(),
        minimum_us: timings[0],
        median_us: percentile(50),
        p95_us: percentile(95),
        maximum_us: *timings.last().context("missing timing")?,
        declared_memory_limit_bytes: run.declared_memory_limit_bytes,
        fuel_consumed: run.fuel_consumed,
        trace_events: run.trace.events.len(),
        output_sha256: hex::encode(Sha256::digest(run.output.as_bytes())),
        frames: run.media.frames.len(),
        audio_renders: run.media.audio.len(),
        graphics_present_calls: run.media_metrics.graphics_present_calls,
        graphics_present_micros: run.media_metrics.graphics_present_micros,
        audio_render_calls: run.media_metrics.audio_render_calls,
        audio_render_micros: run.media_metrics.audio_render_micros,
    };
    write_private(output, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{kind}: {iterations} iteration(s), p95 {} us -> {}",
        report.p95_us,
        output.display()
    );
    Ok(())
}

fn current_time_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("timestamp overflow")
}

fn hash_bounded_file(path: &Path, limit: u64) -> Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("runtime artifact must be a regular file");
    }
    if metadata.len() > limit {
        bail!("file exceeds the {limit}-byte limit");
    }
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = 0_u64;
    let mut digest = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .context("runtime artifact byte length overflowed")?;
        if bytes > limit {
            bail!("file exceeded the {limit}-byte limit while reading");
        }
        digest.update(&buffer[..read]);
    }
    Ok((bytes, hex::encode(digest.finalize())))
}

fn hex_array(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key has the wrong length"))
}

fn supervised_run_command(options: RunCommandOptions<'_>) -> Result<()> {
    let mut worker_args = vec![
        OsString::from("__worker-run"),
        options.package.as_os_str().to_owned(),
    ];
    push_path_option(&mut worker_args, "--trace", options.trace);
    push_path_option(&mut worker_args, "--state-dir", options.state_dir);
    push_path_option(&mut worker_args, "--from-snapshot", options.from_snapshot);
    push_path_option(
        &mut worker_args,
        "--snapshot-output",
        options.snapshot_output,
    );
    push_path_option(&mut worker_args, "--input", options.input);
    push_path_option(&mut worker_args, "--midi", options.midi);
    push_path_option(&mut worker_args, "--media-dir", options.media_dir);
    push_path_option(&mut worker_args, "--http-fixtures", options.http_fixtures);
    push_path_option(
        &mut worker_args,
        "--storage-signature",
        options.storage_signature,
    );
    push_path_option(&mut worker_args, "--storage-trust", options.storage_trust);
    if options.local_storage_authority {
        worker_args.push(OsString::from("--local-storage-authority"));
    }
    if let Some(permissions) = options.permission_ceiling {
        worker_args.push(OsString::from("--capability-ceiling"));
        worker_args.push(OsString::from(permissions_mask(permissions).to_string()));
    }
    push_worker_arguments(&mut worker_args, options.args);
    supervise_worker(options.package, &worker_args, None)
}

fn supervised_replay_command(
    package: &Path,
    trace: &Path,
    media_dir: Option<&Path>,
    args: &[String],
) -> Result<()> {
    let mut worker_args = vec![
        OsString::from("__worker-replay"),
        package.as_os_str().to_owned(),
        trace.as_os_str().to_owned(),
    ];
    push_path_option(&mut worker_args, "--media-dir", media_dir);
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
    durable_auth: &DurableAuth,
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
    push_path_option(
        &mut worker_args,
        "--storage-signature",
        durable_auth.signature.as_deref(),
    );
    push_path_option(
        &mut worker_args,
        "--storage-trust",
        durable_auth.trust.as_deref(),
    );
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

fn permissions_mask(permissions: &Permissions) -> u16 {
    u16::from(permissions.clock)
        | (u16::from(permissions.random) << 1)
        | (u16::from(permissions.assets) << 2)
        | (u16::from(permissions.storage) << 3)
        | (u16::from(permissions.graphics) << 4)
        | (u16::from(permissions.audio) << 5)
        | (u16::from(permissions.midi) << 6)
        | (u16::from(permissions.http) << 7)
}

fn permissions_from_mask(mask: u16) -> Result<Permissions> {
    if mask & !0xff != 0 {
        bail!("capability ceiling contains unknown bits");
    }
    Ok(Permissions {
        clock: mask & 1 != 0,
        random: mask & (1 << 1) != 0,
        assets: mask & (1 << 2) != 0,
        storage: mask & (1 << 3) != 0,
        graphics: mask & (1 << 4) != 0,
        audio: mask & (1 << 5) != 0,
        midi: mask & (1 << 6) != 0,
        http: mask & (1 << 7) != 0,
    })
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
    let mut command = ContainedCommand::new(executable);
    command
        .args(arguments)
        .env("CARTRIDGE_WORKER", "1")
        .stdout(OutputMode::Inherit)
        .stderr(OutputMode::Inherit);
    let mut worker =
        spawn_contained(&mut command, true).context("could not start the cartridge worker")?;

    loop {
        if let Some(status) = worker.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(anyhow::anyhow!("cartridge worker exited with {status}"));
        }
        if Instant::now() >= deadline {
            worker
                .terminate(TERMINATION_GRACE)
                .context("could not terminate the cartridge worker")?;
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
    install_parent_liveness_watchdog()?;
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

fn resolve_command(
    root_path: &Path,
    candidates: &[PathBuf],
    json: bool,
    lock_output: Option<&Path>,
    locked: Option<&Path>,
) -> Result<()> {
    let root = CartridgeArchive::open(root_path)
        .with_context(|| format!("could not inspect {}", root_path.display()))?;
    let candidates = candidates
        .iter()
        .map(|path| {
            CartridgeArchive::open(path)
                .with_context(|| format!("could not inspect {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let lock = composition_lock(&root, &candidates)?;
    finish_resolution(&lock, json, lock_output, locked)
}

fn composition_lock(
    root: &CartridgeArchive,
    candidates: &[CartridgeArchive],
) -> Result<CompositionLock> {
    let manifests = candidates
        .iter()
        .map(|candidate| candidate.manifest.clone())
        .collect::<Vec<_>>();
    let packages = candidates.iter().map(locked_package).collect::<Vec<_>>();
    let plan = resolve_dependencies(&root.manifest, &manifests)?;
    let mut selected = Vec::with_capacity(plan.resolved.len());
    for dependency in &plan.resolved {
        let package = packages
            .iter()
            .find(|package| {
                package.cartridge_id == dependency.cartridge
                    && package.version == dependency.version
            })
            .context("resolver selected a provider without package identity")?;
        if !selected.iter().any(|selected: &LockedPackage| {
            selected.cartridge_id == package.cartridge_id && selected.version == package.version
        }) {
            selected.push(package.clone());
        }
    }
    CompositionLock::new(locked_package(root), selected, plan).map_err(anyhow::Error::msg)
}

fn finish_resolution(
    lock: &CompositionLock,
    json: bool,
    lock_output: Option<&Path>,
    locked: Option<&Path>,
) -> Result<()> {
    if let Some(path) = locked {
        let expected: CompositionLock = serde_json::from_slice(&read_bounded_json(path)?)?;
        expected.validate().map_err(anyhow::Error::msg)?;
        if &expected != lock {
            bail!("composition lock does not match the current package set");
        }
        println!("verified composition lock {}", path.display());
        return Ok(());
    }
    if let Some(path) = lock_output {
        write_private(path, &serde_json::to_vec_pretty(&lock)?)?;
        println!("locked composition plan -> {}", path.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&lock.plan)?);
    } else {
        print_resolution(&lock.plan);
    }
    Ok(())
}

fn library_resolve_command(
    root: &Path,
    cartridge: &str,
    version: Option<&str>,
    lock_output: Option<&Path>,
    locked: Option<&Path>,
    json: bool,
) -> Result<()> {
    let library = Library::open(root).map_err(anyhow::Error::msg)?;
    let root_record = library
        .catalog_package(cartridge, version)
        .map_err(anyhow::Error::msg)?;
    let root_archive = open_catalog_archive(&root_record)?;
    let dependency_ids = root_archive
        .manifest
        .dependencies
        .iter()
        .map(|dependency| dependency.cartridge.as_str())
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for dependency in dependency_ids {
        let remaining = MAX_RESOLUTION_CANDIDATES.saturating_sub(candidates.len());
        for record in library
            .catalog_versions(dependency, remaining)
            .map_err(anyhow::Error::msg)?
        {
            candidates.push(open_catalog_archive(&record)?);
        }
    }
    let lock = composition_lock(&root_archive, &candidates)?;
    finish_resolution(&lock, json, lock_output, locked)
}

fn open_catalog_archive(record: &CatalogPackage) -> Result<CartridgeArchive> {
    let archive = CartridgeArchive::open(&record.path)
        .with_context(|| format!("could not inspect {}", record.path.display()))?;
    if archive.manifest.cartridge.id != record.cartridge_id
        || archive.manifest.cartridge.version != record.version
        || archive.package_sha256 != record.package_sha256
        || archive.package_bytes != record.package_bytes
    {
        bail!("installed package changed after catalog verification");
    }
    Ok(archive)
}

fn locked_package(archive: &CartridgeArchive) -> LockedPackage {
    LockedPackage {
        cartridge_id: archive.manifest.cartridge.id.clone(),
        version: archive.manifest.cartridge.version.clone(),
        package_sha256: archive.package_sha256.clone(),
        package_bytes: archive.package_bytes,
        component_sha256: archive
            .manifest
            .integrity
            .component_sha256
            .to_ascii_lowercase(),
        assets_root_sha256: archive
            .manifest
            .integrity
            .assets_root_sha256
            .to_ascii_lowercase(),
    }
}

fn read_bounded_json(path: &Path) -> Result<Vec<u8>> {
    const LIMIT: u64 = 1024 * 1024;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > LIMIT {
        bail!("composition lock is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("composition lock exceeded its byte limit while reading");
    }
    Ok(bytes)
}

fn run_command(options: RunCommandOptions<'_>) -> Result<()> {
    let input: Vec<InputEvent> = read_optional_event_file(options.input, "input")?;
    let midi: Vec<MidiEvent> = read_optional_event_file(options.midi, "MIDI")?;
    let mut branch = None;
    let report = if let Some(path) = options.from_snapshot {
        let archive = CartridgeArchive::open(options.package)
            .with_context(|| format!("could not inspect {}", options.package.display()))?;
        let snapshot = StorageSnapshot::read(path)
            .with_context(|| format!("could not read snapshot {}", path.display()))?;
        let storage = Arc::new(SnapshotStorage::from_snapshot(
            &snapshot,
            &archive.manifest.cartridge.id,
            storage_limits(&archive.manifest),
        )?);
        let runtime = configure_http(
            Runtime::with_storage(storage.clone())?
                .with_media_input(input.clone(), midi.clone())?,
            options.http_fixtures,
        )?;
        let runtime = apply_permission_ceiling(runtime, options.permission_ceiling);
        branch = Some(storage);
        runtime.run(archive, options.args)?
    } else {
        let runtime = match options.state_dir {
            Some(path) => Runtime::with_storage(Arc::new(DirectoryStorage::open(path)?))?,
            None => Runtime::new()?,
        }
        .with_media_input(input, midi)?;
        let runtime = configure_http(runtime, options.http_fixtures)?;
        let runtime = apply_permission_ceiling(runtime, options.permission_ceiling);
        runtime.run_file(options.package, options.args)?
    };
    println!("{}", terminal_safe(&report.output));
    eprintln!("fuel consumed: {}", report.fuel_consumed);
    if let Some(path) = options.media_dir {
        write_media_artifacts(path, &report.media)?;
        eprintln!(
            "media: {} frame(s), {} audio render(s) -> {}",
            report.media.frames.len(),
            report.media.audio.len(),
            path.display()
        );
    }
    if let Some(path) = options.trace {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private(path, &serde_json::to_vec_pretty(&report.trace)?)?;
        eprintln!("trace: {}", path.display());
    }
    if let Some(path) = options.snapshot_output {
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

fn configure_http(runtime: Runtime, fixtures: Option<&Path>) -> Result<Runtime> {
    let Some(path) = fixtures else {
        return Ok(runtime);
    };
    Ok(runtime.with_http_transport(Arc::new(
        HttpFixtures::read(path).map_err(anyhow::Error::msg)?,
    )))
}

fn apply_permission_ceiling(runtime: Runtime, ceiling: Option<&Permissions>) -> Runtime {
    match ceiling {
        Some(permissions) => runtime.with_permission_ceiling(permissions.clone()),
        None => runtime,
    }
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
                "state_revision": summary.state_revision,
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
        println!("state revision: {}", summary.state_revision);
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
        println!("state revision: {}", summary.state_revision);
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
            SnapshotDifference::Revision { left, right } => {
                println!("state revision differs");
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
    let migration_summary = report.snapshot.summary()?;
    let source_summary = source.snapshot().summary()?;
    let target_generation = source
        .generation()
        .max(migration_summary.state_revision)
        .checked_add(1)
        .context("durable generation overflowed")?;
    let committed_snapshot = report.snapshot.with_state_revision(target_generation)?;
    let summary = committed_snapshot.summary()?;
    let receipt = MigrationReceipt::new(MigrationReceiptPayload {
        format_version: 0,
        cartridge_id: cartridge_id.clone(),
        package_version: report.plan.cartridge_version.clone(),
        component_sha256: report.plan.component_sha256.to_ascii_lowercase(),
        source_generation: source.generation(),
        target_generation,
        migration_revision: migration_summary.state_revision,
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
    let snapshot_format = if payload.format_version == 1 {
        2
    } else {
        current_summary.format_version
    };
    let target_matches = evidence.requested().is_some_and(|captured| {
        captured.generation() == payload.target_generation
            && captured.snapshot().state_schema() == payload.target_schema
            && captured
                .snapshot()
                .payload_sha256_for_format(snapshot_format)
                .is_ok_and(|digest| digest == payload.target_snapshot_sha256)
    });
    let source_matches = current.generation() == payload.source_generation
        && current_summary.state_schema == payload.source_schema
        && current
            .snapshot()
            .payload_sha256_for_format(snapshot_format)?
            == payload.source_snapshot_sha256;
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

fn replay_command(
    package: &Path,
    trace: &Path,
    media_dir: Option<&Path>,
    args: &[String],
) -> Result<()> {
    let trace = read_trace(trace)?;
    let event_count = trace.events.len();
    let report = Runtime::new()?.replay_file(package, args, trace)?;
    println!("{}", terminal_safe(&report.output));
    eprintln!(
        "replay matched {event_count} event(s), {} fuel",
        report.fuel_consumed
    );
    if let Some(path) = media_dir {
        write_media_artifacts(path, &report.media)?;
        eprintln!(
            "media: {} frame(s), {} audio render(s) -> {}",
            report.media.frames.len(),
            report.media.audio.len(),
            path.display()
        );
    }
    Ok(())
}

fn read_optional_event_file<T>(path: Option<&Path>, label: &str) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("could not open {label} events {}", path.display()))?
        .take(MAX_EVENT_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EVENT_DOCUMENT_BYTES {
        bail!("{label} event document exceeds {MAX_EVENT_DOCUMENT_BYTES} bytes");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("could not parse {label} events {}", path.display()))
}

fn write_media_artifacts(directory: &Path, media: &MediaArtifacts) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("could not create media directory {}", directory.display()))?;
    let mut frames = Vec::with_capacity(media.frames.len());
    for (index, frame) in media.frames.iter().enumerate() {
        let name = format!("frame-{index:04}-window-{}.png", frame.receipt.window);
        write_private(&directory.join(&name), &frame.png)?;
        frames.push(serde_json::json!({ "file": name, "receipt": frame.receipt }));
    }
    let mut audio = Vec::with_capacity(media.audio.len());
    for (index, render) in media.audio.iter().enumerate() {
        let name = format!("audio-{index:04}.wav");
        write_private(&directory.join(&name), &render.wav)?;
        audio.push(serde_json::json!({ "file": name, "receipt": render.receipt }));
    }
    let report = serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1,
        "frames": frames,
        "audio": audio,
    }))?;
    write_private(&directory.join("media-report.json"), &report)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_gc_uses_snapshot_reachability_roots() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("blobs");
        let retained_input = directory.path().join("retained.bin");
        let removable_input = directory.path().join("removable.bin");
        fs::write(&retained_input, b"retained").unwrap();
        fs::write(&removable_input, b"removable").unwrap();
        let store = BlobStore::open(&store_path).unwrap();
        let retained = store.put(&retained_input).unwrap();
        let removable = store.put(&removable_input).unwrap();

        let source = StorageSnapshot::from_slice(include_bytes!(
            "../../cartridge-storage/tests/fixtures/snapshot-v2.json"
        ))
        .unwrap();
        let limits = StorageLimits {
            max_bytes: 1024,
            max_keys: 8,
            max_value_bytes: 512,
        };
        let branch =
            SnapshotStorage::from_snapshot(&source, source.cartridge_id(), limits).unwrap();
        let reference =
            cartridge_runtime::BlobReference::new(retained.sha256.clone(), retained.bytes)
                .unwrap()
                .encode()
                .unwrap();
        cartridge_runtime::StorageBackend::put(
            &branch,
            source.cartridge_id(),
            "blobs/retained",
            &reference,
            limits,
        )
        .unwrap();
        let snapshot_path = directory.path().join("state.json");
        branch
            .export_snapshot()
            .unwrap()
            .write_new(&snapshot_path)
            .unwrap();

        let manifest_path = directory.path().join("roots.json");
        let (sources, references) =
            collect_blob_reachability(vec![snapshot_path], Vec::new()).unwrap();
        BlobReachabilityManifest::new(sources, references)
            .unwrap()
            .write_new(&manifest_path)
            .unwrap();
        run_blob_command(BlobCommand::Gc {
            store: store_path.clone(),
            keep: Vec::new(),
            snapshot: Vec::new(),
            capsule: Vec::new(),
            manifest: vec![manifest_path],
            apply: true,
            json: true,
        })
        .unwrap();
        run_blob_command(BlobCommand::List {
            store: store_path.clone(),
            json: true,
        })
        .unwrap();
        run_blob_command(BlobCommand::Audit {
            store: store_path,
            json: true,
        })
        .unwrap();

        store.verify(&retained.sha256).unwrap();
        assert!(store.verify(&removable.sha256).is_err());
    }
}

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use cartridge_core::CartridgeArchive;
use cartridge_runtime::StorageSnapshot;
use cartridge_trace::{ExecutionTrace, MAX_TRACE_DOCUMENT_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CAPSULE_FORMAT_VERSION: u32 = 1;
const MAX_CAPSULE_BYTES: u64 = 128 * 1024;
const MAX_PACKAGE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 144 * 1024 * 1024;
const MAX_ARTIFACT_PATH_BYTES: usize = 512;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_STORAGE_KEYS: usize = 100_000;
const MAX_STORAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOB_REFERENCES: usize = 100_000;

static CAPSULE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {
    payload: CapsulePayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapsulePayload {
    format_version: u32,
    cartridge_id: String,
    cartridge_version: String,
    component_sha256: String,
    runtime_version: String,
    argument_count: usize,
    argument_bytes: usize,
    arguments_sha256: String,
    package: ArtifactReference,
    source_snapshot: SnapshotReference,
    trace: TraceReference,
    result_snapshot: SnapshotReference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReference {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotReference {
    artifact: ArtifactReference,
    state_schema: u32,
    entries: usize,
    bytes: usize,
    payload_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TraceReference {
    artifact: ArtifactReference,
    format_version: u32,
    event_count: usize,
    output_bytes: usize,
    output_sha256: String,
    fuel_consumed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapsuleSummary {
    pub format_version: u32,
    pub cartridge_id: String,
    pub cartridge_version: String,
    pub component_sha256: String,
    pub runtime_version: String,
    pub argument_count: usize,
    pub argument_bytes: usize,
    pub arguments_sha256: String,
    pub source_schema: u32,
    pub source_entries: usize,
    pub source_bytes: usize,
    pub source_snapshot_sha256: String,
    pub result_schema: u32,
    pub result_entries: usize,
    pub result_bytes: usize,
    pub result_snapshot_sha256: String,
    pub trace_events: usize,
    pub trace_output_bytes: usize,
    pub trace_output_sha256: String,
    pub fuel_consumed: u64,
    pub capsule_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapsuleVerification {
    pub valid: bool,
    pub capsule: CapsuleSummary,
    pub package_path: String,
    pub source_snapshot_path: String,
    pub trace_path: String,
    pub result_snapshot_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapsuleComparison {
    pub identical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difference: Option<CapsuleDifference>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CapsuleDifference {
    Field {
        field: String,
        left: Value,
        right: Value,
    },
}

#[derive(Debug)]
pub struct CapsuleReplayInputs {
    pub package_path: PathBuf,
    pub package: CartridgeArchive,
    pub trace: ExecutionTrace,
    pub source: StorageSnapshot,
    pub arguments: Vec<String>,
    pub summary: CapsuleSummary,
}

pub fn create(
    package_path: &Path,
    source_path: &Path,
    trace_path: &Path,
    result_path: &Path,
    output: &Path,
) -> Result<CapsuleSummary> {
    let directory = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    let root = fs::canonicalize(directory)?;
    let package = CartridgeArchive::open(package_path)
        .with_context(|| format!("could not inspect package {}", package_path.display()))?;
    let source = StorageSnapshot::read(source_path).with_context(|| {
        format!(
            "could not inspect source snapshot {}",
            source_path.display()
        )
    })?;
    let trace = read_trace(trace_path)?;
    let result = StorageSnapshot::read(result_path).with_context(|| {
        format!(
            "could not inspect result snapshot {}",
            result_path.display()
        )
    })?;

    validate_identity(&package, &source, &trace, &result)?;
    let source_summary = source.summary()?;
    let result_summary = result.summary()?;
    let trace_summary = trace.summary();
    let argument_bytes = trace.args.iter().try_fold(0usize, |total, argument| {
        total
            .checked_add(argument.len())
            .context("capsule argument size overflowed")
    })?;
    let payload = CapsulePayload {
        format_version: CAPSULE_FORMAT_VERSION,
        cartridge_id: package.manifest.cartridge.id.clone(),
        cartridge_version: package.manifest.cartridge.version.clone(),
        component_sha256: package
            .manifest
            .integrity
            .component_sha256
            .to_ascii_lowercase(),
        runtime_version: trace.runtime_version.clone(),
        argument_count: trace.args.len(),
        argument_bytes,
        arguments_sha256: digest_bytes(&serde_json::to_vec(&trace.args)?),
        package: artifact_reference(&root, package_path, MAX_PACKAGE_FILE_BYTES)?,
        source_snapshot: SnapshotReference {
            artifact: artifact_reference(&root, source_path, MAX_SNAPSHOT_FILE_BYTES)?,
            state_schema: source_summary.state_schema,
            entries: source_summary.entries,
            bytes: source_summary.bytes,
            payload_sha256: source_summary.payload_sha256,
        },
        trace: TraceReference {
            artifact: artifact_reference(&root, trace_path, MAX_TRACE_DOCUMENT_BYTES)?,
            format_version: trace_summary.format_version,
            event_count: trace_summary.event_count,
            output_bytes: trace.result.output.len(),
            output_sha256: digest_bytes(trace.result.output.as_bytes()),
            fuel_consumed: trace.result.fuel_consumed,
        },
        result_snapshot: SnapshotReference {
            artifact: artifact_reference(&root, result_path, MAX_SNAPSHOT_FILE_BYTES)?,
            state_schema: result_summary.state_schema,
            entries: result_summary.entries,
            bytes: result_summary.bytes,
            payload_sha256: result_summary.payload_sha256,
        },
    };
    let capsule = Capsule::new(payload)?;
    capsule.write_new(output)?;
    Ok(verify(output)?.capsule)
}

pub fn inspect(path: &Path) -> Result<CapsuleSummary> {
    Ok(Capsule::read(path)?.summary())
}

pub fn compare(left: &Path, right: &Path) -> Result<CapsuleComparison> {
    let left = Capsule::read(left)?;
    let right = Capsule::read(right)?;
    Ok(compare_capsules(&left, &right))
}

pub fn verify(path: &Path) -> Result<CapsuleVerification> {
    let capsule = Capsule::read(path)?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = fs::canonicalize(directory)?;
    let payload = &capsule.payload;
    let package_path = verify_artifact(&root, &payload.package, MAX_PACKAGE_FILE_BYTES)?;
    let source_path = verify_artifact(
        &root,
        &payload.source_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;
    let trace_path = verify_artifact(&root, &payload.trace.artifact, MAX_TRACE_DOCUMENT_BYTES)?;
    let result_path = verify_artifact(
        &root,
        &payload.result_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;
    let package = CartridgeArchive::open(&package_path)?;
    let source = StorageSnapshot::read(&source_path)?;
    let trace = read_trace(&trace_path)?;
    let result = StorageSnapshot::read(&result_path)?;
    validate_identity(&package, &source, &trace, &result)?;
    verify_semantics(payload, &package, &source, &trace, &result)?;
    verify_artifact(&root, &payload.package, MAX_PACKAGE_FILE_BYTES)?;
    verify_artifact(
        &root,
        &payload.source_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;
    verify_artifact(&root, &payload.trace.artifact, MAX_TRACE_DOCUMENT_BYTES)?;
    verify_artifact(
        &root,
        &payload.result_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;

    Ok(CapsuleVerification {
        valid: true,
        capsule: capsule.summary(),
        package_path: payload.package.path.clone(),
        source_snapshot_path: payload.source_snapshot.artifact.path.clone(),
        trace_path: payload.trace.artifact.path.clone(),
        result_snapshot_path: payload.result_snapshot.artifact.path.clone(),
    })
}

pub fn blob_references(path: &Path) -> Result<BTreeMap<String, u64>> {
    let initial = verify(path)?;
    let capsule = Capsule::read(path)?;
    if capsule.payload_sha256 != initial.capsule.capsule_sha256 {
        bail!("capsule changed while blob references were being loaded");
    }
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = fs::canonicalize(directory)?;
    let source = read_verified_snapshot(&root, &capsule.payload.source_snapshot)?;
    let result = read_verified_snapshot(&root, &capsule.payload.result_snapshot)?;
    let mut references = source.blob_references()?;
    merge_blob_references(&mut references, result.blob_references()?)?;

    let final_verification = verify(path)?;
    if final_verification.capsule.capsule_sha256 != initial.capsule.capsule_sha256 {
        bail!("capsule changed while blob references were being loaded");
    }
    Ok(references)
}

pub fn replay_inputs(path: &Path) -> Result<CapsuleReplayInputs> {
    let initial = verify(path)?;
    let expected_capsule_sha256 = initial.capsule.capsule_sha256.clone();
    let capsule = Capsule::read(path)?;
    if capsule.payload_sha256 != expected_capsule_sha256 {
        bail!("capsule changed while replay inputs were being loaded");
    }
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = fs::canonicalize(directory)?;
    let package_path = verify_artifact(&root, &capsule.payload.package, MAX_PACKAGE_FILE_BYTES)?;
    let package = CartridgeArchive::open(&package_path)?;
    verify_artifact(&root, &capsule.payload.package, MAX_PACKAGE_FILE_BYTES)?;
    let source_path = verify_artifact(
        &root,
        &capsule.payload.source_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;
    let source = StorageSnapshot::read(&source_path)?;
    verify_artifact(
        &root,
        &capsule.payload.source_snapshot.artifact,
        MAX_SNAPSHOT_FILE_BYTES,
    )?;
    let trace_path = verify_artifact(
        &root,
        &capsule.payload.trace.artifact,
        MAX_TRACE_DOCUMENT_BYTES,
    )?;
    let trace = read_trace(&trace_path)?;
    verify_artifact(
        &root,
        &capsule.payload.trace.artifact,
        MAX_TRACE_DOCUMENT_BYTES,
    )?;
    let final_verification = verify(path)?;
    if final_verification.capsule.capsule_sha256 != expected_capsule_sha256 {
        bail!("capsule changed while replay inputs were being loaded");
    }
    let arguments = trace.args.clone();
    Ok(CapsuleReplayInputs {
        package_path,
        package,
        trace,
        source,
        arguments,
        summary: capsule.summary(),
    })
}

impl Capsule {
    fn new(payload: CapsulePayload) -> Result<Self> {
        let payload_sha256 = payload_digest(&payload)?;
        let capsule = Self {
            payload,
            payload_sha256,
        };
        capsule.validate()?;
        Ok(capsule)
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = read_bounded(path, MAX_CAPSULE_BYTES)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAPSULE_BYTES {
            bail!(
                "capsule {} exceeds the {} byte input limit",
                path.display(),
                MAX_CAPSULE_BYTES
            );
        }
        Self::from_slice(&bytes)
    }

    fn from_slice(bytes: &[u8]) -> Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAPSULE_BYTES {
            bail!("capsule exceeds the {MAX_CAPSULE_BYTES} byte input limit");
        }
        let capsule: Self = serde_json::from_slice(bytes).context("invalid capsule")?;
        capsule.validate()?;
        Ok(capsule)
    }

    fn validate(&self) -> Result<()> {
        let payload = &self.payload;
        if payload.format_version != CAPSULE_FORMAT_VERSION {
            bail!(
                "unsupported capsule format {}; expected {CAPSULE_FORMAT_VERSION}",
                payload.format_version
            );
        }
        if !valid_label(&payload.cartridge_id, 128)
            || !valid_label(&payload.cartridge_version, 64)
            || !valid_label(&payload.runtime_version, 128)
            || !valid_sha256(&payload.component_sha256)
            || !valid_sha256(&payload.arguments_sha256)
            || !valid_sha256(&payload.source_snapshot.payload_sha256)
            || !valid_sha256(&payload.trace.output_sha256)
            || !valid_sha256(&payload.result_snapshot.payload_sha256)
        {
            bail!("capsule contains invalid identity or digest metadata");
        }
        validate_artifact(&payload.package, MAX_PACKAGE_FILE_BYTES)?;
        validate_artifact(&payload.source_snapshot.artifact, MAX_SNAPSHOT_FILE_BYTES)?;
        validate_artifact(&payload.trace.artifact, MAX_TRACE_DOCUMENT_BYTES)?;
        validate_artifact(&payload.result_snapshot.artifact, MAX_SNAPSHOT_FILE_BYTES)?;
        if payload.argument_count > MAX_ARGUMENTS
            || payload.argument_bytes > MAX_ARGUMENT_BYTES
            || payload.trace.event_count > MAX_EVENTS
            || payload.trace.output_bytes > MAX_OUTPUT_BYTES
            || payload.source_snapshot.entries > MAX_STORAGE_KEYS
            || payload.result_snapshot.entries > MAX_STORAGE_KEYS
            || payload.source_snapshot.bytes > MAX_STORAGE_BYTES
            || payload.result_snapshot.bytes > MAX_STORAGE_BYTES
        {
            bail!("capsule summary metadata exceeds its resource limits");
        }
        if payload.source_snapshot.state_schema != payload.result_snapshot.state_schema {
            bail!("capsule source and result snapshots use different schemas");
        }
        if self.payload_sha256 != payload_digest(payload)? {
            bail!("capsule payload digest does not match its contents");
        }
        Ok(())
    }

    fn write_new(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAPSULE_BYTES {
            bail!("capsule exceeds the {MAX_CAPSULE_BYTES} byte output limit");
        }
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(directory)?;
        let temporary = temporary_path(directory);
        let mut file = open_private_new(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        fs::remove_file(temporary)?;
        sync_directory(directory)?;
        Ok(())
    }

    fn summary(&self) -> CapsuleSummary {
        let payload = &self.payload;
        CapsuleSummary {
            format_version: payload.format_version,
            cartridge_id: payload.cartridge_id.clone(),
            cartridge_version: payload.cartridge_version.clone(),
            component_sha256: payload.component_sha256.clone(),
            runtime_version: payload.runtime_version.clone(),
            argument_count: payload.argument_count,
            argument_bytes: payload.argument_bytes,
            arguments_sha256: payload.arguments_sha256.clone(),
            source_schema: payload.source_snapshot.state_schema,
            source_entries: payload.source_snapshot.entries,
            source_bytes: payload.source_snapshot.bytes,
            source_snapshot_sha256: payload.source_snapshot.payload_sha256.clone(),
            result_schema: payload.result_snapshot.state_schema,
            result_entries: payload.result_snapshot.entries,
            result_bytes: payload.result_snapshot.bytes,
            result_snapshot_sha256: payload.result_snapshot.payload_sha256.clone(),
            trace_events: payload.trace.event_count,
            trace_output_bytes: payload.trace.output_bytes,
            trace_output_sha256: payload.trace.output_sha256.clone(),
            fuel_consumed: payload.trace.fuel_consumed,
            capsule_sha256: self.payload_sha256.clone(),
        }
    }
}

fn compare_capsules(left: &Capsule, right: &Capsule) -> CapsuleComparison {
    let left = &left.payload;
    let right = &right.payload;
    let difference = compare_identity(left, right)
        .or_else(|| compare_package(left, right))
        .or_else(|| compare_source(left, right))
        .or_else(|| compare_trace(left, right))
        .or_else(|| compare_result(left, right));
    CapsuleComparison {
        identical: difference.is_none(),
        difference,
    }
}

fn first_difference<const N: usize>(
    fields: [(&str, Value, Value); N],
) -> Option<CapsuleDifference> {
    fields
        .into_iter()
        .find(|(_, left, right)| left != right)
        .map(|(field, left, right)| CapsuleDifference::Field {
            field: field.into(),
            left,
            right,
        })
}

fn compare_identity(left: &CapsulePayload, right: &CapsulePayload) -> Option<CapsuleDifference> {
    first_difference([
        (
            "format_version",
            serde_json::json!(left.format_version),
            serde_json::json!(right.format_version),
        ),
        (
            "cartridge_id",
            serde_json::json!(left.cartridge_id),
            serde_json::json!(right.cartridge_id),
        ),
        (
            "cartridge_version",
            serde_json::json!(left.cartridge_version),
            serde_json::json!(right.cartridge_version),
        ),
        (
            "component_sha256",
            serde_json::json!(left.component_sha256),
            serde_json::json!(right.component_sha256),
        ),
        (
            "runtime_version",
            serde_json::json!(left.runtime_version),
            serde_json::json!(right.runtime_version),
        ),
        (
            "argument_count",
            serde_json::json!(left.argument_count),
            serde_json::json!(right.argument_count),
        ),
        (
            "argument_bytes",
            serde_json::json!(left.argument_bytes),
            serde_json::json!(right.argument_bytes),
        ),
        (
            "arguments_sha256",
            serde_json::json!(left.arguments_sha256),
            serde_json::json!(right.arguments_sha256),
        ),
    ])
}

fn compare_package(left: &CapsulePayload, right: &CapsulePayload) -> Option<CapsuleDifference> {
    first_difference([
        (
            "package.bytes",
            serde_json::json!(left.package.bytes),
            serde_json::json!(right.package.bytes),
        ),
        (
            "package.sha256",
            serde_json::json!(left.package.sha256),
            serde_json::json!(right.package.sha256),
        ),
    ])
}

fn compare_source(left: &CapsulePayload, right: &CapsulePayload) -> Option<CapsuleDifference> {
    first_difference([
        (
            "source.state_schema",
            serde_json::json!(left.source_snapshot.state_schema),
            serde_json::json!(right.source_snapshot.state_schema),
        ),
        (
            "source.entries",
            serde_json::json!(left.source_snapshot.entries),
            serde_json::json!(right.source_snapshot.entries),
        ),
        (
            "source.bytes",
            serde_json::json!(left.source_snapshot.bytes),
            serde_json::json!(right.source_snapshot.bytes),
        ),
        (
            "source.payload_sha256",
            serde_json::json!(left.source_snapshot.payload_sha256),
            serde_json::json!(right.source_snapshot.payload_sha256),
        ),
        (
            "source.file_bytes",
            serde_json::json!(left.source_snapshot.artifact.bytes),
            serde_json::json!(right.source_snapshot.artifact.bytes),
        ),
        (
            "source.file_sha256",
            serde_json::json!(left.source_snapshot.artifact.sha256),
            serde_json::json!(right.source_snapshot.artifact.sha256),
        ),
    ])
}

fn compare_trace(left: &CapsulePayload, right: &CapsulePayload) -> Option<CapsuleDifference> {
    first_difference([
        (
            "trace.format_version",
            serde_json::json!(left.trace.format_version),
            serde_json::json!(right.trace.format_version),
        ),
        (
            "trace.event_count",
            serde_json::json!(left.trace.event_count),
            serde_json::json!(right.trace.event_count),
        ),
        (
            "trace.output_bytes",
            serde_json::json!(left.trace.output_bytes),
            serde_json::json!(right.trace.output_bytes),
        ),
        (
            "trace.output_sha256",
            serde_json::json!(left.trace.output_sha256),
            serde_json::json!(right.trace.output_sha256),
        ),
        (
            "trace.fuel_consumed",
            serde_json::json!(left.trace.fuel_consumed),
            serde_json::json!(right.trace.fuel_consumed),
        ),
        (
            "trace.file_bytes",
            serde_json::json!(left.trace.artifact.bytes),
            serde_json::json!(right.trace.artifact.bytes),
        ),
        (
            "trace.file_sha256",
            serde_json::json!(left.trace.artifact.sha256),
            serde_json::json!(right.trace.artifact.sha256),
        ),
    ])
}

fn compare_result(left: &CapsulePayload, right: &CapsulePayload) -> Option<CapsuleDifference> {
    first_difference([
        (
            "result.state_schema",
            serde_json::json!(left.result_snapshot.state_schema),
            serde_json::json!(right.result_snapshot.state_schema),
        ),
        (
            "result.entries",
            serde_json::json!(left.result_snapshot.entries),
            serde_json::json!(right.result_snapshot.entries),
        ),
        (
            "result.bytes",
            serde_json::json!(left.result_snapshot.bytes),
            serde_json::json!(right.result_snapshot.bytes),
        ),
        (
            "result.payload_sha256",
            serde_json::json!(left.result_snapshot.payload_sha256),
            serde_json::json!(right.result_snapshot.payload_sha256),
        ),
        (
            "result.file_bytes",
            serde_json::json!(left.result_snapshot.artifact.bytes),
            serde_json::json!(right.result_snapshot.artifact.bytes),
        ),
        (
            "result.file_sha256",
            serde_json::json!(left.result_snapshot.artifact.sha256),
            serde_json::json!(right.result_snapshot.artifact.sha256),
        ),
    ])
}

fn validate_identity(
    package: &CartridgeArchive,
    source: &StorageSnapshot,
    trace: &ExecutionTrace,
    result: &StorageSnapshot,
) -> Result<()> {
    trace.validate()?;
    let manifest = &package.manifest;
    if source.cartridge_id() != manifest.cartridge.id
        || result.cartridge_id() != manifest.cartridge.id
        || trace.cartridge_id != manifest.cartridge.id
        || trace.cartridge_version != manifest.cartridge.version
        || !trace
            .component_sha256
            .eq_ignore_ascii_case(&manifest.integrity.component_sha256)
    {
        bail!("capsule artifacts do not share one exact package identity");
    }
    if source.state_schema() != result.state_schema()
        || source.state_schema() != manifest.state.schema
    {
        bail!("capsule snapshots do not use the package state schema");
    }
    Ok(())
}

fn verify_semantics(
    payload: &CapsulePayload,
    package: &CartridgeArchive,
    source: &StorageSnapshot,
    trace: &ExecutionTrace,
    result: &StorageSnapshot,
) -> Result<()> {
    let source_summary = source.summary()?;
    let result_summary = result.summary()?;
    let trace_summary = trace.summary();
    let argument_bytes = trace.args.iter().try_fold(0usize, |total, argument| {
        total
            .checked_add(argument.len())
            .context("capsule argument size overflowed")
    })?;
    let matches = payload.cartridge_id == package.manifest.cartridge.id
        && payload.cartridge_version == package.manifest.cartridge.version
        && payload
            .component_sha256
            .eq_ignore_ascii_case(&package.manifest.integrity.component_sha256)
        && payload.runtime_version == trace.runtime_version
        && payload.argument_count == trace.args.len()
        && payload.argument_bytes == argument_bytes
        && payload.arguments_sha256 == digest_bytes(&serde_json::to_vec(&trace.args)?)
        && payload.source_snapshot.state_schema == source_summary.state_schema
        && payload.source_snapshot.entries == source_summary.entries
        && payload.source_snapshot.bytes == source_summary.bytes
        && payload.source_snapshot.payload_sha256 == source_summary.payload_sha256
        && payload.trace.format_version == trace_summary.format_version
        && payload.trace.event_count == trace_summary.event_count
        && payload.trace.output_bytes == trace.result.output.len()
        && payload.trace.output_sha256 == digest_bytes(trace.result.output.as_bytes())
        && payload.trace.fuel_consumed == trace.result.fuel_consumed
        && payload.result_snapshot.state_schema == result_summary.state_schema
        && payload.result_snapshot.entries == result_summary.entries
        && payload.result_snapshot.bytes == result_summary.bytes
        && payload.result_snapshot.payload_sha256 == result_summary.payload_sha256;
    if !matches {
        bail!("capsule metadata does not match its referenced artifacts");
    }
    Ok(())
}

fn read_trace(path: &Path) -> Result<ExecutionTrace> {
    let bytes = read_bounded(path, MAX_TRACE_DOCUMENT_BYTES)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRACE_DOCUMENT_BYTES {
        bail!(
            "trace {} exceeds the {} byte input limit",
            path.display(),
            MAX_TRACE_DOCUMENT_BYTES
        );
    }
    let trace: ExecutionTrace = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid trace {}", path.display()))?;
    trace.validate()?;
    Ok(trace)
}

fn artifact_reference(root: &Path, path: &Path, limit: u64) -> Result<ArtifactReference> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("could not resolve artifact {}", path.display()))?;
    let relative = canonical.strip_prefix(root).with_context(|| {
        format!(
            "artifact {} must be inside capsule directory {}",
            path.display(),
            root.display()
        )
    })?;
    let path = portable_path(relative)?;
    let (bytes, sha256) = hash_file(&canonical, limit)?;
    let artifact = ArtifactReference {
        path,
        bytes,
        sha256,
    };
    validate_artifact(&artifact, limit)?;
    Ok(artifact)
}

fn verify_artifact(root: &Path, artifact: &ArtifactReference, limit: u64) -> Result<PathBuf> {
    validate_artifact(artifact, limit)?;
    let joined = root.join(path_from_portable(&artifact.path)?);
    let canonical = fs::canonicalize(&joined)
        .with_context(|| format!("could not resolve capsule artifact {}", artifact.path))?;
    if !canonical.starts_with(root) {
        bail!("capsule artifact {} escapes its directory", artifact.path);
    }
    let (bytes, sha256) = hash_file(&canonical, limit)?;
    if bytes != artifact.bytes || sha256 != artifact.sha256 {
        bail!(
            "capsule artifact {} does not match its digest",
            artifact.path
        );
    }
    Ok(canonical)
}

fn read_verified_snapshot(root: &Path, reference: &SnapshotReference) -> Result<StorageSnapshot> {
    validate_artifact(&reference.artifact, MAX_SNAPSHOT_FILE_BYTES)?;
    let joined = root.join(path_from_portable(&reference.artifact.path)?);
    let canonical = fs::canonicalize(&joined).with_context(|| {
        format!(
            "could not resolve capsule artifact {}",
            reference.artifact.path
        )
    })?;
    if !canonical.starts_with(root) {
        bail!(
            "capsule artifact {} escapes its directory",
            reference.artifact.path
        );
    }
    let bytes = read_bounded(&canonical, MAX_SNAPSHOT_FILE_BYTES)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.artifact.bytes
        || digest_bytes(&bytes) != reference.artifact.sha256
    {
        bail!(
            "capsule artifact {} does not match its digest",
            reference.artifact.path
        );
    }
    let snapshot = StorageSnapshot::from_slice(&bytes)?;
    let summary = snapshot.summary()?;
    if summary.state_schema != reference.state_schema
        || summary.entries != reference.entries
        || summary.bytes != reference.bytes
        || summary.payload_sha256 != reference.payload_sha256
    {
        bail!(
            "capsule snapshot {} does not match its metadata",
            reference.artifact.path
        );
    }
    Ok(snapshot)
}

fn merge_blob_references(
    target: &mut BTreeMap<String, u64>,
    source: BTreeMap<String, u64>,
) -> Result<()> {
    for (sha256, bytes) in source {
        match target.insert(sha256.clone(), bytes) {
            Some(existing) if existing != bytes => {
                bail!("capsule has conflicting sizes for blob {sha256}");
            }
            _ => {}
        }
        if target.len() > MAX_BLOB_REFERENCES {
            bail!("capsule exceeds the {MAX_BLOB_REFERENCES}-reference limit");
        }
    }
    Ok(())
}

fn validate_artifact(artifact: &ArtifactReference, limit: u64) -> Result<()> {
    if artifact.path.is_empty()
        || artifact.path.len() > MAX_ARTIFACT_PATH_BYTES
        || artifact.bytes > limit
        || !valid_sha256(&artifact.sha256)
    {
        bail!("capsule contains invalid artifact metadata");
    }
    let _ = path_from_portable(&artifact.path)?;
    Ok(())
}

fn portable_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            bail!("capsule artifact path is not portable");
        };
        let part = part
            .to_str()
            .context("capsule artifact path is not valid Unicode")?;
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(['/', '\\'])
            || part.chars().any(char::is_control)
        {
            bail!("capsule artifact path is not portable");
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("capsule artifact path is empty");
    }
    Ok(parts.join("/"))
}

fn path_from_portable(value: &str) -> Result<PathBuf> {
    if value.starts_with('/') || value.contains('\\') {
        bail!("capsule artifact path is not a safe relative path");
    }
    let mut path = PathBuf::new();
    for part in value.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(':')
            || part.chars().any(char::is_control)
        {
            bail!("capsule artifact path is not a safe relative path");
        }
        path.push(part);
    }
    Ok(path)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("could not open artifact {}", path.display()))?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read artifact {}", path.display()))?;
    Ok(bytes)
}

fn hash_file(path: &Path, limit: u64) -> Result<(u64, String)> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        bail!("artifact {} exceeds its file limit", path.display());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .context("artifact size overflowed")?;
        if total > limit {
            bail!("artifact {} exceeds its file limit", path.display());
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

fn valid_label(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn payload_digest(payload: &CapsulePayload) -> Result<String> {
    Ok(digest_bytes(&serde_json::to_vec(payload)?))
}

fn temporary_path(directory: &Path) -> PathBuf {
    let sequence = CAPSULE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".cartridge-capsule-{}-{sequence}.tmp",
        std::process::id()
    ))
}

fn open_private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(directory: &Path) -> Result<()> {
    let _ = fs::metadata(directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule() -> Capsule {
        let artifact = ArtifactReference {
            path: "artifact.bin".into(),
            bytes: 1,
            sha256: "a".repeat(64),
        };
        Capsule::new(CapsulePayload {
            format_version: 1,
            cartridge_id: "dev.example.test".into(),
            cartridge_version: "1.0.0".into(),
            component_sha256: "b".repeat(64),
            runtime_version: "0.1.0".into(),
            argument_count: 0,
            argument_bytes: 0,
            arguments_sha256: digest_bytes(b"[]"),
            package: artifact.clone(),
            source_snapshot: SnapshotReference {
                artifact: artifact.clone(),
                state_schema: 1,
                entries: 0,
                bytes: 0,
                payload_sha256: "c".repeat(64),
            },
            trace: TraceReference {
                artifact: artifact.clone(),
                format_version: 2,
                event_count: 0,
                output_bytes: 0,
                output_sha256: digest_bytes(b""),
                fuel_consumed: 1,
            },
            result_snapshot: SnapshotReference {
                artifact,
                state_schema: 1,
                entries: 0,
                bytes: 0,
                payload_sha256: "d".repeat(64),
            },
        })
        .unwrap()
    }

    #[test]
    fn portable_paths_reject_escapes_and_windows_prefixes() {
        for path in [
            "../state.json",
            "/state.json",
            "C:/state.json",
            "a\\state.json",
        ] {
            assert!(path_from_portable(path).is_err());
        }
        assert_eq!(
            path_from_portable("artifacts/state.json").unwrap(),
            PathBuf::from("artifacts").join("state.json")
        );
    }

    #[test]
    fn changed_capsule_payloads_are_rejected() {
        let mut value = serde_json::to_value(capsule()).unwrap();
        value["payload"]["argument_count"] = serde_json::json!(1);

        assert!(Capsule::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn comparison_reports_the_first_result_state_difference() {
        let left = capsule();
        let mut payload = left.payload.clone();
        payload.result_snapshot.payload_sha256 = "e".repeat(64);
        let right = Capsule::new(payload).unwrap();

        let comparison = compare_capsules(&left, &right);

        assert!(!comparison.identical);
        assert!(matches!(
            comparison.difference,
            Some(CapsuleDifference::Field { field, .. })
                if field == "result.payload_sha256"
        ));
    }

    #[test]
    fn oversized_capsules_are_rejected_before_decoding() {
        let oversized = vec![b' '; usize::try_from(MAX_CAPSULE_BYTES).unwrap() + 1];

        assert!(Capsule::from_slice(&oversized).is_err());
    }

    #[test]
    fn reachability_reads_the_exact_snapshot_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let source = StorageSnapshot::from_slice(include_bytes!(
            "../../cartridge-storage/tests/fixtures/snapshot-v2.json"
        ))
        .unwrap();
        let limits = cartridge_runtime::StorageLimits {
            max_bytes: 1024,
            max_keys: 8,
            max_value_bytes: 512,
        };
        let branch = cartridge_runtime::SnapshotStorage::from_snapshot(
            &source,
            source.cartridge_id(),
            limits,
        )
        .unwrap();
        let reference = cartridge_runtime::BlobReference::new("a".repeat(64), 42)
            .unwrap()
            .encode()
            .unwrap();
        cartridge_runtime::StorageBackend::put(
            &branch,
            source.cartridge_id(),
            "blobs/example",
            &reference,
            limits,
        )
        .unwrap();
        let snapshot = branch.export_snapshot().unwrap();
        let path = directory.path().join("state.json");
        snapshot.write_new(&path).unwrap();
        let summary = snapshot.summary().unwrap();
        let snapshot_reference = SnapshotReference {
            artifact: artifact_reference(&root, &path, MAX_SNAPSHOT_FILE_BYTES).unwrap(),
            state_schema: summary.state_schema,
            entries: summary.entries,
            bytes: summary.bytes,
            payload_sha256: summary.payload_sha256,
        };

        let loaded = read_verified_snapshot(&root, &snapshot_reference).unwrap();
        assert_eq!(
            loaded.blob_references().unwrap(),
            BTreeMap::from([("a".repeat(64), 42)])
        );

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        assert!(read_verified_snapshot(&root, &snapshot_reference).is_err());
    }
}

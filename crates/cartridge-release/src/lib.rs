use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use cartridge_identity::{DeveloperKey, TrustStore};
use fs4::{FileExt, TryLockError};
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const RELEASE_FORMAT_VERSION: u32 = 1;
pub const UPDATE_STATE_FORMAT_VERSION: u32 = 1;
pub const MAX_RELEASE_DOCUMENT_BYTES: u64 = 1024 * 1024;
pub const MAX_RUNTIME_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RELEASE_ARTIFACTS: usize = 32;

static SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub target: String,
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePayload {
    pub format_version: u32,
    pub channel: String,
    pub version: String,
    pub published_at_ms: u64,
    pub minimum_updater_version: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

impl ReleasePayload {
    pub fn new(
        channel: String,
        version: String,
        published_at_ms: u64,
        minimum_updater_version: String,
        artifacts: Vec<ReleaseArtifact>,
    ) -> Result<Self, String> {
        let value = Self {
            format_version: RELEASE_FORMAT_VERSION,
            channel,
            version,
            published_at_ms,
            minimum_updater_version,
            artifacts,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != RELEASE_FORMAT_VERSION || self.published_at_ms == 0 {
            return Err("release metadata version or timestamp is invalid".into());
        }
        validate_token(&self.channel, "release channel", 32)?;
        validate_version(&self.version, "runtime release version")?;
        validate_version(&self.minimum_updater_version, "minimum updater version")?;
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_RELEASE_ARTIFACTS {
            return Err("release artifact count is invalid".into());
        }
        let mut targets = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_token(&artifact.target, "release target", 128)?;
            validate_filename(&artifact.filename)?;
            if artifact.bytes == 0 || artifact.bytes > MAX_RUNTIME_ARTIFACT_BYTES {
                return Err("runtime artifact byte length is invalid".into());
            }
            validate_digest(&artifact.sha256)?;
            if !targets.insert(&artifact.target) {
                return Err("release contains duplicate targets".into());
            }
        }
        Ok(())
    }

    pub fn artifact(&self, target: &str) -> Result<&ReleaseArtifact, String> {
        self.artifacts
            .iter()
            .find(|value| value.target == target)
            .ok_or_else(|| format!("release has no artifact for {target}"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub payload: ReleasePayload,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

impl SignedRelease {
    pub fn create(key: &DeveloperKey, payload: ReleasePayload) -> Result<Self, String> {
        payload.validate()?;
        let bytes = payload_bytes(&payload)?;
        Ok(Self {
            payload,
            algorithm: "ed25519".into(),
            key_id: key.key_id(),
            public_key: key.public_key_hex(),
            signature: key.sign_bytes(b"cartridge-runtime-release-v1", &bytes),
        })
    }

    pub fn verify(&self, trust: &TrustStore, updater_version: &str) -> Result<(), String> {
        self.payload.validate()?;
        if self.algorithm != "ed25519" {
            return Err("runtime release signature algorithm is unsupported".into());
        }
        let updater = Version::parse(updater_version).map_err(|_| "updater version is invalid")?;
        let minimum = Version::parse(&self.payload.minimum_updater_version)
            .map_err(|_| "minimum updater version is invalid")?;
        if updater < minimum {
            return Err(format!(
                "updater {updater} is older than required {minimum}"
            ));
        }
        trust.verify_trusted_bytes(
            &self.key_id,
            &self.public_key,
            b"cartridge-runtime-release-v1",
            &payload_bytes(&self.payload)?,
            &self.signature,
        )
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        read_json(path, MAX_RELEASE_DOCUMENT_BYTES)
    }

    pub fn write_new(&self, path: &Path) -> Result<(), String> {
        self.payload.validate()?;
        write_json_new(path, self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateState {
    format_version: u32,
    channel: String,
    active: Option<InstalledRelease>,
    previous: Option<InstalledRelease>,
    installed: BTreeMap<String, InstalledRelease>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateDocument {
    payload: UpdateState,
    payload_sha256: String,
}

impl StateDocument {
    fn new(payload: UpdateState) -> Result<Self, String> {
        let payload_sha256 = hex::encode(Sha256::digest(state_bytes(&payload)?));
        Ok(Self {
            payload,
            payload_sha256,
        })
    }

    fn validate(self, channel: &str) -> Result<UpdateState, String> {
        validate_digest(&self.payload_sha256)?;
        if hex::encode(Sha256::digest(state_bytes(&self.payload)?)) != self.payload_sha256 {
            return Err("runtime update state checksum is invalid".into());
        }
        validate_state(&self.payload, channel)?;
        Ok(self.payload)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledRelease {
    pub version: String,
    pub target: String,
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
    pub signing_key_id: String,
}

pub struct Updater {
    root: PathBuf,
    state: UpdateState,
    _lock: File,
}

impl Updater {
    pub fn open(root: impl Into<PathBuf>, channel: &str) -> Result<Self, String> {
        validate_token(channel, "release channel", 32)?;
        let root = root.into();
        if root.exists() {
            reject_symlink(&root)?;
            require_directory(&root)?;
        } else {
            fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        }
        set_private_directory(&root)?;
        let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
        let releases = root.join("releases");
        if releases.exists() {
            reject_symlink(&releases)?;
            require_directory(&releases)?;
        } else {
            fs::create_dir(&releases).map_err(|error| error.to_string())?;
        }
        set_private_directory(&releases)?;
        let lock_path = root.join("update.lock");
        if lock_path.exists() {
            reject_symlink(&lock_path)?;
            require_regular_file(&lock_path)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| error.to_string())?;
        set_private_file(&lock_path)?;
        acquire_lock(&lock)?;
        let path = root.join("update.json");
        recover_state(&path, channel)?;
        let state = if path.exists() {
            read_state(&path, channel)?
        } else {
            UpdateState {
                format_version: UPDATE_STATE_FORMAT_VERSION,
                channel: channel.into(),
                ..UpdateState::default()
            }
        };
        validate_state(&state, channel)?;
        Ok(Self {
            root,
            state,
            _lock: lock,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install(
        &mut self,
        release: &SignedRelease,
        trust: &TrustStore,
        artifact_path: &Path,
        target: &str,
        updater_version: &str,
        allow_downgrade: bool,
    ) -> Result<InstalledRelease, String> {
        release.verify(trust, updater_version)?;
        if release.payload.channel != self.state.channel {
            return Err("release channel does not match updater channel".into());
        }
        let artifact = release.payload.artifact(target)?;
        if let Some(active) = &self.state.active {
            let next = Version::parse(&release.payload.version)
                .map_err(|_| "release version is invalid")?;
            let current =
                Version::parse(&active.version).map_err(|_| "active version is invalid")?;
            if next < current && !allow_downgrade {
                return Err("runtime downgrade requires explicit approval".into());
            }
        }
        let version_dir = self.root.join("releases").join(&release.payload.version);
        if version_dir.exists() {
            reject_symlink(&version_dir)?;
            require_directory(&version_dir)?;
        } else {
            fs::create_dir(&version_dir).map_err(|error| error.to_string())?;
        }
        set_private_directory(&version_dir)?;
        let destination = version_dir.join(&artifact.filename);
        if destination.exists() {
            reject_symlink(&destination)?;
            verify_artifact(artifact_path, artifact)?;
            verify_artifact(&destination, artifact).map_err(|_| {
                "installed runtime version differs from signed artifact".to_string()
            })?;
        } else {
            let (bytes, sha256) =
                copy_runtime_new(artifact_path, &destination, MAX_RUNTIME_ARTIFACT_BYTES)?;
            if bytes != artifact.bytes || sha256 != artifact.sha256 {
                let _ = fs::remove_file(&destination);
                return Err("runtime artifact does not match signed release metadata".into());
            }
        }
        let installed = InstalledRelease {
            version: release.payload.version.clone(),
            target: target.into(),
            relative_path: format!("releases/{}/{}", release.payload.version, artifact.filename),
            sha256: artifact.sha256.clone(),
            bytes: artifact.bytes,
            signing_key_id: release.key_id.clone(),
        };
        let mut next = self.state.clone();
        let prior = next.active.replace(installed.clone());
        if prior.as_ref() != Some(&installed) {
            next.previous = prior;
        }
        next.installed
            .insert(installed.version.clone(), installed.clone());
        self.save_state(&next)?;
        self.state = next;
        Ok(installed)
    }

    pub fn rollback(&mut self) -> Result<InstalledRelease, String> {
        let mut next = self.state.clone();
        let previous = next
            .previous
            .take()
            .ok_or_else(|| "no previous runtime release is available".to_string())?;
        verify_installed(&self.root, &previous)?;
        let active = next.active.replace(previous.clone());
        next.previous = active;
        self.save_state(&next)?;
        self.state = next;
        Ok(previous)
    }

    pub fn active(&self) -> Result<Option<InstalledRelease>, String> {
        self.state
            .active
            .as_ref()
            .map(|value| {
                verify_installed(&self.root, value)?;
                Ok(value.clone())
            })
            .transpose()
    }

    fn save_state(&self, state: &UpdateState) -> Result<(), String> {
        validate_state(state, &self.state.channel)?;
        atomic_json_replace(
            &self.root.join("update.json"),
            &StateDocument::new(state.clone())?,
        )
    }
}

fn validate_state(value: &UpdateState, channel: &str) -> Result<(), String> {
    if value.format_version != UPDATE_STATE_FORMAT_VERSION
        || value.channel != channel
        || value.installed.len() > 128
    {
        return Err("runtime update state is invalid".into());
    }
    validate_token(&value.channel, "release channel", 32)?;
    for (version, release) in &value.installed {
        if version != &release.version {
            return Err("installed runtime index is invalid".into());
        }
        validate_installed(release)?;
    }
    for release in value.active.iter().chain(value.previous.iter()) {
        validate_installed(release)?;
        if value.installed.get(&release.version) != Some(release) {
            return Err("active runtime is missing from installed index".into());
        }
    }
    Ok(())
}

fn validate_installed(value: &InstalledRelease) -> Result<(), String> {
    validate_version(&value.version, "installed runtime version")?;
    validate_token(&value.target, "installed target", 128)?;
    validate_digest(&value.sha256)?;
    validate_digest(&value.signing_key_id)?;
    if value.bytes == 0 || value.bytes > MAX_RUNTIME_ARTIFACT_BYTES {
        return Err("installed runtime byte length is invalid".into());
    }
    let expected_prefix = format!("releases/{}/", value.version);
    let filename = value
        .relative_path
        .strip_prefix(&expected_prefix)
        .ok_or_else(|| "installed runtime path is invalid".to_string())?;
    validate_filename(filename)
}

fn verify_installed(root: &Path, value: &InstalledRelease) -> Result<(), String> {
    validate_installed(value)?;
    let path = root.join(&value.relative_path);
    reject_symlink(&path)?;
    let (bytes, sha256) = hash_regular_file(&path, MAX_RUNTIME_ARTIFACT_BYTES)?;
    if bytes != value.bytes || sha256 != value.sha256 {
        return Err("installed runtime artifact failed integrity verification".into());
    }
    Ok(())
}

fn payload_bytes(value: &ReleasePayload) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn state_bytes(value: &UpdateState) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn validate_version(value: &str, label: &str) -> Result<(), String> {
    if value.len() > 128 || !value.is_ascii() || Version::parse(value).is_err() {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_token(value: &str, label: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_filename(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return Err("runtime artifact filename is invalid".into());
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release digest is invalid".into());
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    let mut link_like = metadata.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        link_like |= metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    if link_like {
        return Err(format!(
            "links and reparse points are forbidden in the updater: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<(), String> {
    if !fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        return Err(format!(
            "updater path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), String> {
    if !fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err(format!(
            "updater path is not a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    reject_symlink(path)?;
    require_regular_file(path)?;
    if fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .len()
        > limit
    {
        return Err("file exceeds its byte limit".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("file exceeded its byte limit while reading".into());
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path, limit)?).map_err(|error| error.to_string())
}

fn read_state(path: &Path, channel: &str) -> Result<UpdateState, String> {
    read_json::<StateDocument>(path, MAX_RELEASE_DOCUMENT_BYTES)?.validate(channel)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_RELEASE_DOCUMENT_BYTES {
        return Err("release document exceeds its byte limit".into());
    }
    write_bytes_new(path, &bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    Ok(())
}

fn verify_artifact(path: &Path, artifact: &ReleaseArtifact) -> Result<(), String> {
    let (bytes, sha256) = hash_regular_file(path, MAX_RUNTIME_ARTIFACT_BYTES)?;
    if bytes != artifact.bytes || sha256 != artifact.sha256 {
        return Err("runtime artifact does not match signed release metadata".into());
    }
    Ok(())
}

fn hash_regular_file(path: &Path, limit: u64) -> Result<(u64, String), String> {
    reject_symlink(path)?;
    require_regular_file(path)?;
    if fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .len()
        > limit
    {
        return Err("file exceeds its byte limit".into());
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = 0_u64;
    let mut digest = Sha256::new();
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| "file byte length overflowed".to_string())?;
        if bytes > limit {
            return Err("file exceeded its byte limit while reading".into());
        }
        digest.update(&buffer[..read]);
    }
    Ok((bytes, hex::encode(digest.finalize())))
}

fn copy_runtime_new(
    source: &Path,
    destination: &Path,
    limit: u64,
) -> Result<(u64, String), String> {
    reject_symlink(source)?;
    require_regular_file(source)?;
    if fs::symlink_metadata(source)
        .map_err(|error| error.to_string())?
        .len()
        > limit
    {
        return Err("file exceeds its byte limit".into());
    }
    let mut input = File::open(source).map_err(|error| error.to_string())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut output = options
        .open(destination)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let mut buffer = [0_u8; 16 * 1024];
        let mut bytes = 0_u64;
        let mut digest = Sha256::new();
        loop {
            let read = input.read(&mut buffer).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| "file byte length overflowed".to_string())?;
            if bytes > limit {
                return Err("file exceeded its byte limit while reading".into());
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| error.to_string())?;
            digest.update(&buffer[..read]);
        }
        output.sync_all().map_err(|error| error.to_string())?;
        Ok((bytes, hex::encode(digest.finalize())))
    })();
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

fn atomic_json_replace(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let sequence = SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("json.{}-{sequence}.tmp", std::process::id()));
    let backup = path.with_extension("json.previous");
    if path.exists() {
        reject_symlink(path)?;
        require_regular_file(path)?;
    }
    if backup.exists() {
        reject_symlink(&backup)?;
        require_regular_file(&backup)?;
    }
    write_json_new(&temporary, value)?;
    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup).map_err(|error| error.to_string())?;
        }
        fs::rename(path, &backup).map_err(|error| error.to_string())?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&backup, path);
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    } else {
        fs::rename(temporary, path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn recover_state(path: &Path, channel: &str) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    for candidate in [path, backup.as_path()] {
        if candidate.exists() {
            reject_symlink(candidate)?;
            require_regular_file(candidate)?;
        }
    }
    if !backup.exists() {
        return Ok(());
    }
    if !path.exists() {
        if !state_file_valid(&backup, channel) {
            return Err("runtime update recovery backup is invalid".into());
        }
        fs::rename(backup, path).map_err(|error| error.to_string())?;
        return Ok(());
    }
    if state_file_valid(path, channel) {
        return fs::remove_file(backup).map_err(|error| error.to_string());
    }
    if !state_file_valid(&backup, channel) {
        return Err("runtime update state and recovery backup are invalid".into());
    }
    let corrupt = (0..32)
        .map(|sequence| path.with_extension(format!("json.corrupt-{sequence}")))
        .find(|candidate| !candidate.exists())
        .ok_or_else(|| "runtime update recovery quarantine is full".to_string())?;
    fs::rename(path, corrupt).map_err(|error| error.to_string())?;
    fs::rename(backup, path).map_err(|error| error.to_string())
}

fn set_private_directory(path: &Path) -> Result<(), String> {
    require_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<(), String> {
    require_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn state_file_valid(path: &Path, channel: &str) -> bool {
    read_state(path, channel).is_ok()
}

fn acquire_lock(file: &File) -> Result<(), String> {
    for _ in 0..200 {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::Error(error)) => return Err(error.to_string()),
        }
    }
    Err("runtime updater is busy".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_release(key: &DeveloperKey, version: &str, bytes: &[u8]) -> SignedRelease {
        SignedRelease::create(
            key,
            ReleasePayload::new(
                "stable".into(),
                version.into(),
                1,
                "0.1.0".into(),
                vec![ReleaseArtifact {
                    target: "test-target".into(),
                    filename: "cartridge-runtime".into(),
                    bytes: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(bytes)),
                }],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn signed_updates_install_and_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let key = DeveloperKey::generate();
        let mut trust = TrustStore::new();
        trust
            .trust(key.public_key(), "runtime release", BTreeSet::new())
            .unwrap();
        let first_path = directory.path().join("first.bin");
        let second_path = directory.path().join("second.bin");
        fs::write(&first_path, b"first").unwrap();
        fs::write(&second_path, b"second").unwrap();
        let mut updater = Updater::open(directory.path().join("runtime"), "stable").unwrap();
        updater
            .install(
                &signed_release(&key, "1.0.0", b"first"),
                &trust,
                &first_path,
                "test-target",
                "0.1.0",
                false,
            )
            .unwrap();
        updater
            .install(
                &signed_release(&key, "1.1.0", b"second"),
                &trust,
                &second_path,
                "test-target",
                "0.1.0",
                false,
            )
            .unwrap();
        assert_eq!(updater.rollback().unwrap().version, "1.0.0");
        assert_eq!(updater.active().unwrap().unwrap().version, "1.0.0");
    }

    #[test]
    fn tampered_and_untrusted_releases_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let key = DeveloperKey::generate();
        let trust = TrustStore::new();
        let artifact = directory.path().join("runtime.bin");
        fs::write(&artifact, b"changed").unwrap();
        let mut updater = Updater::open(directory.path().join("runtime"), "stable").unwrap();
        assert!(
            updater
                .install(
                    &signed_release(&key, "1.0.0", b"expected"),
                    &trust,
                    &artifact,
                    "test-target",
                    "0.1.0",
                    false,
                )
                .is_err()
        );
        assert!(updater.active().unwrap().is_none());
    }

    #[test]
    fn downgrade_needs_approval_and_interrupted_state_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let key = DeveloperKey::generate();
        let mut trust = TrustStore::new();
        trust
            .trust(key.public_key(), "runtime release", BTreeSet::new())
            .unwrap();
        let artifact = directory.path().join("runtime.bin");
        fs::write(&artifact, b"runtime").unwrap();
        let root = directory.path().join("runtime-root");
        {
            let mut updater = Updater::open(&root, "stable").unwrap();
            updater
                .install(
                    &signed_release(&key, "2.0.0", b"runtime"),
                    &trust,
                    &artifact,
                    "test-target",
                    "0.1.0",
                    false,
                )
                .unwrap();
            assert!(
                updater
                    .install(
                        &signed_release(&key, "1.0.0", b"runtime"),
                        &trust,
                        &artifact,
                        "test-target",
                        "0.1.0",
                        false
                    )
                    .is_err()
            );
        }
        let state = root.join("update.json");
        fs::rename(&state, root.join("update.json.previous")).unwrap();
        let updater = Updater::open(&root, "stable").unwrap();
        assert_eq!(updater.active().unwrap().unwrap().version, "2.0.0");
    }

    #[test]
    fn metadata_is_canonical_and_artifacts_must_be_regular_files() {
        let key = DeveloperKey::generate();
        let mut payload = signed_release(&key, "1.0.0", b"runtime").payload;
        payload.artifacts[0].sha256.make_ascii_uppercase();
        assert!(payload.validate().is_err());

        let directory = tempfile::tempdir().unwrap();
        let mut trust = TrustStore::new();
        trust
            .trust(key.public_key(), "runtime release", BTreeSet::new())
            .unwrap();
        let mut updater = Updater::open(directory.path().join("runtime"), "stable").unwrap();
        assert!(
            updater
                .install(
                    &signed_release(&key, "1.0.0", b"runtime"),
                    &trust,
                    directory.path(),
                    "test-target",
                    "0.1.0",
                    false,
                )
                .is_err()
        );
    }

    #[test]
    fn checksummed_state_recovers_semantic_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let key = DeveloperKey::generate();
        let mut trust = TrustStore::new();
        trust
            .trust(key.public_key(), "runtime release", BTreeSet::new())
            .unwrap();
        let artifact = directory.path().join("runtime.bin");
        fs::write(&artifact, b"runtime").unwrap();
        let root = directory.path().join("runtime-root");
        {
            let mut updater = Updater::open(&root, "stable").unwrap();
            updater
                .install(
                    &signed_release(&key, "1.0.0", b"runtime"),
                    &trust,
                    &artifact,
                    "test-target",
                    "0.1.0",
                    false,
                )
                .unwrap();
        }
        let state = root.join("update.json");
        fs::copy(&state, root.join("update.json.previous")).unwrap();
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        document["payload"]["active"]["version"] = serde_json::json!("9.9.9");
        fs::write(&state, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let updater = Updater::open(&root, "stable").unwrap();
        assert_eq!(updater.active().unwrap().unwrap().version, "1.0.0");
        assert!(root.join("update.json.corrupt-0").exists());
    }
}

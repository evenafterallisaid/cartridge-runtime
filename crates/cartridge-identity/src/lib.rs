use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use cartridge_core::{CartridgeArchive, PackageManifest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs4::{FileExt, TryLockError};
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const SIGNATURE_FORMAT_VERSION: u32 = 1;
pub const TRUST_FORMAT_VERSION: u32 = 1;
pub const REGISTRY_FORMAT_VERSION: u32 = 1;
pub const ATTESTATION_FORMAT_VERSION: u32 = 1;
pub const MAX_PACKAGE_BYTES: u64 = 160 * 1024 * 1024;
pub const MAX_IDENTITY_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_REGISTRY_VERSIONS: usize = 100_000;
pub const MAX_TRANSPARENCY_ENTRIES: usize = 100_000;

static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub cartridge_id: String,
    pub version: String,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub component_sha256: String,
    pub assets_root_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSignature {
    pub format_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub identity: PackageIdentity,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeveloperKeyFile {
    format_version: u32,
    algorithm: String,
    key_id: String,
    public_key: String,
    secret_key: String,
}

pub struct DeveloperKey {
    signing: SigningKey,
}

impl fmt::Debug for DeveloperKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeveloperKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl DeveloperKey {
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = rand_secret();
        let signing = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing }
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let mut document: DeveloperKeyFile = read_json(path, 16 * 1024)?;
        if document.format_version != SIGNATURE_FORMAT_VERSION || document.algorithm != "ed25519" {
            return Err("unsupported developer key format".into());
        }
        let mut secret = decode_array::<32>(&document.secret_key, "secret key")?;
        let signing = SigningKey::from_bytes(&secret);
        secret.zeroize();
        document.secret_key.zeroize();
        let key = Self { signing };
        if key.key_id() != document.key_id || hex::encode(key.public_key()) != document.public_key {
            return Err("developer key identity does not match its secret".into());
        }
        Ok(key)
    }

    pub fn write_new(&self, path: &Path) -> Result<(), String> {
        let document = DeveloperKeyFile {
            format_version: SIGNATURE_FORMAT_VERSION,
            algorithm: "ed25519".into(),
            key_id: self.key_id(),
            public_key: hex::encode(self.public_key()),
            secret_key: hex::encode(self.signing.to_bytes()),
        };
        write_private_json_new(path, &document)
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn key_id(&self) -> String {
        key_id(&self.public_key())
    }

    pub fn sign_package(&self, path: &Path) -> Result<PackageSignature, String> {
        let (identity, bytes) = package_identity_and_bytes(path)?;
        let payload = package_signature_payload(&identity, &bytes)?;
        let signature = self.signing.sign(&payload);
        Ok(PackageSignature {
            format_version: SIGNATURE_FORMAT_VERSION,
            algorithm: "ed25519".into(),
            key_id: self.key_id(),
            public_key: hex::encode(self.public_key()),
            identity,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    #[must_use]
    pub fn sign_bytes(&self, domain: &[u8], bytes: &[u8]) -> String {
        let payload = framed_payload(domain, bytes);
        hex::encode(self.signing.sign(&payload).to_bytes())
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }
}

pub fn verify_package(
    path: &Path,
    signature: &PackageSignature,
) -> Result<PackageIdentity, String> {
    let (identity, bytes) = package_identity_and_bytes(path)?;
    verify_package_bytes(&bytes, &identity, signature)?;
    Ok(identity)
}

pub fn verify_package_bytes(
    bytes: &[u8],
    identity: &PackageIdentity,
    signature: &PackageSignature,
) -> Result<(), String> {
    validate_signature_document(signature)?;
    if &signature.identity != identity {
        return Err("signed package identity does not match the package".into());
    }
    let public = verifying_key(&signature.public_key)?;
    if key_id(&public.to_bytes()) != signature.key_id {
        return Err("signature key id does not match its public key".into());
    }
    let value = Signature::from_bytes(&decode_array::<64>(&signature.signature, "signature")?);
    public
        .verify(&package_signature_payload(identity, bytes)?, &value)
        .map_err(|_| "package signature verification failed".into())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry {
    pub key_id: String,
    pub public_key: String,
    pub label: String,
    pub recovery_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub format_version: u32,
    pub trusted: BTreeMap<String, TrustEntry>,
    pub revoked: BTreeMap<String, RevocationRecord>,
    pub rotations: Vec<KeyRotation>,
}

impl TrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            format_version: TRUST_FORMAT_VERSION,
            ..Self::default()
        }
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let value: Self = read_json(path, MAX_IDENTITY_DOCUMENT_BYTES)?;
        value.validate()?;
        Ok(value)
    }

    pub fn write_new(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        write_private_json_new(path, self)
    }

    pub fn write_replace(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        atomic_json_replace(path, self)
    }

    pub fn trust(
        &mut self,
        public_key: [u8; 32],
        label: &str,
        recovery_keys: BTreeSet<String>,
    ) -> Result<String, String> {
        validate_label(label)?;
        for recovery in &recovery_keys {
            validate_digest(recovery, "recovery key id")?;
        }
        let id = key_id(&public_key);
        self.trusted.insert(
            id.clone(),
            TrustEntry {
                key_id: id.clone(),
                public_key: hex::encode(public_key),
                label: label.into(),
                recovery_keys,
            },
        );
        Ok(id)
    }

    pub fn verify(
        &self,
        package: &Path,
        signature: &PackageSignature,
    ) -> Result<PackageIdentity, String> {
        let bytes = read_bounded(package, MAX_PACKAGE_BYTES)?;
        self.verify_bytes(&bytes, signature)
    }

    pub fn verify_bytes(
        &self,
        bytes: &[u8],
        signature: &PackageSignature,
    ) -> Result<PackageIdentity, String> {
        self.validate()?;
        if self.revoked.contains_key(&signature.key_id) {
            return Err("package signing key is revoked".into());
        }
        let trusted = self
            .trusted
            .get(&signature.key_id)
            .ok_or_else(|| "package signing key is not trusted".to_string())?;
        if trusted.public_key != signature.public_key {
            return Err("trusted public key does not match the signature".into());
        }
        let identity = package_identity(bytes)?;
        verify_package_bytes(bytes, &identity, signature)?;
        Ok(identity)
    }

    pub fn verify_trusted_bytes(
        &self,
        key_id_value: &str,
        public_key: &str,
        domain: &[u8],
        bytes: &[u8],
        signature: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.revoked.contains_key(key_id_value) {
            return Err("signing key is revoked".into());
        }
        let trusted = self
            .trusted
            .get(key_id_value)
            .ok_or_else(|| "signing key is not trusted".to_string())?;
        if trusted.public_key != public_key {
            return Err("trusted public key does not match the signature".into());
        }
        if key_id(&decode_array::<32>(public_key, "public key")?) != key_id_value {
            return Err("signature key id is invalid".into());
        }
        verify_detached(public_key, domain, bytes, signature)
    }

    pub fn apply_rotation(&mut self, rotation: KeyRotation) -> Result<(), String> {
        rotation.verify()?;
        let old = self
            .trusted
            .get(&rotation.old_key_id)
            .ok_or_else(|| "old rotation key is not trusted".to_string())?
            .clone();
        if old.public_key != rotation.old_public_key {
            return Err("rotation old key does not match trust store".into());
        }
        let new_id = key_id(&decode_array::<32>(
            &rotation.new_public_key,
            "new public key",
        )?);
        if new_id != rotation.new_key_id {
            return Err("rotation new key id is invalid".into());
        }
        self.trusted.remove(&rotation.old_key_id);
        self.trusted.insert(
            new_id.clone(),
            TrustEntry {
                key_id: new_id,
                public_key: rotation.new_public_key.clone(),
                label: old.label,
                recovery_keys: old.recovery_keys,
            },
        );
        self.rotations.push(rotation);
        Ok(())
    }

    pub fn apply_revocation(&mut self, record: RevocationRecord) -> Result<(), String> {
        record.verify()?;
        let trusted = self
            .trusted
            .get(&record.revoked_key_id)
            .ok_or_else(|| "revoked key is not trusted".to_string())?;
        let signer_id = key_id(&decode_array::<32>(
            &record.signer_public_key,
            "revocation signer",
        )?);
        if signer_id != record.revoked_key_id && !trusted.recovery_keys.contains(&signer_id) {
            return Err("revocation signer is not an authorized recovery key".into());
        }
        self.revoked.insert(record.revoked_key_id.clone(), record);
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != TRUST_FORMAT_VERSION
            || self.trusted.len() > 10_000
            || self.revoked.len() > 10_000
            || self.rotations.len() > 10_000
        {
            return Err("invalid or oversized trust store".into());
        }
        for (id, entry) in &self.trusted {
            if id != &entry.key_id
                || key_id(&decode_array::<32>(
                    &entry.public_key,
                    "trusted public key",
                )?) != *id
            {
                return Err("trust entry identity is invalid".into());
            }
            validate_label(&entry.label)?;
            for recovery in &entry.recovery_keys {
                validate_digest(recovery, "recovery key id")?;
            }
        }
        for (id, record) in &self.revoked {
            if id != &record.revoked_key_id {
                return Err("revocation index is invalid".into());
            }
            record.verify()?;
        }
        for rotation in &self.rotations {
            rotation.verify()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotation {
    pub format_version: u32,
    pub old_key_id: String,
    pub old_public_key: String,
    pub new_key_id: String,
    pub new_public_key: String,
    pub reason: String,
    pub old_signature: String,
    pub new_signature: String,
}

impl KeyRotation {
    pub fn create(old: &DeveloperKey, new: &DeveloperKey, reason: &str) -> Result<Self, String> {
        validate_label(reason)?;
        let mut value = Self {
            format_version: TRUST_FORMAT_VERSION,
            old_key_id: old.key_id(),
            old_public_key: hex::encode(old.public_key()),
            new_key_id: new.key_id(),
            new_public_key: hex::encode(new.public_key()),
            reason: reason.into(),
            old_signature: String::new(),
            new_signature: String::new(),
        };
        let payload = value.payload()?;
        value.old_signature = old.sign_bytes(b"cartridge-key-rotation-v1", &payload);
        value.new_signature = new.sign_bytes(b"cartridge-key-rotation-v1", &payload);
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.format_version != TRUST_FORMAT_VERSION || self.old_key_id == self.new_key_id {
            return Err("invalid key rotation".into());
        }
        validate_label(&self.reason)?;
        verify_detached(
            &self.old_public_key,
            b"cartridge-key-rotation-v1",
            &self.payload()?,
            &self.old_signature,
        )?;
        verify_detached(
            &self.new_public_key,
            b"cartridge-key-rotation-v1",
            &self.payload()?,
            &self.new_signature,
        )
    }

    fn payload(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&serde_json::json!({"format_version": self.format_version, "old_key_id": self.old_key_id, "old_public_key": self.old_public_key, "new_key_id": self.new_key_id, "new_public_key": self.new_public_key, "reason": self.reason})).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecord {
    pub format_version: u32,
    pub revoked_key_id: String,
    pub signer_public_key: String,
    pub reason: String,
    pub signature: String,
}

impl RevocationRecord {
    pub fn create(
        revoked_key_id: String,
        signer: &DeveloperKey,
        reason: &str,
    ) -> Result<Self, String> {
        validate_digest(&revoked_key_id, "revoked key id")?;
        validate_label(reason)?;
        let mut value = Self {
            format_version: TRUST_FORMAT_VERSION,
            revoked_key_id,
            signer_public_key: hex::encode(signer.public_key()),
            reason: reason.into(),
            signature: String::new(),
        };
        value.signature = signer.sign_bytes(b"cartridge-key-revocation-v1", &value.payload()?);
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.format_version != TRUST_FORMAT_VERSION {
            return Err("unsupported revocation format".into());
        }
        validate_digest(&self.revoked_key_id, "revoked key id")?;
        validate_label(&self.reason)?;
        verify_detached(
            &self.signer_public_key,
            b"cartridge-key-revocation-v1",
            &self.payload()?,
            &self.signature,
        )
    }

    fn payload(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&serde_json::json!({"format_version": self.format_version, "revoked_key_id": self.revoked_key_id, "signer_public_key": self.signer_public_key, "reason": self.reason})).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildAttestation {
    pub format_version: u32,
    pub identity: PackageIdentity,
    pub source_sha256: String,
    pub toolchain: String,
    pub build_arguments: Vec<String>,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

impl BuildAttestation {
    pub fn create(
        key: &DeveloperKey,
        identity: PackageIdentity,
        source_sha256: String,
        toolchain: String,
        build_arguments: Vec<String>,
    ) -> Result<Self, String> {
        validate_digest(&source_sha256, "source digest")?;
        validate_label(&toolchain)?;
        if build_arguments.len() > 128
            || build_arguments
                .iter()
                .any(|value| value.len() > 4096 || value.contains('\0'))
        {
            return Err("build arguments are invalid".into());
        }
        let mut value = Self {
            format_version: ATTESTATION_FORMAT_VERSION,
            identity,
            source_sha256,
            toolchain,
            build_arguments,
            key_id: key.key_id(),
            public_key: hex::encode(key.public_key()),
            signature: String::new(),
        };
        value.signature = key.sign_bytes(b"cartridge-build-attestation-v1", &value.payload()?);
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.format_version != ATTESTATION_FORMAT_VERSION
            || key_id(&decode_array::<32>(
                &self.public_key,
                "attestation public key",
            )?) != self.key_id
        {
            return Err("invalid build attestation identity".into());
        }
        validate_digest(&self.source_sha256, "source digest")?;
        validate_label(&self.toolchain)?;
        if self.build_arguments.len() > 128
            || self
                .build_arguments
                .iter()
                .any(|value| value.len() > 4096 || value.contains('\0'))
        {
            return Err("build arguments are invalid".into());
        }
        verify_detached(
            &self.public_key,
            b"cartridge-build-attestation-v1",
            &self.payload()?,
            &self.signature,
        )
    }

    fn payload(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&serde_json::json!({"format_version": self.format_version, "identity": self.identity, "source_sha256": self.source_sha256, "toolchain": self.toolchain, "build_arguments": self.build_arguments, "key_id": self.key_id, "public_key": self.public_key})).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryIndex {
    format_version: u32,
    packages: BTreeMap<String, BTreeMap<String, RegistryVersion>>,
    transparency: Vec<TransparencyEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryVersion {
    pub identity: PackageIdentity,
    pub key_id: String,
    pub published_at_ms: u64,
    pub dependencies: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyEntry {
    pub sequence: u64,
    pub cartridge_id: String,
    pub version: String,
    pub package_sha256: String,
    pub key_id: String,
    pub previous_sha256: String,
    pub entry_sha256: String,
}

pub struct Registry {
    root: PathBuf,
    index: RegistryIndex,
    _lock: File,
}

impl Registry {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(root.join("objects")).map_err(|error| error.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("registry.lock"))
            .map_err(|error| error.to_string())?;
        acquire_lock(&lock)?;
        let path = root.join("index.json");
        recover_registry_index(&path)?;
        let index = if path.exists() {
            read_json(&path, MAX_IDENTITY_DOCUMENT_BYTES)?
        } else {
            RegistryIndex {
                format_version: REGISTRY_FORMAT_VERSION,
                ..RegistryIndex::default()
            }
        };
        validate_registry(&index)?;
        Ok(Self {
            root,
            index,
            _lock: lock,
        })
    }

    pub fn publish(
        &mut self,
        package: &Path,
        signature: &PackageSignature,
        trust: &TrustStore,
    ) -> Result<RegistryVersion, String> {
        let bytes = read_bounded(package, MAX_PACKAGE_BYTES)?;
        let identity = trust.verify_bytes(&bytes, signature)?;
        if self
            .index
            .packages
            .values()
            .map(BTreeMap::len)
            .sum::<usize>()
            >= MAX_REGISTRY_VERSIONS
        {
            return Err("registry version limit exceeded".into());
        }
        if let Some(existing) = self
            .index
            .packages
            .get(&identity.cartridge_id)
            .and_then(|versions| versions.get(&identity.version))
        {
            if existing.identity.package_sha256 == identity.package_sha256 {
                return Ok(existing.clone());
            }
            return Err("registry versions are immutable".into());
        }
        let object = self
            .root
            .join("objects")
            .join(format!("{}.cartridge", identity.package_sha256));
        if object.exists() {
            if read_bounded(&object, MAX_PACKAGE_BYTES)? != bytes {
                return Err("registry object does not match its content address".into());
            }
        } else {
            write_bytes_new(&object, &bytes)?;
        }
        let signature_path = self
            .root
            .join("objects")
            .join(format!("{}.signature.json", identity.package_sha256));
        if !signature_path.exists() {
            write_json_new(&signature_path, &signature)?;
        }
        let archive = CartridgeArchive::open(&object).map_err(|error| error.to_string())?;
        let published = RegistryVersion {
            identity: identity.clone(),
            key_id: signature.key_id.clone(),
            published_at_ms: now_ms()?,
            dependencies: archive
                .manifest
                .dependencies
                .iter()
                .map(|value| value.cartridge.clone())
                .collect(),
            capabilities: permission_names(&archive.manifest),
        };
        self.index
            .packages
            .entry(identity.cartridge_id.clone())
            .or_default()
            .insert(identity.version.clone(), published.clone());
        self.append_transparency(&identity, &signature.key_id)?;
        self.save()?;
        Ok(published)
    }

    pub fn resolve(&self, id: &str, requirement: &str) -> Result<Option<RegistryVersion>, String> {
        let requirement =
            semver::VersionReq::parse(requirement).map_err(|error| error.to_string())?;
        Ok(self.index.packages.get(id).and_then(|versions| {
            versions
                .iter()
                .filter_map(|(version, value)| {
                    Version::parse(version)
                        .ok()
                        .filter(|version| requirement.matches(version))
                        .map(|version| (version, value))
                })
                .max_by(|left, right| left.0.cmp(&right.0))
                .map(|(_, value)| value.clone())
        }))
    }

    #[must_use]
    pub fn transparency(&self) -> &[TransparencyEntry] {
        &self.index.transparency
    }

    pub fn audit(&self, trust: &TrustStore) -> Result<usize, String> {
        validate_registry(&self.index)?;
        let mut verified = 0;
        for versions in self.index.packages.values() {
            for version in versions.values() {
                let digest = &version.identity.package_sha256;
                let package = self
                    .root
                    .join("objects")
                    .join(format!("{digest}.cartridge"));
                let signature: PackageSignature = read_json(
                    &self
                        .root
                        .join("objects")
                        .join(format!("{digest}.signature.json")),
                    MAX_IDENTITY_DOCUMENT_BYTES,
                )?;
                let bytes = read_bounded(&package, MAX_PACKAGE_BYTES)?;
                let identity = trust.verify_bytes(&bytes, &signature)?;
                if identity != version.identity || signature.key_id != version.key_id {
                    return Err("registry index does not match a stored signed object".into());
                }
                verified += 1;
            }
        }
        Ok(verified)
    }

    fn append_transparency(
        &mut self,
        identity: &PackageIdentity,
        signing_key: &str,
    ) -> Result<(), String> {
        if self.index.transparency.len() >= MAX_TRANSPARENCY_ENTRIES {
            return Err("transparency log limit exceeded".into());
        }
        let sequence = self.index.transparency.len() as u64;
        let previous = self
            .index
            .transparency
            .last()
            .map_or_else(|| "0".repeat(64), |value| value.entry_sha256.clone());
        let mut entry = TransparencyEntry {
            sequence,
            cartridge_id: identity.cartridge_id.clone(),
            version: identity.version.clone(),
            package_sha256: identity.package_sha256.clone(),
            key_id: signing_key.into(),
            previous_sha256: previous,
            entry_sha256: String::new(),
        };
        entry.entry_sha256 = transparency_hash(&entry)?;
        self.index.transparency.push(entry);
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        validate_registry(&self.index)?;
        atomic_json_replace(&self.root.join("index.json"), &self.index)
    }
}

fn validate_registry(index: &RegistryIndex) -> Result<(), String> {
    if index.format_version != REGISTRY_FORMAT_VERSION
        || index.packages.values().map(BTreeMap::len).sum::<usize>() > MAX_REGISTRY_VERSIONS
        || index.transparency.len() > MAX_TRANSPARENCY_ENTRIES
    {
        return Err("invalid or oversized registry index".into());
    }
    let mut previous = "0".repeat(64);
    let mut logged = BTreeSet::new();
    for (position, entry) in index.transparency.iter().enumerate() {
        if entry.sequence != position as u64
            || entry.previous_sha256 != previous
            || transparency_hash(entry)? != entry.entry_sha256
        {
            return Err("transparency log chain is invalid".into());
        }
        validate_digest(&entry.package_sha256, "transparency package digest")?;
        validate_digest(&entry.key_id, "transparency key id")?;
        if !logged.insert((
            entry.cartridge_id.clone(),
            entry.version.clone(),
            entry.package_sha256.clone(),
            entry.key_id.clone(),
        )) {
            return Err("transparency log contains a duplicate entry".into());
        }
        previous.clone_from(&entry.entry_sha256);
    }
    let versions = index.packages.values().map(BTreeMap::len).sum::<usize>();
    if logged.len() != versions {
        return Err(
            "registry index and transparency log do not describe the same version count".into(),
        );
    }
    for (id, package_versions) in &index.packages {
        for (version, value) in package_versions {
            if &value.identity.cartridge_id != id
                || &value.identity.version != version
                || !logged.contains(&(
                    id.clone(),
                    version.clone(),
                    value.identity.package_sha256.clone(),
                    value.key_id.clone(),
                ))
            {
                return Err("registry version is not bound to its transparency entry".into());
            }
            Version::parse(version)
                .map_err(|_| "registry version is not semantic versioning".to_string())?;
            validate_signature_identity(&value.identity)?;
            validate_digest(&value.key_id, "registry signing key id")?;
        }
    }
    Ok(())
}

fn transparency_hash(entry: &TransparencyEntry) -> Result<String, String> {
    let bytes = serde_json::to_vec(&serde_json::json!({"sequence":entry.sequence,"cartridge_id":entry.cartridge_id,"version":entry.version,"package_sha256":entry.package_sha256,"key_id":entry.key_id,"previous_sha256":entry.previous_sha256})).map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn package_identity_and_bytes(path: &Path) -> Result<(PackageIdentity, Vec<u8>), String> {
    let bytes = read_bounded(path, MAX_PACKAGE_BYTES)?;
    let identity = package_identity(&bytes)?;
    Ok((identity, bytes))
}

fn package_identity(bytes: &[u8]) -> Result<PackageIdentity, String> {
    let archive =
        CartridgeArchive::open_bytes(bytes.to_vec()).map_err(|error| error.to_string())?;
    let identity = PackageIdentity {
        cartridge_id: archive.manifest.cartridge.id,
        version: archive.manifest.cartridge.version,
        package_sha256: hex::encode(Sha256::digest(bytes)),
        package_bytes: bytes.len() as u64,
        component_sha256: archive.manifest.integrity.component_sha256,
        assets_root_sha256: archive.manifest.integrity.assets_root_sha256,
    };
    Ok(identity)
}

pub fn read_signature(path: &Path) -> Result<PackageSignature, String> {
    read_json(path, MAX_IDENTITY_DOCUMENT_BYTES)
}
pub fn write_signature(path: &Path, value: &PackageSignature) -> Result<(), String> {
    validate_signature_document(value)?;
    write_json_new(path, value)
}
pub fn read_rotation(path: &Path) -> Result<KeyRotation, String> {
    let value = read_json(path, MAX_IDENTITY_DOCUMENT_BYTES)?;
    KeyRotation::verify(&value)?;
    Ok(value)
}
pub fn write_rotation(path: &Path, value: &KeyRotation) -> Result<(), String> {
    value.verify()?;
    write_json_new(path, value)
}
pub fn read_revocation(path: &Path) -> Result<RevocationRecord, String> {
    let value = read_json(path, MAX_IDENTITY_DOCUMENT_BYTES)?;
    RevocationRecord::verify(&value)?;
    Ok(value)
}
pub fn write_revocation(path: &Path, value: &RevocationRecord) -> Result<(), String> {
    value.verify()?;
    write_json_new(path, value)
}

fn package_signature_payload(identity: &PackageIdentity, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if identity.package_sha256 != hex::encode(Sha256::digest(bytes))
        || identity.package_bytes != bytes.len() as u64
    {
        return Err("package identity does not match bytes".into());
    }
    let encoded = serde_json::to_vec(identity).map_err(|error| error.to_string())?;
    Ok(framed_payload(b"cartridge-package-signature-v1", &encoded))
}

fn validate_signature_document(value: &PackageSignature) -> Result<(), String> {
    if value.format_version != SIGNATURE_FORMAT_VERSION || value.algorithm != "ed25519" {
        return Err("unsupported package signature format".into());
    }
    validate_signature_identity(&value.identity)?;
    Ok(())
}

fn validate_signature_identity(identity: &PackageIdentity) -> Result<(), String> {
    validate_digest(&identity.package_sha256, "package digest")?;
    validate_digest(&identity.component_sha256, "component digest")?;
    if !identity.assets_root_sha256.is_empty() {
        validate_digest(&identity.assets_root_sha256, "asset root digest")?;
    }
    if identity.package_bytes == 0 || identity.package_bytes > MAX_PACKAGE_BYTES {
        return Err("signed package byte length is invalid".into());
    }
    Version::parse(&identity.version)
        .map_err(|_| "signed package version is invalid".to_string())?;
    Ok(())
}

fn verify_detached(
    public: &str,
    domain: &[u8],
    bytes: &[u8],
    signature: &str,
) -> Result<(), String> {
    let public = verifying_key(public)?;
    let signature = Signature::from_bytes(&decode_array::<64>(signature, "signature")?);
    public
        .verify(&framed_payload(domain, bytes), &signature)
        .map_err(|_| "detached signature verification failed".into())
}

fn verifying_key(value: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&decode_array::<32>(value, "public key")?)
        .map_err(|_| "public key is invalid".into())
}

fn framed_payload(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.len() + bytes.len() + 16);
    payload.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    payload.extend_from_slice(bytes);
    payload
}

fn key_id(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}

fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{label} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is not a SHA-256 digest"));
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err("label is empty, too long, or contains controls".into());
    }
    Ok(())
}

fn permission_names(manifest: &PackageManifest) -> Vec<String> {
    let p = &manifest.permissions;
    [
        ("clock", p.clock),
        ("random", p.random),
        ("assets", p.assets),
        ("storage", p.storage),
        ("graphics", p.graphics),
        ("audio", p.audio),
        ("midi", p.midi),
    ]
    .into_iter()
    .filter(|(_, enabled)| *enabled)
    .map(|(name, _)| name.into())
    .collect()
}

fn rand_secret() -> [u8; 32] {
    rand::random()
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis(),
    )
    .map_err(|_| "timestamp overflow".into())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    if fs::metadata(path).map_err(|error| error.to_string())?.len() > limit {
        return Err(format!("file exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "file exceeded the {limit}-byte limit while reading"
        ));
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path, limit)?).map_err(|error| error.to_string())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_IDENTITY_DOCUMENT_BYTES {
        return Err("identity document exceeds its size limit".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

fn write_private_json_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    write_json_new(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn atomic_json_replace(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_IDENTITY_DOCUMENT_BYTES {
        return Err("registry document exceeds its size limit".into());
    }
    let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("json.{}-{sequence}.tmp", std::process::id()));
    let backup = path.with_extension("json.previous");
    write_json_new(&temp, value)?;
    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup).map_err(|error| error.to_string())?;
        }
        fs::rename(path, &backup).map_err(|error| error.to_string())?;
    }
    if let Err(error) = fs::rename(&temp, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        let _ = fs::remove_file(&temp);
        return Err(error.to_string());
    }
    if backup.exists() {
        fs::remove_file(backup).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn recover_registry_index(path: &Path) -> Result<(), String> {
    let backup = path.with_extension("json.previous");
    if !backup.exists() {
        return Ok(());
    }
    let backup_valid = read_json::<RegistryIndex>(&backup, MAX_IDENTITY_DOCUMENT_BYTES)
        .and_then(|value| validate_registry(&value))
        .is_ok();
    if !path.exists() {
        if !backup_valid {
            return Err("registry index recovery backup is invalid".into());
        }
        fs::rename(backup, path).map_err(|error| error.to_string())?;
        return Ok(());
    }
    let current_valid = read_json::<RegistryIndex>(path, MAX_IDENTITY_DOCUMENT_BYTES)
        .and_then(|value| validate_registry(&value))
        .is_ok();
    if current_valid {
        fs::remove_file(backup).map_err(|error| error.to_string())?;
        return Ok(());
    }
    if !backup_valid {
        return Err("registry index and recovery backup are invalid".into());
    }
    let corrupt = path.with_extension("json.corrupt");
    if corrupt.exists() {
        return Err("registry recovery quarantine already exists".into());
    }
    fs::rename(path, corrupt).map_err(|error| error.to_string())?;
    fs::rename(backup, path).map_err(|error| error.to_string())
}

fn write_bytes_new(destination: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

fn acquire_lock(file: &File) -> Result<(), String> {
    for _ in 0..200 {
        match FileExt::try_lock(file) {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(TryLockError::Error(error)) => return Err(error.to_string()),
        }
    }
    Err("registry is busy".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartridge_core::{PackOptions, pack};

    fn package(root: &Path, version: &str) -> PathBuf {
        let manifest = root.join(format!("{version}.toml"));
        let component = root.join(format!("{version}.wasm"));
        let output = root.join(format!("{version}.cartridge"));
        fs::write(&manifest, format!("format_version = 1\n[cartridge]\nid = \"dev.test.signed\"\nname = \"Signed\"\nversion = \"{version}\"\n")).unwrap();
        fs::write(&component, b"\0asm\x01\0\0\0").unwrap();
        pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output: output.clone(),
        })
        .unwrap();
        output
    }

    #[test]
    fn exact_package_bytes_are_signed() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0");
        let key = DeveloperKey::generate();
        let signature = key.sign_package(&package).unwrap();
        verify_package(&package, &signature).unwrap();
        let mut bytes = fs::read(&package).unwrap();
        bytes.push(0);
        let changed = directory.path().join("changed.cartridge");
        fs::write(&changed, bytes).unwrap();
        assert!(verify_package(&changed, &signature).is_err());
    }

    #[test]
    fn trust_rotation_and_recovery_revocation_work() {
        let old = DeveloperKey::generate();
        let new = DeveloperKey::generate();
        let recovery = DeveloperKey::generate();
        let mut trust = TrustStore::new();
        trust
            .trust(
                old.public_key(),
                "developer",
                BTreeSet::from([recovery.key_id()]),
            )
            .unwrap();
        trust
            .apply_rotation(KeyRotation::create(&old, &new, "routine rotation").unwrap())
            .unwrap();
        trust
            .apply_revocation(
                RevocationRecord::create(new.key_id(), &recovery, "lost key").unwrap(),
            )
            .unwrap();
        assert!(trust.revoked.contains_key(&new.key_id()));
    }

    #[test]
    fn registry_versions_are_immutable_and_transparent() {
        let directory = tempfile::tempdir().unwrap();
        let package = package(directory.path(), "1.0.0");
        let key = DeveloperKey::generate();
        let signature = key.sign_package(&package).unwrap();
        let mut trust = TrustStore::new();
        trust
            .trust(key.public_key(), "developer", BTreeSet::new())
            .unwrap();
        let mut registry = Registry::open(directory.path().join("registry")).unwrap();
        registry.publish(&package, &signature, &trust).unwrap();
        assert_eq!(registry.transparency().len(), 1);
        assert!(registry.resolve("dev.test.signed", "^1").unwrap().is_some());
    }
}

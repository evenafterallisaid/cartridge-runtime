use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::random;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{is_digest, valid_text};

pub const ENGINE_PROBE_FORMAT_VERSION: u32 = 1;
pub const MIN_PROBE_TIMEOUT_MS: u64 = 100;
pub const MAX_PROBE_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const MAX_PROBE_FAILURE_THRESHOLD: u16 = 10;
pub const MAX_PROBE_ENVELOPE_BYTES: usize = 4096;
const PROBE_ASSOCIATED_DATA: &[u8] = b"cartridge-application-health-v1";
const MAX_PROBE_DETAIL_BYTES: usize = 512;

pub struct ProbeChannelKey([u8; 32]);

impl ProbeChannelKey {
    #[must_use]
    pub fn generate() -> Self {
        Self(random())
    }

    pub fn from_hex(value: &str) -> Result<Self, String> {
        if value.len() != 64 || !lower_hex(value) {
            return Err("probe channel key is invalid".into());
        }
        let key = hex::decode(value)
            .map_err(|_| "probe channel key is invalid".to_string())?
            .try_into()
            .map_err(|_| "probe channel key has the wrong length".to_string())?;
        Ok(Self(key))
    }

    #[must_use]
    pub fn expose_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ProbeChannelKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProbeChannelKey")
            .field(&"[redacted]")
            .finish()
    }
}

impl Drop for ProbeChannelKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeSignalKind {
    Started,
    Ready,
    Heartbeat,
    Unhealthy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSignal {
    pub format_version: u32,
    pub run_id: String,
    pub sequence: u64,
    pub emitted_at_ms: u64,
    pub kind: ProbeSignalKind,
    pub detail: String,
}

impl ProbeSignal {
    pub fn new(
        run_id: &str,
        sequence: u64,
        emitted_at_ms: u64,
        kind: ProbeSignalKind,
        detail: impl Into<String>,
    ) -> Result<Self, String> {
        let value = Self {
            format_version: ENGINE_PROBE_FORMAT_VERSION,
            run_id: run_id.into(),
            sequence,
            emitted_at_ms,
            kind,
            detail: detail.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_PROBE_FORMAT_VERSION
            || !is_digest(&self.run_id)
            || self.sequence == 0
            || self.emitted_at_ms == 0
            || self.detail.len() > MAX_PROBE_DETAIL_BYTES
            || !valid_text(&self.detail, MAX_PROBE_DETAIL_BYTES, true)
        {
            return Err("application health signal is invalid".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeEnvelope {
    pub format_version: u32,
    pub run_id: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl ProbeEnvelope {
    pub fn seal(signal: &ProbeSignal, key: &ProbeChannelKey) -> Result<Vec<u8>, String> {
        signal.validate()?;
        let plaintext = serde_json::to_vec(signal).map_err(|error| error.to_string())?;
        let nonce = random::<[u8; 24]>();
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "probe nonce has the wrong length".to_string())?;
        let cipher = XChaCha20Poly1305::new((&key.0).into());
        let associated = associated_data(&signal.run_id);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: &associated,
                },
            )
            .map_err(|_| "probe signal encryption failed".to_string())?;
        let envelope = Self {
            format_version: ENGINE_PROBE_FORMAT_VERSION,
            run_id: signal.run_id.clone(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };
        envelope.validate()?;
        let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_PROBE_ENVELOPE_BYTES {
            return Err("probe envelope exceeds its byte limit".into());
        }
        Ok(bytes)
    }

    pub fn open(
        bytes: &[u8],
        expected_run_id: &str,
        key: &ProbeChannelKey,
    ) -> Result<ProbeSignal, String> {
        if bytes.is_empty() || bytes.len() > MAX_PROBE_ENVELOPE_BYTES || !is_digest(expected_run_id)
        {
            return Err("probe envelope exceeds its byte limit or has invalid context".into());
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| "probe envelope is invalid".to_string())?;
        envelope.validate()?;
        if envelope.run_id != expected_run_id {
            return Err("probe envelope belongs to another worker run".into());
        }
        let nonce: [u8; 24] = hex::decode(&envelope.nonce_hex)
            .map_err(|_| "probe nonce is invalid".to_string())?
            .try_into()
            .map_err(|_| "probe nonce has the wrong length".to_string())?;
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "probe nonce has the wrong length".to_string())?;
        let ciphertext = hex::decode(&envelope.ciphertext_hex)
            .map_err(|_| "probe ciphertext is invalid".to_string())?;
        let cipher = XChaCha20Poly1305::new((&key.0).into());
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data(expected_run_id),
                },
            )
            .map_err(|_| "probe signal authentication failed".to_string())?;
        let signal: ProbeSignal = serde_json::from_slice(&plaintext)
            .map_err(|_| "probe signal plaintext is invalid".to_string())?;
        signal.validate()?;
        if signal.run_id != expected_run_id {
            return Err("probe signal belongs to another worker run".into());
        }
        Ok(signal)
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != ENGINE_PROBE_FORMAT_VERSION
            || !is_digest(&self.run_id)
            || self.nonce_hex.len() != 48
            || !lower_hex(&self.nonce_hex)
            || self.ciphertext_hex.is_empty()
            || self.ciphertext_hex.len() > MAX_PROBE_ENVELOPE_BYTES.saturating_mul(2)
            || self.ciphertext_hex.len() % 2 != 0
            || !lower_hex(&self.ciphertext_hex)
        {
            return Err("probe envelope is invalid".into());
        }
        Ok(())
    }
}

fn associated_data(run_id: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(PROBE_ASSOCIATED_DATA.len() + run_id.len());
    value.extend_from_slice(PROBE_ASSOCIATED_DATA);
    value.extend_from_slice(run_id.as_bytes());
    value
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_signals_are_run_bound_and_tamper_evident() {
        let key = ProbeChannelKey::generate();
        let run_id = "a".repeat(64);
        let signal = ProbeSignal::new(&run_id, 1, 10, ProbeSignalKind::Ready, "ready").unwrap();
        let bytes = ProbeEnvelope::seal(&signal, &key).unwrap();

        assert_eq!(ProbeEnvelope::open(&bytes, &run_id, &key).unwrap(), signal);
        assert!(ProbeEnvelope::open(&bytes, &"b".repeat(64), &key).is_err());
        let mut changed = bytes;
        let index = changed.len() - 3;
        changed[index] = if changed[index] == b'a' { b'b' } else { b'a' };
        assert!(ProbeEnvelope::open(&changed, &run_id, &key).is_err());
    }

    #[test]
    fn keys_and_details_are_bounded_and_redacted() {
        let key = ProbeChannelKey::generate();
        let encoded = key.expose_hex();
        assert!(!format!("{key:?}").contains(&encoded));
        assert!(ProbeChannelKey::from_hex(&encoded).is_ok());
        assert!(
            ProbeSignal::new(
                &"a".repeat(64),
                1,
                1,
                ProbeSignalKind::Unhealthy,
                "x".repeat(MAX_PROBE_DETAIL_BYTES + 1),
            )
            .is_err()
        );
    }
}

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::HostState;

impl HostState {
    pub(super) fn get_storage(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record("storage", "get", json!({ "key": key, "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("storage", "get") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "key", &Value::from(key))?;
            let result = decode_recorded_get(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            self.record("storage", "get", outcome);
            return result;
        }
        match self.storage.get(&self.storage_namespace, key) {
            Ok(Some(bytes)) => {
                self.record(
                    "storage",
                    "get",
                    json!({
                        "key": key,
                        "found": true,
                        "length": bytes.len(),
                        "sha256": hex::encode(Sha256::digest(&bytes)),
                        "bytes": hex::encode(&bytes),
                    }),
                );
                Ok(Some(bytes))
            }
            Ok(None) => {
                self.record("storage", "get", json!({ "key": key, "found": false }));
                Ok(None)
            }
            Err(error) => {
                let error = error.to_string();
                self.record("storage", "get", json!({ "key": key, "error": error }));
                Err(error)
            }
        }
    }

    pub(super) fn put_storage(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record("storage", "put", json!({ "key": key, "denied": error }));
            return Err(error);
        }
        let length = value.len();
        let sha256 = hex::encode(Sha256::digest(value));
        if let Some(outcome) = self.replay_outcome("storage", "put") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "key", &Value::from(key))?;
            self.check_replay_field(&outcome, "length", &Value::from(length))?;
            self.check_replay_field(&outcome, "sha256", &Value::from(sha256.clone()))?;
            let result = decode_recorded_unit(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            self.record("storage", "put", outcome);
            return result;
        }
        match self
            .storage
            .put(&self.storage_namespace, key, value, self.storage_limits)
        {
            Ok(()) => {
                self.record(
                    "storage",
                    "put",
                    json!({ "key": key, "length": length, "sha256": sha256, "stored": true }),
                );
                Ok(())
            }
            Err(error) => {
                let error = error.to_string();
                self.record(
                    "storage",
                    "put",
                    json!({ "key": key, "length": length, "sha256": sha256, "error": error }),
                );
                Err(error)
            }
        }
    }

    pub(super) fn delete_storage(&mut self, key: &str) -> Result<bool, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record("storage", "delete", json!({ "key": key, "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("storage", "delete") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "key", &Value::from(key))?;
            let result = decode_recorded_bool(&outcome, "deleted").inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            self.record("storage", "delete", outcome);
            return result;
        }
        match self.storage.delete(&self.storage_namespace, key) {
            Ok(deleted) => {
                self.record(
                    "storage",
                    "delete",
                    json!({ "key": key, "deleted": deleted }),
                );
                Ok(deleted)
            }
            Err(error) => {
                let error = error.to_string();
                self.record("storage", "delete", json!({ "key": key, "error": error }));
                Err(error)
            }
        }
    }

    pub(super) fn list_storage(&mut self, prefix: &str) -> Result<Vec<String>, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record(
                "storage",
                "list",
                json!({ "prefix": prefix, "denied": error }),
            );
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("storage", "list") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "prefix", &Value::from(prefix))?;
            let result = decode_recorded_list(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            self.record("storage", "list", outcome);
            return result;
        }
        match self.storage.list(&self.storage_namespace, prefix) {
            Ok(keys) => {
                self.record("storage", "list", json!({ "prefix": prefix, "keys": keys }));
                Ok(keys)
            }
            Err(error) => {
                let error = error.to_string();
                self.record(
                    "storage",
                    "list",
                    json!({ "prefix": prefix, "error": error }),
                );
                Err(error)
            }
        }
    }

    fn check_replay_field(
        &mut self,
        outcome: &Value,
        field: &str,
        actual: &Value,
    ) -> Result<(), String> {
        if outcome.get(field) == Some(actual) {
            return Ok(());
        }
        let error = format!(
            "recorded storage {field} was {}, guest supplied {actual}",
            outcome.get(field).unwrap_or(&Value::Null)
        );
        self.set_divergence(error.clone());
        Err(error)
    }
}

fn recorded_error(outcome: &Value) -> Option<String> {
    outcome
        .get("error")
        .or_else(|| outcome.get("denied"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn decode_recorded_get(outcome: &Value) -> Result<Option<Vec<u8>>, String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    match outcome.get("found").and_then(Value::as_bool) {
        Some(false) => Ok(None),
        Some(true) => {
            let encoded = outcome
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(|| "recorded storage value is missing bytes".to_owned())?;
            let bytes = hex::decode(encoded)
                .map_err(|error| format!("recorded storage bytes are invalid: {error}"))?;
            let length = outcome.get("length").and_then(Value::as_u64);
            if length != u64::try_from(bytes.len()).ok() {
                return Err("recorded storage value length does not match its bytes".into());
            }
            let digest = hex::encode(Sha256::digest(&bytes));
            if outcome.get("sha256").and_then(Value::as_str) != Some(&digest) {
                return Err("recorded storage value digest does not match its bytes".into());
            }
            Ok(Some(bytes))
        }
        None => Err("recorded storage get outcome is missing found".into()),
    }
}

fn decode_recorded_unit(outcome: &Value) -> Result<(), String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    if outcome.get("stored").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err("recorded storage put outcome is missing stored".into())
    }
}

fn decode_recorded_bool(outcome: &Value, field: &str) -> Result<bool, String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    outcome
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("recorded storage outcome is missing {field}"))
}

fn decode_recorded_list(outcome: &Value) -> Result<Vec<String>, String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    let keys = outcome
        .get("keys")
        .cloned()
        .ok_or_else(|| "recorded storage list outcome is missing keys".to_owned())?;
    serde_json::from_value(keys)
        .map_err(|error| format!("recorded storage keys are invalid: {error}"))
}

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use cartridge_storage::{
    MAX_TRANSACTION_INPUT_BYTES, MAX_TRANSACTION_OPERATIONS, StorageMutation,
    StorageTransactionResult,
};

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
            if self.apply_replay_storage {
                let actual = self
                    .storage
                    .get(&self.storage_namespace, key)
                    .map_err(|error| error.to_string())?;
                if result.as_ref().is_ok_and(|expected| expected != &actual) {
                    let error = "source state does not match recorded storage get".to_owned();
                    self.set_divergence(error.clone());
                    return Err(error);
                }
            }
            self.record("storage", "get", outcome);
            return result;
        }
        match self.storage.get(&self.storage_namespace, key) {
            Ok(Some(bytes)) => {
                if bytes.len() > self.storage_limits.max_value_bytes {
                    let error = format!(
                        "stored value exceeds the {}-byte runtime limit",
                        self.storage_limits.max_value_bytes
                    );
                    self.record(
                        "storage",
                        "get",
                        json!({ "key": key, "length": bytes.len(), "denied": error }),
                    );
                    return Err(error);
                }
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
            if self.apply_replay_storage && result.is_ok() {
                self.storage
                    .put(&self.storage_namespace, key, value, self.storage_limits)
                    .map_err(|error| {
                        let error = format!("replayed storage put failed: {error}");
                        self.set_divergence(error.clone());
                        error
                    })?;
            }
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
            if self.apply_replay_storage {
                if let Ok(expected) = &result {
                    let actual = self
                        .storage
                        .delete(&self.storage_namespace, key)
                        .map_err(|error| error.to_string())?;
                    if actual != *expected {
                        let error =
                            "source state does not match recorded storage delete".to_owned();
                        self.set_divergence(error.clone());
                        return Err(error);
                    }
                }
            }
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
            if self.apply_replay_storage {
                let actual = self
                    .storage
                    .list(&self.storage_namespace, prefix)
                    .map_err(|error| error.to_string())?;
                if result.as_ref().is_ok_and(|expected| expected != &actual) {
                    let error = "source state does not match recorded storage list".to_owned();
                    self.set_divergence(error.clone());
                    return Err(error);
                }
            }
            self.record("storage", "list", outcome);
            return result;
        }
        match self.storage.list(&self.storage_namespace, prefix) {
            Ok(keys) => {
                if keys.len() > self.storage_limits.max_keys {
                    let error = format!(
                        "stored key count exceeds the {}-key runtime limit",
                        self.storage_limits.max_keys
                    );
                    self.record(
                        "storage",
                        "list",
                        json!({ "prefix": prefix, "count": keys.len(), "denied": error }),
                    );
                    return Err(error);
                }
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

    pub(super) fn storage_revision(&mut self) -> Result<u64, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record("storage", "revision", json!({ "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("storage", "revision") {
            let outcome = outcome?;
            let result = decode_recorded_revision(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            if self.apply_replay_storage {
                let actual = self
                    .storage
                    .revision(&self.storage_namespace)
                    .map_err(|error| error.to_string())?;
                if result.as_ref().is_ok_and(|expected| *expected != actual) {
                    let error = "source state does not match recorded storage revision".to_owned();
                    self.set_divergence(error.clone());
                    return Err(error);
                }
            }
            self.record("storage", "revision", outcome);
            return result;
        }
        match self.storage.revision(&self.storage_namespace) {
            Ok(revision) => {
                self.record("storage", "revision", json!({ "revision": revision }));
                Ok(revision)
            }
            Err(error) => {
                let error = error.to_string();
                self.record("storage", "revision", json!({ "error": error }));
                Err(error)
            }
        }
    }

    pub(super) fn compare_exchange_storage(
        &mut self,
        revision: u64,
        key: &str,
        expected: Option<&[u8]>,
        replacement: Option<&[u8]>,
    ) -> Result<StorageTransactionResult, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record(
                "storage",
                "compare-exchange",
                json!({ "key": key, "denied": error }),
            );
            return Err(error);
        }
        let (expected_value, replacement_value) = value_identities(expected, replacement);
        if let Some(outcome) = self.replay_outcome("storage", "compare-exchange") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "revision", &Value::from(revision))?;
            self.check_replay_field(&outcome, "key", &Value::from(key))?;
            self.check_replay_field(&outcome, "expected", &expected_value)?;
            self.check_replay_field(&outcome, "replacement", &replacement_value)?;
            let result = decode_recorded_transaction(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            if self.apply_replay_storage {
                if let Ok(recorded) = result {
                    let actual = match self.storage.compare_exchange(
                        &self.storage_namespace,
                        revision,
                        key,
                        expected,
                        replacement,
                        self.storage_limits,
                    ) {
                        Ok(actual) => actual,
                        Err(error) => {
                            let error =
                                format!("replayed storage compare-exchange failed: {error}");
                            self.set_divergence(error.clone());
                            return Err(error);
                        }
                    };
                    if actual != recorded {
                        let error = "source state does not match recorded compare-exchange result"
                            .to_owned();
                        self.set_divergence(error.clone());
                        return Err(error);
                    }
                    self.record("storage", "compare-exchange", outcome);
                    return Ok(recorded);
                }
            }
            self.record("storage", "compare-exchange", outcome);
            return result;
        }
        let result = self.storage.compare_exchange(
            &self.storage_namespace,
            revision,
            key,
            expected,
            replacement,
            self.storage_limits,
        );
        self.record_transaction(
            "compare-exchange",
            json!({
                "revision": revision,
                "key": key,
                "expected": expected_value,
                "replacement": replacement_value,
            }),
            result,
        )
    }

    pub(super) fn apply_storage_batch(
        &mut self,
        revision: u64,
        mutations: &[StorageMutation],
    ) -> Result<StorageTransactionResult, String> {
        let request = mutation_identity(mutations);
        self.apply_storage_batch_request(revision, Some(mutations), &request)
    }

    pub(super) fn reject_oversized_storage_batch(
        &mut self,
        revision: u64,
        operations: usize,
    ) -> Result<StorageTransactionResult, String> {
        let request = json!({ "operations": operations, "oversized": true });
        self.apply_storage_batch_request(revision, None, &request)
    }

    fn apply_storage_batch_request(
        &mut self,
        revision: u64,
        mutations: Option<&[StorageMutation]>,
        request: &Value,
    ) -> Result<StorageTransactionResult, String> {
        if !self.permissions.storage {
            let error = "storage capability was not granted".to_owned();
            self.record("storage", "apply", json!({ "denied": error }));
            return Err(error);
        }
        if let Some(outcome) = self.replay_outcome("storage", "apply") {
            let outcome = outcome?;
            self.check_replay_field(&outcome, "revision", &Value::from(revision))?;
            self.check_replay_field(&outcome, "request", request)?;
            let result = decode_recorded_transaction(&outcome).inspect_err(|error| {
                self.set_divergence(error.clone());
            });
            if self.apply_replay_storage {
                if let Ok(recorded) = result {
                    let Some(mutations) = mutations else {
                        let error =
                            "recorded oversized storage batch unexpectedly succeeded".to_owned();
                        self.set_divergence(error.clone());
                        return Err(error);
                    };
                    let actual = match self.storage.apply_batch(
                        &self.storage_namespace,
                        revision,
                        mutations,
                        self.storage_limits,
                    ) {
                        Ok(actual) => actual,
                        Err(error) => {
                            let error = format!("replayed storage batch failed: {error}");
                            self.set_divergence(error.clone());
                            return Err(error);
                        }
                    };
                    if actual != recorded {
                        let error =
                            "source state does not match recorded storage batch result".to_owned();
                        self.set_divergence(error.clone());
                        return Err(error);
                    }
                    self.record("storage", "apply", outcome);
                    return Ok(recorded);
                }
            }
            self.record("storage", "apply", outcome);
            return result;
        }
        let result = mutations.map_or_else(
            || Err(cartridge_storage::Error::InvalidTransaction),
            |mutations| {
                self.storage.apply_batch(
                    &self.storage_namespace,
                    revision,
                    mutations,
                    self.storage_limits,
                )
            },
        );
        self.record_transaction(
            "apply",
            json!({
                "revision": revision,
                "request": request,
            }),
            result,
        )
    }

    fn record_transaction(
        &mut self,
        operation: &str,
        mut identity: Value,
        result: cartridge_storage::Result<StorageTransactionResult>,
    ) -> Result<StorageTransactionResult, String> {
        let object = identity
            .as_object_mut()
            .ok_or_else(|| "storage trace identity is not an object".to_owned())?;
        match result {
            Ok(result) => {
                object.insert("applied".into(), Value::from(result.applied));
                object.insert("result_revision".into(), Value::from(result.revision));
                self.record("storage", operation, identity);
                Ok(result)
            }
            Err(error) => {
                let error = error.to_string();
                object.insert("error".into(), Value::from(error.clone()));
                self.record("storage", operation, identity);
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

fn decode_recorded_revision(outcome: &Value) -> Result<u64, String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    outcome
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| "recorded storage revision is missing".to_owned())
}

fn decode_recorded_transaction(outcome: &Value) -> Result<StorageTransactionResult, String> {
    if let Some(error) = recorded_error(outcome) {
        return Err(error);
    }
    let applied = outcome
        .get("applied")
        .and_then(Value::as_bool)
        .ok_or_else(|| "recorded storage transaction is missing applied".to_owned())?;
    let revision = outcome
        .get("result_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| "recorded storage transaction is missing its revision".to_owned())?;
    Ok(StorageTransactionResult { applied, revision })
}

fn value_identity(value: Option<&[u8]>, hash: bool) -> Value {
    value.map_or(Value::Null, |value| {
        if hash {
            json!({
                "length": value.len(),
                "sha256": hex::encode(Sha256::digest(value)),
            })
        } else {
            json!({ "length": value.len(), "oversized": true })
        }
    })
}

fn value_identities(expected: Option<&[u8]>, replacement: Option<&[u8]>) -> (Value, Value) {
    let total = expected
        .map_or(0, <[u8]>::len)
        .checked_add(replacement.map_or(0, <[u8]>::len));
    let hash = total.is_some_and(|total| total <= MAX_TRANSACTION_INPUT_BYTES);
    (
        value_identity(expected, hash),
        value_identity(replacement, hash),
    )
}

fn mutation_identity(mutations: &[StorageMutation]) -> Value {
    if mutations.len() > MAX_TRANSACTION_OPERATIONS {
        return json!({ "operations": mutations.len(), "oversized": true });
    }
    let input_bytes = mutations.iter().try_fold(0usize, |total, mutation| {
        total.checked_add(mutation.key.len()).and_then(|bytes| {
            mutation
                .value
                .as_ref()
                .map_or(Some(bytes), |value| bytes.checked_add(value.len()))
        })
    });
    let Some(input_bytes) = input_bytes else {
        return json!({
            "operations": mutations.len(),
            "input_bytes": u64::MAX,
            "oversized": true,
        });
    };
    if input_bytes > MAX_TRANSACTION_INPUT_BYTES {
        return json!({
            "operations": mutations.len(),
            "input_bytes": input_bytes,
            "oversized": true,
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(b"cartridge-storage-batch-v1\0");
    hasher.update(
        u64::try_from(mutations.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for mutation in mutations {
        hasher.update(
            u64::try_from(mutation.key.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(mutation.key.as_bytes());
        if let Some(value) = &mutation.value {
            hasher.update([1]);
            hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(value);
        } else {
            hasher.update([0]);
        }
    }
    json!({
        "operations": mutations.len(),
        "input_bytes": input_bytes,
        "sha256": hex::encode(hasher.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_batch_identities_do_not_hash_guest_values() {
        let too_many = vec![
            StorageMutation {
                key: String::new(),
                value: None,
            };
            MAX_TRANSACTION_OPERATIONS + 1
        ];
        assert_eq!(
            mutation_identity(&too_many),
            json!({
                "operations": MAX_TRANSACTION_OPERATIONS + 1,
                "oversized": true,
            })
        );

        let too_large = [StorageMutation {
            key: "key".into(),
            value: Some(vec![0; MAX_TRANSACTION_INPUT_BYTES + 1]),
        }];
        let identity = mutation_identity(&too_large);
        assert_eq!(identity.get("oversized"), Some(&Value::Bool(true)));
        assert!(identity.get("sha256").is_none());
    }
}

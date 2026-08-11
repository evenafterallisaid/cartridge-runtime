#![no_main]

use cartridge_storage::{
    MemoryStorage, StorageBackend, StorageLimits, StorageMutation, StorageUsage,
};
use libfuzzer_sys::fuzz_target;

const NAMESPACE: &str = "dev.example.fuzz";
const LIMITS: StorageLimits = StorageLimits {
    max_bytes: 4096,
    max_keys: 32,
    max_value_bytes: 512,
};

fuzz_target!(|data: &[u8]| {
    let storage = MemoryStorage::new();
    if storage.prepare(NAMESPACE, 0, LIMITS).is_err() {
        return;
    }
    let mutations: Vec<_> = data
        .chunks(4)
        .enumerate()
        .map(|(index, chunk)| StorageMutation {
            key: format!("fuzz/{}", index % 40),
            value: (chunk.first().copied().unwrap_or_default() & 1 != 0).then(|| chunk.to_vec()),
        })
        .collect();
    let result = storage.apply_batch(NAMESPACE, 0, &mutations, LIMITS);
    match result {
        Ok(result) => {
            assert!(result.applied);
            assert_eq!(storage.revision(NAMESPACE).ok(), Some(result.revision));
            let repeated = storage
                .apply_batch(NAMESPACE, 0, &mutations, LIMITS)
                .expect("a previously validated batch must remain valid");
            assert_eq!(repeated.applied, result.revision == 0);
        }
        Err(_) => {
            assert_eq!(storage.revision(NAMESPACE).ok(), Some(0));
            assert_eq!(storage.usage(NAMESPACE).ok(), Some(StorageUsage::default()));
        }
    }
});

#![no_main]

use cartridge_storage::StorageSnapshot;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(snapshot) = StorageSnapshot::from_slice(data) {
        let _ = snapshot.blob_references();
    }
});

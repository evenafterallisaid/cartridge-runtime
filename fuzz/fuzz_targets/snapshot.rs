#![no_main]

use cartridge_storage::StorageSnapshot;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = StorageSnapshot::from_slice(data);
});

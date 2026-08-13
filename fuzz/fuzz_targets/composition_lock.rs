#![no_main]

use cartridge_core::CompositionLock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(lock) = serde_json::from_slice::<CompositionLock>(data) {
        let _ = lock.validate();
    }
});

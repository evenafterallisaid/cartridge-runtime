#![no_main]

use cartridge_release::SignedRelease;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(release) = serde_json::from_slice::<SignedRelease>(data) {
        let _ = release.payload.validate();
    }
});

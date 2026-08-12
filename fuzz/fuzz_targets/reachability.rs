#![no_main]

use cartridge_storage::BlobReachabilityManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = BlobReachabilityManifest::from_slice(data) {
        let _ = manifest.summary();
    }
});

#![no_main]

use cartridge_core::PackageManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(manifest) = toml::from_str::<PackageManifest>(text) {
        let _ = manifest.validate();
    }
});

#![no_main]

use std::io::Write;

use cartridge_core::CartridgeArchive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut file) = tempfile::NamedTempFile::new() else {
        return;
    };
    if file.write_all(data).is_ok() {
        let _ = CartridgeArchive::open(file.path());
    }
});

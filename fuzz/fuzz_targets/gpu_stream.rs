#![no_main]

use cartridge_desktop::{RenderPolicy, ValidatedGpuStream};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ValidatedGpuStream::parse(data.to_vec(), &RenderPolicy::canonical());
});

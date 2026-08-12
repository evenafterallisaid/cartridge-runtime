#![no_main]

use cartridge_media::{AudioLimits, render_audio_document};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = render_audio_document(
        data,
        AudioLimits {
            max_nodes: 16,
            max_events: 128,
            max_frames: 4096,
            max_work_units: 65_536,
        },
    );
});

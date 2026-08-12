#![no_main]

use cartridge_media::{GraphicsLimits, HeadlessDisplay, WindowConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut display = HeadlessDisplay::new(GraphicsLimits {
        max_windows: 1,
        max_pixels: 4096,
        max_commands: 64,
        max_asset_bytes: 4096,
    });
    let window = display
        .open(WindowConfig { title: String::new(), width: 64, height: 64 })
        .unwrap();
    let _ = display.present(window, data, |_| None);
});

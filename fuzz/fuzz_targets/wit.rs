#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;
use wit_parser::Resolve;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut resolve = Resolve::default();
    let _ = resolve.push_str(Path::new("fuzz.wit"), text);
});

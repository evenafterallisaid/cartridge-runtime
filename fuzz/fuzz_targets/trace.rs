#![no_main]

use cartridge_trace::{ExecutionTrace, RedactionProfile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(trace) = serde_json::from_slice::<ExecutionTrace>(data) {
        let _ = trace.validate();
        let _ = trace.redact(RedactionProfile::Metadata);
    }
});

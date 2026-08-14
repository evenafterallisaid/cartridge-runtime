#![no_main]

use cartridge_engine::{EngineEvent, StackManifest, StackPlan, StackRuntimeStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = StackManifest::parse(text);
    }
    if let Ok(plan) = serde_json::from_slice::<StackPlan>(data) {
        let _ = plan.validate();
    }
    if let Ok(event) = serde_json::from_slice::<EngineEvent>(data) {
        let _ = event.validate();
    }
    if let Ok(status) = serde_json::from_slice::<StackRuntimeStatus>(data) {
        let _ = status.validate();
    }
});

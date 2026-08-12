mod bindings {
    wit_bindgen::generate!({ path: "../../wit", world: "cartridge" });
    use super::SynthCartridge;
    export!(SynthCartridge);
}

use bindings::cartridge::api::host::{audio_render, midi_next};

struct SynthCartridge;

impl bindings::Guest for SynthCartridge {
    fn run(_: Vec<String>) -> Result<String, String> {
        let graph = br#"{
            "frames":96000,
            "seed":19,
            "nodes":[
                {"type":"oscillator","id":0,"waveform":"saw","frequency_millihz":220000,"level_q15":12000},
                {"type":"low-pass","id":1,"input":0,"coefficient_q15":5200},
                {"type":"gain","id":2,"input":1,"gain_q15":24000},
                {"type":"output","id":3,"input":2}
            ],
            "events":[
                {"frame":24000,"node":0,"parameter":"frequency-millihz","value":277180},
                {"frame":48000,"node":0,"parameter":"frequency-millihz","value":329630},
                {"frame":72000,"node":0,"parameter":"frequency-millihz","value":440000}
            ]
        }"#;
        let receipt = audio_render(graph)?;
        let midi = midi_next()?.is_some();
        Ok(format!(
            "rendered {} frames {} midi={midi}",
            receipt.frames, receipt.wav_sha256
        ))
    }
}

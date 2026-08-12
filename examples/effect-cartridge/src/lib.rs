mod bindings {
    wit_bindgen::generate!({ path: "../../wit", world: "cartridge" });
    use super::EffectCartridge;
    export!(EffectCartridge);
}

use bindings::cartridge::api::host::audio_render;

struct EffectCartridge;

impl bindings::Guest for EffectCartridge {
    fn run(_: Vec<String>) -> Result<String, String> {
        let graph = br#"{
            "frames":48000,
            "seed":42,
            "nodes":[
                {"type":"oscillator","id":0,"waveform":"square","frequency_millihz":110000,"level_q15":10000},
                {"type":"delay","id":1,"input":0,"delay_frames":6000,"feedback_q15":15000,"mix_q15":12000},
                {"type":"output","id":2,"input":1}
            ],
            "events":[
                {"frame":24000,"node":1,"parameter":"mix-q15","value":22000}
            ]
        }"#;
        let receipt = audio_render(graph)?;
        Ok(format!(
            "effect rendered {} frames {}",
            receipt.frames, receipt.wav_sha256
        ))
    }
}

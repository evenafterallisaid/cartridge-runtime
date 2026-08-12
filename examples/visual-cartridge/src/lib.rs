mod bindings {
    wit_bindgen::generate!({ path: "../../wit", world: "cartridge" });
    use super::VisualCartridge;
    export!(VisualCartridge);
}

use bindings::cartridge::api::host::{
    WindowConfig, graphics_present, input_next, window_close, window_open,
};

struct VisualCartridge;

impl bindings::Guest for VisualCartridge {
    fn run(_: Vec<String>) -> Result<String, String> {
        let window = window_open(&WindowConfig {
            title: "cartridge visual reference".into(),
            width: 640,
            height: 480,
        })?;
        let frame = br#"{
            "logical_width":320,
            "logical_height":240,
            "simulation_tick":0,
            "commands":[
                {"type":"clear","color":{"r":10,"g":12,"b":20,"a":255}},
                {"type":"rect","x":24,"y":28,"width":272,"height":184,"color":{"r":28,"g":35,"b":56,"a":255}},
                {"type":"line","x1":24,"y1":212,"x2":296,"y2":28,"width":3,"color":{"r":95,"g":235,"b":180,"a":255}},
                {"type":"rect","x":112,"y":88,"width":96,"height":64,"color":{"r":135,"g":94,"b":255,"a":210}},
                {"type":"text","text":"CARTRIDGE","font":null,"x":115,"y":110,"scale":2,"color":{"r":245,"g":246,"b":250,"a":255}}
            ]
        }"#;
        let receipt = graphics_present(window, frame)?;
        let input = input_next()?.is_some();
        window_close(window)?;
        Ok(format!(
            "frame {} {}x{} {} input={input}",
            receipt.frame, receipt.width, receipt.height, receipt.png_sha256
        ))
    }
}

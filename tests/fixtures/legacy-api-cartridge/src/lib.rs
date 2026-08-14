mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "cartridge",
    });

    use super::LegacyApiCartridge;
    export!(LegacyApiCartridge);
}

struct LegacyApiCartridge;

impl bindings::Guest for LegacyApiCartridge {
    fn run(_args: Vec<String>) -> Result<String, String> {
        Ok("legacy 0.4 component ran".into())
    }
}

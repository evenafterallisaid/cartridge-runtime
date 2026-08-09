mod bindings {
    wit_bindgen::generate!({
        path: "../../../wit",
        world: "cartridge",
    });

    use super::TimeoutCartridge;
    export!(TimeoutCartridge);
}

struct TimeoutCartridge;

impl bindings::Guest for TimeoutCartridge {
    fn run(_args: Vec<String>) -> Result<String, String> {
        std::thread::sleep(std::time::Duration::from_secs(5));
        Ok("sleep returned".into())
    }
}

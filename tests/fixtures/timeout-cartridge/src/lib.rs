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
    fn run(args: Vec<String>) -> Result<String, String> {
        if args.first().is_some_and(|value| value == "ready-then-silent") {
            bindings::cartridge::api::host::health_report(
                bindings::cartridge::api::host::HealthState::Ready,
                "",
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
        Ok("sleep returned".into())
    }
}

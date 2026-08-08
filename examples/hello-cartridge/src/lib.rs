mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "cartridge",
    });

    use super::HelloCartridge;
    export!(HelloCartridge);
}
use bindings::cartridge::api::host::{LogLevel, log, read_asset, wall_clock_ms};

struct HelloCartridge;

impl bindings::Guest for HelloCartridge {
    fn run(args: Vec<String>) -> Result<String, String> {
        let name = args.first().map_or("there", String::as_str);
        log(LogLevel::Info, &format!("starting for {name}"));

        let message = read_asset("message.txt")?;
        let message = String::from_utf8(message).map_err(|error| error.to_string())?;
        let timestamp = wall_clock_ms()?;
        Ok(format!("{} {name} (host time: {timestamp} ms)", message.trim()))
    }
}

mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "cartridge",
    });

    use super::HelloCartridge;
    export!(HelloCartridge);
}
use bindings::cartridge::api::host::{
    LogLevel, log, read_asset, storage_get, storage_list, storage_put, wall_clock_ms,
};

struct HelloCartridge;

impl bindings::Guest for HelloCartridge {
    fn run(args: Vec<String>) -> Result<String, String> {
        let name = args.first().map_or("there", String::as_str);
        log(LogLevel::Info, &format!("starting for {name}"));

        let message = read_asset("message.txt")?;
        let message = String::from_utf8(message).map_err(|error| error.to_string())?;
        let previous_name = storage_get("session/last-user")?
            .map(String::from_utf8)
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_else(|| "none".into());
        storage_put("session/last-user", name.as_bytes())?;
        let stored_name = storage_get("session/last-user")?
            .ok_or_else(|| "stored name disappeared".to_owned())?;
        if stored_name != name.as_bytes() {
            return Err("stored name changed".into());
        }
        if !storage_list("session/")?
            .iter()
            .any(|key| key == "session/last-user")
        {
            return Err("stored name was not listed".into());
        }
        let timestamp = wall_clock_ms()?;
        Ok(format!(
            "{} {name} (previous: {previous_name}, host time: {timestamp} ms)",
            message.trim()
        ))
    }
}

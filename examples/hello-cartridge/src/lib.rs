mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "cartridge",
    });

    use super::HelloCartridge;
    export!(HelloCartridge);
}
use bindings::cartridge::api::host::{
    HealthState, LogLevel, StorageMutation, health_report, log, read_asset, storage_apply,
    storage_compare_exchange, storage_get, storage_list, storage_revision, wall_clock_ms,
};

struct HelloCartridge;

impl bindings::Guest for HelloCartridge {
    fn run(args: Vec<String>) -> Result<String, String> {
        health_report(HealthState::Started, "");
        let name = args.first().map_or("there", String::as_str);
        log(LogLevel::Info, &format!("starting for {name}"));

        let message = read_asset("message.txt")?;
        let message = String::from_utf8(message).map_err(|error| error.to_string())?;
        let previous_name = storage_get("session/last-user")?
            .map(String::from_utf8)
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_else(|| "none".into());
        let revision = storage_revision()?;
        let transaction = storage_apply(
            revision,
            &[
                StorageMutation {
                    key: "session/last-user".into(),
                    value: Some(name.as_bytes().to_vec()),
                },
                StorageMutation {
                    key: "session/protocol".into(),
                    value: Some(b"atomic-v1".to_vec()),
                },
            ],
        )?;
        if !transaction.applied {
            return Err("session state changed concurrently".into());
        }
        let confirmed = storage_compare_exchange(
            transaction.revision,
            "session/last-user",
            Some(name.as_bytes()),
            Some(name.as_bytes()),
        )?;
        if !confirmed.applied {
            return Err("stored name changed before confirmation".into());
        }
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
        health_report(HealthState::Ready, "");
        Ok(format!(
            "{} {name} (previous: {previous_name}, host time: {timestamp} ms)",
            message.trim()
        ))
    }
}

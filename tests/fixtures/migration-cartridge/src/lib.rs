mod bindings {
    wit_bindgen::generate!({
        path: "../../../wit",
        world: "migratable-cartridge",
    });

    use super::MigrationCartridge;
    export!(MigrationCartridge);
}

use bindings::cartridge::api::host::{storage_delete, storage_get, storage_put};

struct MigrationCartridge;

impl bindings::Guest for MigrationCartridge {
    fn run(_args: Vec<String>) -> Result<String, String> {
        let slug = read_text("profile/slug")?;
        let schema = read_text("meta/schema")?;
        Ok(format!("profile {slug} at schema {schema}"))
    }

    fn migrate(name: String, source: u32, target: u32) -> Result<(), String> {
        match (name.as_str(), source, target) {
            ("add-profile", 0, 1) => {
                let display = read_text("profile/name")?;
                storage_put("profile/display", display.as_bytes())?;
                storage_put("meta/schema", b"1")?;
                Ok(())
            }
            ("normalize-profile", 1, 2) => {
                let display = read_text("profile/display")?;
                if display == "fail" {
                    storage_put("migration/partial", b"must not escape")?;
                    return Err("intentional migration failure".into());
                }
                storage_put("profile/slug", display.to_lowercase().as_bytes())?;
                storage_put("meta/schema", b"2")?;
                storage_delete("profile/name")?;
                Ok(())
            }
            _ => Err("unknown migration step or schema transition".into()),
        }
    }
}

fn read_text(key: &str) -> Result<String, String> {
    let value = storage_get(key)?.ok_or_else(|| format!("missing {key}"))?;
    String::from_utf8(value).map_err(|error| error.to_string())
}

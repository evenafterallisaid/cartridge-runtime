use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use cartridge_desktop::{Library, LibraryEntry};
use cartridge_engine::{
    ApplyReport, EngineEvent, EngineStore, StackManifest, StackPlan, StackStatus,
};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

const SETTINGS_VERSION: u32 = 1;
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

struct AppState {
    library: PathBuf,
    engine: PathBuf,
    settings: PathBuf,
    reviewed_plan: Mutex<Option<StackPlan>>,
}

#[derive(Serialize)]
struct Dashboard {
    packages: Vec<LibraryEntry>,
    stacks: Vec<StackStatus>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ThemePreference {
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DensityPreference {
    Comfortable,
    Compact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum SecurityPreference {
    Strict,
    Balanced,
    Permissive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum SandboxPreference {
    Required,
    Preferred,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AppSettings {
    version: u32,
    theme: ThemePreference,
    density: DensityPreference,
    animations: bool,
    default_security: SecurityPreference,
    default_sandbox: SandboxPreference,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            theme: ThemePreference::System,
            density: DensityPreference::Comfortable,
            animations: true,
            default_security: SecurityPreference::Strict,
            default_sandbox: SandboxPreference::Required,
        }
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn dashboard(state: State<'_, AppState>) -> Result<Dashboard, String> {
    let library = Library::open(&state.library)?;
    let packages = library.list(None);
    drop(library);
    let stacks = EngineStore::open(&state.engine)?.list()?;
    Ok(Dashboard { packages, stacks })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn plan_stack(manifest: String, state: State<'_, AppState>) -> Result<StackPlan, String> {
    let manifest = StackManifest::parse(&manifest)?;
    let library = Library::open(&state.library)?;
    let plan = StackPlan::build(&manifest, &library)?;
    *state
        .reviewed_plan
        .lock()
        .map_err(|_| "reviewed plan lock is poisoned".to_string())? = Some(plan.clone());
    Ok(plan)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn apply_stack(
    plan_sha256: String,
    allow_insecure: bool,
    state: State<'_, AppState>,
) -> Result<ApplyReport, String> {
    let plan = state
        .reviewed_plan
        .lock()
        .map_err(|_| "reviewed plan lock is poisoned".to_string())?
        .as_ref()
        .filter(|plan| plan.plan_sha256 == plan_sha256)
        .cloned()
        .ok_or_else(|| "the reviewed plan is missing or changed; review it again".to_string())?;
    let library = Library::open(&state.library)?;
    plan.verify_installed(&library)?;
    drop(library);
    let report = EngineStore::open(&state.engine)?.apply(&plan, allow_insecure)?;
    let mut reviewed = state
        .reviewed_plan
        .lock()
        .map_err(|_| "reviewed plan lock is poisoned".to_string())?;
    if reviewed
        .as_ref()
        .is_some_and(|current| current.plan_sha256 == plan_sha256)
    {
        *reviewed = None;
    }
    Ok(report)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn stop_stack(stack: String, state: State<'_, AppState>) -> Result<ApplyReport, String> {
    EngineStore::open(&state.engine)?.stop(&stack)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn remove_stack(stack: String, state: State<'_, AppState>) -> Result<ApplyReport, String> {
    EngineStore::open(&state.engine)?.remove(&stack)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn stack_events(stack: String, state: State<'_, AppState>) -> Result<Vec<EngineEvent>, String> {
    EngineStore::open(&state.engine)?.events(&stack)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    load_settings(&state.settings)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn save_settings(settings: AppSettings, state: State<'_, AppState>) -> Result<AppSettings, String> {
    validate_settings(&settings)?;
    write_settings(&state.settings, &settings)?;
    Ok(settings)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let root = app.path().app_local_data_dir()?;
            ensure_app_directory(&root)?;
            app.manage(AppState {
                library: root.join("library"),
                engine: root.join("engine"),
                settings: root.join("settings.json"),
                reviewed_plan: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            dashboard,
            plan_stack,
            apply_stack,
            stop_stack,
            remove_stack,
            stack_events,
            get_settings,
            save_settings
        ])
        .run(tauri::generate_context!())
        .expect("cartridge desktop failed to start");
}

fn validate_settings(settings: &AppSettings) -> Result<(), String> {
    if settings.version != SETTINGS_VERSION {
        return Err("unsupported desktop settings version".into());
    }
    Ok(())
}

fn load_settings(path: &Path) -> Result<AppSettings, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AppSettings::default());
        }
        Err(error) => return Err(format!("could not inspect desktop settings: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("desktop settings path is not a regular file".into());
    }
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Err("desktop settings exceed the size limit".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("could not open desktop settings: {error}"))?
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read desktop settings: {error}"))?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err("desktop settings exceeded the size limit while reading".into());
    }
    let settings: AppSettings = serde_json::from_slice(&bytes)
        .map_err(|error| format!("desktop settings are invalid: {error}"))?;
    validate_settings(&settings)?;
    Ok(settings)
}

fn write_settings(path: &Path, settings: &AppSettings) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "desktop settings path has no parent".to_string())?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("desktop settings path is not a regular file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("could not inspect desktop settings: {error}")),
    }
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("could not encode desktop settings: {error}"))?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err("desktop settings exceed the size limit".into());
    }
    let mut pending = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create pending desktop settings: {error}"))?;
    pending
        .write_all(&bytes)
        .and_then(|()| pending.as_file().sync_all())
        .map_err(|error| format!("could not write desktop settings: {error}"))?;
    pending
        .persist(path)
        .map_err(|error| format!("could not commit desktop settings: {}", error.error))?;
    Ok(())
}

fn ensure_app_directory(path: &std::path::Path) -> Result<(), std::io::Error> {
    if !path.exists() {
        create_private_directory(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::other(
            "desktop data path is not a safe directory",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &std::path::Path) -> Result<(), std::io::Error> {
    fs::create_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_replace_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        assert_eq!(load_settings(&path).unwrap(), AppSettings::default());

        let mut settings = AppSettings {
            theme: ThemePreference::Dark,
            ..AppSettings::default()
        };
        write_settings(&path, &settings).unwrap();
        assert_eq!(load_settings(&path).unwrap(), settings);

        settings.density = DensityPreference::Compact;
        write_settings(&path, &settings).unwrap();
        assert_eq!(load_settings(&path).unwrap(), settings);
    }

    #[test]
    fn settings_reject_unknown_oversized_and_non_file_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, br#"{"version":1,"unknown":true}"#).unwrap();
        assert!(load_settings(&path).is_err());

        let oversized = usize::try_from(MAX_SETTINGS_BYTES).unwrap() + 1;
        fs::write(&path, vec![b' '; oversized]).unwrap();
        assert!(load_settings(&path).is_err());

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(load_settings(&path).is_err());
        assert!(write_settings(&path, &AppSettings::default()).is_err());
    }
}

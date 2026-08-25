use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use cartridge_core::{CartridgeArchive, RuntimeLimits};
use cartridge_desktop::{Capability, Library, LibraryEntry};
use cartridge_engine::{
    ApplyReport, DaemonInfo, DaemonLease, DaemonRequest, DaemonResponse, EngineEvent, EngineStore,
    MAX_DAEMON_EVENTS, StackManifest, StackPlan, StackRuntimeStatus, StackStatus, daemon_request,
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
    engine: EngineConnection,
    packages: Vec<LibraryEntry>,
    stacks: Vec<StackStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum EngineConnectionState {
    Online,
    Offline,
    Degraded,
}

#[derive(Serialize)]
struct EngineConnection {
    state: EngineConnectionState,
    info: Option<DaemonInfo>,
    message: Option<String>,
}

#[derive(Serialize)]
struct StackDetails {
    plan: Option<StackPlan>,
    runtime: Option<StackRuntimeStatus>,
}

#[derive(Serialize)]
struct ImportedPackage {
    cartridge_id: String,
    version: String,
    name: String,
    package_sha256: String,
    package_bytes: u64,
}

#[derive(Serialize)]
struct PackageDetails {
    cartridge_id: String,
    version: String,
    name: String,
    description: String,
    package_sha256: String,
    package_bytes: u64,
    asset_count: usize,
    state_schema: u32,
    runtime: RuntimeLimits,
    requested: Vec<Capability>,
    granted: Vec<Capability>,
    missing: Vec<Capability>,
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
    let (engine, stacks) = engine_dashboard(&state.engine)?;
    Ok(Dashboard {
        engine,
        packages,
        stacks,
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn import_package(state: State<'_, AppState>) -> Result<Option<ImportedPackage>, String> {
    let Some(package) = rfd::FileDialog::new()
        .add_filter("Cartridge package", &["cartridge"])
        .set_title("Import a cartridge package")
        .pick_file()
    else {
        return Ok(None);
    };
    import_package_from_path(&state.library, &package).map(Some)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn package_details(
    cartridge: String,
    version: Option<String>,
    state: State<'_, AppState>,
) -> Result<PackageDetails, String> {
    load_package_details(&state.library, &cartridge, version.as_deref())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn plan_stack(manifest: String, state: State<'_, AppState>) -> Result<StackPlan, String> {
    let manifest = StackManifest::parse(&manifest)?;
    let plan = if DaemonLease::is_active(&state.engine)? {
        match daemon_request(
            &state.engine,
            DaemonRequest::Plan {
                manifest: Box::new(manifest),
            },
        )? {
            DaemonResponse::Planned(plan) => *plan,
            _ => return Err("engine returned an unexpected plan response".into()),
        }
    } else {
        let library = Library::open(&state.library)?;
        StackPlan::build(&manifest, &library)?
    };
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
    let DaemonResponse::Applied(report) = daemon_request(
        &state.engine,
        DaemonRequest::Apply {
            plan: Box::new(plan),
            allow_insecure,
        },
    )?
    else {
        return Err("engine returned an unexpected apply response".into());
    };
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
    match daemon_request(&state.engine, DaemonRequest::Stop { stack })? {
        DaemonResponse::Stopped(report) => Ok(report),
        _ => Err("engine returned an unexpected stop response".into()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn remove_stack(stack: String, state: State<'_, AppState>) -> Result<ApplyReport, String> {
    match daemon_request(&state.engine, DaemonRequest::Remove { stack })? {
        DaemonResponse::Removed(report) => Ok(report),
        _ => Err("engine returned an unexpected remove response".into()),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn stack_events(stack: String, state: State<'_, AppState>) -> Result<Vec<EngineEvent>, String> {
    if DaemonLease::is_active(&state.engine)? {
        return match daemon_request(
            &state.engine,
            DaemonRequest::Events {
                stack,
                tail: MAX_DAEMON_EVENTS,
            },
        )? {
            DaemonResponse::Events(events) => Ok(events),
            _ => Err("engine returned an unexpected events response".into()),
        };
    }
    let mut events = EngineStore::open(&state.engine)?.events(&stack)?;
    let keep = usize::from(MAX_DAEMON_EVENTS);
    if events.len() > keep {
        events.drain(..events.len() - keep);
    }
    Ok(events)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn stack_details(stack: String, state: State<'_, AppState>) -> Result<StackDetails, String> {
    let active = DaemonLease::is_active(&state.engine)?;
    let engine = EngineStore::open(&state.engine)?;
    let plan = engine.desired_plan(&stack)?.map(|(_, _, plan)| plan);
    let runtime = if active {
        drop(engine);
        match daemon_request(&state.engine, DaemonRequest::RuntimeStatus { stack })? {
            DaemonResponse::RuntimeStatus(runtime) => runtime,
            _ => return Err("engine returned an unexpected runtime response".into()),
        }
    } else {
        engine.runtime_status(&stack)?
    };
    Ok(StackDetails { plan, runtime })
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
            import_package,
            package_details,
            plan_stack,
            apply_stack,
            stop_stack,
            remove_stack,
            stack_events,
            stack_details,
            get_settings,
            save_settings
        ])
        .run(tauri::generate_context!())
        .expect("cartridge desktop failed to start");
}

fn import_package_from_path(root: &Path, package: &Path) -> Result<ImportedPackage, String> {
    let metadata = fs::symlink_metadata(package)
        .map_err(|error| format!("could not inspect selected package: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("selected package must be a regular file".into());
    }
    let mut library = Library::open(root)?;
    let installed = library.install(package)?;
    let installed_path = root.join(&installed.relative_path);
    let archive = CartridgeArchive::open(&installed_path)
        .map_err(|error| format!("could not verify installed package: {error}"))?;
    if archive.package_sha256 != installed.package_sha256
        || archive.package_bytes != installed.package_bytes
    {
        return Err("installed package identity changed after import".into());
    }
    Ok(ImportedPackage {
        cartridge_id: archive.manifest.cartridge.id,
        version: archive.manifest.cartridge.version,
        name: archive.manifest.cartridge.name,
        package_sha256: archive.package_sha256,
        package_bytes: archive.package_bytes,
    })
}

fn load_package_details(
    root: &Path,
    cartridge: &str,
    version: Option<&str>,
) -> Result<PackageDetails, String> {
    let library = Library::open(root)?;
    let record = library.catalog_package(cartridge, version)?;
    let preflight = library.preflight(cartridge, Some(&record.version))?;
    let archive = CartridgeArchive::open(&record.path)
        .map_err(|error| format!("could not verify installed package: {error}"))?;
    if archive.manifest.cartridge.id != record.cartridge_id
        || archive.manifest.cartridge.version != record.version
        || archive.package_sha256 != record.package_sha256
        || archive.package_bytes != record.package_bytes
    {
        return Err("installed package no longer matches the library catalog".into());
    }
    Ok(PackageDetails {
        cartridge_id: record.cartridge_id,
        version: record.version,
        name: archive.manifest.cartridge.name,
        description: archive.manifest.cartridge.description,
        package_sha256: archive.package_sha256,
        package_bytes: archive.package_bytes,
        asset_count: archive.assets.len(),
        state_schema: archive.manifest.state.schema,
        runtime: archive.manifest.runtime,
        requested: preflight.requested.into_iter().collect(),
        granted: preflight.granted.into_iter().collect(),
        missing: preflight.missing.into_iter().collect(),
    })
}

fn engine_dashboard(root: &Path) -> Result<(EngineConnection, Vec<StackStatus>), String> {
    let active = match DaemonLease::is_active(root) {
        Ok(active) => active,
        Err(error) => {
            let stacks = EngineStore::open(root)?.list()?;
            return Ok((
                EngineConnection {
                    state: EngineConnectionState::Degraded,
                    info: None,
                    message: Some(bounded_message(&error)),
                },
                stacks,
            ));
        }
    };
    if !active {
        let stacks = EngineStore::open(root)?.list()?;
        return Ok((
            EngineConnection {
                state: EngineConnectionState::Offline,
                info: None,
                message: Some("start the local engine daemon to run or change stacks".into()),
            },
            stacks,
        ));
    }
    let result = (|| {
        let DaemonResponse::Info(info) = daemon_request(root, DaemonRequest::Info)? else {
            return Err("engine returned an unexpected information response".into());
        };
        let DaemonResponse::Stacks(stacks) = daemon_request(root, DaemonRequest::List)? else {
            return Err("engine returned an unexpected stack response".into());
        };
        Ok::<_, String>((info, stacks))
    })();
    match result {
        Ok((info, stacks)) => Ok((
            EngineConnection {
                state: EngineConnectionState::Online,
                info: Some(info),
                message: None,
            },
            stacks,
        )),
        Err(error) => {
            let stacks = EngineStore::open(root)?.list()?;
            Ok((
                EngineConnection {
                    state: EngineConnectionState::Degraded,
                    info: None,
                    message: Some(bounded_message(&error)),
                },
                stacks,
            ))
        }
    }
}

fn bounded_message(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
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
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
    sync_parent_directory(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "desktop settings path has no parent".to_string())?;
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("could not sync desktop settings directory: {error}"))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent_directory(_: &Path) -> Result<(), String> {
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
    use cartridge_core::{PackOptions, pack};

    fn package(root: &Path) -> PathBuf {
        let manifest = root.join("Cartridge.toml");
        let component = root.join("component.wasm");
        let output = root.join("desktop.cartridge");
        fs::write(
            &manifest,
            "format_version = 1\n[cartridge]\nid = \"dev.test.desktop\"\nname = \"Desktop fixture\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(&component, b"\0asm\x01\0\0\0").unwrap();
        pack(&PackOptions {
            manifest,
            component,
            assets: None,
            output: output.clone(),
        })
        .unwrap();
        output
    }

    #[test]
    fn package_import_and_details_bind_the_installed_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let library = directory.path().join("library");
        let imported = import_package_from_path(&library, &package(directory.path())).unwrap();
        assert_eq!(imported.cartridge_id, "dev.test.desktop");
        assert_eq!(imported.version, "1.0.0");

        let details = load_package_details(&library, &imported.cartridge_id, None).unwrap();
        assert_eq!(details.package_sha256, imported.package_sha256);
        assert_eq!(details.package_bytes, imported.package_bytes);
        assert!(details.missing.is_empty());
    }

    #[test]
    fn package_details_reject_tampered_installed_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let library_root = directory.path().join("library");
        let imported = import_package_from_path(&library_root, &package(directory.path())).unwrap();
        let installed = Library::open(&library_root)
            .unwrap()
            .package_path(&imported.cartridge_id, Some(&imported.version))
            .unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(installed).unwrap();
        file.write_all(b"tampered").unwrap();
        file.sync_all().unwrap();

        assert!(load_package_details(&library_root, &imported.cartridge_id, None).is_err());
    }

    #[test]
    fn package_import_rejects_non_files() {
        let directory = tempfile::tempdir().unwrap();
        let library = directory.path().join("library");

        assert!(import_package_from_path(&library, directory.path()).is_err());
    }

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

    #[test]
    fn dashboard_reports_an_inactive_engine_without_mutating_it() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("engine");

        let (connection, stacks) = engine_dashboard(&root).unwrap();

        assert_eq!(connection.state, EngineConnectionState::Offline);
        assert!(connection.info.is_none());
        assert!(stacks.is_empty());
        assert!(!root.join("daemon.json").exists());
    }

    #[test]
    fn engine_errors_are_bounded_and_control_safe_for_the_webview() {
        let message = format!("before\n{}\u{0007}after", "x".repeat(600));
        let bounded = bounded_message(&message);

        assert!(bounded.chars().count() <= 512);
        assert!(!bounded.chars().any(char::is_control));
    }
}

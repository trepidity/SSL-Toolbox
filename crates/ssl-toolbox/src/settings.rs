use crate::workflow::{JobRecord, WorkflowMemory};
use serde::{Deserialize, Serialize};
use ssl_toolbox_core::CsrDefaults;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub struct AppConfig {
    pub csr_defaults: CsrDefaults,
    pub ui_state: UiState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiState {
    #[serde(default)]
    pub recent_paths: BTreeMap<String, String>,
    #[serde(default)]
    pub last_menu_choice: String,
    #[serde(default)]
    pub workflow: WorkflowMemory,
    #[serde(default)]
    pub recent_jobs: Vec<JobRecord>,
}

impl UiState {
    pub fn recent_path(&self, key: &str) -> Option<&str> {
        self.recent_paths.get(key).map(String::as_str)
    }

    pub fn remember_path(&mut self, key: &str, value: &str) {
        self.recent_paths.insert(key.to_string(), value.to_string());
    }

    pub fn remember_menu_choice(&mut self, choice: &str) {
        self.last_menu_choice = choice.to_string();
    }
}

/// Load config by merging: compiled defaults < ~/.ssl-toolbox/config.json < ./.ssl-toolbox/config.json
pub fn load_config() -> AppConfig {
    let mut defaults = CsrDefaults::default();

    for dir in config_dirs() {
        let path = dir.join("config.json");
        if let Ok(contents) = std::fs::read_to_string(&path)
            && let Ok(loaded) = serde_json::from_str::<CsrDefaults>(&contents)
        {
            merge_csr_defaults(&mut defaults, &loaded);
        }
    }

    AppConfig {
        csr_defaults: defaults,
        ui_state: load_state(),
    }
}

pub fn load_state() -> UiState {
    load_state_from(home_dir())
}

pub fn save_state(state: &UiState) -> anyhow::Result<()> {
    save_state_to(home_dir(), state)
}

/// Load a CA plugin config file by name (e.g., "sectigo") from the config directories.
/// Merges files in order: ~/.ssl-toolbox/<name>.json < ./.ssl-toolbox/<name>.json
#[cfg(feature = "sectigo")]
pub fn load_ca_config<T: serde::de::DeserializeOwned + Default>(name: &str) -> T {
    let filename = format!("{}.json", name);
    let mut result: Option<serde_json::Value> = None;

    for dir in config_dirs() {
        let path = dir.join(&filename);
        if let Ok(contents) = std::fs::read_to_string(&path)
            && let Ok(loaded) = serde_json::from_str::<serde_json::Value>(&contents)
        {
            match &mut result {
                Some(base) => {
                    if let (Some(base_obj), Some(loaded_obj)) =
                        (base.as_object_mut(), loaded.as_object())
                    {
                        for (k, v) in loaded_obj {
                            base_obj.insert(k.clone(), v.clone());
                        }
                    }
                }
                None => {
                    result = Some(loaded);
                }
            }
        }
    }

    match result {
        Some(value) => serde_json::from_value(value).unwrap_or_default(),
        None => T::default(),
    }
}

fn config_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home_dir() {
        dirs.push(home.join(".ssl-toolbox"));
    }
    dirs.push(PathBuf::from(".ssl-toolbox"));
    dirs
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn state_path_in(home: Option<PathBuf>) -> Option<PathBuf> {
    home.map(|home| home.join(".ssl-toolbox").join("state.json"))
}

fn load_state_from(home: Option<PathBuf>) -> UiState {
    let Some(path) = state_path_in(home) else {
        return UiState::default();
    };

    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => UiState::default(),
    }
}

fn save_state_to(home: Option<PathBuf>, state: &UiState) -> anyhow::Result<()> {
    let Some(path) = state_path_in(home) else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir_permissions(parent)?;
    }

    let contents = serde_json::to_string_pretty(state)?;
    write_private_file(&path, contents.as_bytes())?;
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.flush()?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub fn resolve_path_from(base_dir: &Path, raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(home) = home_dir()
        && let Some(rest) = trimmed.strip_prefix("~/")
    {
        return home.join(rest);
    }
    if trimmed == "~"
        && let Some(home) = home_dir()
    {
        return home;
    }

    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

pub fn display_path_from(base_dir: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(base_dir) {
        let display = relative.display().to_string();
        return if display.is_empty() {
            ".".to_string()
        } else {
            display
        };
    }

    if let Some(home) = home_dir()
        && let Ok(relative) = path.strip_prefix(&home)
    {
        let display = relative.display().to_string();
        return if display.is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", display)
        };
    }

    path.display().to_string()
}

/// Merge non-empty fields from `overlay` into `base`.
fn merge_csr_defaults(base: &mut CsrDefaults, overlay: &CsrDefaults) {
    if !overlay.country.is_empty() {
        base.country = overlay.country.clone();
    }
    if !overlay.state.is_empty() {
        base.state = overlay.state.clone();
    }
    if !overlay.locality.is_empty() {
        base.locality = overlay.locality.clone();
    }
    if !overlay.organization.is_empty() {
        base.organization = overlay.organization.clone();
    }
    if !overlay.org_unit.is_empty() {
        base.org_unit = overlay.org_unit.clone();
    }
    if !overlay.email.is_empty() {
        base.email = overlay.email.clone();
    }
}

/// Create example config files in the given directory.
/// Returns the list of files written.
pub fn init_config(dir: &std::path::Path) -> anyhow::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut written = Vec::new();

    let config_path = dir.join("config.json");
    if !config_path.exists() {
        let example = serde_json::json!({
            "country": "US",
            "state": "",
            "locality": "",
            "organization": "",
            "org_unit": "",
            "email": ""
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&example)?)?;
        written.push(config_path);
    }

    let sectigo_path = dir.join("sectigo.json");
    if !sectigo_path.exists() {
        let example = serde_json::json!({
            "api_base": "https://cert-manager.com",
            "org_id": "",
            "product_code": "",
            "token_url": ""
        });
        std::fs::write(&sectigo_path, serde_json::to_string_pretty(&example)?)?;
        written.push(sectigo_path);
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn resolves_relative_paths_against_base_dir() {
        let base = Path::new("/tmp/project");
        let resolved = resolve_path_from(base, "certs/server.pem");
        assert_eq!(resolved, PathBuf::from("/tmp/project/certs/server.pem"));
    }

    #[test]
    fn display_path_prefers_relative_when_under_base_dir() {
        let base = Path::new("/tmp/project");
        let display = display_path_from(base, Path::new("/tmp/project/certs/server.pem"));
        assert_eq!(display, "certs/server.pem");
    }

    fn temp_home_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ssl-toolbox-settings-{}-{}",
            std::process::id(),
            nonce
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp home");
        dir
    }

    #[test]
    fn save_state_round_trips_and_restricts_permissions() {
        let home = temp_home_dir();
        let mut state = UiState::default();
        state.remember_path("key", "/tmp/project/keys/server.key");
        state.remember_path("csr", "/tmp/project/csrs/server.csr");
        state.remember_menu_choice("generate");
        state.workflow.config = Some("/tmp/project/openssl.cnf".to_string());
        state.workflow.key = Some("/tmp/project/keys/server.key".to_string());
        state.workflow.active_profile = Some("web-server".to_string());
        state.recent_jobs.push(
            JobRecord::new(
                crate::workflow::ActionKind::Generate,
                "Generate key and CSR",
            )
            .with_input("key", "server.key")
            .with_output("csr", "server.csr")
            .with_replay_data("key_size", "4096"),
        );

        save_state_to(Some(home.clone()), &state).expect("save state");
        let loaded = load_state_from(Some(home.clone()));

        assert_eq!(loaded, state);

        #[cfg(unix)]
        {
            let state_path = home.join(".ssl-toolbox").join("state.json");
            let state_mode = fs::metadata(&state_path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777;
            let dir_mode = fs::metadata(home.join(".ssl-toolbox"))
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(state_mode, 0o600);
            assert_eq!(dir_mode, 0o700);
        }

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn load_state_accepts_legacy_json_without_new_fields() {
        let home = temp_home_dir();
        let state_dir = home.join(".ssl-toolbox");
        fs::create_dir_all(&state_dir).expect("create state dir");
        fs::write(
            state_dir.join("state.json"),
            r#"{
  "recent_paths": {
    "key": "/tmp/legacy/server.key"
  },
  "last_menu_choice": "pfx"
}"#,
        )
        .expect("write legacy state");

        let loaded = load_state_from(Some(home.clone()));
        assert_eq!(loaded.recent_path("key"), Some("/tmp/legacy/server.key"));
        assert_eq!(loaded.last_menu_choice, "pfx");
        assert_eq!(loaded.workflow, WorkflowMemory::default());
        assert!(loaded.recent_jobs.is_empty());

        let _ = fs::remove_dir_all(home);
    }
}

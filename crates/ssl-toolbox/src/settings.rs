use serde::{Deserialize, Serialize};
use ssl_toolbox_core::CsrDefaults;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

pub struct AppConfig {
    pub csr_defaults: CsrDefaults,
    pub ui_state: UiState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UiState {
    #[serde(default)]
    pub recent_paths: BTreeMap<String, String>,
    #[serde(default)]
    pub last_menu_choice: String,
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
    let Some(path) = state_path() else {
        return UiState::default();
    };

    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => UiState::default(),
    }
}

pub fn save_state(state: &UiState) -> anyhow::Result<()> {
    let Some(path) = state_path() else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
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

fn state_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssl-toolbox").join("state.json"))
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
}

use ssl_toolbox_core::CsrDefaults;
use std::path::PathBuf;

pub struct AppConfig {
    pub csr_defaults: CsrDefaults,
}

/// Load config by merging: compiled defaults < ~/.ssl-toolbox/config.json < ./.ssl-toolbox/config.json
pub fn load_config() -> AppConfig {
    let mut defaults = CsrDefaults::default();

    for dir in config_dirs() {
        let path = dir.join("config.json");
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(loaded) = serde_json::from_str::<CsrDefaults>(&contents) {
                merge_csr_defaults(&mut defaults, &loaded);
            }
        }
    }

    AppConfig {
        csr_defaults: defaults,
    }
}

/// Load a CA plugin config file by name (e.g., "sectigo") from the config directories.
/// Merges files in order: ~/.ssl-toolbox/<name>.json < ./.ssl-toolbox/<name>.json
pub fn load_ca_config<T: serde::de::DeserializeOwned + Default>(name: &str) -> T {
    let filename = format!("{}.json", name);
    let mut result: Option<serde_json::Value> = None;

    for dir in config_dirs() {
        let path = dir.join(&filename);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(loaded) = serde_json::from_str::<serde_json::Value>(&contents) {
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

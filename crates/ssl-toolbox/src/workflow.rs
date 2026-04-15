use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ssl_toolbox_core::CsrDefaults;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActionKind {
    Generate,
    CreatePfx,
    CreateLegacyPfx,
    NewConfig,
    ConfigFromExisting,
    ViewCert,
    ViewCsr,
    ViewPfx,
    VerifyHttps,
    VerifyLdaps,
    VerifySmtp,
    Convert,
    Identify,
    CaSubmit,
    CaProfiles,
}

impl ActionKind {
    pub fn alias(self) -> &'static str {
        match self {
            Self::Generate => "g",
            Self::CreatePfx => "pfx",
            Self::CreateLegacyPfx => "legacy",
            Self::NewConfig => "new",
            Self::ConfigFromExisting => "config",
            Self::ViewCert => "cert",
            Self::ViewCsr => "csr",
            Self::ViewPfx => "vpfx",
            Self::VerifyHttps => "https",
            Self::VerifyLdaps => "ldaps",
            Self::VerifySmtp => "smtp",
            Self::Convert => "convert",
            Self::Identify => "id",
            Self::CaSubmit => "submit",
            Self::CaProfiles => "profiles",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Generate => "Generate Key and CSR",
            Self::CreatePfx => "Create PFX",
            Self::CreateLegacyPfx => "Create Legacy PFX",
            Self::NewConfig => "Generate New OpenSSL Config",
            Self::ConfigFromExisting => "Generate Config from Cert/CSR",
            Self::ViewCert => "View Certificate Details",
            Self::ViewCsr => "View CSR Details",
            Self::ViewPfx => "View PFX Contents",
            Self::VerifyHttps => "Verify HTTPS Endpoint",
            Self::VerifyLdaps => "Verify LDAPS Endpoint",
            Self::VerifySmtp => "Verify SMTP Endpoint",
            Self::Convert => "Convert Certificate Format",
            Self::Identify => "Identify Certificate Format",
            Self::CaSubmit => "CA: Submit CSR",
            Self::CaProfiles => "CA: List Profiles",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PaletteEntry {
    pub action: i32,
    pub alias: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub keywords: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteMatch {
    pub action: i32,
    pub alias: String,
    pub title: String,
    pub description: String,
    pub score: i32,
}

pub fn search_palette(query: &str, entries: &[PaletteEntry]) -> Vec<PaletteMatch> {
    let normalized = normalize(query);
    let mut matches = entries
        .iter()
        .filter_map(|entry| {
            score_palette_entry(&normalized, entry).map(|score| PaletteMatch {
                action: entry.action,
                alias: entry.alias.to_string(),
                title: entry.title.to_string(),
                description: entry.description.to_string(),
                score,
            })
        })
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.title.cmp(&right.title))
    });
    matches
}

fn score_palette_entry(query: &str, entry: &PaletteEntry) -> Option<i32> {
    if query.is_empty() {
        return Some(1);
    }

    let alias = normalize(entry.alias);
    let title = normalize(entry.title);
    let description = normalize(entry.description);
    let keywords = entry
        .keywords
        .iter()
        .map(|keyword| normalize(keyword))
        .collect::<Vec<_>>();

    if alias == query {
        return Some(120);
    }
    if title == query {
        return Some(115);
    }
    if alias.starts_with(query) {
        return Some(100);
    }
    if title.starts_with(query) {
        return Some(95);
    }
    if keywords.iter().any(|keyword| keyword == query) {
        return Some(90);
    }
    if keywords.iter().any(|keyword| keyword.starts_with(query)) {
        return Some(80);
    }
    if title.contains(query) {
        return Some(70);
    }
    if description.contains(query) {
        return Some(60);
    }
    if keywords.iter().any(|keyword| keyword.contains(query)) {
        return Some(55);
    }
    if subsequence_score(&title, query) {
        return Some(40);
    }
    if subsequence_score(&alias, query) {
        return Some(35);
    }

    None
}

fn subsequence_score(haystack: &str, needle: &str) -> bool {
    let mut chars = needle.chars();
    let mut current = chars.next();
    if current.is_none() {
        return true;
    }

    for ch in haystack.chars() {
        if Some(ch) == current {
            current = chars.next();
            if current.is_none() {
                return true;
            }
        }
    }

    false
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactKind {
    Config,
    Key,
    Csr,
    Cert,
    Chain,
    Pfx,
    LegacyPfx,
}

impl ArtifactKind {
    pub fn key(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Key => "key",
            Self::Csr => "csr",
            Self::Cert => "cert",
            Self::Chain => "chain",
            Self::Pfx => "pfx",
            Self::LegacyPfx => "legacy_pfx",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Self::Config => "Config",
            Self::Key => "Key",
            Self::Csr => "CSR",
            Self::Cert => "Certificate",
            Self::Chain => "Chain",
            Self::Pfx => "PFX",
            Self::LegacyPfx => "Legacy PFX",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowMemory {
    pub config: Option<String>,
    pub key: Option<String>,
    pub csr: Option<String>,
    pub cert: Option<String>,
    pub chain: Option<String>,
    pub pfx: Option<String>,
    pub legacy_pfx: Option<String>,
    pub active_profile: Option<String>,
    pub https_host: Option<String>,
    pub ldaps_host: Option<String>,
    pub smtp_host: Option<String>,
}

impl WorkflowMemory {
    pub fn get(&self, kind: ArtifactKind) -> Option<&str> {
        match kind {
            ArtifactKind::Config => self.config.as_deref(),
            ArtifactKind::Key => self.key.as_deref(),
            ArtifactKind::Csr => self.csr.as_deref(),
            ArtifactKind::Cert => self.cert.as_deref(),
            ArtifactKind::Chain => self.chain.as_deref(),
            ArtifactKind::Pfx => self.pfx.as_deref(),
            ArtifactKind::LegacyPfx => self.legacy_pfx.as_deref(),
        }
    }

    pub fn set(&mut self, kind: ArtifactKind, value: impl Into<String>) {
        let value = Some(value.into());
        match kind {
            ArtifactKind::Config => self.config = value,
            ArtifactKind::Key => self.key = value,
            ArtifactKind::Csr => self.csr = value,
            ArtifactKind::Cert => self.cert = value,
            ArtifactKind::Chain => self.chain = value,
            ArtifactKind::Pfx => self.pfx = value,
            ArtifactKind::LegacyPfx => self.legacy_pfx = value,
        }
    }

    pub fn artifact_pairs(&self) -> Vec<(ArtifactKind, String)> {
        let mut pairs = Vec::new();
        for kind in [
            ArtifactKind::Config,
            ArtifactKind::Key,
            ArtifactKind::Csr,
            ArtifactKind::Cert,
            ArtifactKind::Chain,
            ArtifactKind::Pfx,
            ArtifactKind::LegacyPfx,
        ] {
            if let Some(value) = self.get(kind) {
                pairs.push((kind, value.to_string()));
            }
        }
        pairs
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub kind: ActionKind,
    pub summary: String,
    pub inputs: BTreeMap<String, String>,
    pub outputs: BTreeMap<String, String>,
    #[serde(default)]
    pub replay_data: BTreeMap<String, String>,
    pub profile: Option<String>,
    pub timestamp_secs: u64,
}

impl JobRecord {
    pub fn new(kind: ActionKind, summary: impl Into<String>) -> Self {
        Self {
            kind,
            summary: summary.into(),
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            replay_data: BTreeMap::new(),
            profile: None,
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or_default(),
        }
    }

    pub fn with_input(mut self, key: &str, value: impl Into<String>) -> Self {
        self.inputs.insert(key.to_string(), value.into());
        self
    }

    pub fn with_output(mut self, key: &str, value: impl Into<String>) -> Self {
        self.outputs.insert(key.to_string(), value.into());
        self
    }

    pub fn with_replay_data(mut self, key: &str, value: impl Into<String>) -> Self {
        self.replay_data.insert(key.to_string(), value.into());
        self
    }
}

pub fn push_recent_job(jobs: &mut Vec<JobRecord>, job: JobRecord) {
    jobs.insert(0, job);
    jobs.truncate(20);
}

pub fn apply_job_to_workflow(memory: &mut WorkflowMemory, job: &JobRecord) {
    for (key, value) in job.inputs.iter().chain(job.outputs.iter()) {
        match key.as_str() {
            "config" => memory.config = Some(value.clone()),
            "key" => memory.key = Some(value.clone()),
            "csr" => memory.csr = Some(value.clone()),
            "cert" => memory.cert = Some(value.clone()),
            "chain" => memory.chain = Some(value.clone()),
            "pfx" => memory.pfx = Some(value.clone()),
            "legacy_pfx" => memory.legacy_pfx = Some(value.clone()),
            "https_host" => memory.https_host = Some(value.clone()),
            "ldaps_host" => memory.ldaps_host = Some(value.clone()),
            "smtp_host" => memory.smtp_host = Some(value.clone()),
            _ => {}
        }
    }
    if let Some(profile) = &job.profile {
        memory.active_profile = Some(profile.clone());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFile {
    pub path: PathBuf,
    pub kind: ArtifactKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    pub root: PathBuf,
    pub files: Vec<WorkspaceFile>,
}

impl WorkspaceSnapshot {
    pub fn scan(root: &Path) -> Self {
        let mut files = Vec::new();
        scan_dir(root, root, 0, &mut files);
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            root: root.to_path_buf(),
            files,
        }
    }

    pub fn detect_workflow(&self) -> WorkflowMemory {
        let mut families: BTreeMap<String, WorkflowMemory> = BTreeMap::new();

        for file in &self.files {
            let family = family_key(&file.path, file.kind);
            let entry = families.entry(family).or_default();
            entry.set(file.kind, file.path.display().to_string());
        }

        let best = families.into_values().max_by_key(workflow_score);

        best.unwrap_or_default()
    }

    pub fn top_files(&self, limit: usize) -> Vec<String> {
        self.files
            .iter()
            .take(limit)
            .map(|file| file.path.display().to_string())
            .collect()
    }
}

fn workflow_score(memory: &WorkflowMemory) -> usize {
    let count = memory.artifact_pairs().len();
    let bonus = if memory.cert.is_some() && memory.key.is_some() {
        2
    } else {
        0
    };
    count + bonus
}

fn family_key(path: &Path, kind: ArtifactKind) -> String {
    let file_name = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default();
    match kind {
        ArtifactKind::LegacyPfx => file_name.replace(".legacy", ""),
        _ => file_name,
    }
}

fn scan_dir(root: &Path, dir: &Path, depth: usize, files: &mut Vec<WorkspaceFile>) {
    if depth > 4 || files.len() >= 200 {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_symlink() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_dir() {
            if should_skip_dir(&file_name) {
                continue;
            }
            scan_dir(root, &path, depth + 1, files);
            if files.len() >= 200 {
                return;
            }
            continue;
        }

        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if let Some(kind) = detect_artifact_kind(&relative) {
            files.push(WorkspaceFile {
                path: relative,
                kind,
            });
        }
    }
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | ".ssl-toolbox" | ".claude" | "node_modules"
    )
}

pub fn detect_artifact_kind(path: &Path) -> Option<ArtifactKind> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let extension = path.extension()?.to_string_lossy().to_ascii_lowercase();
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if extension == "pfx" || extension == "p12" {
        if file_name.contains("legacy") {
            return Some(ArtifactKind::LegacyPfx);
        }
        return Some(ArtifactKind::Pfx);
    }

    if file_name.contains("chain")
        && matches!(extension.as_str(), "crt" | "cer" | "pem" | "p7b" | "p7c")
    {
        return Some(ArtifactKind::Chain);
    }

    match extension.as_str() {
        "cnf" | "conf" => Some(ArtifactKind::Config),
        "key" => Some(ArtifactKind::Key),
        "csr" => Some(ArtifactKind::Csr),
        "crt" | "cer" => Some(ArtifactKind::Cert),
        "pem" => {
            if has_named_suffix(&stem, "key") {
                Some(ArtifactKind::Key)
            } else if has_named_suffix(&stem, "csr") {
                Some(ArtifactKind::Csr)
            } else {
                Some(ArtifactKind::Cert)
            }
        }
        _ => None,
    }
}

fn has_named_suffix(value: &str, suffix: &str) -> bool {
    if let Some(prefix) = value.strip_suffix(suffix) {
        return prefix.is_empty()
            || matches!(prefix.chars().last(), Some('.') | Some('_') | Some('-'));
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSuggestion {
    pub display: String,
    pub path: String,
}

pub fn path_suggestions(
    query: &str,
    preferred_kind: Option<ArtifactKind>,
    recent_paths: &BTreeMap<String, String>,
    workflow: &WorkflowMemory,
    workspace: &WorkspaceSnapshot,
) -> Vec<PathSuggestion> {
    let normalized_query = normalize(query);
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(kind) = preferred_kind
        && let Some(value) = workflow.get(kind)
    {
        push_suggestion(&mut ordered, &mut seen, value, value);
    }

    for value in recent_paths.values() {
        push_suggestion(&mut ordered, &mut seen, value, value);
    }

    for file in &workspace.files {
        if preferred_kind.is_none_or(|kind| kind == file.kind) {
            let display = file.path.display().to_string();
            push_suggestion(
                &mut ordered,
                &mut seen,
                &display,
                &workspace.root.join(&file.path).display().to_string(),
            );
        }
    }

    ordered
        .into_iter()
        .filter(|suggestion| {
            if normalized_query.is_empty() {
                return true;
            }
            let display = normalize(&suggestion.display);
            let path = normalize(&suggestion.path);
            display.contains(&normalized_query) || path.contains(&normalized_query)
        })
        .take(8)
        .collect()
}

fn push_suggestion(
    ordered: &mut Vec<PathSuggestion>,
    seen: &mut BTreeSet<String>,
    display: &str,
    path: &str,
) {
    if seen.insert(path.to_string()) {
        ordered.push(PathSuggestion {
            display: display.to_string(),
            path: path.to_string(),
        });
    }
}

pub fn complete_path(query: &str, suggestions: &[PathSuggestion]) -> Option<String> {
    let normalized = normalize(query);
    let mut matches = suggestions
        .iter()
        .filter(|suggestion| {
            if normalized.is_empty() {
                return false;
            }
            let display = normalize(&suggestion.display);
            let path = normalize(&suggestion.path);
            display.starts_with(&normalized)
                || path.starts_with(&normalized)
                || display.ends_with(&normalized)
                || display.contains(&normalized)
                || path.contains(&normalized)
        })
        .collect::<Vec<_>>();

    matches.dedup_by(|left, right| left.path == right.path);
    if matches.len() == 1 {
        Some(matches[0].path.clone())
    } else {
        None
    }
}

pub fn suggest_output_path(base_input: &str, target: ArtifactKind) -> Option<String> {
    let path = Path::new(base_input);
    let stem = path.file_stem()?.to_string_lossy();
    let parent = path.parent().unwrap_or_else(|| Path::new(""));

    let file_name = match target {
        ArtifactKind::Config => format!("{stem}.conf"),
        ArtifactKind::Key => format!("{stem}.key"),
        ArtifactKind::Csr => format!("{stem}.csr"),
        ArtifactKind::Cert => format!("{stem}.crt"),
        ArtifactKind::Chain => format!("{stem}.chain.pem"),
        ArtifactKind::Pfx => format!("{stem}.pfx"),
        ArtifactKind::LegacyPfx => format!("{stem}.legacy.pfx"),
    };

    Some(parent.join(file_name).display().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationStep {
    pub label: String,
    pub command: String,
}

pub fn validation_steps(job: &JobRecord) -> Vec<ValidationStep> {
    match job.kind {
        ActionKind::Generate => job
            .outputs
            .get("csr")
            .map(|csr| {
                vec![ValidationStep {
                    label: "Validate CSR with openssl".to_string(),
                    command: format!("openssl req -in {} -noout -verify -text", shell_quote(csr)),
                }]
            })
            .unwrap_or_default(),
        ActionKind::CreatePfx | ActionKind::CreateLegacyPfx => {
            let pfx_key = if job.kind == ActionKind::CreateLegacyPfx {
                "legacy_pfx"
            } else {
                "pfx"
            };
            job.outputs
                .get(pfx_key)
                .map(|pfx| {
                    vec![
                        ValidationStep {
                            label: "Inspect PKCS#12 contents with openssl".to_string(),
                            command: format!(
                                "openssl pkcs12 -in {} -info -nokeys",
                                shell_quote(pfx)
                            ),
                        },
                        ValidationStep {
                            label: "Inspect PKCS#12 chain with keytool".to_string(),
                            command: format!(
                                "keytool -list -v -storetype PKCS12 -keystore {}",
                                shell_quote(pfx)
                            ),
                        },
                    ]
                })
                .unwrap_or_default()
        }
        ActionKind::Convert => job
            .outputs
            .get("output")
            .map(|output| {
                vec![ValidationStep {
                    label: "Identify converted artifact".to_string(),
                    command: format!("ssl-toolbox identify --input {}", shell_quote(output)),
                }]
            })
            .unwrap_or_default(),
        ActionKind::CaSubmit => job
            .outputs
            .get("cert")
            .map(|cert| {
                vec![ValidationStep {
                    label: "Inspect downloaded certificate".to_string(),
                    command: format!("openssl x509 -in {} -noout -text", shell_quote(cert)),
                }]
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPreview {
    pub title: String,
    pub lines: Vec<(String, String)>,
}

pub fn build_preview(job: &JobRecord) -> ActionPreview {
    let mut lines = Vec::new();
    for (key, value) in &job.inputs {
        lines.push((format!("Input {}", humanize_key(key)), shell_quote(value)));
    }
    for (key, value) in &job.outputs {
        lines.push((format!("Output {}", humanize_key(key)), shell_quote(value)));
    }
    if let Some(profile) = &job.profile {
        lines.push(("Profile".to_string(), profile.clone()));
    }

    ActionPreview {
        title: job.kind.title().to_string(),
        lines,
    }
}

fn humanize_key(key: &str) -> String {
    key.replace('_', " ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let escaped = value.replace('\'', r#"'"'"'"#);
    format!("'{}'", escaped)
}

pub fn next_steps(job: &JobRecord, memory: &WorkflowMemory) -> Vec<String> {
    match job.kind {
        ActionKind::Generate => {
            let mut steps = vec![
                "View the CSR details to confirm subject and SANs.".to_string(),
                "Submit the CSR to the CA or sign it internally.".to_string(),
            ];
            if let Some(csr) = memory.csr.as_deref() {
                steps.push(format!("Next likely file: {csr}"));
            }
            steps
        }
        ActionKind::CreatePfx | ActionKind::CreateLegacyPfx => vec![
            "Validate the PKCS#12 bundle with openssl and keytool.".to_string(),
            "View the PFX contents in the toolbox.".to_string(),
        ],
        ActionKind::NewConfig | ActionKind::ConfigFromExisting => vec![
            "Generate a key and CSR from the config.".to_string(),
            "Open the config to confirm SAN and EKU settings.".to_string(),
        ],
        ActionKind::VerifyHttps | ActionKind::VerifyLdaps | ActionKind::VerifySmtp => vec![
            "Repeat the check with validation disabled if you need to inspect an untrusted chain."
                .to_string(),
            "Inspect the peer certificate file if you need a local artifact.".to_string(),
        ],
        ActionKind::Convert => vec![
            "Identify the converted artifact format.".to_string(),
            "Inspect the converted certificate details.".to_string(),
        ],
        ActionKind::CaSubmit => vec![
            "Create a PFX once the signed certificate has been reviewed.".to_string(),
            "Validate the downloaded certificate with openssl.".to_string(),
        ],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub csr_defaults: CsrDefaults,
    pub key_size: u32,
    pub extended_key_usage: &'static str,
}

pub fn builtin_profiles() -> Vec<WorkflowProfile> {
    vec![
        WorkflowProfile {
            id: "web-server",
            name: "Web Server",
            description: "Standard HTTPS server certificate defaults",
            csr_defaults: CsrDefaults {
                country: "US".to_string(),
                state: String::new(),
                locality: String::new(),
                organization: String::new(),
                org_unit: "Web".to_string(),
                email: String::new(),
            },
            key_size: 2048,
            extended_key_usage: "serverAuth",
        },
        WorkflowProfile {
            id: "mtls-client",
            name: "mTLS Client",
            description: "Client-auth focused certificate defaults",
            csr_defaults: CsrDefaults {
                country: "US".to_string(),
                state: String::new(),
                locality: String::new(),
                organization: String::new(),
                org_unit: "Client".to_string(),
                email: String::new(),
            },
            key_size: 2048,
            extended_key_usage: "clientAuth",
        },
        WorkflowProfile {
            id: "ldaps",
            name: "LDAPS",
            description: "Directory server certificate defaults",
            csr_defaults: CsrDefaults {
                country: "US".to_string(),
                state: String::new(),
                locality: String::new(),
                organization: String::new(),
                org_unit: "Directory".to_string(),
                email: String::new(),
            },
            key_size: 2048,
            extended_key_usage: "serverAuth",
        },
        WorkflowProfile {
            id: "smtp",
            name: "SMTP",
            description: "Mail transport TLS certificate defaults",
            csr_defaults: CsrDefaults {
                country: "US".to_string(),
                state: String::new(),
                locality: String::new(),
                organization: String::new(),
                org_unit: "Mail".to_string(),
                email: String::new(),
            },
            key_size: 2048,
            extended_key_usage: "serverAuth",
        },
        WorkflowProfile {
            id: "internal-ca",
            name: "Internal CA",
            description: "Internal signing workflow defaults",
            csr_defaults: CsrDefaults {
                country: "US".to_string(),
                state: String::new(),
                locality: String::new(),
                organization: "Internal PKI".to_string(),
                org_unit: "Certificate Services".to_string(),
                email: String::new(),
            },
            key_size: 4096,
            extended_key_usage: "serverAuth, clientAuth",
        },
    ]
}

pub fn profile_by_id(id: &str) -> Option<WorkflowProfile> {
    builtin_profiles()
        .into_iter()
        .find(|profile| profile.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ssl-toolbox-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn command_palette_prefers_alias_prefix() {
        let entries = [
            PaletteEntry {
                action: 1,
                alias: "pfx",
                title: "Create PFX",
                description: "Bundle a certificate",
                keywords: &["pkcs12"],
            },
            PaletteEntry {
                action: 2,
                alias: "vpfx",
                title: "View PFX Contents",
                description: "Inspect an existing bundle",
                keywords: &["pkcs12"],
            },
        ];

        let matches = search_palette("pf", &entries);
        assert_eq!(matches[0].action, 1);
    }

    #[test]
    fn workspace_scan_detects_complete_family() {
        let root = unique_temp_dir("scan");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("server.cnf"), "").unwrap();
        fs::write(root.join("server.key"), "").unwrap();
        fs::write(root.join("server.csr"), "").unwrap();
        fs::write(root.join("server.crt"), "").unwrap();
        fs::write(root.join("server.pfx"), "").unwrap();
        fs::write(root.join("notes.txt"), "").unwrap();

        let snapshot = WorkspaceSnapshot::scan(&root);
        let workflow = snapshot.detect_workflow();

        assert!(workflow.config.as_deref().unwrap().ends_with("server.cnf"));
        assert!(workflow.key.as_deref().unwrap().ends_with("server.key"));
        assert!(workflow.csr.as_deref().unwrap().ends_with("server.csr"));
        assert!(workflow.cert.as_deref().unwrap().ends_with("server.crt"));
        assert!(workflow.pfx.as_deref().unwrap().ends_with("server.pfx"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn workflow_memory_learns_from_jobs() {
        let mut memory = WorkflowMemory::default();
        let job = JobRecord::new(ActionKind::Generate, "Generated server artifacts")
            .with_input("config", "config/server.cnf")
            .with_output("key", "keys/server.key")
            .with_output("csr", "csr/server.csr");

        apply_job_to_workflow(&mut memory, &job);

        assert_eq!(memory.config.as_deref(), Some("config/server.cnf"));
        assert_eq!(memory.key.as_deref(), Some("keys/server.key"));
        assert_eq!(memory.csr.as_deref(), Some("csr/server.csr"));
    }

    #[test]
    fn recent_jobs_keep_latest_first() {
        let mut jobs = Vec::new();
        push_recent_job(&mut jobs, JobRecord::new(ActionKind::Identify, "first"));
        push_recent_job(&mut jobs, JobRecord::new(ActionKind::Convert, "second"));

        assert_eq!(jobs[0].summary, "second");
        assert_eq!(jobs[1].summary, "first");
    }

    #[test]
    fn built_in_profiles_include_expected_defaults() {
        let profile = profile_by_id("internal-ca").unwrap();
        assert_eq!(profile.key_size, 4096);
        assert_eq!(profile.extended_key_usage, "serverAuth, clientAuth");
        assert_eq!(profile.csr_defaults.organization, "Internal PKI");
    }

    #[test]
    fn path_suggestions_merge_workflow_recent_and_workspace() {
        let root = unique_temp_dir("suggestions");
        fs::create_dir_all(root.join("certs")).unwrap();
        fs::write(root.join("certs/server.crt"), "").unwrap();
        let snapshot = WorkspaceSnapshot::scan(&root);

        let mut recent = BTreeMap::new();
        recent.insert("view_cert.input".to_string(), "recent/last.crt".to_string());

        let workflow = WorkflowMemory {
            cert: Some("memory/current.crt".to_string()),
            ..WorkflowMemory::default()
        };

        let suggestions = path_suggestions(
            "crt",
            Some(ArtifactKind::Cert),
            &recent,
            &workflow,
            &snapshot,
        );

        assert_eq!(suggestions[0].path, "memory/current.crt");
        assert!(
            suggestions
                .iter()
                .any(|item| item.path == "recent/last.crt")
        );
        assert!(
            suggestions
                .iter()
                .any(|item| item.path.ends_with("certs/server.crt"))
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn path_completion_resolves_unique_match() {
        let suggestions = vec![
            PathSuggestion {
                display: "certs/server.crt".to_string(),
                path: "/tmp/certs/server.crt".to_string(),
            },
            PathSuggestion {
                display: "certs/client.crt".to_string(),
                path: "/tmp/certs/client.crt".to_string(),
            },
        ];

        assert_eq!(
            complete_path("server", &suggestions).as_deref(),
            Some("/tmp/certs/server.crt")
        );
        assert!(complete_path("certs", &suggestions).is_none());
    }

    #[test]
    fn smart_output_naming_uses_expected_extensions() {
        assert_eq!(
            suggest_output_path("certs/server.csr", ArtifactKind::Cert).as_deref(),
            Some("certs/server.crt")
        );
        assert_eq!(
            suggest_output_path("certs/server.pfx", ArtifactKind::LegacyPfx).as_deref(),
            Some("certs/server.legacy.pfx")
        );
    }

    #[test]
    fn preview_and_validation_steps_quote_paths_for_copy_paste() {
        let mut job = JobRecord::new(ActionKind::CreatePfx, "Create server bundle")
            .with_input("key", "keys/server bundle.key")
            .with_input("cert", "certs/server bundle.crt")
            .with_output("pfx", "dist/server bundle.pfx");

        let preview = build_preview(&job);
        assert!(
            preview
                .lines
                .iter()
                .any(|(label, value)| label == "Input key" && value == "'keys/server bundle.key'")
        );
        assert!(
            preview
                .lines
                .iter()
                .any(|(label, value)| label == "Output pfx" && value == "'dist/server bundle.pfx'")
        );

        let steps = validation_steps(&job);
        assert!(steps.iter().any(
            |step| step.command == "openssl pkcs12 -in 'dist/server bundle.pfx' -info -nokeys"
        ));
        assert!(steps.iter().any(|step| {
            step.command == "keytool -list -v -storetype PKCS12 -keystore 'dist/server bundle.pfx'"
        }));

        job.kind = ActionKind::Convert;
        job.outputs.clear();
        job.outputs
            .insert("output".to_string(), "out/converted bundle.pem".to_string());
        let steps = validation_steps(&job);
        assert_eq!(
            steps[0].command,
            "ssl-toolbox identify --input 'out/converted bundle.pem'"
        );
    }

    #[test]
    fn preview_includes_inputs_outputs_and_profile() {
        let mut job = JobRecord::new(ActionKind::CreatePfx, "Create server bundle")
            .with_input("key", "keys/server.key")
            .with_input("cert", "certs/server.crt")
            .with_output("pfx", "dist/server.pfx");
        job.profile = Some("web-server".to_string());

        let preview = build_preview(&job);
        assert_eq!(preview.title, "Create PFX");
        assert!(preview.lines.iter().any(|(label, _)| label == "Input key"));
        assert!(preview.lines.iter().any(|(label, _)| label == "Output pfx"));
        assert!(
            preview
                .lines
                .iter()
                .any(|(label, value)| label == "Profile" && value == "web-server")
        );
    }

    #[test]
    fn next_steps_reflect_follow_up_workflow() {
        let job = JobRecord::new(ActionKind::Generate, "Generated CSR");
        let memory = WorkflowMemory {
            csr: Some("csr/server.csr".to_string()),
            ..WorkflowMemory::default()
        };

        let steps = next_steps(&job, &memory);
        assert!(steps.iter().any(|step| step.contains("Submit the CSR")));
        assert!(steps.iter().any(|step| step.contains("csr/server.csr")));
    }

    #[test]
    fn validation_plan_matches_artifact_type() {
        let job = JobRecord::new(ActionKind::CreatePfx, "Built PFX")
            .with_output("pfx", "dist/server.pfx");
        let steps = validation_steps(&job);
        assert_eq!(steps.len(), 2);
        assert!(steps[0].command.contains("openssl pkcs12"));
        assert!(steps[1].command.contains("keytool -list"));
    }

    #[test]
    fn history_records_action_kind_for_repeat_clone() {
        let job = JobRecord::new(ActionKind::VerifyHttps, "Checked example.com")
            .with_input("https_host", "example.com");
        assert_eq!(job.kind.alias(), "https");
        assert_eq!(job.kind.title(), "Verify HTTPS Endpoint");
    }

    #[test]
    fn detect_artifact_kind_handles_chain_and_legacy_names() {
        assert_eq!(
            detect_artifact_kind(Path::new("bundle/server.chain.pem")),
            Some(ArtifactKind::Chain)
        );
        assert_eq!(
            detect_artifact_kind(Path::new("bundle/server.legacy.pfx")),
            Some(ArtifactKind::LegacyPfx)
        );
        assert_eq!(
            detect_artifact_kind(Path::new("bundle/server.key.pem")),
            Some(ArtifactKind::Key)
        );
        assert_eq!(
            detect_artifact_kind(Path::new("bundle/server.csr.pem")),
            Some(ArtifactKind::Csr)
        );
    }

    #[test]
    #[cfg(unix)]
    fn workspace_scan_skips_symlinked_directories_outside_root() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("scan-symlink-root");
        let outside = unique_temp_dir("scan-symlink-outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("leaked.key"), "").unwrap();
        fs::write(root.join("local.crt"), "").unwrap();
        symlink(&outside, root.join("external-link")).unwrap();

        let snapshot = WorkspaceSnapshot::scan(&root);
        let rendered = snapshot
            .files
            .iter()
            .map(|file| file.path.display().to_string())
            .collect::<Vec<_>>();

        assert!(rendered.iter().any(|path| path.ends_with("local.crt")));
        assert!(!rendered.iter().any(|path| path.contains("leaked.key")));
        assert!(!rendered.iter().any(|path| path.contains("external-link")));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }
}

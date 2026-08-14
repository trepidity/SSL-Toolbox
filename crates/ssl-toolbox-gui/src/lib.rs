//! Tauri command layer for the SSL Toolbox desktop UI.
//!
//! Every command here is a thin adapter: deserialize, call
//! `ssl_toolbox_ops::run`, serialize. No orchestration, no crypto, no policy —
//! all of that lives in `ssl-toolbox-ops` so the GUI and the CLI cannot drift
//! (ARCHITECTURE.md §10.6).
//!
//! ## Secret handling
//!
//! Passphrases are typed into a webview, which means they briefly live in a JS
//! heap this process does not control. Two rules contain that:
//!
//! 1. `OpRequest` carries passphrases as [`ssl_toolbox_ops::Secret`], which
//!    zeroizes on drop and cannot be serialized — so no secret is ever sent
//!    *back* across the IPC boundary, written to `state.json`, or captured in an
//!    audit entry.
//! 2. The frontend must clear its own passphrase fields on submit and never
//!    place them in persisted or shared state. See `ui/src/lib/secrets.ts`.
//!
//! Devtools are compiled in only for debug builds, so a release binary cannot
//! be used to inspect the webview heap.

use serde::Serialize;
use ssl_toolbox_ops::ops::{OpOutcome, OpRequest};
use ssl_toolbox_ops::workflow::{
    ActionKind, JobRecord, WorkspaceSnapshot, apply_job_to_workflow, push_recent_job,
};
use ssl_toolbox_ops::{endpoint, settings};

/// Errors cross the IPC boundary as a plain message.
///
/// `anyhow`'s full chain is flattened deliberately: the frontend shows one
/// human-readable line, and internal context (absolute paths, OpenSSL internals)
/// is not something to render in a UI.
type CmdResult<T> = Result<T, String>;

fn flatten(error: anyhow::Error) -> String {
    error.to_string()
}

/// Run one toolbox operation.
///
/// This is the GUI's only route to functionality — mirroring the CLI, which has
/// the same single entry point into ops.
#[tauri::command]
async fn run_op(request: OpRequest) -> CmdResult<OpOutcome> {
    // Operations are blocking (OpenSSL, sockets, disk). Move them off the async
    // runtime so a slow TLS scan cannot stall the IPC thread and freeze the UI.
    tauri::async_runtime::spawn_blocking(move || {
        let result = ssl_toolbox_ops::run(request).map_err(flatten)?;
        record_job(result.job);
        Ok(result.outcome)
    })
    .await
    .map_err(|error| format!("Operation task failed: {error}"))?
}

/// Append a completed job to persistent workflow memory.
///
/// Failure to persist is not worth failing the operation the user just ran, so
/// it is swallowed — the artifact on disk is the real result.
fn record_job(job: JobRecord) {
    // Reads — opening the settings screen, unlocking the vault — are operations
    // but not work. Recording them would push real certificate jobs out of a
    // twenty-entry history.
    if job.transient {
        return;
    }

    let mut state = settings::load_state();
    apply_job_to_workflow(&mut state.workflow, &job);
    push_recent_job(&mut state.recent_jobs, job);
    let _ = settings::save_state(&state);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionInfo {
    kind: ActionKind,
    alias: &'static str,
    title: &'static str,
}

/// The action catalogue backing the GUI's command palette.
#[tauri::command]
fn list_actions() -> Vec<ActionInfo> {
    let mut kinds = vec![
        ActionKind::CreateKey,
        ActionKind::Generate,
        ActionKind::CreatePfx,
        ActionKind::CreateLegacyPfx,
        ActionKind::NewConfig,
        ActionKind::ConfigFromExisting,
        ActionKind::ViewCert,
        ActionKind::ViewCsr,
        ActionKind::ViewPfx,
        ActionKind::VerifyHttps,
        ActionKind::VerifyLdaps,
        ActionKind::VerifySmtp,
        ActionKind::VerifySqlServer,
        ActionKind::Convert,
        ActionKind::Identify,
    ];

    if cfg!(feature = "sectigo") {
        kinds.push(ActionKind::CaSubmit);
        kinds.push(ActionKind::CaProfiles);
        kinds.push(ActionKind::CaSettings);
    }

    kinds
        .into_iter()
        .map(|kind| ActionInfo {
            kind,
            alias: kind.alias(),
            title: kind.title(),
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionState {
    workflow: ssl_toolbox_ops::workflow::WorkflowMemory,
    recent_jobs: Vec<JobRecord>,
    csr_defaults: ssl_toolbox_core::CsrDefaults,
    /// Past CA submissions, so the collect screen can offer their IDs back.
    ca_requests: Vec<ssl_toolbox_ops::workflow::CaRequestRecord>,
}

/// Workflow memory, recent jobs, and org CSR defaults, for pre-filling forms.
#[tauri::command]
fn load_session() -> SessionState {
    let config = settings::load_config();
    SessionState {
        workflow: config.ui_state.workflow,
        recent_jobs: config.ui_state.recent_jobs,
        csr_defaults: config.csr_defaults,
        ca_requests: config.ui_state.ca_requests,
    }
}

/// Scan a directory for certificate artifacts so the UI can offer real paths
/// instead of an empty file picker.
#[tauri::command]
async fn scan_workspace(root: Option<String>) -> CmdResult<WorkspaceSnapshot> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = root
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .ok_or_else(|| "Could not determine a directory to scan".to_string())?;
        Ok(WorkspaceSnapshot::scan(&root))
    })
    .await
    .map_err(|error| format!("Workspace scan failed: {error}"))?
}

/// Suggested directory name for exporting a verified endpoint's chain.
#[tauri::command]
fn default_export_dir(host: String, port: u16) -> String {
    endpoint::default_certificate_export_dir(&host, port)
}

/// Read the validation audit history so the UI can show endpoint drift.
#[tauri::command]
fn validation_history() -> Vec<ssl_toolbox_ops::audit::ValidationAuditEntry> {
    settings::load_validation_log()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|_app| {
            // Devtools are debug-only: a release build must not offer a way to
            // inspect a webview that has held a passphrase.
            #[cfg(debug_assertions)]
            {
                use tauri::Manager;
                if let Some(window) = _app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_op,
            list_actions,
            load_session,
            scan_workspace,
            default_export_dir,
            validation_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SSL Toolbox");
}

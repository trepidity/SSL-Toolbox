//! Remembered CA submissions, driven through the ops executor seam.
//!
//! Runs in its own test binary so its `$HOME` override cannot collide with the
//! credential tests', and serialises internally for the same reason those do:
//! `$HOME` decides where the workspace state lives and is process-global.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ssl_toolbox_ops::ops::{OpOutcome, OpRequest, run};
use ssl_toolbox_ops::workflow::{CaRequestRecord, push_ca_request};

fn environment_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct TempHome {
    path: PathBuf,
    previous: Option<std::ffi::OsString>,
}

impl TempHome {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ssl-toolbox-requests-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join(".ssl-toolbox")).expect("create temp home");

        let previous = std::env::var_os("HOME");
        // SAFETY: the environment guard serialises every test that touches HOME.
        unsafe { std::env::set_var("HOME", &path) };
        Self { path, previous }
    }

    fn write_state(&self, json: &str) {
        std::fs::write(self.path.join(".ssl-toolbox").join("state.json"), json)
            .expect("write state");
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // SAFETY: the guard is still held by the running test.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn listed() -> Vec<CaRequestRecord> {
    match run(OpRequest::CaListRequests)
        .expect("listing requests should succeed")
        .outcome
    {
        OpOutcome::CaRequestsListed { requests } => requests,
        other => panic!("expected CaRequestsListed, got {other:?}"),
    }
}

#[test]
fn recorded_submissions_are_offered_back_in_the_order_they_were_made() {
    // The collect screen's dropdown is built from this list, and the ID an
    // operator wants is almost always the one they just submitted.
    let _guard = environment_guard();
    let home = TempHome::new("listing");
    home.write_state(
        r#"{
  "ca_requests": [
    {"request_id": "222", "common_name": "new.example.test", "description": "",
     "profile": "4491", "csr_path": "/tmp/new.csr", "timestamp_secs": 2000},
    {"request_id": "111", "common_name": "old.example.test", "description": "renewal",
     "profile": "4491", "csr_path": "/tmp/old.csr", "timestamp_secs": 1000}
  ]
}"#,
    );

    let requests = listed();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.request_id.as_str())
            .collect::<Vec<_>>(),
        ["222", "111"]
    );
    // The subject is what makes one long numeric ID distinguishable from another
    // in a dropdown, so it has to survive the round trip.
    assert_eq!(requests[0].common_name, "new.example.test");
    assert_eq!(requests[1].description, "renewal");
}

#[test]
fn a_workspace_with_no_submissions_lists_nothing_rather_than_failing() {
    // First run has no state file at all; the collect screen still has to open.
    let _guard = environment_guard();
    let _home = TempHome::new("empty");

    assert!(listed().is_empty());
}

#[test]
fn state_written_before_submissions_existed_still_loads() {
    // `ca_requests` was added after `state.json` was already in the wild. A
    // missing field must not throw away the user's recent jobs and workflow.
    let _guard = environment_guard();
    let home = TempHome::new("legacy");
    home.write_state(r#"{"recent_paths": {"key": "/tmp/server.key"}, "last_menu_choice": "pfx"}"#);

    assert!(listed().is_empty());
}

#[test]
fn resubmitting_the_same_csr_refreshes_its_entry_instead_of_duplicating_it() {
    // Re-submitting after a CA-side error is normal recovery and can return an
    // ID already on the list. Two identical dropdown entries is a bug the user
    // cannot fix, and the newer metadata is the accurate one.
    let mut requests = vec![CaRequestRecord {
        request_id: "111".to_string(),
        common_name: "svc.example.test".to_string(),
        description: "first attempt".to_string(),
        profile: "4491".to_string(),
        csr_path: "/tmp/svc.csr".to_string(),
        timestamp_secs: 1000,
    }];

    push_ca_request(
        &mut requests,
        CaRequestRecord {
            request_id: "111".to_string(),
            common_name: "svc.example.test".to_string(),
            description: "second attempt".to_string(),
            profile: "4491".to_string(),
            csr_path: "/tmp/svc.csr".to_string(),
            timestamp_secs: 2000,
        },
    );

    assert_eq!(requests.len(), 1, "the same ID must not appear twice");
    assert_eq!(requests[0].description, "second attempt");
}

#[test]
fn the_remembered_list_does_not_grow_without_bound() {
    // Otherwise state.json grows forever and the dropdown becomes unusable.
    let mut requests = Vec::new();
    for index in 0..80 {
        push_ca_request(
            &mut requests,
            CaRequestRecord {
                request_id: format!("id-{index}"),
                common_name: String::new(),
                description: String::new(),
                profile: String::new(),
                csr_path: String::new(),
                timestamp_secs: index,
            },
        );
    }

    assert_eq!(requests.len(), 50);
    assert_eq!(requests[0].request_id, "id-79", "newest must be kept");
}

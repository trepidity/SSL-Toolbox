//! Credential resolution, driven through the ops executor seam (ARCHITECTURE.md §2.7).
//!
//! The behaviors here are the ones that decide whether a CA call authenticates
//! as the right identity, as nobody, or leaks a secret on the way. Each is
//! observable from `run(OpRequest)` — no test reaches into the vault module.
//!
//! **Why these run serially.** Three things they exercise are process-global:
//! `$HOME` (which decides where the vault lives), the `SCM_*` environment
//! variables, and the unlocked-credential cache. Rust runs tests in threads
//! inside one process, so a shared guard is the only way these can assert
//! anything stable. The guard is deliberately taken for the whole test body.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ssl_toolbox_ops::credentials::CredentialSource;
use ssl_toolbox_ops::ops::{OpOutcome, OpRequest, run};
use ssl_toolbox_ops::secret::Secret;

const CLIENT_ID: &str = "svc-ssl-toolbox-client-0001";
const CLIENT_SECRET: &str = "T0PS3CRET-client-secret-value";
const VAULT_PASSPHRASE: &str = "correct horse battery staple";

/// Serializes access to `$HOME`, the `SCM_*` variables, and the unlock cache.
fn environment_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A scratch `$HOME` so the vault lands somewhere disposable.
struct TempHome {
    path: PathBuf,
    previous: Option<std::ffi::OsString>,
}

impl TempHome {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ssl-toolbox-credentials-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp home");

        let previous = std::env::var_os("HOME");
        // SAFETY: the environment guard serializes every test that reads or
        // writes these variables, so no other thread observes the change.
        unsafe { std::env::set_var("HOME", &path) };

        clear_environment_credentials();
        run(OpRequest::CaLockCredentials).expect("start from a locked state");

        Self { path, previous }
    }

    fn vault_path(&self) -> PathBuf {
        self.path.join(".ssl-toolbox").join("credentials.vault")
    }

    fn config_dir(&self) -> PathBuf {
        self.path.join(".ssl-toolbox")
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = run(OpRequest::CaLockCredentials);
        clear_environment_credentials();
        // SAFETY: as above — the guard is still held by the running test.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn clear_environment_credentials() {
    // SAFETY: callers hold the environment guard.
    unsafe {
        std::env::remove_var("SCM_CLIENT_ID");
        std::env::remove_var("SCM_CLIENT_SECRET");
    }
}

fn set_environment_credentials(id: &str, secret: &str) {
    // SAFETY: callers hold the environment guard.
    unsafe {
        std::env::set_var("SCM_CLIENT_ID", id);
        std::env::set_var("SCM_CLIENT_SECRET", secret);
    }
}

fn store_credentials() {
    run(OpRequest::CaStoreCredentials {
        client_id: CLIENT_ID.to_string(),
        client_secret: Secret::new(CLIENT_SECRET),
        vault_passphrase: Secret::new(VAULT_PASSPHRASE),
    })
    .expect("storing credentials should succeed");
}

fn settings() -> Box<ssl_toolbox_ops::ops::CaSettingsView> {
    match run(OpRequest::CaLoadSettings)
        .expect("loading settings should succeed")
        .outcome
    {
        OpOutcome::CaSettingsLoaded(view) => view,
        other => panic!("expected CaSettingsLoaded, got {other:?}"),
    }
}

#[test]
fn credentials_saved_in_the_ui_are_the_ones_a_ca_call_would_use() {
    // The whole point of the change: an app launched from Finder has no shell
    // environment, so a credential saved through the UI must be resolvable with
    // nothing exported. If this regresses, the CA screens go back to failing
    // with "no credentials" on a machine where they are plainly configured.
    let _guard = environment_guard();
    let home = TempHome::new("saved");

    store_credentials();

    let status = settings().credentials;
    assert_eq!(status.active_source, Some(CredentialSource::Vault));
    assert!(status.unlocked, "storing should leave the vault usable");
    assert!(status.vault_present);
    assert!(
        home.vault_path().exists(),
        "the vault file should be on disk"
    );
    assert_eq!(status.client_id_length, Some(CLIENT_ID.chars().count()));
}

#[test]
fn environment_variables_still_override_the_vault() {
    // Automation contract: CI jobs and jump hosts export SCM_* today and must
    // keep authenticating as that identity even once a vault exists on the box.
    let _guard = environment_guard();
    let _home = TempHome::new("env-override");

    store_credentials();
    set_environment_credentials("ci-runner-client", "ci-runner-secret");

    let status = settings().credentials;
    assert_eq!(status.active_source, Some(CredentialSource::Environment));
    assert!(status.environment_override);
    assert_eq!(
        status.client_id_length,
        Some("ci-runner-client".chars().count()),
        "the environment identity, not the vault's, should be in play"
    );
}

#[test]
fn half_an_environment_override_is_refused_rather_than_silently_ignored() {
    // Exporting only SCM_CLIENT_ID reads as intent to use that identity. Falling
    // through to the vault would authenticate as somebody else and issue
    // certificates under the wrong account.
    let _guard = environment_guard();
    let _home = TempHome::new("half-env");

    store_credentials();
    // SAFETY: the environment guard is held.
    unsafe { std::env::set_var("SCM_CLIENT_ID", "only-the-id") };

    let error = run(OpRequest::CaListProfiles { debug: false })
        .expect_err("a half-configured override must not fall through to the vault");
    let message = error.to_string();
    assert!(
        message.contains("SCM_CLIENT_SECRET"),
        "the error should name the missing variable, got: {message}"
    );
}

#[test]
fn a_locked_vault_stops_a_ca_call_before_it_reaches_the_network() {
    // Resolution must fail closed. An unlocked-vault check that happened after
    // the HTTP client was built would send an unauthenticated request to the CA.
    let _guard = environment_guard();
    let _home = TempHome::new("locked");

    store_credentials();
    run(OpRequest::CaLockCredentials).expect("locking should succeed");

    let error = run(OpRequest::CaListProfiles { debug: false })
        .expect_err("a locked vault must refuse the call");
    let message = error.to_string();
    assert!(
        message.contains("locked"),
        "the error should say the credentials are locked, got: {message}"
    );
}

#[test]
fn unlocking_restores_the_stored_identity_and_a_wrong_passphrase_does_not() {
    let _guard = environment_guard();
    let _home = TempHome::new("unlock");

    store_credentials();
    run(OpRequest::CaLockCredentials).expect("locking should succeed");

    let wrong = run(OpRequest::CaUnlockCredentials {
        vault_passphrase: Secret::new("not the passphrase"),
    })
    .expect_err("the wrong passphrase must not unlock the vault");
    assert!(
        !settings().credentials.unlocked,
        "a failed unlock must leave the vault locked, error was: {wrong}"
    );

    run(OpRequest::CaUnlockCredentials {
        vault_passphrase: Secret::new(VAULT_PASSPHRASE),
    })
    .expect("the correct passphrase should unlock the vault");

    let status = settings().credentials;
    assert!(status.unlocked);
    assert_eq!(status.client_id_length, Some(CLIENT_ID.chars().count()));
}

#[test]
fn no_credential_ever_lands_in_a_configuration_file() {
    // ARCHITECTURE.md §11.3 rule 2. The settings screen writes endpoint values
    // and credentials through one code path each; this is the test that catches
    // somebody merging them into a single "save everything" JSON write.
    let _guard = environment_guard();
    let home = TempHome::new("no-plaintext");

    store_credentials();
    run(OpRequest::CaSaveSettings {
        api_base: "https://ca.example.test".to_string(),
        org_id: "12345".to_string(),
        product_code: "4491".to_string(),
        token_url: "https://idp.example.test/token".to_string(),
    })
    .expect("saving settings should succeed");

    let mut inspected = 0;
    for entry in std::fs::read_dir(home.config_dir()).expect("config dir should exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        inspected += 1;
        let contents = std::fs::read_to_string(&path).expect("readable config file");
        assert!(
            !contents.contains(CLIENT_SECRET),
            "{} contains the client secret",
            path.display()
        );
        assert!(
            !contents.contains(CLIENT_ID),
            "{} contains the client ID",
            path.display()
        );
    }
    assert!(inspected > 0, "the settings save should have written JSON");

    // And the vault itself holds ciphertext, not a base64-flavoured plaintext.
    let vault = std::fs::read_to_string(home.vault_path()).expect("vault should be readable");
    assert!(!vault.contains(CLIENT_SECRET));
    assert!(!vault.contains(CLIENT_ID));
    assert!(!vault.contains(VAULT_PASSPHRASE));
}

#[cfg(unix)]
#[test]
fn the_credential_vault_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = environment_guard();
    let home = TempHome::new("permissions");

    store_credentials();

    let mode = std::fs::metadata(home.vault_path())
        .expect("vault metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "the vault must not be group- or world-readable"
    );
}

#[test]
fn clearing_the_vault_removes_both_the_file_and_the_unlocked_copy() {
    // Deleting the file while leaving the process holding the credentials would
    // make "Delete vault" look like it worked until the next launch.
    let _guard = environment_guard();
    let home = TempHome::new("clear");

    store_credentials();
    run(OpRequest::CaClearCredentials).expect("clearing should succeed");

    assert!(!home.vault_path().exists(), "the vault file should be gone");
    let status = settings().credentials;
    assert!(!status.unlocked);
    assert!(!status.vault_present);
    assert_eq!(status.active_source, None);
}

#[test]
fn saved_endpoint_settings_are_what_a_later_load_reports() {
    // Both front-ends read this file, and the CLI writes it too — the keys are a
    // contract, not an implementation detail. A renamed field would silently
    // reset the org ID to empty on the next launch.
    let _guard = environment_guard();
    let _home = TempHome::new("endpoint");

    run(OpRequest::CaSaveSettings {
        api_base: "https://ca.example.test".to_string(),
        org_id: "org-9910".to_string(),
        product_code: "4491".to_string(),
        token_url: "https://idp.example.test/protocol/openid-connect/token".to_string(),
    })
    .expect("saving settings should succeed");

    let view = settings();
    assert_eq!(view.api_base, "https://ca.example.test");
    assert_eq!(view.org_id, "org-9910");
    assert_eq!(view.product_code, "4491");
    assert_eq!(
        view.token_url,
        "https://idp.example.test/protocol/openid-connect/token"
    );
}

#[test]
fn opening_the_settings_screen_does_not_enter_the_job_history() {
    // Recent jobs holds twenty entries. If a settings read counted, opening the
    // screen a few times would evict the certificate work the history exists for.
    let _guard = environment_guard();
    let _home = TempHome::new("transient");

    let result = run(OpRequest::CaLoadSettings).expect("loading settings should succeed");
    assert!(
        result.job.transient,
        "a settings read must be marked transient"
    );

    let saved = run(OpRequest::CaSaveSettings {
        api_base: "https://ca.example.test".to_string(),
        org_id: String::new(),
        product_code: String::new(),
        token_url: "https://idp.example.test/token".to_string(),
    })
    .expect("saving settings should succeed");
    assert!(
        !saved.job.transient,
        "an actual settings change is worth recording"
    );
}
